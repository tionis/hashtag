package main

import (
	"context"
	stderrors "errors"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"github.com/benbjohnson/litestream"
	_ "github.com/benbjohnson/litestream/s3"
	"github.com/tionis/forge/internal/forgeconfig"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

const (
	forgeNodeNameEnv              = "FORGE_NODE_NAME"
	forgeNodeSSHKeyEnv            = "FORGE_NODE_SSH_KEY"
	forgeNodeSSHKeyPassphraseEnv  = "FORGE_NODE_SSH_KEY_PASSPHRASE"
	defaultSnapshotReplicaPathKey = "db/snapshot"
	defaultRefsReplicaPathPrefix  = "gc/node-refs"
	defaultRefsReplicaName        = "refs"
)

type backgroundReplicaTarget struct {
	Name         string
	DBPath       string
	ReplicaURL   string
	UseAgeCrypto bool
}

type backgroundReplicationManager struct {
	handles []backgroundReplicaHandle
}

type backgroundReplicaHandle struct {
	Name string
	DB   *litestream.DB
}

type snapshotEncryptionMaterial struct {
	Recipients []age.Recipient
	Identities []age.Identity
}

func runReplicateDaemonCommand(args []string) error {
	fs := flag.NewFlagSet("replicate daemon", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s replicate daemon [options]\n\n", os.Args[0])
		fmt.Fprintln(fs.Output(), "Run the background database replication daemon.")
		fmt.Fprintln(fs.Output(), "\nOptions:")
		fs.PrintDefaults()
		fmt.Fprintln(fs.Output(), "\nEnvironment:")
		fmt.Fprintf(fs.Output(), "  %s, %s, %s\n", forgeNodeNameEnv, forgeNodeSSHKeyEnv, forgeNodeSSHKeyPassphraseEnv)
	}

	defaultNodeName := defaultReplicationNodeName()
	defaultNodeSSHKey := strings.TrimSpace(os.Getenv(forgeNodeSSHKeyEnv))
	defaultNodeSSHKeyPassphrase := strings.TrimSpace(os.Getenv(forgeNodeSSHKeyPassphraseEnv))
	snapshotDBPath := fs.String("snapshot-db", forgeconfig.SnapshotDBPath(), "Path to snapshot database")
	refsDBPath := fs.String("refs-db", forgeconfig.RefsDBPath(), "Path to refs database")
	nodeName := fs.String("node-name", defaultNodeName, "Node name used to resolve trust-node recipient mapping")
	nodePublicKey := fs.String("node-public-key", "", "Override node SSH public key recipient (authorized_keys format)")
	nodeSSHKey := fs.String("node-ssh-key", defaultNodeSSHKey, "Path to node SSH private key used to decrypt encrypted replica data")
	nodeSSHKeyPassphrase := fs.String("node-ssh-key-passphrase", defaultNodeSSHKeyPassphrase, "Passphrase for encrypted -node-ssh-key")

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments: %s", strings.Join(fs.Args(), " "))
	}

	logger := log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	session, err := loadRemoteBackendSession(ctx)
	if err != nil {
		return fmt.Errorf("load remote backend session for replication daemon: %w", err)
	}

	normalizedNodeName := strings.TrimSpace(*nodeName)
	if normalizedNodeName == "" {
		normalizedNodeName = defaultReplicationNodeName()
	}
	resolvedNodePublicKey, err := resolveReplicationNodePublicKey(session.Config, normalizedNodeName, *nodePublicKey)
	if err != nil {
		return err
	}
	snapshotEnc, err := buildSnapshotEncryptionMaterial(resolvedNodePublicKey, *nodeSSHKey, *nodeSSHKeyPassphrase)
	if err != nil {
		return err
	}

	targets, err := buildBackgroundReplicaTargets(session.Bootstrap, session.Config, normalizedNodeName, *snapshotDBPath, *refsDBPath)
	if err != nil {
		return err
	}

	manager, err := startBackgroundReplication(ctx, targets, snapshotEnc, logger)
	if err != nil {
		return err
	}
	defer func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 15*time.Second)
		_ = manager.Close(closeCtx)
		closeCancel()
	}()

	snapshotPath := ""
	refsPath := ""
	for _, target := range targets {
		switch target.Name {
		case "snapshot":
			snapshotPath = target.DBPath
		case "refs":
			refsPath = target.DBPath
		}
	}

	logger.Printf("replication daemon started: snapshot=%s refs=%s node=%s", snapshotPath, refsPath, normalizedNodeName)
	<-ctx.Done()
	return nil
}

func defaultReplicationNodeName() string {
	if env := strings.TrimSpace(os.Getenv(forgeNodeNameEnv)); env != "" {
		return env
	}
	hostname, err := os.Hostname()
	if err == nil && strings.TrimSpace(hostname) != "" {
		return hostname
	}
	return "unknown-node"
}

func buildBackgroundReplicaTargets(bootstrap remoteS3Bootstrap, cfg remoteGlobalConfig, nodeName string, snapshotDBPath string, refsDBPath string) ([]backgroundReplicaTarget, error) {
	snapshotPath, err := filepath.Abs(strings.TrimSpace(snapshotDBPath))
	if err != nil {
		return nil, fmt.Errorf("resolve snapshot db path: %w", err)
	}
	refsPath, err := filepath.Abs(strings.TrimSpace(refsDBPath))
	if err != nil {
		return nil, fmt.Errorf("resolve refs db path: %w", err)
	}

	snapshotURL, err := buildReplicaURLForPath(bootstrap, cfg, strings.Split(defaultSnapshotReplicaPathKey, "/")...)
	if err != nil {
		return nil, fmt.Errorf("build snapshot replica URL: %w", err)
	}

	nodeSegment, err := sanitizeS3PathSegment(nodeName)
	if err != nil {
		return nil, fmt.Errorf("sanitize node name for refs replica path: %w", err)
	}
	refsPrefix := strings.Split(defaultRefsReplicaPathPrefix, "/")
	refsSegments := make([]string, 0, len(refsPrefix)+2)
	refsSegments = append(refsSegments, refsPrefix...)
	refsSegments = append(refsSegments, nodeSegment, defaultRefsReplicaName)
	refsURL, err := buildReplicaURLForPath(bootstrap, cfg, refsSegments...)
	if err != nil {
		return nil, fmt.Errorf("build refs replica URL: %w", err)
	}

	return []backgroundReplicaTarget{
		{
			Name:         "snapshot",
			DBPath:       snapshotPath,
			ReplicaURL:   snapshotURL,
			UseAgeCrypto: true,
		},
		{
			Name:         "refs",
			DBPath:       refsPath,
			ReplicaURL:   refsURL,
			UseAgeCrypto: false,
		},
	}, nil
}

func sanitizeS3PathSegment(value string) (string, error) {
	segment := strings.TrimSpace(value)
	if segment == "" {
		return "", fmt.Errorf("empty segment")
	}
	segment = strings.ReplaceAll(segment, "/", "_")
	segment = strings.ReplaceAll(segment, "\\", "_")
	segment = strings.ReplaceAll(segment, " ", "_")
	segment = normalizeS3ObjectKey(segment)
	if segment == "" {
		return "", fmt.Errorf("empty segment after normalization")
	}
	return segment, nil
}

func buildReplicaURLForPath(bootstrap remoteS3Bootstrap, cfg remoteGlobalConfig, segments ...string) (string, error) {
	bucket := strings.TrimSpace(bootstrap.Bucket)
	if bucket == "" {
		return "", fmt.Errorf("bucket is required for replication")
	}

	parts := make([]string, 0, len(segments)+1)
	if base := normalizeS3Prefix(cfg.S3.ObjectPrefix); base != "" {
		parts = append(parts, base)
	}
	for _, segment := range segments {
		normalized := normalizeS3ObjectKey(segment)
		if normalized == "" {
			continue
		}
		parts = append(parts, normalized)
	}
	if len(parts) == 0 {
		return "", fmt.Errorf("replica path must not be empty")
	}

	u := &url.URL{
		Scheme: "s3",
		Host:   bucket,
		Path:   "/" + strings.Join(parts, "/"),
	}

	query := u.Query()
	if endpoint := ensureHTTPSEndpointScheme(strings.TrimSpace(bootstrap.EndpointURL)); endpoint != "" {
		query.Set("endpoint", endpoint)
	}
	if region := strings.TrimSpace(bootstrap.Region); region != "" {
		query.Set("region", region)
	}
	if bootstrap.ForcePathStyle {
		query.Set("forcePathStyle", "true")
	}
	u.RawQuery = query.Encode()
	return u.String(), nil
}

func resolveReplicationNodePublicKey(cfg remoteGlobalConfig, nodeName string, override string) (string, error) {
	override = strings.TrimSpace(override)
	if override != "" {
		_, authorized, err := parseAuthorizedKeyString(override)
		if err != nil {
			return "", fmt.Errorf("parse -node-public-key: %w", err)
		}
		return authorized, nil
	}
	for _, node := range cfg.Trust.Nodes {
		if node.Revoked {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(node.Name), strings.TrimSpace(nodeName)) {
			_, authorized, err := parseAuthorizedKeyString(node.PublicKey)
			if err != nil {
				return "", fmt.Errorf("parse trust node %q public key: %w", node.Name, err)
			}
			return authorized, nil
		}
	}
	return "", fmt.Errorf("no active trust node found for node name %q (set -node-public-key to override)", nodeName)
}

func buildSnapshotEncryptionMaterial(nodePublicKey string, nodeSSHKeyPath string, nodeSSHKeyPassphrase string) (snapshotEncryptionMaterial, error) {
	nodeRecipient, err := parseAgeRecipient(nodePublicKey)
	if err != nil {
		return snapshotEncryptionMaterial{}, fmt.Errorf("parse node age recipient: %w", err)
	}

	recipients := []age.Recipient{nodeRecipient}
	roots, err := loadTrustedRootPublicKeys()
	if err != nil {
		return snapshotEncryptionMaterial{}, fmt.Errorf("load trusted root keys for snapshot encryption recipients: %w", err)
	}
	for _, root := range roots {
		rootAuthorized := normalizeAuthorizedKey(root)
		rootRecipient, parseErr := parseAgeRecipient(rootAuthorized)
		if parseErr != nil {
			return snapshotEncryptionMaterial{}, fmt.Errorf("parse trusted root recipient %q: %w", rootAuthorized, parseErr)
		}
		recipients = append(recipients, rootRecipient)
	}

	identity, err := loadNodeAgeIdentity(nodePublicKey, nodeSSHKeyPath, nodeSSHKeyPassphrase)
	if err != nil {
		return snapshotEncryptionMaterial{}, err
	}
	return snapshotEncryptionMaterial{
		Recipients: recipients,
		Identities: []age.Identity{identity},
	}, nil
}

func parseAgeRecipient(value string) (age.Recipient, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil, fmt.Errorf("empty recipient value")
	}
	if strings.HasPrefix(trimmed, "age1") {
		recipient, err := age.ParseX25519Recipient(trimmed)
		if err != nil {
			return nil, err
		}
		return recipient, nil
	}
	return agessh.ParseRecipient(trimmed)
}

func loadNodeAgeIdentity(nodePublicKey string, nodeSSHKeyPath string, nodeSSHKeyPassphrase string) (age.Identity, error) {
	path := strings.TrimSpace(nodeSSHKeyPath)
	if path == "" {
		return nil, fmt.Errorf("snapshot encryption requires node SSH private key (-node-ssh-key or %s)", forgeNodeSSHKeyEnv)
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve node SSH private key path: %w", err)
	}
	raw, err := os.ReadFile(absPath)
	if err != nil {
		return nil, fmt.Errorf("read node SSH private key %q: %w", absPath, err)
	}

	identity, err := agessh.ParseIdentity(raw)
	if err == nil {
		return identity, nil
	}

	var missing *ssh.PassphraseMissingError
	if !stderrors.As(err, &missing) {
		return nil, fmt.Errorf("parse node SSH private key %q: %w", absPath, err)
	}

	pub, _, parseErr := parseAuthorizedKeyString(nodePublicKey)
	if parseErr != nil {
		return nil, fmt.Errorf("parse node public key for encrypted private key %q: %w", absPath, parseErr)
	}

	passphrase := strings.TrimSpace(nodeSSHKeyPassphrase)
	if passphrase == "" {
		if !terminal.IsTerminal(int(os.Stdin.Fd())) {
			return nil, fmt.Errorf("node SSH private key %q is encrypted; provide -node-ssh-key-passphrase or %s", absPath, forgeNodeSSHKeyPassphraseEnv)
		}
		prompted, promptErr := promptSSHKeyPassphrase(absPath)
		if promptErr != nil {
			return nil, promptErr
		}
		passphrase = prompted
	}

	if _, parseErr := ssh.ParseRawPrivateKeyWithPassphrase(raw, []byte(passphrase)); parseErr != nil {
		return nil, fmt.Errorf("parse encrypted node SSH private key %q: %w", absPath, parseErr)
	}

	identity, err = agessh.NewEncryptedSSHIdentity(pub, raw, func() ([]byte, error) {
		return []byte(passphrase), nil
	})
	if err != nil {
		return nil, fmt.Errorf("build encrypted SSH age identity for %q: %w", absPath, err)
	}
	return identity, nil
}

func promptSSHKeyPassphrase(path string) (string, error) {
	fmt.Fprintf(os.Stderr, "Enter passphrase for SSH key %s: ", path)
	passphraseBytes, err := terminal.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("read SSH key passphrase: %w", err)
	}
	return strings.TrimSpace(string(passphraseBytes)), nil
}

func startBackgroundReplication(ctx context.Context, targets []backgroundReplicaTarget, snapshotEnc snapshotEncryptionMaterial, logger *log.Logger) (*backgroundReplicationManager, error) {
	manager := &backgroundReplicationManager{}
	cleanup := func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 15*time.Second)
		_ = manager.Close(closeCtx)
		closeCancel()
	}

	for _, target := range targets {
		if err := ensureParentDirForFile(target.DBPath); err != nil {
			cleanup()
			return nil, err
		}

		client, err := litestream.NewReplicaClientFromURL(target.ReplicaURL)
		if err != nil {
			cleanup()
			return nil, fmt.Errorf("create litestream replica client for %s: %w", target.Name, err)
		}

		if target.UseAgeCrypto {
			client, err = newAgeEncryptedReplicaClient(client, snapshotEnc.Recipients, snapshotEnc.Identities)
			if err != nil {
				cleanup()
				return nil, fmt.Errorf("configure encrypted replica client for %s: %w", target.Name, err)
			}
		}

		db := litestream.NewDB(target.DBPath)
		replica := litestream.NewReplicaWithClient(db, client)
		db.Replica = replica
		if err := db.Open(); err != nil {
			cleanup()
			return nil, fmt.Errorf("open litestream db for %s: %w", target.Name, err)
		}

		logger.Printf("replication enabled (%s): db=%s replica=%s encryption=%t", target.Name, target.DBPath, maskURLCredentialsForLog(target.ReplicaURL), target.UseAgeCrypto)
		manager.handles = append(manager.handles, backgroundReplicaHandle{
			Name: target.Name,
			DB:   db,
		})
	}

	return manager, nil
}

func (m *backgroundReplicationManager) Close(ctx context.Context) error {
	if m == nil {
		return nil
	}
	var closeErr error
	for _, handle := range m.handles {
		if handle.DB == nil {
			continue
		}
		if err := handle.DB.Close(ctx); err != nil {
			closeErr = stderrors.Join(closeErr, fmt.Errorf("%s replication close: %w", handle.Name, err))
		}
	}
	return closeErr
}
