package main

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/tionis/forge/internal/forgeconfig"
)

const (
	projectBinaryName = "forge"
	projectModulePath = "github.com/tionis/forge"

	exitCodeFailure         = 1
	exitCodePartialWarnings = 2
)

type cliExitError struct {
	code  int
	cause error
}

func (e cliExitError) Error() string {
	if e.cause == nil {
		return ""
	}
	return e.cause.Error()
}

func (e cliExitError) Unwrap() error {
	return e.cause
}

func (e cliExitError) ExitCode() int {
	return e.code
}

func newCLIExitError(code int, cause error) error {
	if cause == nil {
		return nil
	}
	return cliExitError{code: code, cause: cause}
}

func resolveCLIExitCode(err error) int {
	if err == nil {
		return 0
	}
	if coder, ok := err.(interface{ ExitCode() int }); ok {
		code := coder.ExitCode()
		if code > 0 {
			return code
		}
	}
	return exitCodeFailure
}

func main() {
	if err := executeCLI(os.Args[1:]); err != nil {
		log.Print(err)
		os.Exit(resolveCLIExitCode(err))
	}
}

func executeCLI(args []string) error {
	root := newRootCommand()
	root.SetArgs(normalizeLegacySingleDashLongArgs(args))
	return root.Execute()
}

func runLegacyCommandWithCobra(run func([]string) error) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		return run(rebuildLegacyRunArgs(cmd, args))
	}
}

func rebuildLegacyRunArgs(cmd *cobra.Command, args []string) []string {
	out := make([]string, 0, len(args)+8)
	cmd.Flags().Visit(func(f *flag.Flag) {
		if strings.TrimSpace(f.Name) == "" || f.Name == "help" {
			return
		}
		// Skip hidden shorthand-alias helper flags if any are present.
		if strings.HasPrefix(f.Name, "__") {
			return
		}
		if f.Value.Type() == "bool" {
			out = append(out, "--"+f.Name+"="+f.Value.String())
			return
		}
		out = append(out, "--"+f.Name, f.Value.String())
	})
	out = append(out, args...)
	return out
}

func normalizeLegacySingleDashLongArgs(args []string) []string {
	if len(args) == 0 {
		return args
	}
	out := make([]string, 0, len(args))
	passthrough := false
	for _, arg := range args {
		if passthrough {
			out = append(out, arg)
			continue
		}
		if arg == "--" {
			passthrough = true
			out = append(out, arg)
			continue
		}
		if !strings.HasPrefix(arg, "-") || strings.HasPrefix(arg, "--") || arg == "-" {
			out = append(out, arg)
			continue
		}
		if looksLikeNegativeNumberArg(arg) {
			out = append(out, arg)
			continue
		}
		withoutDash := arg[1:]
		if len(withoutDash) <= 1 {
			out = append(out, arg)
			continue
		}
		out = append(out, "--"+withoutDash)
	}
	return out
}

func looksLikeNegativeNumberArg(arg string) bool {
	if len(arg) < 2 || arg[0] != '-' {
		return false
	}
	_, err := strconv.ParseFloat(arg, 64)
	return err == nil
}

func newRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:           projectBinaryName,
		Short:         "Forge is a multi-tool CLI for filesystem workflows.",
		Long:          fmt.Sprintf("Forge is a multi-tool CLI for filesystem workflows.\nModule: %s", projectModulePath),
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.AddCommand(newHashCommand())
	root.AddCommand(newDupesCommand())
	root.AddCommand(newSnapCommand())
	root.AddCommand(newSnapshotCommand())
	root.AddCommand(newHashmapCommand())
	root.AddCommand(newTagsCommand())
	root.AddCommand(newConfigCommand())
	root.AddCommand(newSkillsCommand())
	root.AddCommand(newRemoteCommand())
	root.AddCommand(newBlobCommand())
	root.AddCommand(newVectorCommand())
	root.AddCommand(newReplicateCommand())
	root.AddCommand(newCompletionCommand(root))
	return root
}

func newHashCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "hash [options] [path]",
		Short: "Hash files and cache digests in xattrs.",
		RunE:  runLegacyCommandWithCobra(runHashCommand),
	}
	flags := cmd.Flags()
	flags.IntP("workers", "w", runtime.NumCPU(), "Number of parallel workers")
	flags.BoolP("verbose", "v", false, "Verbose output")
	flags.String("algos", "blake3", "Comma-separated list of hash algorithms to use")
	flags.Bool("clean", false, "Force invalidation of existing caches (re-hash everything)")
	flags.Bool("remove", false, "Remove all checksum attributes from files instead of hashing")
	flags.StringP("output", "o", outputModeAuto, "Output mode: auto|pretty|kv|json")
	return cmd
}

func newDupesCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dupes [options] [path]",
		Short: "Find duplicate files by content.",
		RunE:  runLegacyCommandWithCobra(runDupesCommand),
	}
	flags := cmd.Flags()
	flags.Int64("min-size", 1, "Only consider files with size >= min-size bytes")
	flags.Bool("cache", true, "Use checksum xattr cache when available")
	flags.Bool("update-cache", false, "Update checksum xattrs for newly hashed files")
	flags.StringP("output", "o", "", "Output mode: auto|pretty|table|json|paths|paths0")
	flags.BoolP("verbose", "v", false, "Verbose output")
	return cmd
}

func newSnapCommand() *cobra.Command {
	snapCmd := &cobra.Command{
		Use:   "snap",
		Short: "Work with snapper-based btrfs snapshots using git-like workflows.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	configs := &cobra.Command{
		Use:   "configs [options]",
		Short: "List snapper configs and subvolumes.",
		RunE:  runLegacyCommandWithCobra(runSnapConfigsCommand),
	}
	configs.Flags().Bool("no-dbus", false, "Call snapper with --no-dbus")
	configs.Flags().StringP("output", "o", outputModeAuto, "Output mode: auto|pretty|kv|json")
	snapCmd.AddCommand(configs)

	logCmd := &cobra.Command{
		Use:   "log [options]",
		Short: "List snapshot history with optional per-snapshot change stats.",
		RunE:  runLegacyCommandWithCobra(runSnapLogCommand),
	}
	logFlags := logCmd.Flags()
	logFlags.StringP("path", "p", ".", "Path used to resolve the snapper config")
	logFlags.StringP("config", "c", "", "Explicit snapper config (skip path-based selection)")
	logFlags.IntP("limit", "n", 20, "Maximum number of snapshots to show (0 for all)")
	logFlags.Bool("stat", true, "Include change summary against the previous snapshot")
	logFlags.Bool("no-dbus", false, "Call snapper with --no-dbus")
	logFlags.StringP("output", "o", outputModeAuto, "Output mode: auto|pretty|kv|json")
	snapCmd.AddCommand(logCmd)

	status := &cobra.Command{
		Use:   "status [options]",
		Short: "Show changes between two snapper revisions (default latest..0).",
		RunE:  runLegacyCommandWithCobra(runSnapStatusCommand),
	}
	statusFlags := status.Flags()
	statusFlags.StringP("path", "p", ".", "Path used to resolve the snapper config")
	statusFlags.StringP("config", "c", "", "Explicit snapper config (skip path-based selection)")
	statusFlags.StringP("from", "f", "latest", "From revision selector (latest|previous|<number>)")
	statusFlags.StringP("to", "t", "0", "To revision selector (latest|previous|current|<number>)")
	statusFlags.Bool("no-dbus", false, "Call snapper with --no-dbus")
	statusFlags.StringP("output", "o", outputModeAuto, "Output mode: auto|pretty|kv|json")
	snapCmd.AddCommand(status)

	diffCmd := &cobra.Command{
		Use:   "diff [options] [files...]",
		Short: "Show textual diff between two snapper revisions (default latest..0).",
		RunE:  runLegacyCommandWithCobra(runSnapDiffCommand),
	}
	diffFlags := diffCmd.Flags()
	diffFlags.StringP("path", "p", ".", "Path used to resolve the snapper config")
	diffFlags.StringP("config", "c", "", "Explicit snapper config (skip path-based selection)")
	diffFlags.StringP("from", "f", "latest", "From revision selector (latest|previous|<number>)")
	diffFlags.StringP("to", "t", "0", "To revision selector (latest|previous|current|<number>)")
	diffFlags.Bool("no-dbus", false, "Call snapper with --no-dbus")
	snapCmd.AddCommand(diffCmd)

	restore := &cobra.Command{
		Use:     "restore [options] [files...]",
		Aliases: []string{"undo"},
		Short:   "Undo changes (snapper undochange) between two revisions.",
		RunE:    runLegacyCommandWithCobra(runSnapRestoreCommand),
	}
	restoreFlags := restore.Flags()
	restoreFlags.StringP("path", "p", ".", "Path used to resolve the snapper config")
	restoreFlags.StringP("config", "c", "", "Explicit snapper config (skip path-based selection)")
	restoreFlags.StringP("from", "f", "latest", "From revision selector (latest|previous|<number>)")
	restoreFlags.StringP("to", "t", "0", "To revision selector (latest|previous|current|<number>)")
	restoreFlags.BoolP("apply", "a", false, "Apply undochange (default is preview only)")
	restoreFlags.Bool("no-dbus", false, "Call snapper with --no-dbus")
	restoreFlags.StringP("output", "o", outputModeAuto, "Output mode: auto|pretty|kv|json")
	snapCmd.AddCommand(restore)

	save := &cobra.Command{
		Use:     "save [options]",
		Aliases: []string{"create"},
		Short:   "Create a snapper snapshot for the selected config/path.",
		RunE:    runLegacyCommandWithCobra(runSnapSaveCommand),
	}
	saveFlags := save.Flags()
	saveFlags.StringP("path", "p", ".", "Path used to resolve the snapper config")
	saveFlags.StringP("config", "c", "", "Explicit snapper config (skip path-based selection)")
	saveFlags.String("description", "", "Snapshot description")
	saveFlags.String("cleanup", "", "Snapper cleanup algorithm")
	saveFlags.String("userdata", "", "Snapper userdata string")
	saveFlags.Bool("no-dbus", false, "Call snapper with --no-dbus")
	saveFlags.StringP("output", "o", outputModeAuto, "Output mode: auto|pretty|kv|json")
	snapCmd.AddCommand(save)

	return snapCmd
}

func newSnapshotCommand() *cobra.Command {
	snapshotCmd := &cobra.Command{
		Use:   "snapshot",
		Short: "Create, inspect, and diff filesystem snapshots.",
		RunE:  runLegacyCommandWithCobra(runSnapshotCreateCommand),
	}
	addSnapshotCreateFlags(snapshotCmd.Flags(), "Fail immediately on scan warnings (permission or transient path errors)")

	create := &cobra.Command{
		Use:   "create [options] [path]",
		Short: "Create a snapshot pointer for a filesystem path.",
		RunE:  runLegacyCommandWithCobra(runSnapshotCreateCommand),
	}
	addSnapshotCreateFlags(create.Flags(), "Fail immediately on scan warnings (permission or transient path errors)")
	snapshotCmd.AddCommand(create)

	history := &cobra.Command{
		Use:   "history [options] [path]",
		Short: "List snapshots for a path.",
		RunE:  runLegacyCommandWithCobra(runSnapshotHistoryCommand),
	}
	history.Flags().StringP("db", "d", defaultSnapshotDBPath(), "Path to snapshot database")
	history.Flags().IntP("limit", "n", 20, "Maximum number of history entries to return")
	history.Flags().StringP("output", "o", outputModeAuto, "Output mode: auto|pretty|kv|json")
	snapshotCmd.AddCommand(history)

	diff := &cobra.Command{
		Use:   "diff [options] [path]",
		Short: "Show differences between two snapshots.",
		RunE:  runLegacyCommandWithCobra(runSnapshotDiffCommand),
	}
	diff.Flags().StringP("db", "d", defaultSnapshotDBPath(), "Path to snapshot database")
	diff.Flags().Int64P("from", "f", 0, "Older snapshot time (unix nanoseconds)")
	diff.Flags().Int64P("to", "t", 0, "Newer snapshot time (unix nanoseconds)")
	diff.Flags().StringP("output", "o", outputModeAuto, "Output mode: auto|pretty|kv|json")
	snapshotCmd.AddCommand(diff)

	inspect := &cobra.Command{
		Use:   "inspect [options]",
		Short: "Inspect entries and tags for a tree hash.",
		RunE:  runLegacyCommandWithCobra(runSnapshotInspectCommand),
	}
	inspect.Flags().StringP("db", "d", defaultSnapshotDBPath(), "Path to snapshot database")
	inspect.Flags().StringP("tree", "T", "", "Tree hash to inspect (required)")
	inspect.Flags().BoolP("recursive", "r", false, "Recursively inspect descendant tree entries")
	inspect.Flags().StringP("output", "o", outputModeAuto, "Output mode: auto|pretty|kv|json")
	snapshotCmd.AddCommand(inspect)

	query := &cobra.Command{
		Use:   "query [options]",
		Short: "Query tree entries by required tags.",
		RunE:  runLegacyCommandWithCobra(runSnapshotQueryCommand),
	}
	query.Flags().StringP("db", "d", defaultSnapshotDBPath(), "Path to snapshot database")
	query.Flags().StringP("tree", "T", "", "Tree hash to query (required)")
	query.Flags().StringP("tags", "t", "", "Comma-separated list of required tags (required)")
	query.Flags().StringP("kind", "k", snapshotKindFile, "Entry kind filter: file|symlink|tree|all")
	query.Flags().StringP("output", "o", outputModeAuto, "Output mode: auto|pretty|kv|json")
	snapshotCmd.AddCommand(query)

	remote := &cobra.Command{
		Use:   "remote [options] <remote:path>",
		Short: "Create a snapshot pointer for an rclone remote target.",
		RunE:  runLegacyCommandWithCobra(runSnapshotRemoteCommand),
	}
	addSnapshotCreateFlags(remote.Flags(), "Fail immediately on recoverable remote listing/hash/metadata warnings")
	snapshotCmd.AddCommand(remote)

	return snapshotCmd
}

func addSnapshotCreateFlags(flags *flag.FlagSet, strictUsage string) {
	flags.StringP("db", "d", defaultSnapshotDBPath(), "Path to snapshot database")
	flags.BoolP("verbose", "v", false, "Verbose output")
	flags.BoolP("strict", "s", false, strictUsage)
	flags.BoolP("basic-tree", "b", false, "Store tree entries without mode/modtime metadata (mode=0, mod_time_ns=0)")
	flags.StringP("output", "o", outputModeAuto, "Output mode: auto|pretty|kv|json")
}

func newHashmapCommand() *cobra.Command {
	hashmapCmd := &cobra.Command{
		Use:   "hashmap",
		Short: "Manage mappings between BLAKE3 and other file digests.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	ingest := &cobra.Command{
		Use:   "ingest [options] [path]",
		Short: "Scan files and ingest checksum xattr mappings.",
		RunE:  runLegacyCommandWithCobra(runHashmapIngestCommand),
	}
	ingest.Flags().StringP("db", "d", defaultSnapshotDBPath(), "Path to snapshot database")
	ingest.Flags().BoolP("verbose", "v", false, "Verbose output")
	ingest.Flags().StringP("output", "o", outputModeAuto, "Output mode: auto|pretty|kv|json")
	hashmapCmd.AddCommand(ingest)

	lookup := &cobra.Command{
		Use:   "lookup [options]",
		Short: "Lookup BLAKE3 by external algorithm digest.",
		RunE:  runLegacyCommandWithCobra(runHashmapLookupCommand),
	}
	lookup.Flags().StringP("db", "d", defaultSnapshotDBPath(), "Path to snapshot database")
	lookup.Flags().StringP("algo", "a", "", "Hash algorithm to search (required)")
	lookup.Flags().StringP("digest", "g", "", "Digest to search (required)")
	lookup.Flags().StringP("output", "o", outputModeAuto, "Output mode: auto|pretty|kv|json")
	hashmapCmd.AddCommand(lookup)

	show := &cobra.Command{
		Use:   "show [options]",
		Short: "Show known algorithm digests for a BLAKE3 digest.",
		RunE:  runLegacyCommandWithCobra(runHashmapShowCommand),
	}
	show.Flags().StringP("db", "d", defaultSnapshotDBPath(), "Path to snapshot database")
	show.Flags().StringP("blake3", "b", "", "BLAKE3 digest to inspect (required)")
	show.Flags().StringP("output", "o", outputModeAuto, "Output mode: auto|pretty|kv|json")
	hashmapCmd.AddCommand(show)

	return hashmapCmd
}

func newCompletionCommand(root *cobra.Command) *cobra.Command {
	return &cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "Generate shell completion scripts.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			switch args[0] {
			case "bash":
				return root.GenBashCompletionV2(os.Stdout, true)
			case "zsh":
				return root.GenZshCompletion(os.Stdout)
			case "fish":
				return root.GenFishCompletion(os.Stdout, true)
			case "powershell":
				return root.GenPowerShellCompletionWithDesc(os.Stdout)
			default:
				return fmt.Errorf("unsupported shell %q", args[0])
			}
		},
	}
}

func newBlobCommand() *cobra.Command {
	blobCmd := &cobra.Command{
		Use:   "blob",
		Short: "Manage convergent blobs with plaintext local cache and encrypted remote storage.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	put := &cobra.Command{
		Use:   "put [options] <path>",
		Short: "Encrypt a file into a deterministic blob and cache it locally.",
		RunE:  runLegacyCommandWithCobra(runBlobPutCommand),
	}
	putFlags := put.Flags()
	putFlags.StringP("db", "d", defaultBlobDBPath(), "Path to blob metadata database")
	putFlags.String("cache", defaultBlobCacheDir(), "Path to local blob cache directory")
	putFlags.String("refs-db", defaultRefsDBPath(), "Path to refs database for local keep-set tracking")
	putFlags.Bool("remote", false, "Upload encrypted blob payload to configured remote S3")
	putFlags.Bool("verify-remote-cache", true, "Verify cached remote-existence hits before skipping upload")
	putFlags.Bool("strict-remote-cache", false, "Fail when cached remote-existence hits cannot be verified (no fallback upload)")
	putFlags.StringP("output", "o", outputModeAuto, "Output mode: auto|pretty|kv|json")
	putFlags.BoolP("verbose", "v", false, "Verbose output")
	blobCmd.AddCommand(put)

	get := &cobra.Command{
		Use:   "get [options]",
		Short: "Fetch and decrypt a blob by CID or OID.",
		RunE:  runLegacyCommandWithCobra(runBlobGetCommand),
	}
	getFlags := get.Flags()
	getFlags.StringP("db", "d", defaultBlobDBPath(), "Path to blob metadata database")
	getFlags.String("cache", defaultBlobCacheDir(), "Path to local blob cache directory")
	getFlags.String("refs-db", defaultRefsDBPath(), "Path to refs database for local keep-set tracking")
	getFlags.Bool("remote", false, "Fetch encrypted blob from configured remote S3 when local cache misses")
	getFlags.String("cid", "", "Cleartext BLAKE3 content hash (hex)")
	getFlags.String("oid", "", "Encrypted blob object ID (hex)")
	getFlags.StringP("out", "o", "", "Output plaintext file path")
	getFlags.String("output", outputModeAuto, "Output mode: auto|pretty|kv|json")
	getFlags.BoolP("verbose", "v", false, "Verbose output")
	blobCmd.AddCommand(get)

	ls := &cobra.Command{
		Use:   "ls [options]",
		Short: "List known blob mappings from the local metadata DB.",
		RunE:  runLegacyCommandWithCobra(runBlobListCommand),
	}
	ls.Flags().StringP("db", "d", defaultBlobDBPath(), "Path to blob metadata database")
	ls.Flags().IntP("limit", "n", 20, "Maximum number of rows to list")
	ls.Flags().StringP("output", "o", outputModeAuto, "Output mode: auto|pretty|kv|json")
	blobCmd.AddCommand(ls)

	rm := &cobra.Command{
		Use:     "rm [options]",
		Aliases: []string{"delete", "del"},
		Short:   "Remove blob data from local cache and optionally remote backend.",
		RunE:    runLegacyCommandWithCobra(runBlobRemoveCommand),
	}
	rmFlags := rm.Flags()
	rmFlags.StringP("db", "d", defaultBlobDBPath(), "Path to blob metadata database")
	rmFlags.String("cache", defaultBlobCacheDir(), "Path to local blob cache directory")
	rmFlags.String("refs-db", defaultRefsDBPath(), "Path to refs database for local keep-set tracking")
	rmFlags.String("cid", "", "Cleartext BLAKE3 content hash (hex)")
	rmFlags.String("oid", "", "Encrypted blob object ID (hex)")
	rmFlags.Bool("local", true, "Delete local cached plaintext and local blob mapping metadata")
	rmFlags.Bool("remote", false, "Delete encrypted blob from remote backend and clear matching remote inventory rows")
	rmFlags.StringP("output", "o", outputModeAuto, "Output mode: auto|pretty|kv|json")
	rmFlags.BoolP("verbose", "v", false, "Verbose output")
	blobCmd.AddCommand(rm)

	gc := &cobra.Command{
		Use:   "gc [options]",
		Short: "Garbage collect local blob cache/metadata from local reference roots.",
		RunE:  runLegacyCommandWithCobra(runBlobGCCommand),
	}
	gcFlags := gc.Flags()
	gcFlags.StringP("db", "d", defaultBlobDBPath(), "Path to blob metadata database")
	gcFlags.String("cache", defaultBlobCacheDir(), "Path to local blob cache directory")
	gcFlags.String("refs-db", defaultRefsDBPath(), "Path to refs database for local keep-set tracking")
	gcFlags.String("snapshot-db", defaultSnapshotDBPath(), "Path to snapshot database for tree-entry references")
	gcFlags.String("vector-queue-db", forgeconfig.VectorQueueDBPath(), "Path to vector queue database for payload references")
	gcFlags.Bool("no-snapshot-refs", false, "Disable snapshot tree-entry references as GC roots")
	gcFlags.Bool("no-vector-refs", false, "Disable vector queue references as GC roots")
	gcFlags.Bool("include-error-jobs", true, "Treat vector queue status=error jobs as GC roots")
	gcFlags.BoolP("apply", "a", false, "Apply deletions (default is dry-run)")
	gcFlags.StringP("output", "o", outputModeAuto, "Output mode: auto|pretty|kv|json")
	gcFlags.BoolP("verbose", "v", false, "Verbose output")
	blobCmd.AddCommand(gc)

	inventoryCmd := &cobra.Command{
		Use:   "inventory",
		Short: "Manage remote blob inventory snapshots and gc_info pointer state.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}
	publish := &cobra.Command{
		Use:   "publish [options]",
		Short: "Publish immutable remote inventory snapshot DB and update gc_info pointer.",
		RunE:  runLegacyCommandWithCobra(runBlobInventoryPublishCommand),
	}
	publish.Flags().String("generation", "", "Opaque GC generation ID")
	publish.Flags().String("worker-id", "", "GC worker identifier")
	publish.Flags().Int64("deleted-count", 0, "Number of remote blobs deleted in this GC cycle")
	publish.Flags().StringP("output", "o", outputModeAuto, "Output mode: auto|pretty|kv|json")
	inventoryCmd.AddCommand(publish)
	blobCmd.AddCommand(inventoryCmd)

	return blobCmd
}

func newRemoteCommand() *cobra.Command {
	remoteCmd := &cobra.Command{
		Use:   "remote",
		Short: "Manage global remote backend configuration.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	configCmd := &cobra.Command{
		Use:   "config",
		Short: "Manage global remote config object in S3.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	init := &cobra.Command{
		Use:   "init [options]",
		Short: "Initialize or update the global remote config object.",
		RunE:  runLegacyCommandWithCobra(runRemoteConfigInitCommand),
	}
	initFlags := init.Flags()
	initFlags.Bool("overwrite", false, "Overwrite existing config object")
	initFlags.String("object-prefix", defaultS3ObjectPrefix, "Global object prefix for Forge data in the bucket")
	initFlags.String("blob-prefix", defaultS3BlobKeyPrefix, "Blob object prefix under object-prefix")
	initFlags.Int("config-cache-ttl", defaultRemoteConfigCacheTTLSeconds, "Local remote-config cache TTL in seconds")
	initFlags.Bool("probe-capabilities", true, "Probe S3 capability flags on the target bucket")
	initFlags.Bool("cap-if-none-match", defaultCapabilityIfNone, "Manual If-None-Match support value (used when -probe-capabilities=false)")
	initFlags.Bool("cap-if-match", defaultCapabilityIfMatch, "Manual If-Match support value (used when -probe-capabilities=false)")
	initFlags.Bool("cap-response-checksums", defaultCapabilityResponseChecksums, "Manual response-checksum support value (used when -probe-capabilities=false)")
	initFlags.String("vector-lease-mode", defaultVectorLeaseMode, "Vector writer lease mode: auto|hard|soft|off")
	initFlags.String("vector-lease-resource", defaultVectorLeaseResource, "Vector writer lease resource key")
	initFlags.Int("vector-lease-duration", defaultVectorLeaseDurationSeconds, "Vector writer lease duration in seconds")
	initFlags.Int("vector-lease-renew-interval", defaultVectorLeaseRenewIntervalSeconds, "Vector writer lease renew interval in seconds")
	initFlags.String("signing-key", "", "Path to OpenSSH private key used to sign remote config document")
	initFlags.String("signing-key-passphrase", "", "Passphrase for encrypted OpenSSH private key used by -signing-key")
	initFlags.Int64("doc-version", 0, "Signed document version (default: auto)")
	initFlags.Int("doc-expires-seconds", defaultRemoteDocExpiresSeconds, "Optional signed document expiry in seconds (0 means no expiry)")
	initFlags.String("trust-nodes-file", "", "Optional path to trust nodes JSON file (array or object with \"nodes\")")
	initFlags.String("root-node-name", defaultRemoteRootNodeName, "Node name for signing root key in trust map")
	initFlags.StringP("output", "o", outputModeAuto, "Output mode: auto|pretty|kv|json")
	configCmd.AddCommand(init)

	show := &cobra.Command{
		Use:   "show [options]",
		Short: "Show the global remote config object.",
		RunE:  runLegacyCommandWithCobra(runRemoteConfigShowCommand),
	}
	show.Flags().StringP("output", "o", outputModeAuto, "Output mode: auto|pretty|kv|json")
	configCmd.AddCommand(show)

	set := &cobra.Command{
		Use:   "set [options]",
		Short: "Update mutable values in the global remote config object.",
		RunE:  runLegacyCommandWithCobra(runRemoteConfigSetCommand),
	}
	setFlags := set.Flags()
	setFlags.String("object-prefix", "", "Set s3.object_prefix")
	setFlags.String("blob-prefix", "", "Set s3.blob_prefix")
	setFlags.Int("config-cache-ttl", -1, "Set cache.remote_config_ttl_seconds")
	setFlags.String("cap-if-none-match", "", "Set s3.capabilities.conditional_if_none_match (true|false)")
	setFlags.String("cap-if-match", "", "Set s3.capabilities.conditional_if_match (true|false)")
	setFlags.String("cap-response-checksums", "", "Set s3.capabilities.response_checksums (true|false)")
	setFlags.String("vector-lease-mode", "", "Set coordination.vector_writer_lease.mode (auto|hard|soft|off)")
	setFlags.String("vector-lease-resource", "", "Set coordination.vector_writer_lease.resource")
	setFlags.Int("vector-lease-duration", -1, "Set coordination.vector_writer_lease.duration_seconds")
	setFlags.Int("vector-lease-renew-interval", -1, "Set coordination.vector_writer_lease.renew_interval_seconds")
	setFlags.String("signing-key", "", "Path to OpenSSH private key used to sign updated config")
	setFlags.String("signing-key-passphrase", "", "Passphrase for encrypted OpenSSH private key used by -signing-key")
	setFlags.Int64("doc-version", 0, "Signed document version (default: auto)")
	setFlags.Int("doc-expires-seconds", remoteDocExpiresPreserve, "Signed document expiry in seconds (-1 preserve existing, 0 disable)")
	setFlags.StringP("output", "o", outputModeAuto, "Output mode: auto|pretty|kv|json")
	configCmd.AddCommand(set)

	nodeCmd := &cobra.Command{
		Use:     "node",
		Aliases: []string{"nodes"},
		Short:   "Manage trust nodes in the global remote config object.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}
	list := &cobra.Command{
		Use:     "list [options]",
		Aliases: []string{"ls"},
		Short:   "List trust nodes from global remote config.",
		RunE:    runLegacyCommandWithCobra(runRemoteConfigNodeListCommand),
	}
	list.Flags().StringP("output", "o", outputModeAuto, "Output mode: auto|pretty|kv|json")
	nodeCmd.AddCommand(list)

	add := &cobra.Command{
		Use:   "add [options]",
		Short: "Add a trust node to global remote config.",
		RunE:  runLegacyCommandWithCobra(runRemoteConfigNodeAddCommand),
	}
	addFlags := add.Flags()
	addFlags.StringP("name", "n", "", "Node name")
	addFlags.StringP("public-key", "k", "", "Node OpenSSH public key")
	addFlags.StringP("roles", "r", "", "Comma-separated trust roles")
	addFlags.Bool("revoked", false, "Set revoked state on add")
	addFlags.String("signing-key", "", "Path to OpenSSH private key used to sign updated config")
	addFlags.String("signing-key-passphrase", "", "Passphrase for encrypted OpenSSH private key used by -signing-key")
	addFlags.Int64("doc-version", 0, "Signed document version (default: auto)")
	addFlags.Int("doc-expires-seconds", remoteDocExpiresPreserve, "Signed document expiry in seconds (-1 preserve existing, 0 disable)")
	addFlags.StringP("output", "o", outputModeAuto, "Output mode: auto|pretty|kv|json")
	nodeCmd.AddCommand(add)

	update := &cobra.Command{
		Use:   "update [options]",
		Short: "Update a trust node in global remote config.",
		RunE:  runLegacyCommandWithCobra(runRemoteConfigNodeUpdateCommand),
	}
	updateFlags := update.Flags()
	updateFlags.StringP("name", "n", "", "Node name")
	updateFlags.StringP("public-key", "k", "", "Replacement OpenSSH public key")
	updateFlags.StringP("roles", "r", "", "Replacement comma-separated trust roles")
	updateFlags.Bool("clear-roles", false, "Clear node roles")
	updateFlags.String("revoked", "", "Set revoked state (true|false)")
	updateFlags.String("signing-key", "", "Path to OpenSSH private key used to sign updated config")
	updateFlags.String("signing-key-passphrase", "", "Passphrase for encrypted OpenSSH private key used by -signing-key")
	updateFlags.Int64("doc-version", 0, "Signed document version (default: auto)")
	updateFlags.Int("doc-expires-seconds", remoteDocExpiresPreserve, "Signed document expiry in seconds (-1 preserve existing, 0 disable)")
	updateFlags.StringP("output", "o", outputModeAuto, "Output mode: auto|pretty|kv|json")
	nodeCmd.AddCommand(update)

	remove := &cobra.Command{
		Use:     "remove [options]",
		Aliases: []string{"rm", "delete", "del"},
		Short:   "Remove a trust node from global remote config.",
		RunE:    runLegacyCommandWithCobra(runRemoteConfigNodeRemoveCommand),
	}
	removeFlags := remove.Flags()
	removeFlags.StringP("name", "n", "", "Node name")
	removeFlags.String("signing-key", "", "Path to OpenSSH private key used to sign updated config")
	removeFlags.String("signing-key-passphrase", "", "Passphrase for encrypted OpenSSH private key used by -signing-key")
	removeFlags.Int64("doc-version", 0, "Signed document version (default: auto)")
	removeFlags.Int("doc-expires-seconds", remoteDocExpiresPreserve, "Signed document expiry in seconds (-1 preserve existing, 0 disable)")
	removeFlags.StringP("output", "o", outputModeAuto, "Output mode: auto|pretty|kv|json")
	nodeCmd.AddCommand(remove)
	configCmd.AddCommand(nodeCmd)
	remoteCmd.AddCommand(configCmd)

	return remoteCmd
}

func newConfigCommand() *cobra.Command {
	configCmd := &cobra.Command{
		Use:   "config",
		Short: "Inspect effective local and remote Forge configuration.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	show := &cobra.Command{
		Use:   "show [options]",
		Short: "Show effective config values resolved from env/defaults and remote state.",
		RunE:  runLegacyCommandWithCobra(runConfigShowCommand),
	}
	show.Flags().Bool("effective", true, "Show effective resolved configuration values")
	show.Flags().StringP("output", "o", outputModeAuto, "Output mode: auto|pretty|kv|json")
	configCmd.AddCommand(show)

	return configCmd
}

func newSkillsCommand() *cobra.Command {
	skillsCmd := &cobra.Command{
		Use:   "skills",
		Short: "List and install embedded Forge skill definitions for agent tooling.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	list := &cobra.Command{
		Use:   "list [options]",
		Short: "List embedded skills shipped in the Forge binary.",
		RunE:  runLegacyCommandWithCobra(runSkillsListCommand),
	}
	list.Flags().StringP("output", "o", outputModeAuto, "Output mode: auto|pretty|kv|json")
	skillsCmd.AddCommand(list)

	install := &cobra.Command{
		Use:   "install [options]",
		Short: "Install embedded skills to a local directory.",
		RunE:  runLegacyCommandWithCobra(runSkillsInstallCommand),
	}
	installFlags := install.Flags()
	installFlags.StringP("dir", "d", forgeconfig.SkillsDir(), "Destination directory for installed skills")
	installFlags.StringP("skills", "s", "", "Comma-separated skill names to install (default: all embedded skills)")
	installFlags.BoolP("force", "f", false, "Overwrite already-installed skills")
	installFlags.Bool("dry-run", false, "Preview installation without writing files")
	installFlags.StringP("output", "o", outputModeAuto, "Output mode: auto|pretty|kv|json")
	skillsCmd.AddCommand(install)

	return skillsCmd
}

func newVectorCommand() *cobra.Command {
	vectorCmd := &cobra.Command{
		Use:   "vector",
		Short: "Run vector embedding service and ingestion workflows.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	serve := &cobra.Command{
		Use:   "serve",
		Short: "Run the VectorForge coordinator service.",
		RunE:  runLegacyCommandWithCobra(runVectorServeCommand),
	}
	vectorCmd.AddCommand(serve)

	ingest := &cobra.Command{
		Use:   "ingest [options]",
		Short: "Scan local files and upload missing embedding jobs.",
		RunE:  runLegacyCommandWithCobra(runVectorIngestCommand),
	}
	ingestFlags := ingest.Flags()
	ingestFlags.String("server", "http://localhost:8080", "Coordinator base URL")
	ingestFlags.String("root", ".", "Root directory to scan")
	ingestFlags.String("kind", "image", "Embedding kind: image or text")
	ingestFlags.String("algo", "blake3", "Hash algorithm for XATTR cache key (must be blake3)")
	ingestFlags.String("hydrated-db", forgeconfig.VectorHydratedDBPath(), "Local hydrated embeddings DB path for pre-checks")
	ingestFlags.Int("workers", runtime.NumCPU(), "Worker count for hashing and uploads")
	ingestFlags.Int("lookup-batch", 500, "Hashes per lookup request")
	ingestFlags.Duration("http-timeout", 120*time.Second, "HTTP request timeout")
	ingestFlags.BoolP("verbose", "v", false, "Verbose logging")
	vectorCmd.AddCommand(ingest)

	leaseStatus := &cobra.Command{
		Use:   "lease-status [options]",
		Short: "Show remote writer lease state for vector replication.",
		RunE:  runLegacyCommandWithCobra(runVectorLeaseStatusCommand),
	}
	leaseStatus.Flags().String("resource", "", "Override lease resource key")
	leaseStatus.Flags().StringP("output", "o", outputModeAuto, "Output mode: auto|pretty|kv|json")
	vectorCmd.AddCommand(leaseStatus)

	return vectorCmd
}

func newReplicateCommand() *cobra.Command {
	replicateCmd := &cobra.Command{
		Use:   "replicate",
		Short: "Run background replication workflows.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	daemon := &cobra.Command{
		Use:   "daemon [options]",
		Short: "Run the background database replication daemon.",
		RunE:  runLegacyCommandWithCobra(runReplicateDaemonCommand),
	}
	daemonFlags := daemon.Flags()
	daemonFlags.String("snapshot-db", forgeconfig.SnapshotDBPath(), "Path to snapshot database")
	daemonFlags.String("refs-db", forgeconfig.RefsDBPath(), "Path to refs database")
	daemonFlags.String("node-name", defaultReplicationNodeName(), "Node name used to resolve trust-node recipient mapping")
	daemonFlags.String("node-public-key", "", "Override node SSH public key recipient (authorized_keys format)")
	daemonFlags.String("node-ssh-key", strings.TrimSpace(os.Getenv(forgeNodeSSHKeyEnv)), "Path to node SSH private key used to decrypt encrypted replica data")
	daemonFlags.String("node-ssh-key-passphrase", strings.TrimSpace(os.Getenv(forgeNodeSSHKeyPassphraseEnv)), "Passphrase for encrypted -node-ssh-key")
	replicateCmd.AddCommand(daemon)

	return replicateCmd
}

func newTagsCommand() *cobra.Command {
	tagsCmd := &cobra.Command{
		Use:   "tags",
		Short: "Manage user.xdg.tags on files.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	get := &cobra.Command{
		Use:   "get [options] [path]",
		Short: "Show normalized tags for a path.",
		RunE:  runLegacyCommandWithCobra(runTagsGetCommand),
	}
	get.Flags().StringP("output", "o", outputModeAuto, "Output mode: auto|pretty|kv|json")
	tagsCmd.AddCommand(get)

	set := &cobra.Command{
		Use:   "set [options] [path]",
		Short: "Replace tags on a path with the provided set.",
		RunE:  runLegacyCommandWithCobra(runTagsSetCommand),
	}
	set.Flags().StringP("tags", "t", "", "Comma/semicolon-separated tag list (required)")
	set.Flags().StringP("output", "o", outputModeAuto, "Output mode: auto|pretty|kv|json")
	tagsCmd.AddCommand(set)

	add := &cobra.Command{
		Use:   "add [options] [path]",
		Short: "Add tags to a path.",
		RunE:  runLegacyCommandWithCobra(runTagsAddCommand),
	}
	add.Flags().StringP("tags", "t", "", "Comma/semicolon-separated tag list to add (required)")
	add.Flags().StringP("output", "o", outputModeAuto, "Output mode: auto|pretty|kv|json")
	tagsCmd.AddCommand(add)

	remove := &cobra.Command{
		Use:   "remove [options] [path]",
		Short: "Remove tags from a path.",
		RunE:  runLegacyCommandWithCobra(runTagsRemoveCommand),
	}
	remove.Flags().StringP("tags", "t", "", "Comma/semicolon-separated tag list to remove (required)")
	remove.Flags().StringP("output", "o", outputModeAuto, "Output mode: auto|pretty|kv|json")
	tagsCmd.AddCommand(remove)

	clear := &cobra.Command{
		Use:   "clear [options] [path]",
		Short: "Clear all tags on a path.",
		RunE:  runLegacyCommandWithCobra(runTagsClearCommand),
	}
	clear.Flags().StringP("output", "o", outputModeAuto, "Output mode: auto|pretty|kv|json")
	tagsCmd.AddCommand(clear)

	return tagsCmd
}
