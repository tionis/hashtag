package main

import (
	"bytes"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	stderrors "errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/zeebo/blake3"
	"golang.org/x/crypto/chacha20poly1305"
	_ "modernc.org/sqlite"
)

const (
	blobDBEnv            = "FORGE_BLOB_DB"
	blobCacheEnv         = "FORGE_BLOB_CACHE"
	blobServerRootEnv    = "FORGE_BLOB_SERVER_ROOT"
	blobDBDefaultFile    = "blob.db"
	blobServerDefaultDir = "blob-server"
	blobCacheDefaultDir  = "blobs"

	blobEncAlgorithm = "xchacha20poly1305"
	blobEncVersion   = 1

	blobMagic         = "FBLB1"
	blobDigestHexSize = 64
	blobDigestBytes   = 32
	blobHeaderLen     = len(blobMagic) + 1 + 8 + blobDigestBytes

	blobRemoteBackendDefault = "blob-http"
	blobRemoteBucketDefault  = "default"
)

type blobCipherPackage struct {
	CID        string
	OID        string
	PlainSize  int64
	CipherSize int64
	CipherHash string
	Encoded    []byte
}

type blobPutOutput struct {
	SourcePath string `json:"source_path"`
	CID        string `json:"cid"`
	OID        string `json:"oid"`
	PlainSize  int64  `json:"plain_size"`
	CipherSize int64  `json:"cipher_size"`
	CipherHash string `json:"cipher_hash"`
	CachePath  string `json:"cache_path"`
	Uploaded   bool   `json:"uploaded"`
	Server     string `json:"server,omitempty"`
}

type blobGetOutput struct {
	CID        string `json:"cid"`
	OID        string `json:"oid"`
	OutPath    string `json:"out_path"`
	Source     string `json:"source"`
	PlainSize  int64  `json:"plain_size"`
	CipherSize int64  `json:"cipher_size"`
	CipherHash string `json:"cipher_hash"`
	CachePath  string `json:"cache_path"`
}

type blobListEntryOutput struct {
	CID          string `json:"cid"`
	OID          string `json:"oid"`
	PlainSize    int64  `json:"plain_size"`
	CipherSize   int64  `json:"cipher_size"`
	CipherHash   string `json:"cipher_hash"`
	UpdatedAtNS  int64  `json:"updated_at_ns"`
	UpdatedAtUTC string `json:"updated_at_utc"`
}

type blobListOutput struct {
	DB      string                `json:"db"`
	Count   int                   `json:"count"`
	Entries []blobListEntryOutput `json:"entries"`
}

type blobMapRow struct {
	CID        string
	OID        string
	PlainSize  int64
	CipherSize int64
	CipherHash string
	CachePath  string
	UpdatedAt  int64
}

type blobRemoteInventoryRow struct {
	Backend    string
	Bucket     string
	ObjectKey  string
	OID        string
	Size       int64
	ETag       string
	CipherHash string
	LastSeenNS int64
	ScanID     string
}

func runBlobPutCommand(args []string) error {
	defaultDB := defaultBlobDBPath()
	defaultCache := defaultBlobCacheDir()

	fs := flag.NewFlagSet("blob put", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s blob put [options] <path>\n\n", os.Args[0])
		fmt.Fprintln(fs.Output(), "Encrypt a file deterministically and persist blob metadata/cache.")
		fmt.Fprintln(fs.Output(), "\nOptions:")
		fs.PrintDefaults()
	}

	dbPath := fs.String("db", defaultDB, "Path to blob metadata database")
	cacheDir := fs.String("cache", defaultCache, "Path to local blob cache directory")
	serverURL := fs.String("server", "", "Optional blob backend server base URL")
	backend := fs.String("backend", blobRemoteBackendDefault, "Inventory backend name when server upload is used")
	bucket := fs.String("bucket", blobRemoteBucketDefault, "Inventory bucket name when server upload is used")
	outputMode := fs.String("output", outputModeAuto, "Output mode: auto|pretty|kv|json")
	verbose := fs.Bool("v", false, "Verbose output")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}

	resolvedOutputMode, err := resolvePrettyKVJSONOutputMode(*outputMode)
	if err != nil {
		return err
	}

	inputPath := strings.TrimSpace(fs.Arg(0))
	if inputPath == "" {
		return fmt.Errorf("input path is required")
	}
	absInputPath, err := filepath.Abs(inputPath)
	if err != nil {
		return fmt.Errorf("resolve input path: %w", err)
	}

	plain, err := os.ReadFile(absInputPath)
	if err != nil {
		return fmt.Errorf("read input file %q: %w", absInputPath, err)
	}

	pkg, err := encryptBlobData(plain)
	if err != nil {
		return err
	}

	cachePath, err := blobObjectPath(*cacheDir, pkg.OID)
	if err != nil {
		return err
	}
	if err := ensureBlobObject(cachePath, pkg.Encoded, pkg.CipherHash); err != nil {
		return err
	}

	absDBPath, err := filepath.Abs(*dbPath)
	if err != nil {
		return fmt.Errorf("resolve db path: %w", err)
	}
	db, err := openBlobDB(absDBPath)
	if err != nil {
		return err
	}
	defer db.Close()

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("start blob db transaction: %w", err)
	}
	defer tx.Rollback()

	if err := upsertBlobMap(tx, blobMapRow{
		CID:        pkg.CID,
		OID:        pkg.OID,
		PlainSize:  pkg.PlainSize,
		CipherSize: pkg.CipherSize,
		CipherHash: pkg.CipherHash,
		CachePath:  cachePath,
		UpdatedAt:  time.Now().UTC().UnixNano(),
	}); err != nil {
		return err
	}

	uploaded := false
	if strings.TrimSpace(*serverURL) != "" {
		if *verbose {
			log.Printf("[blob] uploading %s to %s", pkg.OID, *serverURL)
		}
		etag, err := uploadBlobToServer(*serverURL, pkg.OID, pkg.Encoded)
		if err != nil {
			return err
		}
		if etag == "" {
			etag = pkg.CipherHash
		}
		scanID := fmt.Sprintf("blob-put-%d", time.Now().UTC().UnixNano())
		if err := upsertRemoteBlobInventory(tx, blobRemoteInventoryRow{
			Backend:    strings.TrimSpace(*backend),
			Bucket:     strings.TrimSpace(*bucket),
			ObjectKey:  pkg.OID,
			OID:        pkg.OID,
			Size:       pkg.CipherSize,
			ETag:       etag,
			CipherHash: pkg.CipherHash,
			LastSeenNS: time.Now().UTC().UnixNano(),
			ScanID:     scanID,
		}); err != nil {
			return err
		}
		uploaded = true
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit blob transaction: %w", err)
	}

	return renderBlobPutOutput(
		resolvedOutputMode,
		blobPutOutput{
			SourcePath: absInputPath,
			CID:        pkg.CID,
			OID:        pkg.OID,
			PlainSize:  pkg.PlainSize,
			CipherSize: pkg.CipherSize,
			CipherHash: pkg.CipherHash,
			CachePath:  cachePath,
			Uploaded:   uploaded,
			Server:     strings.TrimSpace(*serverURL),
		},
	)
}

func runBlobGetCommand(args []string) error {
	defaultDB := defaultBlobDBPath()
	defaultCache := defaultBlobCacheDir()

	fs := flag.NewFlagSet("blob get", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s blob get [options]\n\n", os.Args[0])
		fmt.Fprintln(fs.Output(), "Fetch an encrypted blob, decrypt it, and write the plaintext to -out.")
		fmt.Fprintln(fs.Output(), "\nOptions:")
		fs.PrintDefaults()
	}

	dbPath := fs.String("db", defaultDB, "Path to blob metadata database")
	cacheDir := fs.String("cache", defaultCache, "Path to local blob cache directory")
	serverURL := fs.String("server", "", "Optional blob backend server base URL")
	backend := fs.String("backend", blobRemoteBackendDefault, "Inventory backend name when server fetch is used")
	bucket := fs.String("bucket", blobRemoteBucketDefault, "Inventory bucket name when server fetch is used")
	cidFlag := fs.String("cid", "", "Cleartext BLAKE3 content hash (hex)")
	oidFlag := fs.String("oid", "", "Encrypted blob object ID (hex)")
	outPath := fs.String("out", "", "Output plaintext file path")
	outputMode := fs.String("output", outputModeAuto, "Output mode: auto|pretty|kv|json")
	verbose := fs.Bool("v", false, "Verbose output")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}

	if strings.TrimSpace(*outPath) == "" {
		return fmt.Errorf("-out is required")
	}

	resolvedOutputMode, err := resolvePrettyKVJSONOutputMode(*outputMode)
	if err != nil {
		return err
	}

	requestedCID := normalizeDigestHex(strings.TrimSpace(*cidFlag))
	requestedOID := normalizeDigestHex(strings.TrimSpace(*oidFlag))
	if requestedCID == "" && requestedOID == "" {
		return fmt.Errorf("either -cid or -oid must be provided")
	}

	if requestedCID != "" {
		cidBytes, err := parseDigestHex32(requestedCID)
		if err != nil {
			return fmt.Errorf("parse -cid: %w", err)
		}
		derivedOID := deriveBlobOID(cidBytes)
		if requestedOID == "" {
			requestedOID = derivedOID
		} else if requestedOID != derivedOID {
			return fmt.Errorf("-oid does not match deterministic OID derived from -cid")
		}
	}

	cachePath, err := blobObjectPath(*cacheDir, requestedOID)
	if err != nil {
		return err
	}

	encoded, err := os.ReadFile(cachePath)
	source := "cache"
	etag := ""
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("read cached blob %q: %w", cachePath, err)
		}
		if strings.TrimSpace(*serverURL) == "" {
			return fmt.Errorf("blob %q not found in cache and no -server provided", requestedOID)
		}
		if *verbose {
			log.Printf("[blob] cache miss for %s, fetching from %s", requestedOID, *serverURL)
		}
		encoded, etag, err = fetchBlobFromServer(*serverURL, requestedOID)
		if err != nil {
			return err
		}
		if err := ensureBlobObject(cachePath, encoded, blake3Hex(encoded)); err != nil {
			return err
		}
		source = "server"
	}

	pkg, plain, err := decodeAndDecryptBlobData(encoded)
	if err != nil {
		return err
	}
	if requestedCID != "" && pkg.CID != requestedCID {
		return fmt.Errorf("decrypted CID mismatch: expected %s got %s", requestedCID, pkg.CID)
	}
	if requestedOID != "" && pkg.OID != requestedOID {
		return fmt.Errorf("decrypted OID mismatch: expected %s got %s", requestedOID, pkg.OID)
	}

	absOutPath, err := filepath.Abs(*outPath)
	if err != nil {
		return fmt.Errorf("resolve output path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(absOutPath), 0o755); err != nil {
		return fmt.Errorf("create output directory for %q: %w", absOutPath, err)
	}
	if err := os.WriteFile(absOutPath, plain, 0o600); err != nil {
		return fmt.Errorf("write output file %q: %w", absOutPath, err)
	}

	absDBPath, err := filepath.Abs(*dbPath)
	if err != nil {
		return fmt.Errorf("resolve db path: %w", err)
	}
	db, err := openBlobDB(absDBPath)
	if err != nil {
		return err
	}
	defer db.Close()

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("start blob db transaction: %w", err)
	}
	defer tx.Rollback()

	if err := upsertBlobMap(tx, blobMapRow{
		CID:        pkg.CID,
		OID:        pkg.OID,
		PlainSize:  pkg.PlainSize,
		CipherSize: pkg.CipherSize,
		CipherHash: pkg.CipherHash,
		CachePath:  cachePath,
		UpdatedAt:  time.Now().UTC().UnixNano(),
	}); err != nil {
		return err
	}

	if source == "server" {
		if etag == "" {
			etag = pkg.CipherHash
		}
		scanID := fmt.Sprintf("blob-get-%d", time.Now().UTC().UnixNano())
		if err := upsertRemoteBlobInventory(tx, blobRemoteInventoryRow{
			Backend:    strings.TrimSpace(*backend),
			Bucket:     strings.TrimSpace(*bucket),
			ObjectKey:  pkg.OID,
			OID:        pkg.OID,
			Size:       pkg.CipherSize,
			ETag:       etag,
			CipherHash: pkg.CipherHash,
			LastSeenNS: time.Now().UTC().UnixNano(),
			ScanID:     scanID,
		}); err != nil {
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit blob transaction: %w", err)
	}

	return renderBlobGetOutput(
		resolvedOutputMode,
		blobGetOutput{
			CID:        pkg.CID,
			OID:        pkg.OID,
			OutPath:    absOutPath,
			Source:     source,
			PlainSize:  pkg.PlainSize,
			CipherSize: pkg.CipherSize,
			CipherHash: pkg.CipherHash,
			CachePath:  cachePath,
		},
	)
}

func runBlobListCommand(args []string) error {
	defaultDB := defaultBlobDBPath()

	fs := flag.NewFlagSet("blob ls", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s blob ls [options]\n\n", os.Args[0])
		fmt.Fprintln(fs.Output(), "List known blob mappings from local metadata.")
		fmt.Fprintln(fs.Output(), "\nOptions:")
		fs.PrintDefaults()
	}

	dbPath := fs.String("db", defaultDB, "Path to blob metadata database")
	limit := fs.Int("limit", 20, "Maximum number of rows to list")
	outputMode := fs.String("output", outputModeAuto, "Output mode: auto|pretty|kv|json")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if *limit <= 0 {
		return fmt.Errorf("limit must be > 0")
	}

	resolvedOutputMode, err := resolvePrettyKVJSONOutputMode(*outputMode)
	if err != nil {
		return err
	}

	absDBPath, err := filepath.Abs(*dbPath)
	if err != nil {
		return fmt.Errorf("resolve db path: %w", err)
	}
	db, err := openBlobDB(absDBPath)
	if err != nil {
		return err
	}
	defer db.Close()

	rows, err := listBlobMappings(db, *limit)
	if err != nil {
		return err
	}

	entries := make([]blobListEntryOutput, 0, len(rows))
	for _, row := range rows {
		entries = append(entries, blobListEntryOutput{
			CID:          row.CID,
			OID:          row.OID,
			PlainSize:    row.PlainSize,
			CipherSize:   row.CipherSize,
			CipherHash:   row.CipherHash,
			UpdatedAtNS:  row.UpdatedAt,
			UpdatedAtUTC: time.Unix(0, row.UpdatedAt).UTC().Format(time.RFC3339Nano),
		})
	}

	return renderBlobListOutput(resolvedOutputMode, blobListOutput{
		DB:      absDBPath,
		Count:   len(entries),
		Entries: entries,
	})
}

func runBlobServeCommand(args []string) error {
	defaultDB := defaultBlobDBPath()
	defaultRoot := defaultBlobServerRootDir()

	fs := flag.NewFlagSet("blob serve", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s blob serve [options]\n\n", os.Args[0])
		fmt.Fprintln(fs.Output(), "Run a minimal HTTP server for deterministic encrypted blobs.")
		fmt.Fprintln(fs.Output(), "\nOptions:")
		fs.PrintDefaults()
	}

	listenAddr := fs.String("listen", "127.0.0.1:8787", "HTTP listen address")
	rootDir := fs.String("root", defaultRoot, "Root directory for stored encrypted blobs")
	dbPath := fs.String("db", defaultDB, "Path to blob metadata database")
	backend := fs.String("backend", blobRemoteBackendDefault, "Inventory backend name used by this server")
	bucket := fs.String("bucket", blobRemoteBucketDefault, "Inventory bucket name used by this server")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}

	if err := os.MkdirAll(*rootDir, 0o755); err != nil {
		return fmt.Errorf("create blob server root %q: %w", *rootDir, err)
	}

	absDBPath, err := filepath.Abs(*dbPath)
	if err != nil {
		return fmt.Errorf("resolve db path: %w", err)
	}
	db, err := openBlobDB(absDBPath)
	if err != nil {
		return err
	}
	defer db.Close()

	handler := newBlobHTTPHandler(*rootDir, db, strings.TrimSpace(*backend), strings.TrimSpace(*bucket))
	server := &http.Server{
		Addr:              *listenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("[blob] serving blob backend on %s (root=%s)", *listenAddr, *rootDir)
	if err := server.ListenAndServe(); err != nil && !stderrors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("blob server failed: %w", err)
	}
	return nil
}

func newBlobHTTPHandler(rootDir string, db *sql.DB, backend string, bucket string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("/v1/blobs/", func(w http.ResponseWriter, r *http.Request) {
		oid, err := parseBlobOIDFromRequestPath(r.URL.Path)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		objectPath, err := blobObjectPath(rootDir, oid)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		switch r.Method {
		case http.MethodPut:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, fmt.Sprintf("read request body: %v", err), http.StatusBadRequest)
				return
			}
			pkg, err := inspectCipherBlobData(body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if pkg.OID != oid {
				http.Error(w, "oid does not match encrypted blob payload", http.StatusBadRequest)
				return
			}

			created := false
			if _, statErr := os.Stat(objectPath); statErr == nil {
				existing, readErr := os.ReadFile(objectPath)
				if readErr != nil {
					http.Error(w, fmt.Sprintf("read existing blob: %v", readErr), http.StatusInternalServerError)
					return
				}
				if blake3Hex(existing) != pkg.CipherHash {
					http.Error(w, "existing blob data hash mismatch", http.StatusConflict)
					return
				}
			} else if os.IsNotExist(statErr) {
				if err := ensureBlobObject(objectPath, body, pkg.CipherHash); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				created = true
			} else {
				http.Error(w, fmt.Sprintf("stat blob object: %v", statErr), http.StatusInternalServerError)
				return
			}

			if err := upsertRemoteBlobInventoryDB(db, blobRemoteInventoryRow{
				Backend:    backend,
				Bucket:     bucket,
				ObjectKey:  oid,
				OID:        oid,
				Size:       pkg.CipherSize,
				ETag:       pkg.CipherHash,
				CipherHash: pkg.CipherHash,
				LastSeenNS: time.Now().UTC().UnixNano(),
				ScanID:     fmt.Sprintf("serve-put-%d", time.Now().UTC().UnixNano()),
			}); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			w.Header().Set("ETag", fmt.Sprintf("\"%s\"", pkg.CipherHash))
			w.Header().Set("Content-Type", "application/octet-stream")
			if created {
				w.WriteHeader(http.StatusCreated)
				return
			}
			w.WriteHeader(http.StatusOK)
		case http.MethodHead, http.MethodGet:
			data, err := os.ReadFile(objectPath)
			if err != nil {
				if os.IsNotExist(err) {
					http.Error(w, "blob not found", http.StatusNotFound)
					return
				}
				http.Error(w, fmt.Sprintf("read blob object: %v", err), http.StatusInternalServerError)
				return
			}
			cipherHash := blake3Hex(data)
			w.Header().Set("ETag", fmt.Sprintf("\"%s\"", cipherHash))
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Length", strconv.Itoa(len(data)))
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusOK)
				return
			}
			_, _ = w.Write(data)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	return mux
}

func renderBlobPutOutput(mode string, output blobPutOutput) error {
	switch mode {
	case outputModeKV:
		fmt.Printf("source_path=%s\n", output.SourcePath)
		fmt.Printf("cid=%s\n", output.CID)
		fmt.Printf("oid=%s\n", output.OID)
		fmt.Printf("plain_size=%d\n", output.PlainSize)
		fmt.Printf("cipher_size=%d\n", output.CipherSize)
		fmt.Printf("cipher_hash=%s\n", output.CipherHash)
		fmt.Printf("cache_path=%s\n", output.CachePath)
		fmt.Printf("uploaded=%t\n", output.Uploaded)
		if output.Server != "" {
			fmt.Printf("server=%s\n", output.Server)
		}
		return nil
	case outputModeJSON:
		return printJSON(output)
	case outputModePretty:
		printPrettyTitle("Blob Put")
		printPrettyFields([]outputField{
			{Label: "Source Path", Value: output.SourcePath},
			{Label: "CID", Value: output.CID},
			{Label: "OID", Value: output.OID},
			{Label: "Plain Size", Value: strconv.FormatInt(output.PlainSize, 10)},
			{Label: "Cipher Size", Value: strconv.FormatInt(output.CipherSize, 10)},
			{Label: "Cipher Hash", Value: output.CipherHash},
			{Label: "Cache Path", Value: output.CachePath},
			{Label: "Uploaded", Value: strconv.FormatBool(output.Uploaded)},
			{Label: "Server", Value: output.Server},
		})
		return nil
	default:
		return fmt.Errorf("unsupported output mode %q", mode)
	}
}

func renderBlobGetOutput(mode string, output blobGetOutput) error {
	switch mode {
	case outputModeKV:
		fmt.Printf("cid=%s\n", output.CID)
		fmt.Printf("oid=%s\n", output.OID)
		fmt.Printf("out_path=%s\n", output.OutPath)
		fmt.Printf("source=%s\n", output.Source)
		fmt.Printf("plain_size=%d\n", output.PlainSize)
		fmt.Printf("cipher_size=%d\n", output.CipherSize)
		fmt.Printf("cipher_hash=%s\n", output.CipherHash)
		fmt.Printf("cache_path=%s\n", output.CachePath)
		return nil
	case outputModeJSON:
		return printJSON(output)
	case outputModePretty:
		printPrettyTitle("Blob Get")
		printPrettyFields([]outputField{
			{Label: "CID", Value: output.CID},
			{Label: "OID", Value: output.OID},
			{Label: "Output Path", Value: output.OutPath},
			{Label: "Source", Value: output.Source},
			{Label: "Plain Size", Value: strconv.FormatInt(output.PlainSize, 10)},
			{Label: "Cipher Size", Value: strconv.FormatInt(output.CipherSize, 10)},
			{Label: "Cipher Hash", Value: output.CipherHash},
			{Label: "Cache Path", Value: output.CachePath},
		})
		return nil
	default:
		return fmt.Errorf("unsupported output mode %q", mode)
	}
}

func renderBlobListOutput(mode string, output blobListOutput) error {
	switch mode {
	case outputModeKV:
		fmt.Printf("db=%s\n", output.DB)
		fmt.Printf("count=%d\n", output.Count)
		fmt.Println("cid\toid\tplain_size\tcipher_size\tcipher_hash\tupdated_at_ns")
		for _, entry := range output.Entries {
			fmt.Printf("%s\t%s\t%d\t%d\t%s\t%d\n", entry.CID, entry.OID, entry.PlainSize, entry.CipherSize, entry.CipherHash, entry.UpdatedAtNS)
		}
		return nil
	case outputModeJSON:
		return printJSON(output)
	case outputModePretty:
		printPrettyTitle("Blob Map")
		printPrettyFields([]outputField{
			{Label: "Database", Value: output.DB},
			{Label: "Entries", Value: strconv.Itoa(output.Count)},
		})
		printPrettySection("Mappings")
		if len(output.Entries) == 0 {
			fmt.Println("No blob mappings found.")
			return nil
		}
		rows := make([][]string, 0, len(output.Entries))
		for _, entry := range output.Entries {
			rows = append(rows, []string{
				entry.CID,
				entry.OID,
				strconv.FormatInt(entry.PlainSize, 10),
				strconv.FormatInt(entry.CipherSize, 10),
				entry.UpdatedAtUTC,
			})
		}
		printPrettyTable([]string{"CID", "OID", "Plain", "Cipher", "Updated"}, rows)
		return nil
	default:
		return fmt.Errorf("unsupported output mode %q", mode)
	}
}

func defaultBlobDBPath() string {
	if custom := strings.TrimSpace(os.Getenv(blobDBEnv)); custom != "" {
		return custom
	}
	dataHome := os.Getenv("XDG_DATA_HOME")
	if strings.TrimSpace(dataHome) == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return blobDBDefaultFile
		}
		dataHome = filepath.Join(home, ".local", "share")
	}
	return filepath.Join(dataHome, snapshotDBDirName, blobDBDefaultFile)
}

func defaultBlobCacheDir() string {
	if custom := strings.TrimSpace(os.Getenv(blobCacheEnv)); custom != "" {
		return custom
	}
	cacheHome := os.Getenv("XDG_CACHE_HOME")
	if strings.TrimSpace(cacheHome) == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return filepath.Join(snapshotDBDirName, blobCacheDefaultDir)
		}
		cacheHome = filepath.Join(home, ".cache")
	}
	return filepath.Join(cacheHome, snapshotDBDirName, blobCacheDefaultDir)
}

func defaultBlobServerRootDir() string {
	if custom := strings.TrimSpace(os.Getenv(blobServerRootEnv)); custom != "" {
		return custom
	}
	dataHome := os.Getenv("XDG_DATA_HOME")
	if strings.TrimSpace(dataHome) == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return filepath.Join(snapshotDBDirName, blobServerDefaultDir)
		}
		dataHome = filepath.Join(home, ".local", "share")
	}
	return filepath.Join(dataHome, snapshotDBDirName, blobServerDefaultDir)
}

func openBlobDB(path string) (*sql.DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create blob db directory: %w", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open blob db: %w", err)
	}
	db.SetMaxOpenConns(1)
	if err := initBlobSchema(db); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func initBlobSchema(db *sql.DB) error {
	stmts := []string{
		"PRAGMA journal_mode=WAL;",
		"PRAGMA synchronous=NORMAL;",
		"PRAGMA foreign_keys=ON;",
		`CREATE TABLE IF NOT EXISTS blob_map (
			cid TEXT PRIMARY KEY,
			oid TEXT NOT NULL UNIQUE,
			plain_size INTEGER NOT NULL,
			cipher_size INTEGER NOT NULL,
			cipher_hash TEXT NOT NULL,
			enc_algo TEXT NOT NULL,
			enc_version INTEGER NOT NULL,
			cache_path TEXT NOT NULL,
			created_at_ns INTEGER NOT NULL,
			updated_at_ns INTEGER NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS remote_blob_inventory (
			backend TEXT NOT NULL,
			bucket TEXT NOT NULL,
			object_key TEXT NOT NULL,
			oid TEXT NOT NULL,
			size INTEGER NOT NULL,
			etag TEXT NOT NULL,
			cipher_hash TEXT NOT NULL,
			last_seen_ns INTEGER NOT NULL,
			scan_id TEXT NOT NULL,
			PRIMARY KEY (backend, bucket, object_key)
		);`,
		"CREATE INDEX IF NOT EXISTS blob_map_oid_idx ON blob_map(oid);",
		"CREATE INDEX IF NOT EXISTS remote_blob_inventory_oid_idx ON remote_blob_inventory(oid);",
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("initialize blob db schema: %w", err)
		}
	}
	return nil
}

func upsertBlobMap(tx *sql.Tx, row blobMapRow) error {
	now := time.Now().UTC().UnixNano()
	createdAt := now
	if row.UpdatedAt > 0 {
		now = row.UpdatedAt
		createdAt = row.UpdatedAt
	}
	if _, err := tx.Exec(
		`INSERT INTO blob_map(
			cid,
			oid,
			plain_size,
			cipher_size,
			cipher_hash,
			enc_algo,
			enc_version,
			cache_path,
			created_at_ns,
			updated_at_ns
		) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(cid) DO UPDATE SET
			oid = excluded.oid,
			plain_size = excluded.plain_size,
			cipher_size = excluded.cipher_size,
			cipher_hash = excluded.cipher_hash,
			enc_algo = excluded.enc_algo,
			enc_version = excluded.enc_version,
			cache_path = excluded.cache_path,
			updated_at_ns = excluded.updated_at_ns`,
		row.CID,
		row.OID,
		row.PlainSize,
		row.CipherSize,
		row.CipherHash,
		blobEncAlgorithm,
		blobEncVersion,
		row.CachePath,
		createdAt,
		now,
	); err != nil {
		return fmt.Errorf("upsert blob map for cid=%q: %w", row.CID, err)
	}
	return nil
}

func upsertRemoteBlobInventory(tx *sql.Tx, row blobRemoteInventoryRow) error {
	backend := strings.TrimSpace(row.Backend)
	if backend == "" {
		backend = blobRemoteBackendDefault
	}
	bucket := strings.TrimSpace(row.Bucket)
	if bucket == "" {
		bucket = blobRemoteBucketDefault
	}
	if row.LastSeenNS == 0 {
		row.LastSeenNS = time.Now().UTC().UnixNano()
	}
	if row.ScanID == "" {
		row.ScanID = fmt.Sprintf("scan-%d", row.LastSeenNS)
	}
	if _, err := tx.Exec(
		`INSERT INTO remote_blob_inventory(
			backend,
			bucket,
			object_key,
			oid,
			size,
			etag,
			cipher_hash,
			last_seen_ns,
			scan_id
		) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(backend, bucket, object_key) DO UPDATE SET
			oid = excluded.oid,
			size = excluded.size,
			etag = excluded.etag,
			cipher_hash = excluded.cipher_hash,
			last_seen_ns = excluded.last_seen_ns,
			scan_id = excluded.scan_id`,
		backend,
		bucket,
		row.ObjectKey,
		row.OID,
		row.Size,
		row.ETag,
		row.CipherHash,
		row.LastSeenNS,
		row.ScanID,
	); err != nil {
		return fmt.Errorf("upsert remote blob inventory for key=%q: %w", row.ObjectKey, err)
	}
	return nil
}

func upsertRemoteBlobInventoryDB(db *sql.DB, row blobRemoteInventoryRow) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("start blob inventory transaction: %w", err)
	}
	defer tx.Rollback()
	if err := upsertRemoteBlobInventory(tx, row); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit blob inventory transaction: %w", err)
	}
	return nil
}

func listBlobMappings(db *sql.DB, limit int) ([]blobMapRow, error) {
	rows, err := db.Query(
		`SELECT cid, oid, plain_size, cipher_size, cipher_hash, cache_path, updated_at_ns
		 FROM blob_map
		 ORDER BY updated_at_ns DESC, cid ASC
		 LIMIT ?`,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("query blob mappings: %w", err)
	}
	defer rows.Close()

	result := make([]blobMapRow, 0, limit)
	for rows.Next() {
		row := blobMapRow{}
		if err := rows.Scan(&row.CID, &row.OID, &row.PlainSize, &row.CipherSize, &row.CipherHash, &row.CachePath, &row.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan blob mapping row: %w", err)
		}
		result = append(result, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate blob mappings: %w", err)
	}
	return result, nil
}

func encryptBlobData(plain []byte) (blobCipherPackage, error) {
	cid := blake3.Sum256(plain)
	header := buildBlobHeader(cid, int64(len(plain)))
	key := deriveBlobMaterial(cid, "enc-key", chacha20poly1305.KeySize)
	nonce := deriveBlobMaterial(cid, "enc-nonce", chacha20poly1305.NonceSizeX)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return blobCipherPackage{}, fmt.Errorf("initialize xchacha20poly1305: %w", err)
	}
	ciphertext := aead.Seal(nil, nonce, plain, header)
	encoded := append(append([]byte{}, header...), ciphertext...)
	cipherHash := blake3Hex(encoded)
	oid := deriveBlobOID(cid)
	return blobCipherPackage{
		CID:        hex.EncodeToString(cid[:]),
		OID:        oid,
		PlainSize:  int64(len(plain)),
		CipherSize: int64(len(encoded)),
		CipherHash: cipherHash,
		Encoded:    encoded,
	}, nil
}

func decodeAndDecryptBlobData(encoded []byte) (blobCipherPackage, []byte, error) {
	cid, plainSize, header, err := parseBlobHeader(encoded)
	if err != nil {
		return blobCipherPackage{}, nil, err
	}
	key := deriveBlobMaterial(cid, "enc-key", chacha20poly1305.KeySize)
	nonce := deriveBlobMaterial(cid, "enc-nonce", chacha20poly1305.NonceSizeX)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return blobCipherPackage{}, nil, fmt.Errorf("initialize xchacha20poly1305: %w", err)
	}
	plaintext, err := aead.Open(nil, nonce, encoded[len(header):], header)
	if err != nil {
		return blobCipherPackage{}, nil, fmt.Errorf("decrypt blob payload: %w", err)
	}
	if int64(len(plaintext)) != plainSize {
		return blobCipherPackage{}, nil, fmt.Errorf("decrypted size mismatch: expected %d got %d", plainSize, len(plaintext))
	}
	cidCheck := blake3.Sum256(plaintext)
	if !bytes.Equal(cidCheck[:], cid[:]) {
		return blobCipherPackage{}, nil, fmt.Errorf("decrypted content hash mismatch")
	}

	pkg := blobCipherPackage{
		CID:        hex.EncodeToString(cid[:]),
		OID:        deriveBlobOID(cid),
		PlainSize:  plainSize,
		CipherSize: int64(len(encoded)),
		CipherHash: blake3Hex(encoded),
		Encoded:    encoded,
	}
	return pkg, plaintext, nil
}

func inspectCipherBlobData(encoded []byte) (blobCipherPackage, error) {
	cid, plainSize, _, err := parseBlobHeader(encoded)
	if err != nil {
		return blobCipherPackage{}, err
	}
	return blobCipherPackage{
		CID:        hex.EncodeToString(cid[:]),
		OID:        deriveBlobOID(cid),
		PlainSize:  plainSize,
		CipherSize: int64(len(encoded)),
		CipherHash: blake3Hex(encoded),
		Encoded:    encoded,
	}, nil
}

func buildBlobHeader(cid [blobDigestBytes]byte, plainSize int64) []byte {
	header := make([]byte, 0, blobHeaderLen)
	header = append(header, []byte(blobMagic)...)
	header = append(header, byte(blobEncVersion))
	sizeBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(sizeBuf, uint64(plainSize))
	header = append(header, sizeBuf...)
	header = append(header, cid[:]...)
	return header
}

func parseBlobHeader(encoded []byte) ([blobDigestBytes]byte, int64, []byte, error) {
	cid := [blobDigestBytes]byte{}
	if len(encoded) < blobHeaderLen {
		return cid, 0, nil, fmt.Errorf("blob payload too short: got %d bytes", len(encoded))
	}
	if string(encoded[:len(blobMagic)]) != blobMagic {
		return cid, 0, nil, fmt.Errorf("unsupported blob magic")
	}
	if int(encoded[len(blobMagic)]) != blobEncVersion {
		return cid, 0, nil, fmt.Errorf("unsupported blob version %d", encoded[len(blobMagic)])
	}
	sizeU64 := binary.BigEndian.Uint64(encoded[len(blobMagic)+1 : len(blobMagic)+1+8])
	if sizeU64 > uint64(^uint(0)>>1) {
		return cid, 0, nil, fmt.Errorf("blob plain size too large: %d", sizeU64)
	}
	plainSize := int64(sizeU64)
	copy(cid[:], encoded[len(blobMagic)+1+8:blobHeaderLen])
	return cid, plainSize, encoded[:blobHeaderLen], nil
}

func deriveBlobMaterial(cid [blobDigestBytes]byte, label string, outLen int) []byte {
	if outLen <= 0 {
		return nil
	}
	out := make([]byte, 0, outLen)
	counter := uint32(0)
	for len(out) < outLen {
		h := blake3.New()
		h.Write([]byte("forge.blob.v1:"))
		h.Write([]byte(label))
		counterBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(counterBuf, counter)
		h.Write(counterBuf)
		h.Write(cid[:])
		sum := h.Sum(nil)
		needed := outLen - len(out)
		if needed >= len(sum) {
			out = append(out, sum...)
		} else {
			out = append(out, sum[:needed]...)
		}
		counter++
	}
	return out
}

func deriveBlobOID(cid [blobDigestBytes]byte) string {
	return hex.EncodeToString(deriveBlobMaterial(cid, "oid", blobDigestBytes))
}

func parseDigestHex32(value string) ([blobDigestBytes]byte, error) {
	out := [blobDigestBytes]byte{}
	normalized := normalizeDigestHex(value)
	if normalized == "" {
		return out, fmt.Errorf("digest is empty")
	}
	if len(normalized) != blobDigestHexSize {
		return out, fmt.Errorf("digest must be %d hex characters", blobDigestHexSize)
	}
	decoded, err := hex.DecodeString(normalized)
	if err != nil {
		return out, fmt.Errorf("decode digest hex: %w", err)
	}
	copy(out[:], decoded)
	return out, nil
}

func normalizeDigestHex(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func validateBlobOID(oid string) error {
	normalized := normalizeDigestHex(oid)
	if len(normalized) != blobDigestHexSize {
		return fmt.Errorf("blob oid must be %d hex characters", blobDigestHexSize)
	}
	if _, err := hex.DecodeString(normalized); err != nil {
		return fmt.Errorf("invalid blob oid %q: %w", oid, err)
	}
	return nil
}

func parseBlobOIDFromRequestPath(path string) (string, error) {
	const prefix = "/v1/blobs/"
	if !strings.HasPrefix(path, prefix) {
		return "", fmt.Errorf("unexpected blob path")
	}
	oid := strings.TrimSpace(strings.TrimPrefix(path, prefix))
	if oid == "" || strings.Contains(oid, "/") {
		return "", fmt.Errorf("blob oid is required in path")
	}
	oid = normalizeDigestHex(oid)
	if err := validateBlobOID(oid); err != nil {
		return "", err
	}
	return oid, nil
}

func blobObjectPath(rootDir string, oid string) (string, error) {
	normalized := normalizeDigestHex(oid)
	if err := validateBlobOID(normalized); err != nil {
		return "", err
	}
	return filepath.Join(rootDir, normalized[:2], normalized[2:4], normalized+".fblob"), nil
}

func ensureBlobObject(objectPath string, encoded []byte, expectedCipherHash string) error {
	if expectedCipherHash == "" {
		expectedCipherHash = blake3Hex(encoded)
	}
	if err := os.MkdirAll(filepath.Dir(objectPath), 0o755); err != nil {
		return fmt.Errorf("create blob object directory %q: %w", filepath.Dir(objectPath), err)
	}

	if existing, err := os.ReadFile(objectPath); err == nil {
		if blake3Hex(existing) != expectedCipherHash {
			return fmt.Errorf("existing blob object %q has mismatched hash", objectPath)
		}
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("read existing blob object %q: %w", objectPath, err)
	}

	file, err := os.OpenFile(objectPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			existing, readErr := os.ReadFile(objectPath)
			if readErr != nil {
				return fmt.Errorf("read concurrently created blob object %q: %w", objectPath, readErr)
			}
			if blake3Hex(existing) != expectedCipherHash {
				return fmt.Errorf("concurrently created blob object %q has mismatched hash", objectPath)
			}
			return nil
		}
		return fmt.Errorf("create blob object %q: %w", objectPath, err)
	}
	defer file.Close()

	if _, err := file.Write(encoded); err != nil {
		_ = os.Remove(objectPath)
		return fmt.Errorf("write blob object %q: %w", objectPath, err)
	}
	if err := file.Sync(); err != nil {
		_ = os.Remove(objectPath)
		return fmt.Errorf("sync blob object %q: %w", objectPath, err)
	}
	return nil
}

func uploadBlobToServer(serverURL string, oid string, encoded []byte) (string, error) {
	normalizedOID := normalizeDigestHex(oid)
	if err := validateBlobOID(normalizedOID); err != nil {
		return "", err
	}
	url := strings.TrimRight(strings.TrimSpace(serverURL), "/") + "/v1/blobs/" + normalizedOID
	req, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(encoded))
	if err != nil {
		return "", fmt.Errorf("create upload request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("upload blob %q to %q: %w", normalizedOID, serverURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8*1024))
		return "", fmt.Errorf("upload blob %q failed: status=%d body=%s", normalizedOID, resp.StatusCode, strings.TrimSpace(string(body)))
	}

	etag := strings.TrimSpace(resp.Header.Get("ETag"))
	etag = strings.Trim(etag, "\"")
	return normalizeDigestHex(etag), nil
}

func fetchBlobFromServer(serverURL string, oid string) ([]byte, string, error) {
	normalizedOID := normalizeDigestHex(oid)
	if err := validateBlobOID(normalizedOID); err != nil {
		return nil, "", err
	}
	url := strings.TrimRight(strings.TrimSpace(serverURL), "/") + "/v1/blobs/" + normalizedOID
	resp, err := http.Get(url)
	if err != nil {
		return nil, "", fmt.Errorf("fetch blob %q from %q: %w", normalizedOID, serverURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8*1024))
		return nil, "", fmt.Errorf("fetch blob %q failed: status=%d body=%s", normalizedOID, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("read blob response for %q: %w", normalizedOID, err)
	}
	etag := strings.TrimSpace(resp.Header.Get("ETag"))
	etag = strings.Trim(etag, "\"")
	return payload, normalizeDigestHex(etag), nil
}
