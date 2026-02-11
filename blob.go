package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	stderrors "errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/tionis/forge/internal/forgeconfig"
	"github.com/zeebo/blake3"
	"golang.org/x/crypto/chacha20poly1305"
	_ "modernc.org/sqlite"
)

const (
	blobEncAlgorithm = "xchacha20poly1305"
	blobEncVersion   = 1

	blobMagic         = "FBLB1"
	blobDigestHexSize = 64
	blobDigestBytes   = 32
	blobHeaderLen     = len(blobMagic) + 1 + 8 + blobDigestBytes

	blobRemoteBackendDefault = defaultS3BackendName
	blobRemoteBucketDefault  = "default"
)

var errReflinkUnsupported = stderrors.New("copy-on-write clone not supported")
var cloneFileCoWFunc = cloneFileCoW
var openBlobRemoteStoreFunc = openConfiguredBlobRemoteStore

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
	Remote     bool   `json:"remote"`
	Backend    string `json:"backend,omitempty"`
	Bucket     string `json:"bucket,omitempty"`
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

type blobRemoveOutput struct {
	CID                string `json:"cid"`
	OID                string `json:"oid"`
	CachePath          string `json:"cache_path"`
	LocalRequested     bool   `json:"local_requested"`
	LocalRemoved       bool   `json:"local_removed"`
	RemoteRequested    bool   `json:"remote_requested"`
	RemoteRemoved      bool   `json:"remote_removed"`
	BlobMapRowsDeleted int64  `json:"blob_map_rows_deleted"`
	InventoryRowsDel   int64  `json:"inventory_rows_deleted"`
	Backend            string `json:"backend,omitempty"`
	Bucket             string `json:"bucket,omitempty"`
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

type blobGCOutput struct {
	DB                   string `json:"db"`
	CacheDir             string `json:"cache_dir"`
	SnapshotDB           string `json:"snapshot_db,omitempty"`
	VectorQueueDB        string `json:"vector_queue_db,omitempty"`
	Applied              bool   `json:"applied"`
	SnapshotRefsEnabled  bool   `json:"snapshot_refs_enabled"`
	VectorRefsEnabled    bool   `json:"vector_refs_enabled"`
	SnapshotRefsFound    int    `json:"snapshot_refs_found"`
	VectorRefsFound      int    `json:"vector_refs_found"`
	LiveCIDCount         int    `json:"live_cid_count"`
	BlobMapRowsScanned   int    `json:"blob_map_rows_scanned"`
	BlobMapDeletePlan    int    `json:"blob_map_delete_plan"`
	BlobMapRowsDeleted   int64  `json:"blob_map_rows_deleted"`
	CacheDeletePlan      int    `json:"cache_delete_plan"`
	CacheFilesDeleted    int    `json:"cache_files_deleted"`
	CacheDeleteWarnCount int    `json:"cache_delete_warning_count"`
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
		fmt.Fprintln(fs.Output(), "Cache a plaintext blob locally and optionally upload encrypted blob payload to configured remote S3.")
		fmt.Fprintln(fs.Output(), "\nOptions:")
		fs.PrintDefaults()
	}

	dbPath := fs.String("db", defaultDB, "Path to blob metadata database")
	cacheDir := fs.String("cache", defaultCache, "Path to local blob cache directory")
	remoteUpload := fs.Bool("remote", false, "Upload encrypted blob payload to configured remote S3")
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

	cidSum := blake3.Sum256(plain)
	cid := hex.EncodeToString(cidSum[:])
	oid := deriveBlobOID(cidSum)
	cachePath, err := blobPlainCachePath(*cacheDir, cid)
	if err != nil {
		return err
	}
	if err := ensurePlainBlobCacheObject(cachePath, absInputPath, plain, cid, *verbose); err != nil {
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

	cipherSize := int64(0)
	cipherHash := ""
	if err := upsertBlobMap(tx, blobMapRow{
		CID:        cid,
		OID:        oid,
		PlainSize:  int64(len(plain)),
		CipherSize: cipherSize,
		CipherHash: cipherHash,
		CachePath:  cachePath,
		UpdatedAt:  time.Now().UTC().UnixNano(),
	}); err != nil {
		return err
	}

	uploaded := false
	remoteBackend := ""
	remoteBucket := ""
	if *remoteUpload {
		ctx := context.Background()
		remoteStore, err := openBlobRemoteStoreFunc(ctx)
		if err != nil {
			return err
		}
		remoteBackend = remoteStore.BackendName()
		remoteBucket = remoteStore.BucketName()

		pkg, err := encryptBlobData(plain)
		if err != nil {
			return err
		}
		if pkg.CID != cid || pkg.OID != oid {
			return fmt.Errorf("internal blob identity mismatch while preparing encrypted payload")
		}
		cipherSize = pkg.CipherSize
		cipherHash = pkg.CipherHash

		if err := upsertBlobMap(tx, blobMapRow{
			CID:        cid,
			OID:        oid,
			PlainSize:  int64(len(plain)),
			CipherSize: cipherSize,
			CipherHash: cipherHash,
			CachePath:  cachePath,
			UpdatedAt:  time.Now().UTC().UnixNano(),
		}); err != nil {
			return err
		}

		if *verbose {
			log.Printf("[blob] uploading %s to %s://%s", oid, remoteBackend, remoteBucket)
		}
		etag, err := remoteStore.PutBlob(ctx, oid, pkg.Encoded)
		if err != nil {
			return err
		}
		if etag == "" {
			etag = cipherHash
		}
		scanID := fmt.Sprintf("blob-put-%d", time.Now().UTC().UnixNano())
		if err := upsertRemoteBlobInventory(tx, blobRemoteInventoryRow{
			Backend:    remoteBackend,
			Bucket:     remoteBucket,
			ObjectKey:  oid,
			OID:        oid,
			Size:       cipherSize,
			ETag:       etag,
			CipherHash: cipherHash,
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
			CID:        cid,
			OID:        oid,
			PlainSize:  int64(len(plain)),
			CipherSize: cipherSize,
			CipherHash: cipherHash,
			CachePath:  cachePath,
			Uploaded:   uploaded,
			Remote:     *remoteUpload,
			Backend:    remoteBackend,
			Bucket:     remoteBucket,
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
		fmt.Fprintln(fs.Output(), "Read a plaintext blob from local cache, or fetch encrypted data from configured remote S3 and decrypt to -out.")
		fmt.Fprintln(fs.Output(), "\nOptions:")
		fs.PrintDefaults()
	}

	dbPath := fs.String("db", defaultDB, "Path to blob metadata database")
	cacheDir := fs.String("cache", defaultCache, "Path to local blob cache directory")
	remoteFetch := fs.Bool("remote", false, "Fetch encrypted blob from configured remote S3 when local cache misses")
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
	} else if err := validateBlobOID(requestedOID); err != nil {
		return fmt.Errorf("parse -oid: %w", err)
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

	var existingRow blobMapRow
	existingFound := false
	if requestedCID == "" {
		row, found, err := lookupBlobMapByOID(db, requestedOID)
		if err != nil {
			return err
		}
		if found {
			existingRow = row
			existingFound = true
			requestedCID = row.CID
		}
	} else {
		row, found, err := lookupBlobMapByCID(db, requestedCID)
		if err != nil {
			return err
		}
		if found {
			existingRow = row
			existingFound = true
		}
	}
	if requestedOID == "" && requestedCID != "" {
		cidBytes, err := parseDigestHex32(requestedCID)
		if err != nil {
			return fmt.Errorf("parse resolved cid: %w", err)
		}
		requestedOID = deriveBlobOID(cidBytes)
	}

	plain := []byte(nil)
	pkg := blobCipherPackage{}
	source := "cache"
	etag := ""
	cachePath := ""
	cacheHit := false
	remoteBackend := ""
	remoteBucket := ""

	if requestedCID != "" {
		cachePath, err = blobPlainCachePath(*cacheDir, requestedCID)
		if err != nil {
			return err
		}
		plain, err = os.ReadFile(cachePath)
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("read cached blob %q: %w", cachePath, err)
		}
		if err == nil {
			cidSum := blake3.Sum256(plain)
			actualCID := hex.EncodeToString(cidSum[:])
			if actualCID != requestedCID {
				return fmt.Errorf("cached blob %q cid mismatch: expected %s got %s", cachePath, requestedCID, actualCID)
			}
			pkg = blobCipherPackage{
				CID:       requestedCID,
				OID:       deriveBlobOID(cidSum),
				PlainSize: int64(len(plain)),
			}
			if existingFound && existingRow.CID == requestedCID {
				pkg.CipherSize = existingRow.CipherSize
				pkg.CipherHash = existingRow.CipherHash
			}
			cacheHit = true
		}
	}

	if !cacheHit && *remoteFetch {
		if requestedOID == "" {
			return fmt.Errorf("cannot fetch from remote without oid")
		}
		ctx := context.Background()
		remoteStore, err := openBlobRemoteStoreFunc(ctx)
		if err != nil {
			return err
		}
		remoteBackend = remoteStore.BackendName()
		remoteBucket = remoteStore.BucketName()

		if *verbose {
			log.Printf("[blob] cache miss for %s, fetching from %s://%s", requestedOID, remoteBackend, remoteBucket)
		}
		encoded, fetchedETag, found, err := remoteStore.GetBlob(ctx, requestedOID)
		if err != nil {
			return err
		}
		if !found {
			return fmt.Errorf("blob %q not found on remote %s://%s", requestedOID, remoteBackend, remoteBucket)
		}
		decodedPkg, decodedPlain, err := decodeAndDecryptBlobData(encoded)
		if err != nil {
			return err
		}
		if requestedCID != "" && decodedPkg.CID != requestedCID {
			return fmt.Errorf("decrypted CID mismatch: expected %s got %s", requestedCID, decodedPkg.CID)
		}
		if requestedOID != "" && decodedPkg.OID != requestedOID {
			return fmt.Errorf("decrypted OID mismatch: expected %s got %s", requestedOID, decodedPkg.OID)
		}
		requestedCID = decodedPkg.CID
		requestedOID = decodedPkg.OID
		plain = decodedPlain
		pkg = decodedPkg
		etag = fetchedETag
		cachePath, err = blobPlainCachePath(*cacheDir, requestedCID)
		if err != nil {
			return err
		}
		if err := ensureBlobObject(cachePath, plain, requestedCID); err != nil {
			return err
		}
		source = "remote"
		cacheHit = true
	}
	if !cacheHit {
		if requestedCID != "" {
			return fmt.Errorf("blob %q not found in local cache and no -remote fetch enabled", requestedCID)
		}
		return fmt.Errorf("blob %q not found in metadata/local cache and no -remote fetch enabled", requestedOID)
	}

	if pkg.CID == "" {
		cidSum := blake3.Sum256(plain)
		pkg.CID = hex.EncodeToString(cidSum[:])
		pkg.OID = deriveBlobOID(cidSum)
		pkg.PlainSize = int64(len(plain))
	}

	if requestedCID != "" && pkg.CID != requestedCID {
		return fmt.Errorf("resolved CID mismatch: expected %s got %s", requestedCID, pkg.CID)
	}
	if requestedOID != "" && pkg.OID != requestedOID {
		return fmt.Errorf("resolved OID mismatch: expected %s got %s", requestedOID, pkg.OID)
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

	if source == "remote" {
		if etag == "" {
			etag = pkg.CipherHash
		}
		scanID := fmt.Sprintf("blob-get-%d", time.Now().UTC().UnixNano())
		if err := upsertRemoteBlobInventory(tx, blobRemoteInventoryRow{
			Backend:    remoteBackend,
			Bucket:     remoteBucket,
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

func runBlobRemoveCommand(args []string) error {
	defaultDB := defaultBlobDBPath()
	defaultCache := defaultBlobCacheDir()

	fs := flag.NewFlagSet("blob rm", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s blob rm [options]\n\n", os.Args[0])
		fmt.Fprintln(fs.Output(), "Remove a blob from local plaintext cache and optionally from configured remote S3.")
		fmt.Fprintln(fs.Output(), "\nOptions:")
		fs.PrintDefaults()
	}

	dbPath := fs.String("db", defaultDB, "Path to blob metadata database")
	cacheDir := fs.String("cache", defaultCache, "Path to local blob cache directory")
	cidFlag := fs.String("cid", "", "Cleartext BLAKE3 content hash (hex)")
	oidFlag := fs.String("oid", "", "Encrypted blob object ID (hex)")
	local := fs.Bool("local", true, "Delete local cached plaintext and local blob mapping metadata")
	remote := fs.Bool("remote", false, "Delete encrypted blob from remote backend and clear matching remote inventory rows")
	outputMode := fs.String("output", outputModeAuto, "Output mode: auto|pretty|kv|json")
	verbose := fs.Bool("v", false, "Verbose output")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}

	if !*local && !*remote {
		return fmt.Errorf("nothing to do: enable at least one of -local or -remote")
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
	} else if err := validateBlobOID(requestedOID); err != nil {
		return fmt.Errorf("parse -oid: %w", err)
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

	if requestedCID == "" {
		row, found, err := lookupBlobMapByOID(db, requestedOID)
		if err != nil {
			return err
		}
		if found {
			requestedCID = row.CID
		}
	}
	if requestedOID == "" && requestedCID != "" {
		cidBytes, err := parseDigestHex32(requestedCID)
		if err != nil {
			return fmt.Errorf("parse resolved cid: %w", err)
		}
		requestedOID = deriveBlobOID(cidBytes)
	}

	cachePath := ""
	localRemoved := false
	if *local {
		if requestedCID == "" {
			return fmt.Errorf("cannot remove local cache with unknown cid; provide -cid or keep blob mapping metadata")
		}
		cachePath, err = blobPlainCachePath(*cacheDir, requestedCID)
		if err != nil {
			return err
		}
		if err := os.Remove(cachePath); err != nil {
			if !os.IsNotExist(err) {
				return fmt.Errorf("remove local blob cache %q: %w", cachePath, err)
			}
		} else {
			localRemoved = true
			if *verbose {
				log.Printf("[blob] removed local cache object %s", cachePath)
			}
		}
	}

	remoteRemoved := false
	remoteBackend := ""
	remoteBucket := ""
	if *remote {
		ctx := context.Background()
		remoteStore, err := openBlobRemoteStoreFunc(ctx)
		if err != nil {
			return err
		}
		remoteBackend = remoteStore.BackendName()
		remoteBucket = remoteStore.BucketName()

		remoteRemoved, err = remoteStore.DeleteBlob(ctx, requestedOID)
		if err != nil {
			return err
		}
		if *verbose {
			if remoteRemoved {
				log.Printf("[blob] removed remote encrypted object %s from %s://%s", requestedOID, remoteBackend, remoteBucket)
			} else {
				log.Printf("[blob] remote encrypted object %s not found on %s://%s", requestedOID, remoteBackend, remoteBucket)
			}
		}
	}

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("start blob remove transaction: %w", err)
	}
	defer tx.Rollback()

	rowsDeleted := int64(0)
	if *local {
		rowsDeleted, err = deleteBlobMapRows(tx, requestedCID, requestedOID)
		if err != nil {
			return err
		}
	}
	inventoryDeleted := int64(0)
	if *remote {
		inventoryDeleted, err = deleteRemoteBlobInventoryByOID(tx, remoteBackend, remoteBucket, requestedOID)
		if err != nil {
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit blob remove transaction: %w", err)
	}

	return renderBlobRemoveOutput(
		resolvedOutputMode,
		blobRemoveOutput{
			CID:                requestedCID,
			OID:                requestedOID,
			CachePath:          cachePath,
			LocalRequested:     *local,
			LocalRemoved:       localRemoved,
			RemoteRequested:    *remote,
			RemoteRemoved:      remoteRemoved,
			BlobMapRowsDeleted: rowsDeleted,
			InventoryRowsDel:   inventoryDeleted,
			Backend:            remoteBackend,
			Bucket:             remoteBucket,
		},
	)
}

func runBlobGCCommand(args []string) error {
	defaultDB := defaultBlobDBPath()
	defaultCache := defaultBlobCacheDir()
	defaultSnapshot := defaultSnapshotDBPath()
	defaultVectorQueue := defaultVectorQueueDBPathForGC()

	fs := flag.NewFlagSet("blob gc", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s blob gc [options]\n\n", os.Args[0])
		fmt.Fprintln(fs.Output(), "Garbage collect local blob cache/metadata based on local references.")
		fmt.Fprintln(fs.Output(), "Default mode is dry-run; pass -apply to perform deletions.")
		fmt.Fprintln(fs.Output(), "\nOptions:")
		fs.PrintDefaults()
	}

	dbPath := fs.String("db", defaultDB, "Path to blob metadata database")
	cacheDir := fs.String("cache", defaultCache, "Path to local blob cache directory")
	snapshotDBPath := fs.String("snapshot-db", defaultSnapshot, "Path to snapshot database for tree-entry references")
	vectorQueueDBPath := fs.String("vector-queue-db", defaultVectorQueue, "Path to vector queue database for payload references")
	noSnapshotRefs := fs.Bool("no-snapshot-refs", false, "Disable snapshot tree-entry references as GC roots")
	noVectorRefs := fs.Bool("no-vector-refs", false, "Disable vector queue references as GC roots")
	includeErrorJobs := fs.Bool("include-error-jobs", true, "Treat vector queue status=error jobs as GC roots")
	apply := fs.Bool("apply", false, "Apply deletions (default is dry-run)")
	outputMode := fs.String("output", outputModeAuto, "Output mode: auto|pretty|kv|json")
	verbose := fs.Bool("v", false, "Verbose output")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if *noSnapshotRefs && *noVectorRefs {
		return fmt.Errorf("no reference roots enabled; keep at least one of snapshot/vector references")
	}

	resolvedOutputMode, err := resolvePrettyKVJSONOutputMode(*outputMode)
	if err != nil {
		return err
	}

	absDBPath, err := filepath.Abs(*dbPath)
	if err != nil {
		return fmt.Errorf("resolve db path: %w", err)
	}
	absCacheDir, err := filepath.Abs(*cacheDir)
	if err != nil {
		return fmt.Errorf("resolve cache dir: %w", err)
	}
	absSnapshotDBPath, err := filepath.Abs(*snapshotDBPath)
	if err != nil {
		return fmt.Errorf("resolve snapshot db path: %w", err)
	}
	absVectorQueueDBPath, err := filepath.Abs(*vectorQueueDBPath)
	if err != nil {
		return fmt.Errorf("resolve vector queue db path: %w", err)
	}

	db, err := openBlobDB(absDBPath)
	if err != nil {
		return err
	}
	defer db.Close()

	live := make(map[string]struct{})
	snapshotRefs := 0
	vectorRefs := 0
	if !*noSnapshotRefs {
		n, err := collectLiveBlobRefsFromSnapshotDB(absSnapshotDBPath, live)
		if err != nil {
			return err
		}
		snapshotRefs = n
	}
	if !*noVectorRefs {
		n, err := collectLiveBlobRefsFromVectorQueueDB(absVectorQueueDBPath, *includeErrorJobs, live)
		if err != nil {
			return err
		}
		vectorRefs = n
	}

	rows, err := listAllBlobMappings(db)
	if err != nil {
		return err
	}

	deletePlanRows := make([]blobMapRow, 0)
	for _, row := range rows {
		if _, ok := live[row.CID]; ok {
			continue
		}
		deletePlanRows = append(deletePlanRows, row)
		if *verbose {
			log.Printf("[blob gc] stale blob_map cid=%s oid=%s cache_path=%s", row.CID, row.OID, row.CachePath)
		}
	}

	rowsDeleted := int64(0)
	cacheDeleted := 0
	cacheDeleteWarnings := 0
	if *apply && len(deletePlanRows) > 0 {
		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("start blob gc transaction: %w", err)
		}
		defer tx.Rollback()

		for _, row := range deletePlanRows {
			res, err := tx.Exec(`DELETE FROM blob_map WHERE cid = ?`, row.CID)
			if err != nil {
				return fmt.Errorf("delete blob_map row for cid %q: %w", row.CID, err)
			}
			affected, err := res.RowsAffected()
			if err != nil {
				return fmt.Errorf("read blob_map delete rows affected for cid %q: %w", row.CID, err)
			}
			rowsDeleted += affected
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit blob gc transaction: %w", err)
		}

		for _, row := range deletePlanRows {
			cachePath := strings.TrimSpace(row.CachePath)
			if cachePath == "" {
				resolved, err := blobPlainCachePath(absCacheDir, row.CID)
				if err == nil {
					cachePath = resolved
				}
			}
			if cachePath == "" {
				continue
			}
			err := os.Remove(cachePath)
			if err == nil {
				cacheDeleted++
				if *verbose {
					log.Printf("[blob gc] removed cache file %s", cachePath)
				}
				continue
			}
			if os.IsNotExist(err) {
				continue
			}
			cacheDeleteWarnings++
			log.Printf("[blob gc] warning: remove cache file %s: %v", cachePath, err)
		}
	}

	return renderBlobGCOutput(
		resolvedOutputMode,
		blobGCOutput{
			DB:                   absDBPath,
			CacheDir:             absCacheDir,
			SnapshotDB:           absSnapshotDBPath,
			VectorQueueDB:        absVectorQueueDBPath,
			Applied:              *apply,
			SnapshotRefsEnabled:  !*noSnapshotRefs,
			VectorRefsEnabled:    !*noVectorRefs,
			SnapshotRefsFound:    snapshotRefs,
			VectorRefsFound:      vectorRefs,
			LiveCIDCount:         len(live),
			BlobMapRowsScanned:   len(rows),
			BlobMapDeletePlan:    len(deletePlanRows),
			BlobMapRowsDeleted:   rowsDeleted,
			CacheDeletePlan:      len(deletePlanRows),
			CacheFilesDeleted:    cacheDeleted,
			CacheDeleteWarnCount: cacheDeleteWarnings,
		},
	)
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
		fmt.Printf("remote=%t\n", output.Remote)
		if output.Backend != "" {
			fmt.Printf("backend=%s\n", output.Backend)
		}
		if output.Bucket != "" {
			fmt.Printf("bucket=%s\n", output.Bucket)
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
			{Label: "Remote", Value: strconv.FormatBool(output.Remote)},
			{Label: "Backend", Value: output.Backend},
			{Label: "Bucket", Value: output.Bucket},
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

func renderBlobRemoveOutput(mode string, output blobRemoveOutput) error {
	switch mode {
	case outputModeKV:
		fmt.Printf("cid=%s\n", output.CID)
		fmt.Printf("oid=%s\n", output.OID)
		fmt.Printf("cache_path=%s\n", output.CachePath)
		fmt.Printf("local_requested=%t\n", output.LocalRequested)
		fmt.Printf("local_removed=%t\n", output.LocalRemoved)
		fmt.Printf("remote_requested=%t\n", output.RemoteRequested)
		fmt.Printf("remote_removed=%t\n", output.RemoteRemoved)
		fmt.Printf("blob_map_rows_deleted=%d\n", output.BlobMapRowsDeleted)
		fmt.Printf("inventory_rows_deleted=%d\n", output.InventoryRowsDel)
		if output.Backend != "" {
			fmt.Printf("backend=%s\n", output.Backend)
		}
		if output.Bucket != "" {
			fmt.Printf("bucket=%s\n", output.Bucket)
		}
		return nil
	case outputModeJSON:
		return printJSON(output)
	case outputModePretty:
		printPrettyTitle("Blob Remove")
		printPrettyFields([]outputField{
			{Label: "CID", Value: output.CID},
			{Label: "OID", Value: output.OID},
			{Label: "Cache Path", Value: output.CachePath},
			{Label: "Local Requested", Value: strconv.FormatBool(output.LocalRequested)},
			{Label: "Local Removed", Value: strconv.FormatBool(output.LocalRemoved)},
			{Label: "Remote Requested", Value: strconv.FormatBool(output.RemoteRequested)},
			{Label: "Remote Removed", Value: strconv.FormatBool(output.RemoteRemoved)},
			{Label: "Blob Map Rows Deleted", Value: strconv.FormatInt(output.BlobMapRowsDeleted, 10)},
			{Label: "Inventory Rows Deleted", Value: strconv.FormatInt(output.InventoryRowsDel, 10)},
			{Label: "Backend", Value: output.Backend},
			{Label: "Bucket", Value: output.Bucket},
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

func renderBlobGCOutput(mode string, output blobGCOutput) error {
	switch mode {
	case outputModeKV:
		fmt.Printf("db=%s\n", output.DB)
		fmt.Printf("cache_dir=%s\n", output.CacheDir)
		fmt.Printf("snapshot_db=%s\n", output.SnapshotDB)
		fmt.Printf("vector_queue_db=%s\n", output.VectorQueueDB)
		fmt.Printf("applied=%t\n", output.Applied)
		fmt.Printf("snapshot_refs_enabled=%t\n", output.SnapshotRefsEnabled)
		fmt.Printf("vector_refs_enabled=%t\n", output.VectorRefsEnabled)
		fmt.Printf("snapshot_refs_found=%d\n", output.SnapshotRefsFound)
		fmt.Printf("vector_refs_found=%d\n", output.VectorRefsFound)
		fmt.Printf("live_cid_count=%d\n", output.LiveCIDCount)
		fmt.Printf("blob_map_rows_scanned=%d\n", output.BlobMapRowsScanned)
		fmt.Printf("blob_map_delete_plan=%d\n", output.BlobMapDeletePlan)
		fmt.Printf("blob_map_rows_deleted=%d\n", output.BlobMapRowsDeleted)
		fmt.Printf("cache_delete_plan=%d\n", output.CacheDeletePlan)
		fmt.Printf("cache_files_deleted=%d\n", output.CacheFilesDeleted)
		fmt.Printf("cache_delete_warning_count=%d\n", output.CacheDeleteWarnCount)
		return nil
	case outputModeJSON:
		return printJSON(output)
	case outputModePretty:
		printPrettyTitle("Blob GC")
		printPrettyFields([]outputField{
			{Label: "Database", Value: output.DB},
			{Label: "Cache Dir", Value: output.CacheDir},
			{Label: "Snapshot DB", Value: output.SnapshotDB},
			{Label: "Vector Queue DB", Value: output.VectorQueueDB},
			{Label: "Applied", Value: strconv.FormatBool(output.Applied)},
			{Label: "Snapshot Refs Enabled", Value: strconv.FormatBool(output.SnapshotRefsEnabled)},
			{Label: "Vector Refs Enabled", Value: strconv.FormatBool(output.VectorRefsEnabled)},
			{Label: "Snapshot Refs Found", Value: strconv.Itoa(output.SnapshotRefsFound)},
			{Label: "Vector Refs Found", Value: strconv.Itoa(output.VectorRefsFound)},
			{Label: "Live CIDs", Value: strconv.Itoa(output.LiveCIDCount)},
			{Label: "Blob Map Rows Scanned", Value: strconv.Itoa(output.BlobMapRowsScanned)},
			{Label: "Blob Map Delete Plan", Value: strconv.Itoa(output.BlobMapDeletePlan)},
			{Label: "Blob Map Rows Deleted", Value: strconv.FormatInt(output.BlobMapRowsDeleted, 10)},
			{Label: "Cache Delete Plan", Value: strconv.Itoa(output.CacheDeletePlan)},
			{Label: "Cache Files Deleted", Value: strconv.Itoa(output.CacheFilesDeleted)},
			{Label: "Cache Delete Warnings", Value: strconv.Itoa(output.CacheDeleteWarnCount)},
		})
		return nil
	default:
		return fmt.Errorf("unsupported output mode %q", mode)
	}
}

func defaultBlobDBPath() string {
	return forgeconfig.BlobDBPath()
}

func defaultBlobCacheDir() string {
	return forgeconfig.BlobCacheDir()
}

func defaultVectorQueueDBPathForGC() string {
	return forgeconfig.VectorQueueDBPath()
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

func listAllBlobMappings(db *sql.DB) ([]blobMapRow, error) {
	rows, err := db.Query(
		`SELECT cid, oid, plain_size, cipher_size, cipher_hash, cache_path, updated_at_ns
		 FROM blob_map
		 ORDER BY cid ASC`,
	)
	if err != nil {
		return nil, fmt.Errorf("query all blob mappings: %w", err)
	}
	defer rows.Close()

	result := make([]blobMapRow, 0)
	for rows.Next() {
		row := blobMapRow{}
		if err := rows.Scan(&row.CID, &row.OID, &row.PlainSize, &row.CipherSize, &row.CipherHash, &row.CachePath, &row.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan all blob mapping row: %w", err)
		}
		result = append(result, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate all blob mappings: %w", err)
	}
	return result, nil
}

func collectLiveBlobRefsFromSnapshotDB(dbPath string, live map[string]struct{}) (int, error) {
	if strings.TrimSpace(dbPath) == "" {
		return 0, nil
	}
	if _, err := os.Stat(dbPath); err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("stat snapshot db %q: %w", dbPath, err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return 0, fmt.Errorf("open snapshot db %q: %w", dbPath, err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	rows, err := db.Query(`SELECT DISTINCT target_hash FROM tree_entries WHERE kind = ?`, snapshotKindFile)
	if err != nil {
		if isSQLiteNoSuchTableError(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("query snapshot tree entry refs from %q: %w", dbPath, err)
	}
	defer rows.Close()

	added := 0
	for rows.Next() {
		var targetHash string
		if err := rows.Scan(&targetHash); err != nil {
			return added, fmt.Errorf("scan snapshot tree ref row: %w", err)
		}
		cid, ok := normalizeBlobCIDRef(targetHash)
		if !ok {
			continue
		}
		if _, exists := live[cid]; !exists {
			live[cid] = struct{}{}
			added++
		}
	}
	if err := rows.Err(); err != nil {
		return added, fmt.Errorf("iterate snapshot tree refs: %w", err)
	}
	return added, nil
}

func collectLiveBlobRefsFromVectorQueueDB(dbPath string, includeErrorJobs bool, live map[string]struct{}) (int, error) {
	if strings.TrimSpace(dbPath) == "" {
		return 0, nil
	}
	if _, err := os.Stat(dbPath); err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("stat vector queue db %q: %w", dbPath, err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return 0, fmt.Errorf("open vector queue db %q: %w", dbPath, err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	query := `SELECT DISTINCT file_path FROM jobs WHERE status IN ('pending', 'processing')`
	if includeErrorJobs {
		query = `SELECT DISTINCT file_path FROM jobs WHERE status IN ('pending', 'processing', 'error')`
	}
	rows, err := db.Query(query)
	if err != nil {
		if isSQLiteNoSuchTableError(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("query vector queue refs from %q: %w", dbPath, err)
	}
	defer rows.Close()

	added := 0
	for rows.Next() {
		var payloadRef string
		if err := rows.Scan(&payloadRef); err != nil {
			return added, fmt.Errorf("scan vector queue ref row: %w", err)
		}
		cid, ok := normalizeBlobCIDRef(payloadRef)
		if !ok {
			continue
		}
		if _, exists := live[cid]; !exists {
			live[cid] = struct{}{}
			added++
		}
	}
	if err := rows.Err(); err != nil {
		return added, fmt.Errorf("iterate vector queue refs: %w", err)
	}
	return added, nil
}

func normalizeBlobCIDRef(value string) (string, bool) {
	normalized := normalizeDigestHex(value)
	if _, err := parseDigestHex32(normalized); err != nil {
		return "", false
	}
	return normalized, true
}

func isSQLiteNoSuchTableError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "no such table")
}

func lookupBlobMapByCID(db *sql.DB, cid string) (blobMapRow, bool, error) {
	row := blobMapRow{}
	if err := db.QueryRow(
		`SELECT cid, oid, plain_size, cipher_size, cipher_hash, cache_path, updated_at_ns
		 FROM blob_map
		 WHERE cid = ?`,
		cid,
	).Scan(&row.CID, &row.OID, &row.PlainSize, &row.CipherSize, &row.CipherHash, &row.CachePath, &row.UpdatedAt); err != nil {
		if stderrors.Is(err, sql.ErrNoRows) {
			return blobMapRow{}, false, nil
		}
		return blobMapRow{}, false, fmt.Errorf("lookup blob map by cid %q: %w", cid, err)
	}
	return row, true, nil
}

func lookupBlobMapByOID(db *sql.DB, oid string) (blobMapRow, bool, error) {
	row := blobMapRow{}
	if err := db.QueryRow(
		`SELECT cid, oid, plain_size, cipher_size, cipher_hash, cache_path, updated_at_ns
		 FROM blob_map
		 WHERE oid = ?`,
		oid,
	).Scan(&row.CID, &row.OID, &row.PlainSize, &row.CipherSize, &row.CipherHash, &row.CachePath, &row.UpdatedAt); err != nil {
		if stderrors.Is(err, sql.ErrNoRows) {
			return blobMapRow{}, false, nil
		}
		return blobMapRow{}, false, fmt.Errorf("lookup blob map by oid %q: %w", oid, err)
	}
	return row, true, nil
}

func deleteBlobMapRows(tx *sql.Tx, cid string, oid string) (int64, error) {
	cid = strings.TrimSpace(cid)
	oid = strings.TrimSpace(oid)
	if cid == "" && oid == "" {
		return 0, fmt.Errorf("blob map delete requires cid or oid")
	}

	var (
		res sql.Result
		err error
	)
	switch {
	case cid != "" && oid != "":
		res, err = tx.Exec(`DELETE FROM blob_map WHERE cid = ? OR oid = ?`, cid, oid)
	case cid != "":
		res, err = tx.Exec(`DELETE FROM blob_map WHERE cid = ?`, cid)
	default:
		res, err = tx.Exec(`DELETE FROM blob_map WHERE oid = ?`, oid)
	}
	if err != nil {
		return 0, fmt.Errorf("delete blob map row(s) cid=%q oid=%q: %w", cid, oid, err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("get blob map delete row count: %w", err)
	}
	return rows, nil
}

func deleteRemoteBlobInventoryByOID(tx *sql.Tx, backend string, bucket string, oid string) (int64, error) {
	oid = strings.TrimSpace(oid)
	if oid == "" {
		return 0, fmt.Errorf("inventory delete by oid requires oid")
	}
	backend = strings.TrimSpace(backend)
	bucket = strings.TrimSpace(bucket)

	var (
		res sql.Result
		err error
	)
	switch {
	case backend != "" && bucket != "":
		res, err = tx.Exec(`DELETE FROM remote_blob_inventory WHERE oid = ? AND backend = ? AND bucket = ?`, oid, backend, bucket)
	case backend != "":
		res, err = tx.Exec(`DELETE FROM remote_blob_inventory WHERE oid = ? AND backend = ?`, oid, backend)
	case bucket != "":
		res, err = tx.Exec(`DELETE FROM remote_blob_inventory WHERE oid = ? AND bucket = ?`, oid, bucket)
	default:
		res, err = tx.Exec(`DELETE FROM remote_blob_inventory WHERE oid = ?`, oid)
	}
	if err != nil {
		return 0, fmt.Errorf("delete remote blob inventory rows by oid=%q: %w", oid, err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("get remote inventory delete row count: %w", err)
	}
	return rows, nil
}

func deleteRemoteBlobInventoryObjectKey(tx *sql.Tx, backend string, bucket string, objectKey string) (int64, error) {
	objectKey = strings.TrimSpace(objectKey)
	if objectKey == "" {
		return 0, fmt.Errorf("inventory delete by object key requires object key")
	}
	backend = strings.TrimSpace(backend)
	bucket = strings.TrimSpace(bucket)

	var (
		res sql.Result
		err error
	)
	switch {
	case backend != "" && bucket != "":
		res, err = tx.Exec(`DELETE FROM remote_blob_inventory WHERE object_key = ? AND backend = ? AND bucket = ?`, objectKey, backend, bucket)
	case backend != "":
		res, err = tx.Exec(`DELETE FROM remote_blob_inventory WHERE object_key = ? AND backend = ?`, objectKey, backend)
	case bucket != "":
		res, err = tx.Exec(`DELETE FROM remote_blob_inventory WHERE object_key = ? AND bucket = ?`, objectKey, bucket)
	default:
		res, err = tx.Exec(`DELETE FROM remote_blob_inventory WHERE object_key = ?`, objectKey)
	}
	if err != nil {
		return 0, fmt.Errorf("delete remote blob inventory rows by object key=%q: %w", objectKey, err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("get remote inventory delete row count: %w", err)
	}
	return rows, nil
}

func deleteRemoteBlobInventoryObjectKeyDB(db *sql.DB, backend string, bucket string, objectKey string) (int64, error) {
	tx, err := db.Begin()
	if err != nil {
		return 0, fmt.Errorf("start inventory delete transaction: %w", err)
	}
	defer tx.Rollback()
	rows, err := deleteRemoteBlobInventoryObjectKey(tx, backend, bucket, objectKey)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit inventory delete transaction: %w", err)
	}
	return rows, nil
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

func blobPlainCachePath(rootDir string, cid string) (string, error) {
	normalized := normalizeDigestHex(cid)
	if _, err := parseDigestHex32(normalized); err != nil {
		return "", fmt.Errorf("invalid blob cid %q: %w", cid, err)
	}
	return filepath.Join(rootDir, normalized[:2], normalized[2:4], normalized+".blob"), nil
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

func ensurePlainBlobCacheObject(cachePath string, sourcePath string, plain []byte, expectedCID string, verbose bool) error {
	if expectedCID == "" {
		expectedCID = blake3Hex(plain)
	}
	if err := os.MkdirAll(filepath.Dir(cachePath), 0o755); err != nil {
		return fmt.Errorf("create blob cache directory %q: %w", filepath.Dir(cachePath), err)
	}

	if existing, err := os.ReadFile(cachePath); err == nil {
		if blake3Hex(existing) != expectedCID {
			return fmt.Errorf("existing blob cache object %q has mismatched cid", cachePath)
		}
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("read existing blob cache object %q: %w", cachePath, err)
	}

	if strings.TrimSpace(sourcePath) != "" {
		switch err := cloneFileCoWFunc(cachePath, sourcePath); {
		case err == nil:
			cloned, readErr := os.ReadFile(cachePath)
			if readErr != nil {
				_ = os.Remove(cachePath)
				if verbose {
					log.Printf("[blob] reflink verification read failed for %q, falling back to copy: %v", cachePath, readErr)
				}
			} else if blake3Hex(cloned) == expectedCID {
				if verbose {
					log.Printf("[blob] cached %q via reflink clone", cachePath)
				}
				return nil
			} else {
				_ = os.Remove(cachePath)
				if verbose {
					log.Printf("[blob] reflink verification hash mismatch for %q, falling back to copy", cachePath)
				}
			}
		case stderrors.Is(err, os.ErrExist):
			// A concurrent writer may have created the file; verify via ensureBlobObject fallback.
		case stderrors.Is(err, errReflinkUnsupported):
			if verbose {
				log.Printf("[blob] reflink clone not available for %q, falling back to copy", cachePath)
			}
		default:
			if verbose {
				log.Printf("[blob] reflink clone failed for %q, falling back to copy: %v", cachePath, err)
			}
		}
	}

	return ensureBlobObject(cachePath, plain, expectedCID)
}
