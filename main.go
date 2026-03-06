package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	flag "github.com/spf13/pflag"
	"hash"
	"hash/adler32"
	"hash/crc32"
	"hash/crc64"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cespare/xxhash/v2"
	"github.com/zeebo/blake3"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/sha3"
)

// Constants as per specification
const (
	XattrPrefix   = "user.checksum."
	XattrMtimeKey = "user.checksum.mtime"
	BufferSize    = 128 * 1024 // 128KB
)

// Statistics for the run
var (
	filesChecked uint64
	filesHashed  uint64
	filesSkipped uint64
	errors       uint64
)

// Buffer pool to reduce GC pressure
var bufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, BufferSize)
		return &b
	},
}

// AlgoFactory defines a function that returns a new hash.Hash
type AlgoFactory func() hash.Hash

var availableAlgos = map[string]AlgoFactory{
	// Legacy / Common
	"md5":       func() hash.Hash { return md5.New() },
	"sha1":      func() hash.Hash { return sha1.New() },
	"adler32":   func() hash.Hash { return adler32.New() },
	"crc32":     func() hash.Hash { return crc32.NewIEEE() },
	"crc64":     func() hash.Hash { return crc64.New(crc64.MakeTable(crc64.ISO)) },
	"ripemd160": func() hash.Hash { return ripemd160.New() },

	// SHA-2 Family
	"sha224":     func() hash.Hash { return sha256.New224() },
	"sha256":     func() hash.Hash { return sha256.New() },
	"sha384":     func() hash.Hash { return sha512.New384() },
	"sha512":     func() hash.Hash { return sha512.New() },
	"sha512-224": func() hash.Hash { return sha512.New512_224() },
	"sha512-256": func() hash.Hash { return sha512.New512_256() },

	// SHA-3 Family
	"sha3-224": func() hash.Hash { return sha3.New224() },
	"sha3-256": func() hash.Hash { return sha3.New256() },
	"sha3-384": func() hash.Hash { return sha3.New384() },
	"sha3-512": func() hash.Hash { return sha3.New512() },

	// BLAKE Family
	"blake2s-256": func() hash.Hash { h, _ := blake2s.New256(nil); return h },
	"blake2b-256": func() hash.Hash { h, _ := blake2b.New256(nil); return h },
	"blake2b-384": func() hash.Hash { h, _ := blake2b.New384(nil); return h },
	"blake2b-512": func() hash.Hash { h, _ := blake2b.New512(nil); return h },
	"blake3":      func() hash.Hash { return blake3.New() },

	// Modern Non-Cryptographic
	"xxhash": func() hash.Hash { return xxhash.New() },
}

type hashRunOutput struct {
	Operation  string   `json:"operation"`
	Root       string   `json:"root"`
	Workers    int      `json:"workers"`
	Algorithms []string `json:"algorithms,omitempty"`
	DurationMS int64    `json:"duration_ms"`
	Checked    uint64   `json:"checked"`
	Updated    uint64   `json:"updated"`
	Skipped    uint64   `json:"skipped"`
	Errors     uint64   `json:"errors"`
}

func renderHashRunOutput(mode string, output hashRunOutput) error {
	switch mode {
	case outputModeKV:
		fmt.Printf("operation=%s\n", output.Operation)
		fmt.Printf("root=%s\n", output.Root)
		fmt.Printf("workers=%d\n", output.Workers)
		fmt.Printf("algorithms=%s\n", strings.Join(output.Algorithms, ","))
		fmt.Printf("duration_ms=%d\n", output.DurationMS)
		fmt.Printf("checked=%d\n", output.Checked)
		fmt.Printf("updated=%d\n", output.Updated)
		fmt.Printf("skipped=%d\n", output.Skipped)
		fmt.Printf("errors=%d\n", output.Errors)
		return nil
	case outputModeJSON:
		return printJSON(output)
	case outputModePretty:
		title := "Hash Run Summary"
		if output.Operation == "remove" {
			title = "Hash Removal Summary"
		}
		printPrettyTitle(title)
		printPrettyFields([]outputField{
			{Label: "Operation", Value: output.Operation},
			{Label: "Root", Value: output.Root},
			{Label: "Workers", Value: strconv.Itoa(output.Workers)},
			{Label: "Algorithms", Value: strings.Join(output.Algorithms, ",")},
			{Label: "Duration (ms)", Value: strconv.FormatInt(output.DurationMS, 10)},
			{Label: "Checked", Value: strconv.FormatUint(output.Checked, 10)},
			{Label: "Updated", Value: strconv.FormatUint(output.Updated, 10)},
			{Label: "Skipped", Value: strconv.FormatUint(output.Skipped, 10)},
			{Label: "Errors", Value: strconv.FormatUint(output.Errors, 10)},
		})
		return nil
	default:
		return fmt.Errorf("unsupported output mode %q", mode)
	}
}

func runHashCommand(args []string) error {
	atomic.StoreUint64(&filesChecked, 0)
	atomic.StoreUint64(&filesHashed, 0)
	atomic.StoreUint64(&filesSkipped, 0)
	atomic.StoreUint64(&errors, 0)

	// Parse CLI args
	fs := flag.NewFlagSet("hash", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage:\n  %s hash [options] [path]\n\nOptions:\n", projectBinaryName)
		fs.PrintDefaults()
		fmt.Fprintf(fs.Output(), "\nSupported Hash Algorithms:\n  %s\n", strings.Join(getSortedAlgoNames(), ", "))
	}
	workers := fs.IntP("workers", "w", runtime.NumCPU(), "Number of parallel workers")
	verbose := fs.BoolP("verbose", "v", false, "Verbose output")
	algosFlag := fs.String("algos", "blake3", "Comma-separated list of hash algorithms to use")
	clean := fs.Bool("clean", false, "Force invalidation of existing caches (re-hash everything)")
	remove := fs.Bool("remove", false, "Remove all checksum attributes from files instead of hashing")
	outputMode := fs.StringP("output", "o", outputModeAuto, "Output mode: auto|pretty|kv|json")
	applyCommandFlagConventions(fs)
	if err := fs.Parse(normalizePFlagArgs(fs, args)); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return fmt.Errorf("parse hash flags: %w", err)
	}
	resolvedOutputMode, err := resolvePrettyKVJSONOutputMode(*outputMode)
	if err != nil {
		return err
	}

	var factories = make(map[string]AlgoFactory)
	if !*remove {
		// Parse requested algorithms
		requestedAlgos := strings.Split(*algosFlag, ",")
		for _, name := range requestedAlgos {
			name = strings.TrimSpace(strings.ToLower(name))
			if name == "" {
				continue
			}
			// Alias support
			if name == "blake2b" {
				name = "blake2b-512"
			}
			if name == "blake2s" {
				name = "blake2s-256"
			}

			if factory, ok := availableAlgos[name]; ok {
				factories[name] = factory
			} else {
				return fmt.Errorf("unknown algorithm %q. Available: %s", name, strings.Join(getSortedAlgoNames(), ", "))
			}
		}

		if len(factories) == 0 {
			return fmt.Errorf("no valid algorithms specified")
		}
	}

	root := fs.Arg(0)
	if root == "" {
		root = "."
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("resolve root path: %w", err)
	}

	start := time.Now()
	if *verbose {
		if *remove {
			log.Printf("Starting attribute removal on: %s (Workers: %d)", absRoot, *workers)
		} else {
			log.Printf("Starting forge hash on: %s (Workers: %d)", absRoot, *workers)
			log.Printf("Algorithms: %s", *algosFlag)
		}
	}

	// Worker Pool Channels
	jobs := make(chan string, 100)
	var wg sync.WaitGroup

	// Start Workers
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range jobs {
				processFile(path, factories, *clean, *remove, *verbose)
			}
		}()
	}

	// Walk filesystem
	err = filepath.WalkDir(absRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			log.Printf("Error accessing path %q: %v", path, err)
			return nil
		}
		// Skip directories and non-regular files
		if !d.Type().IsRegular() {
			return nil
		}
		// Skip .git directory
		if d.IsDir() && d.Name() == ".git" {
			return filepath.SkipDir
		}

		jobs <- path
		return nil
	})

	close(jobs)
	wg.Wait()

	if err != nil {
		log.Printf("Walk error: %v", err)
	}

	duration := time.Since(start)
	if *verbose {
		log.Printf("\nDone in %s.", duration)
	}
	updated := atomic.LoadUint64(&filesHashed)
	skipped := atomic.LoadUint64(&filesSkipped)
	operation := "hash"
	if *remove {
		operation = "remove"
		updated = atomic.LoadUint64(&filesSkipped)
		skipped = 0
	}
	if *verbose {
		if *remove {
			log.Printf("Checked: %d | Removed: %d | Errors: %d",
				atomic.LoadUint64(&filesChecked),
				updated,
				atomic.LoadUint64(&errors),
			)
		} else {
			log.Printf("Checked: %d | Hashed (New/Updated): %d | Skipped (Cache Hit): %d | Errors: %d",
				atomic.LoadUint64(&filesChecked),
				updated,
				skipped,
				atomic.LoadUint64(&errors),
			)
		}
	}

	algorithms := make([]string, 0, len(factories))
	for name := range factories {
		algorithms = append(algorithms, name)
	}
	sort.Strings(algorithms)

	return renderHashRunOutput(
		resolvedOutputMode,
		hashRunOutput{
			Operation:  operation,
			Root:       absRoot,
			Workers:    *workers,
			Algorithms: algorithms,
			DurationMS: duration.Milliseconds(),
			Checked:    atomic.LoadUint64(&filesChecked),
			Updated:    updated,
			Skipped:    skipped,
			Errors:     atomic.LoadUint64(&errors),
		},
	)
}

func getSortedAlgoNames() []string {
	names := make([]string, 0, len(availableAlgos))
	for name := range availableAlgos {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func processFile(path string, factories map[string]AlgoFactory, forceClean bool, removeOnly bool, verbose bool) {
	atomic.AddUint64(&filesChecked, 1)

	if removeOnly {
		if err := removeAllChecksumXattrs(path); err != nil {
			handleError(path, err, verbose)
		} else {
			atomic.AddUint64(&filesSkipped, 1)
			if verbose {
				fmt.Printf("[REMOVE] %s\n", path)
			}
		}
		return
	}

	info, err := os.Stat(path)
	if err != nil {
		handleError(path, err, verbose)
		return
	}
	currentMtime := info.ModTime().Unix()

	// Check existing mtime xattr
	cachedMtimeBytes, err := getXattr(path, XattrMtimeKey)
	var cachedMtime int64 = -1
	if err == nil {
		cachedMtime, _ = strconv.ParseInt(string(cachedMtimeBytes), 10, 64)
	}

	// Determine if we need to clean old hashes
	cleanNeeded := forceClean || (cachedMtime != currentMtime)

	// Identify which algos we actually need to compute
	toCompute := make(map[string]AlgoFactory)

	if cleanNeeded {
		for k, v := range factories {
			toCompute[k] = v
		}
	} else {
		for name, factory := range factories {
			key := XattrPrefix + name
			_, err := getXattr(path, key)
			if err != nil { // Missing this specific hash
				toCompute[name] = factory
			}
		}
	}

	if len(toCompute) == 0 {
		atomic.AddUint64(&filesSkipped, 1)
		if verbose {
			fmt.Printf("[SKIP] %s\n", path)
		}
		return
	}

	// --- Compute Hashes ---
	var writers []io.Writer
	var hashers = make(map[string]hash.Hash)
	for name, factory := range toCompute {
		h := factory()
		hashers[name] = h
		writers = append(writers, h)
	}
	multiWriter := io.MultiWriter(writers...)

	bufPtr := bufPool.Get().(*[]byte)
	buf := *bufPtr
	defer bufPool.Put(bufPtr)

	f, err := os.Open(path)
	if err != nil {
		handleError(path, err, verbose)
		return
	}

	if _, err := io.CopyBuffer(multiWriter, f, buf); err != nil {
		f.Close()
		handleError(path, err, verbose)
		return
	}
	f.Close()

	// --- Atomicity Check ---
	infoPost, err := os.Stat(path)
	if err != nil {
		handleError(path, err, verbose)
		return
	}
	if info.ModTime() != infoPost.ModTime() {
		if verbose {
			log.Printf("[WARN] File modified during read, skipping: %s", path)
		}
		return
	}

	// --- Update Xattrs ---
	if cleanNeeded {
		if err := removeAllChecksumXattrs(path); err != nil {
			handleError(path, err, verbose)
			return
		}
	}

	for name, h := range hashers {
		val := hex.EncodeToString(h.Sum(nil))
		key := XattrPrefix + name
		if err := setXattr(path, key, []byte(val)); err != nil {
			handleError(path, err, verbose)
			return
		}
	}

	mtimeStr := strconv.FormatInt(currentMtime, 10)
	if err := setXattr(path, XattrMtimeKey, []byte(mtimeStr)); err != nil {
		handleError(path, err, verbose)
		return
	}

	atomic.AddUint64(&filesHashed, 1)
	if verbose {
		fmt.Printf("[HASH] %s (%d algos)\n", path, len(toCompute))
	}
}

func removeAllChecksumXattrs(path string) error {
	keys, err := listXattrs(path)
	if err != nil {
		return err
	}

	for _, key := range keys {
		if strings.HasPrefix(key, XattrPrefix) {
			if err := removeXattr(path, key); err != nil {
				return err
			}
		}
	}
	return nil
}

func handleError(path string, err error, verbose bool) {
	atomic.AddUint64(&errors, 1)
	if verbose {
		log.Printf("Error on %s: %v", path, err)
	}
}

// --- Low Level Syscall Wrappers (Linux Specific) ---

func getXattr(path string, name string) ([]byte, error) {
	dest := make([]byte, 128)
	sz, err := syscall.Getxattr(path, name, dest)
	if err != nil {
		return nil, err
	}
	return dest[:sz], nil
}

func setXattr(path string, name string, data []byte) error {
	return syscall.Setxattr(path, name, data, 0)
}

func removeXattr(path string, name string) error {
	return syscall.Removexattr(path, name)
}

func listXattrs(path string) ([]string, error) {
	dest := make([]byte, 1024)
	sz, err := syscall.Listxattr(path, dest)
	if err != nil {
		if err == syscall.ERANGE {
			// Buffer too small, try larger
			dest = make([]byte, 64*1024)
			sz, err = syscall.Listxattr(path, dest)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	if sz <= 0 {
		return []string{}, nil
	}

	content := dest[:sz]
	if content[len(content)-1] == 0 {
		content = content[:len(content)-1]
	}

	parts := strings.Split(string(content), "\x00")
	return parts, nil
}
