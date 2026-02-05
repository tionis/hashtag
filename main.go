package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"flag"
	"fmt"
	"hash"
	"hash/adler32"
	"hash/crc32"
	"hash/crc64"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
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

func main() {
	// Parse CLI args
	workers := flag.Int("w", runtime.NumCPU(), "Number of parallel workers")
	verbose := flag.Bool("v", false, "Verbose output")
	algosFlag := flag.String("algos", "sha256", "Comma-separated list of hash algorithms to use")
	clean := flag.Bool("clean", false, "Force invalidation of existing caches (re-hash everything)")
	remove := flag.Bool("remove", false, "Remove all checksum attributes from files instead of hashing")
	flag.Parse()

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
				log.Fatalf("Unknown algorithm: %s. Available: %s", name, strings.Join(getSortedAlgoNames(), ", "))
			}
		}

		if len(factories) == 0 {
			log.Fatal("No valid algorithms specified.")
		}
	}

	root := flag.Arg(0)
	if root == "" {
		root = "."
	}

	start := time.Now()
	if *remove {
		log.Printf("Starting attribute removal on: %s (Workers: %d)", root, *workers)
	} else {
		log.Printf("Starting hash tagger on: %s (Workers: %d)", root, *workers)
		log.Printf("Algorithms: %s", *algosFlag)
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
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
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
	log.Printf("\nDone in %s.", duration)
	if *remove {
		log.Printf("Checked: %d | Removed: %d | Errors: %d",
			atomic.LoadUint64(&filesChecked),
			atomic.LoadUint64(&filesSkipped),
			atomic.LoadUint64(&errors),
		)
	} else {
		log.Printf("Checked: %d | Hashed (New/Updated): %d | Skipped (Cache Hit): %d | Errors: %d",
			atomic.LoadUint64(&filesChecked),
			atomic.LoadUint64(&filesHashed),
			atomic.LoadUint64(&filesSkipped),
			atomic.LoadUint64(&errors),
		)
	}
}

func getSortedAlgoNames() []string {
	names := make([]string, 0, len(availableAlgos))
	for name := range availableAlgos {
		names = append(names, name)
	}
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