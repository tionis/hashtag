package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	flag "github.com/spf13/pflag"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/zeebo/blake3"
)

const dupesHashAlgo = "blake3"

const (
	dupesOutputAuto   = "auto"
	dupesOutputPretty = "pretty"
	dupesOutputTable  = "table"
	dupesOutputJSON   = "json"
	dupesOutputPaths  = "paths"
	dupesOutputPaths0 = "paths0"
)

type dupesOptions struct {
	root        string
	minSize     int64
	useCache    bool
	updateCache bool
	verbose     bool
}

type dupesScanStats struct {
	scanned         int
	hashed          int
	cacheHits       int
	skippedTooSmall int
	errors          int
}

type dupesCandidate struct {
	path    string
	size    int64
	modTime int64
}

type dupesGroup struct {
	hash  string
	size  int64
	paths []string
}

type dupesHashKey struct {
	size int64
	hash string
}

type dupesSummary struct {
	Groups          int   `json:"groups"`
	DuplicateFiles  int   `json:"duplicate_files"`
	WastedBytes     int64 `json:"wasted_bytes"`
	Scanned         int   `json:"scanned"`
	Hashed          int   `json:"hashed"`
	CacheHits       int   `json:"cache_hits"`
	SkippedTooSmall int   `json:"skipped_too_small"`
	Errors          int   `json:"errors"`
}

type dupesJSONGroup struct {
	Group int      `json:"group"`
	Hash  string   `json:"hash"`
	Size  int64    `json:"size"`
	Paths []string `json:"paths"`
}

type dupesJSONOutput struct {
	Root    string           `json:"root"`
	Summary dupesSummary     `json:"summary"`
	Groups  []dupesJSONGroup `json:"groups"`
}

func runDupesCommand(args []string) error {
	fs := flag.NewFlagSet("dupes", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s dupes [options] [path]\n\n", os.Args[0])
		fmt.Fprintln(fs.Output(), "Find duplicate files by content hash.")
		fmt.Fprintln(fs.Output(), "\nOptions:")
		fs.PrintDefaults()
	}

	minSize := fs.Int64("min-size", 1, "Only consider files with size >= min-size bytes")
	useCache := fs.Bool("cache", true, "Use checksum xattr cache when available")
	updateCache := fs.Bool("update-cache", false, "Update checksum xattrs for newly hashed files")
	outputMode := fs.StringP("output", "o", dupesOutputAuto, "Output mode: auto|pretty|table|json|paths|paths0")
	verbose := fs.BoolP("verbose", "v", false, "Verbose output")
	applyCommandFlagConventions(fs)
	if err := fs.Parse(normalizePFlagArgs(fs, args)); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if *minSize < 0 {
		return fmt.Errorf("min-size must be >= 0")
	}
	resolvedOutputMode, err := resolveDupesOutputMode(*outputMode)
	if err != nil {
		return err
	}

	root := fs.Arg(0)
	if root == "" {
		root = "."
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("resolve root path: %w", err)
	}

	opts := dupesOptions{
		root:        absRoot,
		minSize:     *minSize,
		useCache:    *useCache,
		updateCache: *updateCache,
		verbose:     *verbose,
	}
	groups, stats, err := findDuplicateGroups(opts)
	if err != nil {
		return err
	}

	summary := summarizeDupes(groups, stats)
	switch resolvedOutputMode {
	case dupesOutputPretty:
		return renderDupesPretty(absRoot, summary, groups)
	case dupesOutputTable:
		return renderDupesTable(absRoot, summary, groups)
	case dupesOutputJSON:
		return renderDupesJSON(absRoot, summary, groups)
	case dupesOutputPaths:
		return renderDupesPaths(groups, "\n")
	case dupesOutputPaths0:
		return renderDupesPaths(groups, "\x00")
	default:
		return fmt.Errorf("unsupported output mode %q", *outputMode)
	}
}

func resolveDupesOutputMode(mode string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(mode))
	switch normalized {
	case "", dupesOutputAuto:
		if stdoutIsTerminal() {
			return dupesOutputPretty, nil
		}
		return dupesOutputTable, nil
	case dupesOutputPretty, dupesOutputTable, dupesOutputJSON, dupesOutputPaths, dupesOutputPaths0:
		return normalized, nil
	default:
		return "", fmt.Errorf("unsupported output mode %q (expected auto|pretty|table|json|paths|paths0)", mode)
	}
}

func summarizeDupes(groups []dupesGroup, stats dupesScanStats) dupesSummary {
	summary := dupesSummary{
		Groups:          len(groups),
		Scanned:         stats.scanned,
		Hashed:          stats.hashed,
		CacheHits:       stats.cacheHits,
		SkippedTooSmall: stats.skippedTooSmall,
		Errors:          stats.errors,
	}
	for _, group := range groups {
		summary.DuplicateFiles += len(group.paths)
		summary.WastedBytes += group.size * int64(len(group.paths)-1)
	}
	return summary
}

func renderDupesTable(root string, summary dupesSummary, groups []dupesGroup) error {
	fmt.Printf("root=%s\n", root)
	fmt.Printf("groups=%d\n", summary.Groups)
	fmt.Printf("duplicate_files=%d\n", summary.DuplicateFiles)
	fmt.Printf("wasted_bytes=%d\n", summary.WastedBytes)
	fmt.Printf("scanned=%d\n", summary.Scanned)
	fmt.Printf("hashed=%d\n", summary.Hashed)
	fmt.Printf("cache_hits=%d\n", summary.CacheHits)
	fmt.Printf("skipped_too_small=%d\n", summary.SkippedTooSmall)
	fmt.Printf("errors=%d\n", summary.Errors)

	fmt.Println("group\thash\tsize\tpath")
	for i, group := range groups {
		groupID := i + 1
		for _, path := range group.paths {
			fmt.Printf("%d\t%s\t%d\t%s\n", groupID, group.hash, group.size, path)
		}
	}
	return nil
}

func renderDupesPretty(root string, summary dupesSummary, groups []dupesGroup) error {
	printPrettyTitle("Duplicate Files")
	printPrettyFields([]outputField{
		{Label: "Root", Value: root},
		{Label: "Groups", Value: strconv.Itoa(summary.Groups)},
		{Label: "Duplicate Files", Value: strconv.Itoa(summary.DuplicateFiles)},
		{Label: "Wasted Bytes", Value: strconv.FormatInt(summary.WastedBytes, 10)},
		{Label: "Scanned", Value: strconv.Itoa(summary.Scanned)},
		{Label: "Hashed", Value: strconv.Itoa(summary.Hashed)},
		{Label: "Cache Hits", Value: strconv.Itoa(summary.CacheHits)},
		{Label: "Skipped Too Small", Value: strconv.Itoa(summary.SkippedTooSmall)},
		{Label: "Errors", Value: strconv.Itoa(summary.Errors)},
	})

	printPrettySection("Duplicate Groups")
	if len(groups) == 0 {
		fmt.Println("No duplicate groups found.")
		return nil
	}
	rows := make([][]string, 0)
	for i, group := range groups {
		groupID := strconv.Itoa(i + 1)
		for _, path := range group.paths {
			rows = append(rows, []string{
				groupID,
				group.hash,
				strconv.FormatInt(group.size, 10),
				path,
			})
		}
	}
	printPrettyTable([]string{"Group", "Hash", "Size", "Path"}, rows)
	return nil
}

func renderDupesJSON(root string, summary dupesSummary, groups []dupesGroup) error {
	jsonGroups := make([]dupesJSONGroup, 0, len(groups))
	for i, group := range groups {
		jsonGroups = append(jsonGroups, dupesJSONGroup{
			Group: i + 1,
			Hash:  group.hash,
			Size:  group.size,
			Paths: append([]string(nil), group.paths...),
		})
	}

	payload := dupesJSONOutput{
		Root:    root,
		Summary: summary,
		Groups:  jsonGroups,
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(payload)
}

func renderDupesPaths(groups []dupesGroup, delimiter string) error {
	wroteAny := false
	for i, group := range groups {
		for j, path := range group.paths {
			fmt.Print(path)
			wroteAny = true
			last := i == len(groups)-1 && j == len(group.paths)-1
			if !last {
				fmt.Print(delimiter)
			}
		}
	}
	if wroteAny && delimiter != "\x00" {
		fmt.Println()
	}
	return nil
}

func findDuplicateGroups(opts dupesOptions) ([]dupesGroup, dupesScanStats, error) {
	sizeBuckets := make(map[int64][]dupesCandidate)
	stats := dupesScanStats{}

	walkErr := filepath.WalkDir(opts.root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			stats.errors++
			if opts.verbose {
				log.Printf("[dupes] walk error at %s: %v", path, walkErr)
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			stats.errors++
			if opts.verbose {
				log.Printf("[dupes] stat error at %s: %v", path, err)
			}
			return nil
		}

		stats.scanned++
		size := info.Size()
		if size < opts.minSize {
			stats.skippedTooSmall++
			return nil
		}

		sizeBuckets[size] = append(sizeBuckets[size], dupesCandidate{
			path:    path,
			size:    size,
			modTime: info.ModTime().Unix(),
		})
		return nil
	})
	if walkErr != nil {
		return nil, stats, fmt.Errorf("walk root path %q: %w", opts.root, walkErr)
	}

	hashBuckets := make(map[dupesHashKey][]string)

	sizes := make([]int64, 0, len(sizeBuckets))
	for size := range sizeBuckets {
		sizes = append(sizes, size)
	}
	sort.Slice(sizes, func(i, j int) bool {
		return sizes[i] < sizes[j]
	})

	for _, size := range sizes {
		candidates := sizeBuckets[size]
		if len(candidates) < 2 {
			continue
		}

		for _, candidate := range candidates {
			hash, fromCache, err := hashCandidateFile(candidate, opts)
			if err != nil {
				stats.errors++
				if opts.verbose {
					log.Printf("[dupes] hash error at %s: %v", candidate.path, err)
				}
				continue
			}
			if fromCache {
				stats.cacheHits++
			} else {
				stats.hashed++
			}

			key := dupesHashKey{
				size: candidate.size,
				hash: hash,
			}
			hashBuckets[key] = append(hashBuckets[key], candidate.path)
		}
	}

	groups := make([]dupesGroup, 0)
	for key, paths := range hashBuckets {
		if len(paths) < 2 {
			continue
		}
		sort.Strings(paths)
		groups = append(groups, dupesGroup{
			hash:  key.hash,
			size:  key.size,
			paths: paths,
		})
	}

	sort.Slice(groups, func(i, j int) bool {
		if groups[i].size != groups[j].size {
			return groups[i].size > groups[j].size
		}
		if groups[i].hash != groups[j].hash {
			return groups[i].hash < groups[j].hash
		}
		return groups[i].paths[0] < groups[j].paths[0]
	})

	return groups, stats, nil
}

func hashCandidateFile(candidate dupesCandidate, opts dupesOptions) (string, bool, error) {
	if opts.useCache {
		if cachedHash, ok := readCachedBlake3(candidate.path, candidate.modTime); ok {
			return cachedHash, true, nil
		}
	}

	hasher := blake3.New()
	bufPtr := bufPool.Get().(*[]byte)
	buf := *bufPtr
	defer bufPool.Put(bufPtr)

	f, err := os.Open(candidate.path)
	if err != nil {
		return "", false, fmt.Errorf("open file %q: %w", candidate.path, err)
	}
	defer f.Close()

	if _, err := io.CopyBuffer(hasher, f, buf); err != nil {
		return "", false, fmt.Errorf("read file %q: %w", candidate.path, err)
	}

	infoPost, err := os.Stat(candidate.path)
	if err != nil {
		return "", false, fmt.Errorf("re-stat file %q: %w", candidate.path, err)
	}
	if infoPost.ModTime().Unix() != candidate.modTime || infoPost.Size() != candidate.size {
		return "", false, fmt.Errorf("file changed while hashing %q", candidate.path)
	}

	digest := hex.EncodeToString(hasher.Sum(nil))
	if opts.updateCache {
		if err := writeBlake3Cache(candidate.path, candidate.modTime, digest); err != nil && opts.verbose {
			log.Printf("[dupes] cache write skipped for %s: %v", candidate.path, err)
		}
	}

	return digest, false, nil
}

func readCachedBlake3(path string, modTimeUnix int64) (string, bool) {
	cachedMtimeBytes, err := getXattr(path, XattrMtimeKey)
	if err != nil {
		return "", false
	}

	cachedMtime, err := strconv.ParseInt(string(cachedMtimeBytes), 10, 64)
	if err != nil || cachedMtime != modTimeUnix {
		return "", false
	}

	cachedHashBytes, err := getXattr(path, XattrPrefix+dupesHashAlgo)
	if err != nil {
		return "", false
	}
	cachedHash := strings.TrimSpace(string(cachedHashBytes))
	if cachedHash == "" {
		return "", false
	}

	return cachedHash, true
}

func writeBlake3Cache(path string, modTimeUnix int64, digest string) error {
	if err := setXattr(path, XattrPrefix+dupesHashAlgo, []byte(digest)); err != nil {
		return err
	}
	return setXattr(path, XattrMtimeKey, []byte(strconv.FormatInt(modTimeUnix, 10)))
}
