package main

import (
	"database/sql"
	"fmt"
	flag "github.com/spf13/pflag"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type snapshotTreePathEntry struct {
	Path  string
	Entry treeEntry
}

type snapshotInspectEntryOutput struct {
	Path       string   `json:"path"`
	Kind       string   `json:"kind"`
	TargetHash string   `json:"target_hash"`
	Mode       uint32   `json:"mode"`
	ModeOctal  string   `json:"mode_octal"`
	ModTimeNS  int64    `json:"mod_time_ns"`
	Size       int64    `json:"size"`
	Tags       []string `json:"tags"`
}

type snapshotInspectOutput struct {
	DB         string                       `json:"db"`
	TreeHash   string                       `json:"tree_hash"`
	Recursive  bool                         `json:"recursive"`
	EntryCount int                          `json:"entry_count"`
	Entries    []snapshotInspectEntryOutput `json:"entries"`
}

type snapshotQueryMatchOutput struct {
	Path       string   `json:"path"`
	Kind       string   `json:"kind"`
	TargetHash string   `json:"target_hash"`
	Tags       []string `json:"tags"`
}

type snapshotQueryOutput struct {
	DB           string                     `json:"db"`
	TreeHash     string                     `json:"tree_hash"`
	RequiredTags []string                   `json:"required_tags"`
	Kind         string                     `json:"kind"`
	MatchCount   int                        `json:"match_count"`
	Matches      []snapshotQueryMatchOutput `json:"matches"`
}

func renderSnapshotInspectOutput(mode string, output snapshotInspectOutput) error {
	switch mode {
	case outputModeKV:
		fmt.Printf("db=%s\n", output.DB)
		fmt.Printf("tree_hash=%s\n", output.TreeHash)
		fmt.Printf("recursive=%t\n", output.Recursive)
		fmt.Printf("entry_count=%d\n", output.EntryCount)
		if output.Recursive {
			fmt.Println("path\tkind\ttarget_hash\tmode\tmod_time_ns\tsize\ttags")
		} else {
			fmt.Println("name\tkind\ttarget_hash\tmode\tmod_time_ns\tsize\ttags")
		}
		for _, entry := range output.Entries {
			fmt.Printf(
				"%s\t%s\t%s\t%s\t%d\t%d\t%s\n",
				entry.Path,
				entry.Kind,
				entry.TargetHash,
				entry.ModeOctal,
				entry.ModTimeNS,
				entry.Size,
				formatTags(entry.Tags),
			)
		}
		return nil
	case outputModeJSON:
		return printJSON(output)
	case outputModePretty:
		printPrettyTitle("Snapshot Inspect")
		printPrettyFields([]outputField{
			{Label: "Tree Hash", Value: output.TreeHash},
			{Label: "Database", Value: output.DB},
			{Label: "Recursive", Value: strconv.FormatBool(output.Recursive)},
			{Label: "Entries", Value: strconv.Itoa(output.EntryCount)},
		})

		printPrettySection("Tree Entries")
		rows := make([][]string, 0, len(output.Entries))
		for _, entry := range output.Entries {
			rows = append(rows, []string{
				entry.Path,
				entry.Kind,
				entry.TargetHash,
				entry.ModeOctal,
				strconv.FormatInt(entry.ModTimeNS, 10),
				strconv.FormatInt(entry.Size, 10),
				formatTags(entry.Tags),
			})
		}
		if len(rows) == 0 {
			fmt.Println("No entries found.")
			return nil
		}
		printPrettyTable([]string{"Path", "Kind", "Target Hash", "Mode", "Mod Time (ns)", "Size", "Tags"}, rows)
		return nil
	default:
		return fmt.Errorf("unsupported output mode %q", mode)
	}
}

func renderSnapshotQueryOutput(mode string, output snapshotQueryOutput) error {
	switch mode {
	case outputModeKV:
		fmt.Printf("db=%s\n", output.DB)
		fmt.Printf("tree_hash=%s\n", output.TreeHash)
		fmt.Printf("required_tags=%s\n", strings.Join(output.RequiredTags, ","))
		fmt.Printf("kind=%s\n", output.Kind)
		fmt.Printf("match_count=%d\n", output.MatchCount)
		fmt.Println("path\tkind\ttarget_hash\ttags")
		for _, match := range output.Matches {
			fmt.Printf("%s\t%s\t%s\t%s\n", match.Path, match.Kind, match.TargetHash, formatTags(match.Tags))
		}
		return nil
	case outputModeJSON:
		return printJSON(output)
	case outputModePretty:
		printPrettyTitle("Snapshot Query")
		printPrettyFields([]outputField{
			{Label: "Tree Hash", Value: output.TreeHash},
			{Label: "Database", Value: output.DB},
			{Label: "Required Tags", Value: strings.Join(output.RequiredTags, ",")},
			{Label: "Kind Filter", Value: output.Kind},
			{Label: "Matches", Value: strconv.Itoa(output.MatchCount)},
		})

		printPrettySection("Matches")
		rows := make([][]string, 0, len(output.Matches))
		for _, match := range output.Matches {
			rows = append(rows, []string{
				match.Path,
				match.Kind,
				match.TargetHash,
				formatTags(match.Tags),
			})
		}
		if len(rows) == 0 {
			fmt.Println("No matches found.")
			return nil
		}
		printPrettyTable([]string{"Path", "Kind", "Target Hash", "Tags"}, rows)
		return nil
	default:
		return fmt.Errorf("unsupported output mode %q", mode)
	}
}

func runSnapshotInspectCommand(args []string) error {
	defaultDB := defaultSnapshotDBPath()

	fs := flag.NewFlagSet("snapshot inspect", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s snapshot inspect [options]\n\n", os.Args[0])
		fmt.Fprintln(fs.Output(), "Inspect tree entries and tags for a tree hash.")
		fmt.Fprintln(fs.Output(), "\nOptions:")
		fs.PrintDefaults()
	}

	dbPath := fs.StringP("db", "d", defaultDB, "Path to snapshot database")
	treeHash := fs.StringP("tree", "T", "", "Tree hash to inspect (required)")
	recursive := fs.BoolP("recursive", "r", false, "Recursively inspect descendant tree entries")
	outputMode := fs.StringP("output", "o", outputModeAuto, "Output mode: auto|pretty|kv|json")
	applyCommandFlagConventions(fs)
	if err := fs.Parse(normalizePFlagArgs(fs, args)); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	resolvedOutputMode, err := resolvePrettyKVJSONOutputMode(*outputMode)
	if err != nil {
		return err
	}
	if strings.TrimSpace(*treeHash) == "" {
		return fmt.Errorf("tree hash is required")
	}

	absDBPath, err := filepath.Abs(*dbPath)
	if err != nil {
		return fmt.Errorf("resolve db path: %w", err)
	}

	db, err := openSnapshotDB(absDBPath)
	if err != nil {
		return fmt.Errorf("open snapshot db: %w", err)
	}
	defer db.Close()

	exists, err := treeHashExists(db, *treeHash)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("tree %q not found", *treeHash)
	}

	outEntries := make([]snapshotInspectEntryOutput, 0)
	if *recursive {
		records, err := collectTreeEntriesRecursive(db, *treeHash)
		if err != nil {
			return err
		}

		for _, record := range records {
			outEntries = append(outEntries, snapshotInspectEntryOutput{
				Path:       record.Path,
				Kind:       record.Entry.Kind,
				TargetHash: record.Entry.TargetHash,
				Mode:       record.Entry.Mode,
				ModeOctal:  fmt.Sprintf("%04o", record.Entry.Mode&0o7777),
				ModTimeNS:  record.Entry.ModTimeUnix,
				Size:       record.Entry.Size,
				Tags:       append([]string(nil), record.Entry.Tags...),
			})
		}
		return renderSnapshotInspectOutput(
			resolvedOutputMode,
			snapshotInspectOutput{
				DB:         absDBPath,
				TreeHash:   *treeHash,
				Recursive:  true,
				EntryCount: len(outEntries),
				Entries:    outEntries,
			},
		)
	}

	entries, err := loadTreeEntriesWithTags(db, *treeHash)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		outEntries = append(outEntries, snapshotInspectEntryOutput{
			Path:       entry.Name,
			Kind:       entry.Kind,
			TargetHash: entry.TargetHash,
			Mode:       entry.Mode,
			ModeOctal:  fmt.Sprintf("%04o", entry.Mode&0o7777),
			ModTimeNS:  entry.ModTimeUnix,
			Size:       entry.Size,
			Tags:       append([]string(nil), entry.Tags...),
		})
	}

	return renderSnapshotInspectOutput(
		resolvedOutputMode,
		snapshotInspectOutput{
			DB:         absDBPath,
			TreeHash:   *treeHash,
			Recursive:  false,
			EntryCount: len(outEntries),
			Entries:    outEntries,
		},
	)
}

func runSnapshotQueryCommand(args []string) error {
	defaultDB := defaultSnapshotDBPath()

	fs := flag.NewFlagSet("snapshot query", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s snapshot query [options]\n\n", os.Args[0])
		fmt.Fprintln(fs.Output(), "Query tree entries by tag filters.")
		fmt.Fprintln(fs.Output(), "\nOptions:")
		fs.PrintDefaults()
	}

	dbPath := fs.StringP("db", "d", defaultDB, "Path to snapshot database")
	treeHash := fs.StringP("tree", "T", "", "Tree hash to query (required)")
	tagsFlag := fs.StringP("tags", "t", "", "Comma-separated list of required tags (required)")
	kindFilter := fs.StringP("kind", "k", snapshotKindFile, "Entry kind filter: file|symlink|tree|all")
	outputMode := fs.StringP("output", "o", outputModeAuto, "Output mode: auto|pretty|kv|json")
	applyCommandFlagConventions(fs)
	if err := fs.Parse(normalizePFlagArgs(fs, args)); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	resolvedOutputMode, err := resolvePrettyKVJSONOutputMode(*outputMode)
	if err != nil {
		return err
	}
	if strings.TrimSpace(*treeHash) == "" {
		return fmt.Errorf("tree hash is required")
	}

	requiredTags := normalizeTags(*tagsFlag)
	if len(requiredTags) == 0 {
		return fmt.Errorf("at least one tag is required")
	}

	filter := strings.ToLower(strings.TrimSpace(*kindFilter))
	switch filter {
	case snapshotKindFile, snapshotKindSymlink, snapshotKindTree, "all":
	default:
		return fmt.Errorf("unsupported kind filter %q (expected file|symlink|tree|all)", *kindFilter)
	}

	absDBPath, err := filepath.Abs(*dbPath)
	if err != nil {
		return fmt.Errorf("resolve db path: %w", err)
	}

	db, err := openSnapshotDB(absDBPath)
	if err != nil {
		return fmt.Errorf("open snapshot db: %w", err)
	}
	defer db.Close()

	exists, err := treeHashExists(db, *treeHash)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("tree %q not found", *treeHash)
	}

	records, err := collectTreeEntriesRecursive(db, *treeHash)
	if err != nil {
		return err
	}

	matches := make([]snapshotTreePathEntry, 0)
	for _, record := range records {
		if !entryKindMatches(record.Entry.Kind, filter) {
			continue
		}
		if !tagsContainAll(record.Entry.Tags, requiredTags) {
			continue
		}
		matches = append(matches, record)
	}

	outMatches := make([]snapshotQueryMatchOutput, 0, len(matches))
	for _, match := range matches {
		outMatches = append(outMatches, snapshotQueryMatchOutput{
			Path:       match.Path,
			Kind:       match.Entry.Kind,
			TargetHash: match.Entry.TargetHash,
			Tags:       append([]string(nil), match.Entry.Tags...),
		})
	}

	return renderSnapshotQueryOutput(
		resolvedOutputMode,
		snapshotQueryOutput{
			DB:           absDBPath,
			TreeHash:     *treeHash,
			RequiredTags: append([]string(nil), requiredTags...),
			Kind:         filter,
			MatchCount:   len(outMatches),
			Matches:      outMatches,
		},
	)
}

func treeHashExists(db *sql.DB, treeHash string) (bool, error) {
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM trees WHERE hash = ?`, treeHash).Scan(&count); err != nil {
		return false, fmt.Errorf("check tree existence for %q: %w", treeHash, err)
	}
	return count > 0, nil
}

func collectTreeEntriesRecursive(db *sql.DB, treeHash string) ([]snapshotTreePathEntry, error) {
	records := make([]snapshotTreePathEntry, 0)
	stack := make(map[string]struct{})
	if err := collectTreeEntriesRecursiveInto(db, treeHash, "", stack, &records); err != nil {
		return nil, err
	}

	sort.Slice(records, func(i, j int) bool {
		return records[i].Path < records[j].Path
	})
	return records, nil
}

func collectTreeEntriesRecursiveInto(db *sql.DB, treeHash, parentPath string, stack map[string]struct{}, out *[]snapshotTreePathEntry) error {
	if _, exists := stack[treeHash]; exists {
		return fmt.Errorf("detected tree cycle at hash %q", treeHash)
	}

	stack[treeHash] = struct{}{}
	defer delete(stack, treeHash)

	entries, err := loadTreeEntriesWithTags(db, treeHash)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		path := joinSnapshotRelativePath(parentPath, entry.Name)
		*out = append(*out, snapshotTreePathEntry{
			Path:  path,
			Entry: entry,
		})

		if entry.Kind == snapshotKindTree {
			if err := collectTreeEntriesRecursiveInto(db, entry.TargetHash, path, stack, out); err != nil {
				return err
			}
		}
	}

	return nil
}

func loadTreeEntriesWithTags(db *sql.DB, treeHash string) ([]treeEntry, error) {
	return loadTreeEntries(db, make(map[string][]treeEntry), treeHash)
}

func normalizeTags(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}

	raw = strings.ReplaceAll(raw, ";", ",")
	parts := strings.Split(raw, ",")
	seen := make(map[string]struct{}, len(parts))
	tags := make([]string, 0, len(parts))
	for _, part := range parts {
		tag := strings.TrimSpace(part)
		if tag == "" {
			continue
		}
		if _, exists := seen[tag]; exists {
			continue
		}
		seen[tag] = struct{}{}
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	return tags
}

func tagsContainAll(entryTags, requiredTags []string) bool {
	if len(requiredTags) == 0 {
		return true
	}
	if len(entryTags) < len(requiredTags) {
		return false
	}

	available := make(map[string]struct{}, len(entryTags))
	for _, tag := range entryTags {
		available[tag] = struct{}{}
	}
	for _, required := range requiredTags {
		if _, exists := available[required]; !exists {
			return false
		}
	}
	return true
}

func entryKindMatches(kind, filter string) bool {
	if filter == "all" {
		return true
	}
	return kind == filter
}

func formatTags(tags []string) string {
	if len(tags) == 0 {
		return ""
	}
	return strings.Join(tags, ",")
}
