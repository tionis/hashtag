package main

import (
	"database/sql"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type snapshotTreePathEntry struct {
	Path  string
	Entry treeEntry
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

	dbPath := fs.String("db", defaultDB, "Path to snapshot database")
	treeHash := fs.String("tree", "", "Tree hash to inspect (required)")
	recursive := fs.Bool("recursive", false, "Recursively inspect descendant tree entries")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
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

	fmt.Printf("db=%s\n", absDBPath)
	fmt.Printf("tree_hash=%s\n", *treeHash)
	fmt.Printf("recursive=%t\n", *recursive)

	if *recursive {
		records, err := collectTreeEntriesRecursive(db, *treeHash)
		if err != nil {
			return err
		}

		fmt.Printf("entry_count=%d\n", len(records))
		fmt.Println("path\tkind\ttarget_hash\tmode\tmod_time_ns\tsize\ttags\ttags_hash")
		for _, record := range records {
			fmt.Printf(
				"%s\t%s\t%s\t%04o\t%d\t%d\t%s\t%s\n",
				record.Path,
				record.Entry.Kind,
				record.Entry.TargetHash,
				record.Entry.Mode&0o7777,
				record.Entry.ModTimeUnix,
				record.Entry.Size,
				formatTags(record.Entry.Tags),
				record.Entry.TagsHash,
			)
		}
		return nil
	}

	entries, err := loadTreeEntriesWithTags(db, *treeHash)
	if err != nil {
		return err
	}

	fmt.Printf("entry_count=%d\n", len(entries))
	fmt.Println("name\tkind\ttarget_hash\tmode\tmod_time_ns\tsize\ttags\ttags_hash")
	for _, entry := range entries {
		fmt.Printf(
			"%s\t%s\t%s\t%04o\t%d\t%d\t%s\t%s\n",
			entry.Name,
			entry.Kind,
			entry.TargetHash,
			entry.Mode&0o7777,
			entry.ModTimeUnix,
			entry.Size,
			formatTags(entry.Tags),
			entry.TagsHash,
		)
	}

	return nil
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

	dbPath := fs.String("db", defaultDB, "Path to snapshot database")
	treeHash := fs.String("tree", "", "Tree hash to query (required)")
	tagsFlag := fs.String("tags", "", "Comma-separated list of required tags (required)")
	kindFilter := fs.String("kind", snapshotKindFile, "Entry kind filter: file|symlink|tree|all")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
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

	fmt.Printf("db=%s\n", absDBPath)
	fmt.Printf("tree_hash=%s\n", *treeHash)
	fmt.Printf("required_tags=%s\n", strings.Join(requiredTags, ","))
	fmt.Printf("kind=%s\n", filter)
	fmt.Printf("match_count=%d\n", len(matches))
	fmt.Println("path\tkind\ttarget_hash\ttags")
	for _, match := range matches {
		fmt.Printf("%s\t%s\t%s\t%s\n", match.Path, match.Entry.Kind, match.Entry.TargetHash, formatTags(match.Entry.Tags))
	}

	return nil
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
	entries, err := loadTreeEntries(db, make(map[string][]treeEntry), treeHash)
	if err != nil {
		return nil, err
	}

	tagRows, err := db.Query(
		`SELECT et.name, t.name
		 FROM tree_entry_tags et
		 JOIN tags t ON t.id = et.tag_id
		 WHERE et.tree_hash = ?
		 ORDER BY et.name ASC, t.name ASC`,
		treeHash,
	)
	if err != nil {
		return nil, fmt.Errorf("query tree entry tags for tree %q: %w", treeHash, err)
	}
	defer tagRows.Close()

	tagMap := make(map[string][]string)
	for tagRows.Next() {
		var entryName string
		var tagName string
		if err := tagRows.Scan(&entryName, &tagName); err != nil {
			return nil, fmt.Errorf("scan tree entry tag row in tree %q: %w", treeHash, err)
		}
		tagMap[entryName] = append(tagMap[entryName], tagName)
	}
	if err := tagRows.Err(); err != nil {
		return nil, fmt.Errorf("iterate tree entry tags for tree %q: %w", treeHash, err)
	}

	for i := range entries {
		entries[i].Tags = tagMap[entries[i].Name]
		if entries[i].TagsHash == "" && len(entries[i].Tags) > 0 {
			entries[i].TagsHash = hashNormalizedTags(entries[i].Tags)
		}
	}

	return entries, nil
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
