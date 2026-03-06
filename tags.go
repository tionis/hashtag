package main

import (
	"fmt"
	flag "github.com/spf13/pflag"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

type tagsCommandOutput struct {
	Operation string   `json:"operation"`
	Path      string   `json:"path"`
	Xattr     string   `json:"xattr"`
	Count     int      `json:"count"`
	Tags      []string `json:"tags"`
	Changed   bool     `json:"changed,omitempty"`
	Before    []string `json:"before,omitempty"`
	After     []string `json:"after,omitempty"`
}

func runTagsGetCommand(args []string) error {
	fs := flag.NewFlagSet("tags get", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s tags get [options] [path]\n\n", os.Args[0])
		fmt.Fprintln(fs.Output(), "Read normalized user.xdg.tags from a file path.")
		fmt.Fprintln(fs.Output(), "\nOptions:")
		fs.PrintDefaults()
	}

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

	absPath, err := resolveTagsPathArg(fs.Arg(0))
	if err != nil {
		return err
	}

	tags, err := readTagsFromPath(absPath)
	if err != nil {
		return err
	}

	return renderTagsOutput(resolvedOutputMode, tagsCommandOutput{
		Operation: "get",
		Path:      absPath,
		Xattr:     snapshotXDGTagsKey,
		Count:     len(tags),
		Tags:      append([]string(nil), tags...),
	})
}

func runTagsSetCommand(args []string) error {
	fs := flag.NewFlagSet("tags set", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s tags set [options] [path]\n\n", os.Args[0])
		fmt.Fprintln(fs.Output(), "Set normalized user.xdg.tags on a file path.")
		fmt.Fprintln(fs.Output(), "\nOptions:")
		fs.PrintDefaults()
	}

	tagsFlag := fs.StringP("tags", "t", "", "Comma/semicolon-separated tag list (required)")
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

	requestedTags := normalizeTags(*tagsFlag)
	if len(requestedTags) == 0 {
		return fmt.Errorf("at least one tag is required")
	}

	absPath, err := resolveTagsPathArg(fs.Arg(0))
	if err != nil {
		return err
	}

	before, err := readTagsFromPath(absPath)
	if err != nil {
		return err
	}

	after := append([]string(nil), requestedTags...)
	changed := !stringSlicesEqual(before, after)
	if changed {
		if err := writeTagsToPath(absPath, after); err != nil {
			return err
		}
	}

	return renderTagsOutput(resolvedOutputMode, tagsCommandOutput{
		Operation: "set",
		Path:      absPath,
		Xattr:     snapshotXDGTagsKey,
		Count:     len(after),
		Tags:      append([]string(nil), after...),
		Changed:   changed,
		Before:    append([]string(nil), before...),
		After:     append([]string(nil), after...),
	})
}

func runTagsAddCommand(args []string) error {
	fs := flag.NewFlagSet("tags add", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s tags add [options] [path]\n\n", os.Args[0])
		fmt.Fprintln(fs.Output(), "Add normalized tags to user.xdg.tags on a file path.")
		fmt.Fprintln(fs.Output(), "\nOptions:")
		fs.PrintDefaults()
	}

	tagsFlag := fs.StringP("tags", "t", "", "Comma/semicolon-separated tag list to add (required)")
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

	addTags := normalizeTags(*tagsFlag)
	if len(addTags) == 0 {
		return fmt.Errorf("at least one tag is required")
	}

	absPath, err := resolveTagsPathArg(fs.Arg(0))
	if err != nil {
		return err
	}

	before, err := readTagsFromPath(absPath)
	if err != nil {
		return err
	}
	after := mergeTags(before, addTags)
	changed := !stringSlicesEqual(before, after)
	if changed {
		if err := writeTagsToPath(absPath, after); err != nil {
			return err
		}
	}

	return renderTagsOutput(resolvedOutputMode, tagsCommandOutput{
		Operation: "add",
		Path:      absPath,
		Xattr:     snapshotXDGTagsKey,
		Count:     len(after),
		Tags:      append([]string(nil), after...),
		Changed:   changed,
		Before:    append([]string(nil), before...),
		After:     append([]string(nil), after...),
	})
}

func runTagsRemoveCommand(args []string) error {
	fs := flag.NewFlagSet("tags remove", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s tags remove [options] [path]\n\n", os.Args[0])
		fmt.Fprintln(fs.Output(), "Remove normalized tags from user.xdg.tags on a file path.")
		fmt.Fprintln(fs.Output(), "\nOptions:")
		fs.PrintDefaults()
	}

	tagsFlag := fs.StringP("tags", "t", "", "Comma/semicolon-separated tag list to remove (required)")
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

	removeTags := normalizeTags(*tagsFlag)
	if len(removeTags) == 0 {
		return fmt.Errorf("at least one tag is required")
	}

	absPath, err := resolveTagsPathArg(fs.Arg(0))
	if err != nil {
		return err
	}

	before, err := readTagsFromPath(absPath)
	if err != nil {
		return err
	}
	after := subtractTags(before, removeTags)
	changed := !stringSlicesEqual(before, after)
	if changed {
		if err := writeTagsToPath(absPath, after); err != nil {
			return err
		}
	}

	return renderTagsOutput(resolvedOutputMode, tagsCommandOutput{
		Operation: "remove",
		Path:      absPath,
		Xattr:     snapshotXDGTagsKey,
		Count:     len(after),
		Tags:      append([]string(nil), after...),
		Changed:   changed,
		Before:    append([]string(nil), before...),
		After:     append([]string(nil), after...),
	})
}

func runTagsClearCommand(args []string) error {
	fs := flag.NewFlagSet("tags clear", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s tags clear [options] [path]\n\n", os.Args[0])
		fmt.Fprintln(fs.Output(), "Clear user.xdg.tags on a file path.")
		fmt.Fprintln(fs.Output(), "\nOptions:")
		fs.PrintDefaults()
	}

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

	absPath, err := resolveTagsPathArg(fs.Arg(0))
	if err != nil {
		return err
	}

	before, err := readTagsFromPath(absPath)
	if err != nil {
		return err
	}
	after := []string(nil)
	changed := len(before) > 0
	if changed {
		if err := writeTagsToPath(absPath, nil); err != nil {
			return err
		}
	}

	return renderTagsOutput(resolvedOutputMode, tagsCommandOutput{
		Operation: "clear",
		Path:      absPath,
		Xattr:     snapshotXDGTagsKey,
		Count:     0,
		Tags:      after,
		Changed:   changed,
		Before:    append([]string(nil), before...),
		After:     after,
	})
}

func resolveTagsPathArg(pathArg string) (string, error) {
	if strings.TrimSpace(pathArg) == "" {
		pathArg = "."
	}
	absPath, err := filepath.Abs(pathArg)
	if err != nil {
		return "", fmt.Errorf("resolve target path: %w", err)
	}
	if _, err := os.Lstat(absPath); err != nil {
		return "", fmt.Errorf("stat target path: %w", err)
	}
	return absPath, nil
}

func readTagsFromPath(path string) ([]string, error) {
	data, err := getXattr(path, snapshotXDGTagsKey)
	if err != nil {
		switch err {
		case syscall.ENODATA:
			return nil, nil
		default:
			if isXattrUnsupportedErr(err) {
				return nil, fmt.Errorf("xattrs are not supported for %q: %w", path, err)
			}
			return nil, fmt.Errorf("read xattr %s for %q: %w", snapshotXDGTagsKey, path, err)
		}
	}
	return normalizeTags(string(data)), nil
}

func writeTagsToPath(path string, tags []string) error {
	if len(tags) == 0 {
		if err := removeXattr(path, snapshotXDGTagsKey); err != nil {
			switch err {
			case syscall.ENODATA, syscall.ENOENT:
				return nil
			default:
				if isXattrUnsupportedErr(err) {
					return fmt.Errorf("xattrs are not supported for %q: %w", path, err)
				}
				return fmt.Errorf("remove xattr %s for %q: %w", snapshotXDGTagsKey, path, err)
			}
		}
		return nil
	}

	serialized := strings.Join(tags, ",")
	if err := setXattr(path, snapshotXDGTagsKey, []byte(serialized)); err != nil {
		if isXattrUnsupportedErr(err) {
			return fmt.Errorf("xattrs are not supported for %q: %w", path, err)
		}
		return fmt.Errorf("write xattr %s for %q: %w", snapshotXDGTagsKey, path, err)
	}
	return nil
}

func isXattrUnsupportedErr(err error) bool {
	return err == syscall.ENOTSUP || err == syscall.EOPNOTSUPP
}

func mergeTags(existingTags, addTags []string) []string {
	combined := make(map[string]struct{}, len(existingTags)+len(addTags))
	for _, tag := range existingTags {
		combined[tag] = struct{}{}
	}
	for _, tag := range addTags {
		combined[tag] = struct{}{}
	}

	tags := make([]string, 0, len(combined))
	for tag := range combined {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	return tags
}

func subtractTags(existingTags, removeTags []string) []string {
	if len(existingTags) == 0 {
		return nil
	}
	if len(removeTags) == 0 {
		return append([]string(nil), existingTags...)
	}

	removeSet := make(map[string]struct{}, len(removeTags))
	for _, tag := range removeTags {
		removeSet[tag] = struct{}{}
	}

	tags := make([]string, 0, len(existingTags))
	for _, tag := range existingTags {
		if _, remove := removeSet[tag]; remove {
			continue
		}
		tags = append(tags, tag)
	}
	return tags
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func renderTagsOutput(mode string, output tagsCommandOutput) error {
	switch mode {
	case outputModeKV:
		fmt.Printf("operation=%s\n", output.Operation)
		fmt.Printf("path=%s\n", output.Path)
		fmt.Printf("xattr=%s\n", output.Xattr)
		fmt.Printf("count=%d\n", output.Count)
		fmt.Printf("tags=%s\n", strings.Join(output.Tags, ","))
		if output.Operation != "get" {
			fmt.Printf("changed=%t\n", output.Changed)
			fmt.Printf("before=%s\n", strings.Join(output.Before, ","))
			fmt.Printf("after=%s\n", strings.Join(output.After, ","))
		}
		return nil
	case outputModeJSON:
		return printJSON(output)
	case outputModePretty:
		title := "File Tags"
		if output.Operation != "get" {
			title = "File Tags Updated"
		}
		printPrettyTitle(title)
		fields := []outputField{
			{Label: "Operation", Value: output.Operation},
			{Label: "Path", Value: output.Path},
			{Label: "Xattr", Value: output.Xattr},
			{Label: "Count", Value: strconv.Itoa(output.Count)},
		}
		if output.Operation != "get" {
			fields = append(fields, outputField{Label: "Changed", Value: strconv.FormatBool(output.Changed)})
		}
		printPrettyFields(fields)

		printPrettySection("Current Tags")
		if len(output.Tags) == 0 {
			fmt.Println("No tags set.")
		} else {
			rows := make([][]string, 0, len(output.Tags))
			for _, tag := range output.Tags {
				rows = append(rows, []string{tag})
			}
			printPrettyTable([]string{"Tag"}, rows)
		}

		if output.Operation != "get" {
			printPrettySection("Delta")
			printPrettyFields([]outputField{
				{Label: "Before", Value: strings.Join(output.Before, ",")},
				{Label: "After", Value: strings.Join(output.After, ",")},
			})
		}
		return nil
	default:
		return fmt.Errorf("unsupported output mode %q", mode)
	}
}
