package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	flag "github.com/spf13/pflag"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type snapperExecFunc func(args ...string) ([]byte, error)

var runSnapperCommand snapperExecFunc = executeSnapperCommand

type snapContext struct {
	Path      string
	Config    string
	Subvolume string
	NoDBus    bool
}

type snapperConfigEntry struct {
	Config    string `json:"config"`
	Subvolume string `json:"subvolume"`
}

type snapperSnapshotEntry struct {
	Number      int64  `json:"number"`
	Type        string `json:"type"`
	Date        string `json:"date"`
	Description string `json:"description"`
	UserData    string `json:"userdata"`
	Cleanup     string `json:"cleanup"`
	PreNumber   int64  `json:"pre_number,omitempty"`
}

type snapChange struct {
	Code  string `json:"code"`
	Path  string `json:"path"`
	Class string `json:"class"`
}

type snapChangeSummary struct {
	Total      int `json:"total"`
	Added      int `json:"added"`
	Removed    int `json:"removed"`
	Modified   int `json:"modified"`
	TypeChange int `json:"type_change"`
}

type snapConfigsOutput struct {
	Count   int                `json:"count"`
	Configs []snapConfigOutput `json:"configs"`
}

type snapConfigOutput struct {
	Config    string `json:"config"`
	Subvolume string `json:"subvolume"`
}

type snapLogOutput struct {
	Config  string               `json:"config"`
	Path    string               `json:"path"`
	Count   int                  `json:"count"`
	Entries []snapLogEntryOutput `json:"entries"`
}

type snapLogEntryOutput struct {
	Number      int64             `json:"number"`
	Type        string            `json:"type"`
	Date        string            `json:"date"`
	Description string            `json:"description"`
	StatRange   string            `json:"stat_range,omitempty"`
	HasStat     bool              `json:"has_stat"`
	Summary     snapChangeSummary `json:"summary"`
}

type snapStatusOutput struct {
	Config  string            `json:"config"`
	Path    string            `json:"path"`
	From    string            `json:"from"`
	To      string            `json:"to"`
	Range   string            `json:"range"`
	Summary snapChangeSummary `json:"summary"`
	Changes []snapChange      `json:"changes"`
}

type snapRestoreOutput struct {
	Config       string            `json:"config"`
	Path         string            `json:"path"`
	From         string            `json:"from"`
	To           string            `json:"to"`
	Range        string            `json:"range"`
	Apply        bool              `json:"apply"`
	Files        []string          `json:"files"`
	Summary      snapChangeSummary `json:"summary,omitempty"`
	Changes      []snapChange      `json:"changes,omitempty"`
	SnapperStdio string            `json:"snapper_stdio,omitempty"`
}

type snapSaveOutput struct {
	Config       string `json:"config"`
	Path         string `json:"path"`
	SnapshotID   int64  `json:"snapshot_id"`
	Description  string `json:"description,omitempty"`
	SnapperStdio string `json:"snapper_stdio,omitempty"`
}

func runSnapConfigsCommand(args []string) error {
	fs := flag.NewFlagSet("snap configs", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s snap configs [options]\n\n", os.Args[0])
		fmt.Fprintln(fs.Output(), "List snapper configs and associated subvolumes.")
		fmt.Fprintln(fs.Output(), "\nOptions:")
		fs.PrintDefaults()
	}

	noDBus := fs.Bool("no-dbus", false, "Call snapper with --no-dbus")
	outputMode := fs.StringP("output", "o", outputModeAuto, "Output mode: auto|pretty|kv|json")
	applyCommandFlagConventions(fs)
	if err := fs.Parse(normalizePFlagArgs(fs, args)); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments: %s", strings.Join(fs.Args(), " "))
	}

	resolvedOutputMode, err := resolvePrettyKVJSONOutputMode(*outputMode)
	if err != nil {
		return err
	}

	configs, err := listSnapperConfigs(*noDBus)
	if err != nil {
		return err
	}
	out := snapConfigsOutput{
		Count:   len(configs),
		Configs: make([]snapConfigOutput, 0, len(configs)),
	}
	for _, cfg := range configs {
		out.Configs = append(out.Configs, snapConfigOutput{
			Config:    cfg.Config,
			Subvolume: cfg.Subvolume,
		})
	}
	return renderSnapConfigsOutput(resolvedOutputMode, out)
}

func runSnapLogCommand(args []string) error {
	fs := flag.NewFlagSet("snap log", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s snap log [options]\n\n", os.Args[0])
		fmt.Fprintln(fs.Output(), "Show snapper snapshot history for a directory.")
		fmt.Fprintln(fs.Output(), "\nOptions:")
		fs.PrintDefaults()
	}

	pathFlag := fs.StringP("path", "p", ".", "Path used to resolve the snapper config")
	configFlag := fs.StringP("config", "c", "", "Explicit snapper config (skip path-based selection)")
	limit := fs.IntP("limit", "n", 20, "Maximum number of snapshots to show (0 for all)")
	withStat := fs.Bool("stat", true, "Include change summary against the previous snapshot")
	noDBus := fs.Bool("no-dbus", false, "Call snapper with --no-dbus")
	outputMode := fs.StringP("output", "o", outputModeAuto, "Output mode: auto|pretty|kv|json")
	applyCommandFlagConventions(fs)
	if err := fs.Parse(normalizePFlagArgs(fs, args)); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments: %s", strings.Join(fs.Args(), " "))
	}

	resolvedOutputMode, err := resolvePrettyKVJSONOutputMode(*outputMode)
	if err != nil {
		return err
	}

	ctx, err := resolveSnapContext(*pathFlag, *configFlag, *noDBus)
	if err != nil {
		return err
	}

	snapshots, err := listSnapperSnapshots(ctx)
	if err != nil {
		return err
	}
	sort.Slice(snapshots, func(i, j int) bool {
		return snapshots[i].Number < snapshots[j].Number
	})
	if *limit > 0 && len(snapshots) > *limit {
		snapshots = snapshots[len(snapshots)-*limit:]
	}

	out := snapLogOutput{
		Config:  ctx.Config,
		Path:    ctx.Path,
		Count:   len(snapshots),
		Entries: make([]snapLogEntryOutput, 0, len(snapshots)),
	}

	for i, snapshot := range snapshots {
		entry := snapLogEntryOutput{
			Number:      snapshot.Number,
			Type:        snapshot.Type,
			Date:        snapshot.Date,
			Description: snapshot.Description,
			HasStat:     false,
			Summary:     snapChangeSummary{},
		}
		if *withStat && i > 0 {
			prev := snapshots[i-1]
			statRange := fmt.Sprintf("%d..%d", prev.Number, snapshot.Number)
			changes, err := runSnapperStatus(ctx, statRange)
			if err != nil {
				return fmt.Errorf("collect stat for %s: %w", statRange, err)
			}
			entry.HasStat = true
			entry.StatRange = statRange
			entry.Summary = summarizeSnapChanges(changes)
		}
		out.Entries = append(out.Entries, entry)
	}

	return renderSnapLogOutput(resolvedOutputMode, out)
}

func runSnapStatusCommand(args []string) error {
	fs := flag.NewFlagSet("snap status", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s snap status [options]\n\n", os.Args[0])
		fmt.Fprintln(fs.Output(), "Show changed files between two snapper revisions.")
		fmt.Fprintln(fs.Output(), "\nOptions:")
		fs.PrintDefaults()
	}

	pathFlag := fs.StringP("path", "p", ".", "Path used to resolve the snapper config")
	configFlag := fs.StringP("config", "c", "", "Explicit snapper config (skip path-based selection)")
	fromFlag := fs.StringP("from", "f", "latest", "From revision selector (latest|previous|<number>)")
	toFlag := fs.StringP("to", "t", "0", "To revision selector (latest|previous|current|<number>)")
	noDBus := fs.Bool("no-dbus", false, "Call snapper with --no-dbus")
	outputMode := fs.StringP("output", "o", outputModeAuto, "Output mode: auto|pretty|kv|json")
	applyCommandFlagConventions(fs)
	if err := fs.Parse(normalizePFlagArgs(fs, args)); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments: %s", strings.Join(fs.Args(), " "))
	}

	resolvedOutputMode, err := resolvePrettyKVJSONOutputMode(*outputMode)
	if err != nil {
		return err
	}

	ctx, err := resolveSnapContext(*pathFlag, *configFlag, *noDBus)
	if err != nil {
		return err
	}
	snapshots, err := listSnapperSnapshots(ctx)
	if err != nil {
		return err
	}

	from, to, err := resolveSnapRange(*fromFlag, *toFlag, snapshots)
	if err != nil {
		return err
	}
	rangeExpr := fmt.Sprintf("%s..%s", from, to)

	changes, err := runSnapperStatus(ctx, rangeExpr)
	if err != nil {
		return err
	}

	out := snapStatusOutput{
		Config:  ctx.Config,
		Path:    ctx.Path,
		From:    from,
		To:      to,
		Range:   rangeExpr,
		Summary: summarizeSnapChanges(changes),
		Changes: changes,
	}
	return renderSnapStatusOutput(resolvedOutputMode, out)
}

func runSnapDiffCommand(args []string) error {
	fs := flag.NewFlagSet("snap diff", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s snap diff [options] [files...]\n\n", os.Args[0])
		fmt.Fprintln(fs.Output(), "Show textual diff between two snapper revisions.")
		fmt.Fprintln(fs.Output(), "\nOptions:")
		fs.PrintDefaults()
	}

	pathFlag := fs.StringP("path", "p", ".", "Path used to resolve the snapper config")
	configFlag := fs.StringP("config", "c", "", "Explicit snapper config (skip path-based selection)")
	fromFlag := fs.StringP("from", "f", "latest", "From revision selector (latest|previous|<number>)")
	toFlag := fs.StringP("to", "t", "0", "To revision selector (latest|previous|current|<number>)")
	noDBus := fs.Bool("no-dbus", false, "Call snapper with --no-dbus")
	applyCommandFlagConventions(fs)
	if err := fs.Parse(normalizePFlagArgs(fs, args)); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}

	ctx, err := resolveSnapContext(*pathFlag, *configFlag, *noDBus)
	if err != nil {
		return err
	}
	snapshots, err := listSnapperSnapshots(ctx)
	if err != nil {
		return err
	}
	from, to, err := resolveSnapRange(*fromFlag, *toFlag, snapshots)
	if err != nil {
		return err
	}
	rangeExpr := fmt.Sprintf("%s..%s", from, to)

	fileFilters := normalizeSnapperFileFilters(ctx, fs.Args())
	cmdArgs := []string{"diff", rangeExpr}
	cmdArgs = append(cmdArgs, fileFilters...)
	out, err := runSnapperWithContext(ctx, cmdArgs...)
	if err != nil {
		return err
	}
	fmt.Print(string(out))
	return nil
}

func runSnapRestoreCommand(args []string) error {
	fs := flag.NewFlagSet("snap restore", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s snap restore [options] [files...]\n\n", os.Args[0])
		fmt.Fprintln(fs.Output(), "Preview or apply undochange between two snapper revisions.")
		fmt.Fprintln(fs.Output(), "\nOptions:")
		fs.PrintDefaults()
	}

	pathFlag := fs.StringP("path", "p", ".", "Path used to resolve the snapper config")
	configFlag := fs.StringP("config", "c", "", "Explicit snapper config (skip path-based selection)")
	fromFlag := fs.StringP("from", "f", "latest", "From revision selector (latest|previous|<number>)")
	toFlag := fs.StringP("to", "t", "0", "To revision selector (latest|previous|current|<number>)")
	apply := fs.BoolP("apply", "a", false, "Apply undochange (default is preview only)")
	noDBus := fs.Bool("no-dbus", false, "Call snapper with --no-dbus")
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

	ctx, err := resolveSnapContext(*pathFlag, *configFlag, *noDBus)
	if err != nil {
		return err
	}
	snapshots, err := listSnapperSnapshots(ctx)
	if err != nil {
		return err
	}
	from, to, err := resolveSnapRange(*fromFlag, *toFlag, snapshots)
	if err != nil {
		return err
	}
	rangeExpr := fmt.Sprintf("%s..%s", from, to)

	fileFilters := normalizeSnapperFileFilters(ctx, fs.Args())

	out := snapRestoreOutput{
		Config: ctx.Config,
		Path:   ctx.Path,
		From:   from,
		To:     to,
		Range:  rangeExpr,
		Apply:  *apply,
		Files:  fileFilters,
	}

	if !*apply {
		changes, err := runSnapperStatus(ctx, rangeExpr)
		if err != nil {
			return err
		}
		if len(fileFilters) > 0 {
			changes = filterSnapChangesByPaths(changes, fileFilters)
		}
		out.Changes = changes
		out.Summary = summarizeSnapChanges(changes)
		return renderSnapRestoreOutput(resolvedOutputMode, out)
	}

	cmdArgs := []string{"undochange", rangeExpr}
	cmdArgs = append(cmdArgs, fileFilters...)
	commandOutput, err := runSnapperWithContext(ctx, cmdArgs...)
	if err != nil {
		return err
	}
	out.SnapperStdio = strings.TrimSpace(string(commandOutput))
	return renderSnapRestoreOutput(resolvedOutputMode, out)
}

func runSnapSaveCommand(args []string) error {
	fs := flag.NewFlagSet("snap save", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s snap save [options]\n\n", os.Args[0])
		fmt.Fprintln(fs.Output(), "Create a snapper single snapshot.")
		fmt.Fprintln(fs.Output(), "\nOptions:")
		fs.PrintDefaults()
	}

	pathFlag := fs.StringP("path", "p", ".", "Path used to resolve the snapper config")
	configFlag := fs.StringP("config", "c", "", "Explicit snapper config (skip path-based selection)")
	description := fs.String("description", "", "Snapshot description")
	cleanup := fs.String("cleanup", "", "Snapper cleanup algorithm")
	userdata := fs.String("userdata", "", "Snapper userdata string")
	noDBus := fs.Bool("no-dbus", false, "Call snapper with --no-dbus")
	outputMode := fs.StringP("output", "o", outputModeAuto, "Output mode: auto|pretty|kv|json")
	applyCommandFlagConventions(fs)
	if err := fs.Parse(normalizePFlagArgs(fs, args)); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments: %s", strings.Join(fs.Args(), " "))
	}

	resolvedOutputMode, err := resolvePrettyKVJSONOutputMode(*outputMode)
	if err != nil {
		return err
	}

	ctx, err := resolveSnapContext(*pathFlag, *configFlag, *noDBus)
	if err != nil {
		return err
	}

	desc := strings.TrimSpace(*description)
	if desc == "" {
		desc = "forge snap save"
	}

	cmdArgs := []string{"create", "--type", "single", "--print-number", "--description", desc}
	if cleanupValue := strings.TrimSpace(*cleanup); cleanupValue != "" {
		cmdArgs = append(cmdArgs, "--cleanup-algorithm", cleanupValue)
	}
	if userdataValue := strings.TrimSpace(*userdata); userdataValue != "" {
		cmdArgs = append(cmdArgs, "--userdata", userdataValue)
	}

	commandOutput, err := runSnapperWithContext(ctx, cmdArgs...)
	if err != nil {
		return err
	}

	snapshotID, err := parseFirstInt64(commandOutput)
	if err != nil {
		return fmt.Errorf("parse snapper snapshot id: %w", err)
	}
	out := snapSaveOutput{
		Config:       ctx.Config,
		Path:         ctx.Path,
		SnapshotID:   snapshotID,
		Description:  desc,
		SnapperStdio: strings.TrimSpace(string(commandOutput)),
	}
	return renderSnapSaveOutput(resolvedOutputMode, out)
}

func runSnapperWithContext(ctx snapContext, args ...string) ([]byte, error) {
	return runSnapperWithOptions(ctx.NoDBus, ctx.Config, args...)
}

func runSnapperWithOptions(noDBus bool, config string, args ...string) ([]byte, error) {
	commandArgs := make([]string, 0, len(args)+4)
	if noDBus {
		commandArgs = append(commandArgs, "--no-dbus")
	}
	if trimmedConfig := strings.TrimSpace(config); trimmedConfig != "" {
		commandArgs = append(commandArgs, "-c", trimmedConfig)
	}
	commandArgs = append(commandArgs, args...)
	return runSnapperCommand(commandArgs...)
}

func executeSnapperCommand(args ...string) ([]byte, error) {
	cmd := exec.Command("snapper", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			return out, fmt.Errorf("snapper %s failed: %w", strings.Join(args, " "), err)
		}
		return out, fmt.Errorf("snapper %s failed: %w: %s", strings.Join(args, " "), err, msg)
	}
	return out, nil
}

func listSnapperConfigs(noDBus bool) ([]snapperConfigEntry, error) {
	out, err := runSnapperWithOptions(noDBus, "", "--jsonout", "list-configs")
	if err != nil {
		return nil, err
	}
	objects, err := parseSnapperJSONObjectArray(out, "configs")
	if err != nil {
		return nil, fmt.Errorf("parse snapper list-configs output: %w", err)
	}
	configs := make([]snapperConfigEntry, 0, len(objects))
	for _, object := range objects {
		cfg := snapperConfigEntry{
			Config:    getStringField(object, "config", "name"),
			Subvolume: getStringField(object, "subvolume", "subVolume"),
		}
		if strings.TrimSpace(cfg.Config) == "" {
			continue
		}
		configs = append(configs, cfg)
	}
	sort.Slice(configs, func(i, j int) bool {
		if configs[i].Config == configs[j].Config {
			return configs[i].Subvolume < configs[j].Subvolume
		}
		return configs[i].Config < configs[j].Config
	})
	return configs, nil
}

func listSnapperSnapshots(ctx snapContext) ([]snapperSnapshotEntry, error) {
	out, err := runSnapperWithContext(
		ctx,
		"--jsonout",
		"list",
		"--disable-used-space",
		"--columns",
		"number,type,date,description,userdata,cleanup,pre-number",
	)
	if err != nil {
		return nil, err
	}
	objects, err := parseSnapperJSONObjectArray(out, "snapshots")
	if err != nil {
		return nil, fmt.Errorf("parse snapper list output: %w", err)
	}

	snapshots := make([]snapperSnapshotEntry, 0, len(objects))
	for _, object := range objects {
		number, ok := getInt64Field(object, "number")
		if !ok {
			continue
		}
		preNumber, _ := getInt64Field(object, "pre-number", "pre_number")
		snapshots = append(snapshots, snapperSnapshotEntry{
			Number:      number,
			Type:        getStringField(object, "type"),
			Date:        getStringField(object, "date"),
			Description: getStringField(object, "description"),
			UserData:    getStringField(object, "userdata", "user_data"),
			Cleanup:     getStringField(object, "cleanup"),
			PreNumber:   preNumber,
		})
	}

	sort.Slice(snapshots, func(i, j int) bool {
		return snapshots[i].Number < snapshots[j].Number
	})
	return snapshots, nil
}

func resolveSnapContext(targetPath string, configOverride string, noDBus bool) (snapContext, error) {
	absPath, err := filepath.Abs(strings.TrimSpace(targetPath))
	if err != nil {
		return snapContext{}, fmt.Errorf("resolve path %q: %w", targetPath, err)
	}

	ctx := snapContext{
		Path:   absPath,
		Config: strings.TrimSpace(configOverride),
		NoDBus: noDBus,
	}

	configs, err := listSnapperConfigs(noDBus)
	if err != nil {
		if ctx.Config != "" {
			return ctx, nil
		}
		return snapContext{}, fmt.Errorf("list snapper configs: %w", err)
	}

	if ctx.Config != "" {
		for _, cfg := range configs {
			if cfg.Config == ctx.Config {
				ctx.Subvolume = filepath.Clean(cfg.Subvolume)
				break
			}
		}
		return ctx, nil
	}

	config, found := selectSnapperConfigForPath(configs, absPath)
	if !found {
		return snapContext{}, fmt.Errorf("no snapper config found for path %q (use -config to select explicitly)", absPath)
	}
	ctx.Config = config.Config
	ctx.Subvolume = filepath.Clean(config.Subvolume)
	return ctx, nil
}

func selectSnapperConfigForPath(configs []snapperConfigEntry, targetPath string) (snapperConfigEntry, bool) {
	cleanTarget := filepath.Clean(targetPath)
	best := snapperConfigEntry{}
	bestLen := -1

	for _, cfg := range configs {
		subvolume := strings.TrimSpace(cfg.Subvolume)
		if subvolume == "" {
			continue
		}
		cleanSubvolume := filepath.Clean(subvolume)
		if !pathWithinBase(cleanSubvolume, cleanTarget) {
			continue
		}
		if len(cleanSubvolume) > bestLen {
			bestLen = len(cleanSubvolume)
			best = cfg
			best.Subvolume = cleanSubvolume
		}
	}

	return best, bestLen >= 0
}

func pathWithinBase(basePath string, targetPath string) bool {
	cleanBase := filepath.Clean(basePath)
	cleanTarget := filepath.Clean(targetPath)
	if cleanBase == cleanTarget {
		return true
	}
	relative, err := filepath.Rel(cleanBase, cleanTarget)
	if err != nil {
		return false
	}
	if relative == "." {
		return true
	}
	return relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator))
}

func resolveSnapRange(fromSelector string, toSelector string, snapshots []snapperSnapshotEntry) (string, string, error) {
	from, err := resolveSnapSelector(fromSelector, snapshots, true)
	if err != nil {
		return "", "", fmt.Errorf("resolve -from selector %q: %w", fromSelector, err)
	}
	to, err := resolveSnapSelector(toSelector, snapshots, false)
	if err != nil {
		return "", "", fmt.Errorf("resolve -to selector %q: %w", toSelector, err)
	}
	return from, to, nil
}

func resolveSnapSelector(selector string, snapshots []snapperSnapshotEntry, requireSnapshot bool) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(selector))
	if normalized == "" {
		if requireSnapshot {
			normalized = "latest"
		} else {
			normalized = "0"
		}
	}

	switch normalized {
	case "current":
		return "0", nil
	case "latest":
		if len(snapshots) == 0 {
			return "", fmt.Errorf("no snapshots available")
		}
		return strconv.FormatInt(snapshots[len(snapshots)-1].Number, 10), nil
	case "previous":
		if len(snapshots) < 2 {
			return "", fmt.Errorf("need at least two snapshots")
		}
		return strconv.FormatInt(snapshots[len(snapshots)-2].Number, 10), nil
	default:
		number, err := strconv.ParseInt(normalized, 10, 64)
		if err != nil || number < 0 {
			return "", fmt.Errorf("invalid revision selector %q", selector)
		}
		return strconv.FormatInt(number, 10), nil
	}
}

func runSnapperStatus(ctx snapContext, rangeExpr string) ([]snapChange, error) {
	out, err := runSnapperWithContext(ctx, "status", rangeExpr)
	if err != nil {
		return nil, err
	}
	changes, parseErr := parseSnapperStatusChanges(out)
	if parseErr != nil {
		return nil, parseErr
	}
	return changes, nil
}

func parseSnapperStatusChanges(out []byte) ([]snapChange, error) {
	scanner := bufio.NewScanner(bytes.NewReader(out))
	changes := make([]snapChange, 0)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		code := strings.TrimSpace(fields[0])
		path := strings.TrimSpace(strings.Join(fields[1:], " "))
		if code == "" || path == "" {
			continue
		}
		changes = append(changes, snapChange{
			Code:  code,
			Path:  path,
			Class: classifySnapperStatusCode(code),
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read snapper status output: %w", err)
	}
	return changes, nil
}

func classifySnapperStatusCode(code string) string {
	trimmed := strings.TrimSpace(code)
	if trimmed == "" {
		return "modified"
	}
	switch trimmed[0] {
	case '+':
		return "added"
	case '-':
		return "removed"
	case 't':
		return "type_change"
	}
	if strings.Contains(trimmed, "t") {
		return "type_change"
	}
	return "modified"
}

func summarizeSnapChanges(changes []snapChange) snapChangeSummary {
	summary := snapChangeSummary{}
	for _, change := range changes {
		summary.Total++
		switch change.Class {
		case "added":
			summary.Added++
		case "removed":
			summary.Removed++
		case "type_change":
			summary.TypeChange++
		default:
			summary.Modified++
		}
	}
	return summary
}

func normalizeSnapperFileFilters(ctx snapContext, rawFilters []string) []string {
	if len(rawFilters) == 0 {
		return nil
	}

	normalized := make([]string, 0, len(rawFilters))
	for _, rawFilter := range rawFilters {
		trimmed := strings.TrimSpace(rawFilter)
		if trimmed == "" {
			continue
		}
		filter := filepath.ToSlash(trimmed)
		if ctx.Subvolume == "" {
			normalized = append(normalized, filter)
			continue
		}

		candidate := trimmed
		if !filepath.IsAbs(candidate) {
			candidate = filepath.Join(ctx.Path, candidate)
		}
		candidate = filepath.Clean(candidate)
		if !pathWithinBase(ctx.Subvolume, candidate) {
			normalized = append(normalized, filter)
			continue
		}

		relative, err := filepath.Rel(ctx.Subvolume, candidate)
		if err != nil {
			normalized = append(normalized, filter)
			continue
		}
		relative = filepath.ToSlash(relative)
		if relative == "." || relative == "" {
			continue
		}
		normalized = append(normalized, relative)
	}
	return normalized
}

func filterSnapChangesByPaths(changes []snapChange, filters []string) []snapChange {
	if len(filters) == 0 {
		return changes
	}
	out := make([]snapChange, 0, len(changes))
	for _, change := range changes {
		if snapPathMatchesAny(change.Path, filters) {
			out = append(out, change)
		}
	}
	return out
}

func snapPathMatchesAny(path string, filters []string) bool {
	target := strings.TrimPrefix(filepath.ToSlash(strings.TrimSpace(path)), "./")
	for _, filter := range filters {
		normalizedFilter := strings.TrimPrefix(filepath.ToSlash(strings.TrimSpace(filter)), "./")
		normalizedFilter = strings.TrimSuffix(normalizedFilter, "/")
		if normalizedFilter == "" {
			continue
		}
		if target == normalizedFilter || strings.HasPrefix(target, normalizedFilter+"/") {
			return true
		}
	}
	return false
}

func parseSnapperJSONObjectArray(raw []byte, preferredKey string) ([]map[string]any, error) {
	payload, err := extractJSONPayload(raw)
	if err != nil {
		return nil, err
	}

	var decoded any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return nil, err
	}

	switch value := decoded.(type) {
	case []any:
		return convertJSONArrayToObjects(value), nil
	case map[string]any:
		if preferredKey != "" {
			if array, ok := value[preferredKey].([]any); ok {
				return convertJSONArrayToObjects(array), nil
			}
		}
		for _, entry := range value {
			if array, ok := entry.([]any); ok {
				return convertJSONArrayToObjects(array), nil
			}
		}
		return nil, fmt.Errorf("json payload does not contain an object array")
	default:
		return nil, fmt.Errorf("unsupported json payload type %T", decoded)
	}
}

func extractJSONPayload(raw []byte) ([]byte, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("empty output")
	}
	if json.Valid(trimmed) {
		return trimmed, nil
	}

	objectStart := bytes.IndexByte(trimmed, '{')
	objectEnd := bytes.LastIndexByte(trimmed, '}')
	if objectStart >= 0 && objectEnd > objectStart {
		candidate := trimmed[objectStart : objectEnd+1]
		if json.Valid(candidate) {
			return candidate, nil
		}
	}

	arrayStart := bytes.IndexByte(trimmed, '[')
	arrayEnd := bytes.LastIndexByte(trimmed, ']')
	if arrayStart >= 0 && arrayEnd > arrayStart {
		candidate := trimmed[arrayStart : arrayEnd+1]
		if json.Valid(candidate) {
			return candidate, nil
		}
	}

	return nil, fmt.Errorf("could not find valid json payload in output")
}

func convertJSONArrayToObjects(array []any) []map[string]any {
	objects := make([]map[string]any, 0, len(array))
	for _, value := range array {
		if object, ok := value.(map[string]any); ok {
			objects = append(objects, object)
		}
	}
	return objects
}

func getStringField(object map[string]any, keys ...string) string {
	for _, key := range keys {
		raw, ok := object[key]
		if !ok {
			continue
		}
		switch value := raw.(type) {
		case string:
			return strings.TrimSpace(value)
		case json.Number:
			return value.String()
		case float64:
			return strconv.FormatInt(int64(value), 10)
		case int64:
			return strconv.FormatInt(value, 10)
		case int:
			return strconv.Itoa(value)
		}
	}
	return ""
}

func getInt64Field(object map[string]any, keys ...string) (int64, bool) {
	for _, key := range keys {
		raw, ok := object[key]
		if !ok {
			continue
		}
		switch value := raw.(type) {
		case json.Number:
			n, err := value.Int64()
			if err == nil {
				return n, true
			}
		case float64:
			return int64(value), true
		case int64:
			return value, true
		case int:
			return int64(value), true
		case string:
			n, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
			if err == nil {
				return n, true
			}
		}
	}
	return 0, false
}

func parseFirstInt64(raw []byte) (int64, error) {
	fields := strings.Fields(string(raw))
	for _, field := range fields {
		value, err := strconv.ParseInt(field, 10, 64)
		if err == nil {
			return value, nil
		}
	}
	return 0, fmt.Errorf("no integer found in output %q", strings.TrimSpace(string(raw)))
}

func renderSnapConfigsOutput(mode string, output snapConfigsOutput) error {
	switch mode {
	case outputModeKV:
		fmt.Printf("count=%d\n", output.Count)
		fmt.Println("config\tsubvolume")
		for _, cfg := range output.Configs {
			fmt.Printf("%s\t%s\n", cfg.Config, cfg.Subvolume)
		}
		return nil
	case outputModeJSON:
		return printJSON(output)
	case outputModePretty:
		printPrettyTitle("Snapper Configs")
		printPrettyFields([]outputField{
			{Label: "Count", Value: strconv.Itoa(output.Count)},
		})
		printPrettySection("Configs")
		rows := make([][]string, 0, len(output.Configs))
		for _, cfg := range output.Configs {
			rows = append(rows, []string{cfg.Config, cfg.Subvolume})
		}
		if len(rows) == 0 {
			fmt.Println("No snapper configs found.")
			return nil
		}
		printPrettyTable([]string{"Config", "Subvolume"}, rows)
		return nil
	default:
		return fmt.Errorf("unsupported output mode %q", mode)
	}
}

func renderSnapLogOutput(mode string, output snapLogOutput) error {
	switch mode {
	case outputModeKV:
		fmt.Printf("config=%s\n", output.Config)
		fmt.Printf("path=%s\n", output.Path)
		fmt.Printf("count=%d\n", output.Count)
		fmt.Println("number\ttype\tdate\tchanges\tadded\tremoved\tmodified\ttype_change\tdescription")
		for _, entry := range output.Entries {
			fmt.Printf(
				"%d\t%s\t%s\t%d\t%d\t%d\t%d\t%d\t%s\n",
				entry.Number,
				entry.Type,
				entry.Date,
				entry.Summary.Total,
				entry.Summary.Added,
				entry.Summary.Removed,
				entry.Summary.Modified,
				entry.Summary.TypeChange,
				entry.Description,
			)
		}
		return nil
	case outputModeJSON:
		return printJSON(output)
	case outputModePretty:
		printPrettyTitle("Snapper Log")
		printPrettyFields([]outputField{
			{Label: "Config", Value: output.Config},
			{Label: "Path", Value: output.Path},
			{Label: "Entries", Value: strconv.Itoa(output.Count)},
		})
		printPrettySection("Snapshots")
		rows := make([][]string, 0, len(output.Entries))
		for _, entry := range output.Entries {
			rows = append(rows, []string{
				strconv.FormatInt(entry.Number, 10),
				entry.Type,
				entry.Date,
				strconv.Itoa(entry.Summary.Total),
				strconv.Itoa(entry.Summary.Added),
				strconv.Itoa(entry.Summary.Removed),
				strconv.Itoa(entry.Summary.Modified),
				strconv.Itoa(entry.Summary.TypeChange),
				entry.Description,
			})
		}
		if len(rows) == 0 {
			fmt.Println("No snapshots found.")
			return nil
		}
		printPrettyTable([]string{"Nr", "Type", "Date", "Files", "+", "-", "M", "T", "Description"}, rows)
		return nil
	default:
		return fmt.Errorf("unsupported output mode %q", mode)
	}
}

func renderSnapStatusOutput(mode string, output snapStatusOutput) error {
	switch mode {
	case outputModeKV:
		fmt.Printf("config=%s\n", output.Config)
		fmt.Printf("path=%s\n", output.Path)
		fmt.Printf("from=%s\n", output.From)
		fmt.Printf("to=%s\n", output.To)
		fmt.Printf("range=%s\n", output.Range)
		fmt.Printf("total=%d\n", output.Summary.Total)
		fmt.Printf("added=%d\n", output.Summary.Added)
		fmt.Printf("removed=%d\n", output.Summary.Removed)
		fmt.Printf("modified=%d\n", output.Summary.Modified)
		fmt.Printf("type_change=%d\n", output.Summary.TypeChange)
		fmt.Println("code\tclass\tpath")
		for _, change := range output.Changes {
			fmt.Printf("%s\t%s\t%s\n", change.Code, change.Class, change.Path)
		}
		return nil
	case outputModeJSON:
		return printJSON(output)
	case outputModePretty:
		printPrettyTitle("Snapper Status")
		printPrettyFields([]outputField{
			{Label: "Config", Value: output.Config},
			{Label: "Path", Value: output.Path},
			{Label: "Range", Value: output.Range},
		})
		printPrettySection("Summary")
		printPrettyFields([]outputField{
			{Label: "Total", Value: strconv.Itoa(output.Summary.Total)},
			{Label: "Added", Value: strconv.Itoa(output.Summary.Added)},
			{Label: "Removed", Value: strconv.Itoa(output.Summary.Removed)},
			{Label: "Modified", Value: strconv.Itoa(output.Summary.Modified)},
			{Label: "Type Changed", Value: strconv.Itoa(output.Summary.TypeChange)},
		})
		printPrettySection("Changes")
		rows := make([][]string, 0, len(output.Changes))
		for _, change := range output.Changes {
			rows = append(rows, []string{change.Code, change.Class, change.Path})
		}
		if len(rows) == 0 {
			fmt.Println("No changes detected.")
			return nil
		}
		printPrettyTable([]string{"Code", "Class", "Path"}, rows)
		return nil
	default:
		return fmt.Errorf("unsupported output mode %q", mode)
	}
}

func renderSnapRestoreOutput(mode string, output snapRestoreOutput) error {
	switch mode {
	case outputModeKV:
		fmt.Printf("config=%s\n", output.Config)
		fmt.Printf("path=%s\n", output.Path)
		fmt.Printf("range=%s\n", output.Range)
		fmt.Printf("apply=%t\n", output.Apply)
		fmt.Printf("files=%s\n", strings.Join(output.Files, ","))
		if !output.Apply {
			fmt.Printf("total=%d\n", output.Summary.Total)
			fmt.Printf("added=%d\n", output.Summary.Added)
			fmt.Printf("removed=%d\n", output.Summary.Removed)
			fmt.Printf("modified=%d\n", output.Summary.Modified)
			fmt.Printf("type_change=%d\n", output.Summary.TypeChange)
			fmt.Println("code\tclass\tpath")
			for _, change := range output.Changes {
				fmt.Printf("%s\t%s\t%s\n", change.Code, change.Class, change.Path)
			}
		}
		if output.SnapperStdio != "" {
			fmt.Printf("snapper_output=%s\n", output.SnapperStdio)
		}
		return nil
	case outputModeJSON:
		return printJSON(output)
	case outputModePretty:
		title := "Snap Restore Preview"
		if output.Apply {
			title = "Snap Restore Applied"
		}
		printPrettyTitle(title)
		printPrettyFields([]outputField{
			{Label: "Config", Value: output.Config},
			{Label: "Path", Value: output.Path},
			{Label: "Range", Value: output.Range},
			{Label: "Apply", Value: strconv.FormatBool(output.Apply)},
			{Label: "Files", Value: strings.Join(output.Files, ", ")},
		})
		if output.Apply {
			if output.SnapperStdio != "" {
				printPrettySection("Snapper Output")
				fmt.Println(output.SnapperStdio)
			}
			return nil
		}
		printPrettySection("Summary")
		printPrettyFields([]outputField{
			{Label: "Total", Value: strconv.Itoa(output.Summary.Total)},
			{Label: "Added", Value: strconv.Itoa(output.Summary.Added)},
			{Label: "Removed", Value: strconv.Itoa(output.Summary.Removed)},
			{Label: "Modified", Value: strconv.Itoa(output.Summary.Modified)},
			{Label: "Type Changed", Value: strconv.Itoa(output.Summary.TypeChange)},
		})
		printPrettySection("Changes")
		rows := make([][]string, 0, len(output.Changes))
		for _, change := range output.Changes {
			rows = append(rows, []string{change.Code, change.Class, change.Path})
		}
		if len(rows) == 0 {
			fmt.Println("No matching changes detected.")
		} else {
			printPrettyTable([]string{"Code", "Class", "Path"}, rows)
		}
		fmt.Println()
		fmt.Printf("Run with -apply to execute undochange for %s.\n", output.Range)
		return nil
	default:
		return fmt.Errorf("unsupported output mode %q", mode)
	}
}

func renderSnapSaveOutput(mode string, output snapSaveOutput) error {
	switch mode {
	case outputModeKV:
		fmt.Printf("config=%s\n", output.Config)
		fmt.Printf("path=%s\n", output.Path)
		fmt.Printf("snapshot_id=%d\n", output.SnapshotID)
		fmt.Printf("description=%s\n", output.Description)
		if output.SnapperStdio != "" {
			fmt.Printf("snapper_output=%s\n", output.SnapperStdio)
		}
		return nil
	case outputModeJSON:
		return printJSON(output)
	case outputModePretty:
		printPrettyTitle("Snapper Snapshot Created")
		printPrettyFields([]outputField{
			{Label: "Config", Value: output.Config},
			{Label: "Path", Value: output.Path},
			{Label: "Snapshot ID", Value: strconv.FormatInt(output.SnapshotID, 10)},
			{Label: "Description", Value: output.Description},
		})
		if output.SnapperStdio != "" {
			printPrettySection("Snapper Output")
			fmt.Println(output.SnapperStdio)
		}
		return nil
	default:
		return fmt.Errorf("unsupported output mode %q", mode)
	}
}
