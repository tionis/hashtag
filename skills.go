package main

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	flag "github.com/spf13/pflag"
	"github.com/tionis/forge/internal/forgeconfig"
)

const (
	embeddedSkillsBaseDir = "embedded_skills"
	skillManifestFileName = "SKILL.md"
)

//go:embed embedded_skills
var embeddedSkillsFS embed.FS

type embeddedSkill struct {
	Name  string
	Files []string
}

type skillsListItem struct {
	Name      string `json:"name"`
	FileCount int    `json:"file_count"`
}

type skillsListOutput struct {
	Count  int              `json:"count"`
	Skills []skillsListItem `json:"skills"`
}

type skillsInstallItem struct {
	Name      string `json:"name"`
	Status    string `json:"status"`
	Path      string `json:"path"`
	FileCount int    `json:"file_count"`
}

type skillsInstallOutput struct {
	Destination  string              `json:"destination"`
	Force        bool                `json:"force"`
	DryRun       bool                `json:"dry_run"`
	Requested    []string            `json:"requested"`
	Embedded     int                 `json:"embedded"`
	Selected     int                 `json:"selected"`
	Installed    int                 `json:"installed"`
	Planned      int                 `json:"planned"`
	Skipped      int                 `json:"skipped"`
	FilesWritten int                 `json:"files_written"`
	Skills       []skillsInstallItem `json:"skills"`
}

func runSkillsListCommand(args []string) error {
	fs := flag.NewFlagSet("skills list", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s skills list [options]\n\n", os.Args[0])
		fmt.Fprintln(fs.Output(), "List embedded Forge skill definitions bundled in this binary.")
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
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments: %s", strings.Join(fs.Args(), " "))
	}

	mode, err := resolvePrettyKVJSONOutputMode(*outputMode)
	if err != nil {
		return err
	}

	embeddedSkills, err := listEmbeddedSkills()
	if err != nil {
		return err
	}
	output := skillsListOutput{Count: len(embeddedSkills), Skills: make([]skillsListItem, 0, len(embeddedSkills))}
	for _, skill := range embeddedSkills {
		output.Skills = append(output.Skills, skillsListItem{Name: skill.Name, FileCount: len(skill.Files)})
	}
	return renderSkillsListOutput(mode, output)
}

func runSkillsInstallCommand(args []string) error {
	fs := flag.NewFlagSet("skills install", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s skills install [options]\n\n", os.Args[0])
		fmt.Fprintln(fs.Output(), "Install embedded Forge skill definitions to a target directory.")
		fmt.Fprintln(fs.Output(), "\nOptions:")
		fs.PrintDefaults()
	}

	destination := fs.StringP("dir", "d", forgeconfig.SkillsDir(), "Destination directory for installed skills")
	requested := fs.StringP("skills", "s", "", "Comma-separated skill names to install (default: all embedded skills)")
	force := fs.BoolP("force", "f", false, "Overwrite already-installed skills")
	dryRun := fs.Bool("dry-run", false, "Preview installation without writing files")
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

	mode, err := resolvePrettyKVJSONOutputMode(*outputMode)
	if err != nil {
		return err
	}

	embeddedSkills, err := listEmbeddedSkills()
	if err != nil {
		return err
	}
	selectedSkills, requestedNames, err := selectEmbeddedSkills(embeddedSkills, *requested)
	if err != nil {
		return err
	}

	destinationDir := strings.TrimSpace(*destination)
	if destinationDir == "" {
		return fmt.Errorf("-dir is required")
	}
	if err := ensureSkillsDestination(destinationDir, *dryRun); err != nil {
		return err
	}

	output := skillsInstallOutput{
		Destination: destinationDir,
		Force:       *force,
		DryRun:      *dryRun,
		Requested:   requestedNames,
		Embedded:    len(embeddedSkills),
		Selected:    len(selectedSkills),
		Skills:      make([]skillsInstallItem, 0, len(selectedSkills)),
	}

	for _, skill := range selectedSkills {
		item, err := installEmbeddedSkill(skill, destinationDir, *force, *dryRun)
		if err != nil {
			return err
		}
		switch item.Status {
		case "installed", "overwritten":
			output.Installed++
			output.FilesWritten += item.FileCount
		case "would_install", "would_overwrite":
			output.Planned++
		case "skipped_exists":
			output.Skipped++
		}
		output.Skills = append(output.Skills, item)
	}

	return renderSkillsInstallOutput(mode, output)
}

func renderSkillsListOutput(mode string, output skillsListOutput) error {
	switch mode {
	case outputModeKV:
		fmt.Printf("count=%d\n", output.Count)
		for i, skill := range output.Skills {
			fmt.Printf("skill.%d.name=%s\n", i, skill.Name)
			fmt.Printf("skill.%d.file_count=%d\n", i, skill.FileCount)
		}
		return nil
	case outputModeJSON:
		return printJSON(output)
	case outputModePretty:
		printPrettyTitle("Embedded Skills")
		printPrettyFields([]outputField{{Label: "Count", Value: fmt.Sprintf("%d", output.Count)}})
		if len(output.Skills) == 0 {
			return nil
		}
		printPrettySection("Skills")
		rows := make([][]string, 0, len(output.Skills))
		for _, skill := range output.Skills {
			rows = append(rows, []string{skill.Name, fmt.Sprintf("%d", skill.FileCount)})
		}
		printPrettyTable([]string{"Skill", "Files"}, rows)
		return nil
	default:
		return fmt.Errorf("unsupported output mode %q", mode)
	}
}

func renderSkillsInstallOutput(mode string, output skillsInstallOutput) error {
	switch mode {
	case outputModeKV:
		fmt.Printf("destination=%s\n", output.Destination)
		fmt.Printf("force=%t\n", output.Force)
		fmt.Printf("dry_run=%t\n", output.DryRun)
		fmt.Printf("embedded=%d\n", output.Embedded)
		fmt.Printf("selected=%d\n", output.Selected)
		fmt.Printf("installed=%d\n", output.Installed)
		fmt.Printf("planned=%d\n", output.Planned)
		fmt.Printf("skipped=%d\n", output.Skipped)
		fmt.Printf("files_written=%d\n", output.FilesWritten)
		for i, name := range output.Requested {
			fmt.Printf("requested.%d=%s\n", i, name)
		}
		for i, skill := range output.Skills {
			fmt.Printf("skill.%d.name=%s\n", i, skill.Name)
			fmt.Printf("skill.%d.status=%s\n", i, skill.Status)
			fmt.Printf("skill.%d.path=%s\n", i, skill.Path)
			fmt.Printf("skill.%d.file_count=%d\n", i, skill.FileCount)
		}
		return nil
	case outputModeJSON:
		return printJSON(output)
	case outputModePretty:
		title := "Skills Installed"
		if output.DryRun {
			title = "Skills Install Preview"
		}
		printPrettyTitle(title)
		printPrettyFields([]outputField{
			{Label: "Destination", Value: output.Destination},
			{Label: "Embedded", Value: fmt.Sprintf("%d", output.Embedded)},
			{Label: "Selected", Value: fmt.Sprintf("%d", output.Selected)},
			{Label: "Installed", Value: fmt.Sprintf("%d", output.Installed)},
			{Label: "Planned", Value: fmt.Sprintf("%d", output.Planned)},
			{Label: "Skipped", Value: fmt.Sprintf("%d", output.Skipped)},
			{Label: "Files Written", Value: fmt.Sprintf("%d", output.FilesWritten)},
		})
		if len(output.Skills) == 0 {
			return nil
		}
		printPrettySection("Results")
		rows := make([][]string, 0, len(output.Skills))
		for _, skill := range output.Skills {
			rows = append(rows, []string{skill.Name, skill.Status, skill.Path, fmt.Sprintf("%d", skill.FileCount)})
		}
		printPrettyTable([]string{"Skill", "Status", "Path", "Files"}, rows)
		return nil
	default:
		return fmt.Errorf("unsupported output mode %q", mode)
	}
}

func listEmbeddedSkills() ([]embeddedSkill, error) {
	entries, err := fs.ReadDir(embeddedSkillsFS, embeddedSkillsBaseDir)
	if err != nil {
		return nil, fmt.Errorf("read embedded skills root: %w", err)
	}

	skills := make([]embeddedSkill, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		skillName := strings.TrimSpace(entry.Name())
		if skillName == "" {
			continue
		}

		skillRoot := path.Join(embeddedSkillsBaseDir, skillName)
		skillDocPath := path.Join(skillRoot, skillManifestFileName)
		if _, err := fs.Stat(embeddedSkillsFS, skillDocPath); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("stat embedded skill manifest %q: %w", skillDocPath, err)
		}

		files := make([]string, 0, 8)
		walkErr := fs.WalkDir(embeddedSkillsFS, skillRoot, func(currentPath string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() {
				return nil
			}
			relPath := strings.TrimPrefix(currentPath, skillRoot+"/")
			if relPath == "." {
				return nil
			}
			files = append(files, relPath)
			return nil
		})
		if walkErr != nil {
			return nil, fmt.Errorf("walk embedded skill %q: %w", skillName, walkErr)
		}
		sort.Strings(files)
		skills = append(skills, embeddedSkill{Name: skillName, Files: files})
	}

	sort.Slice(skills, func(i, j int) bool {
		return skills[i].Name < skills[j].Name
	})
	return skills, nil
}

func selectEmbeddedSkills(embeddedSkills []embeddedSkill, rawRequested string) ([]embeddedSkill, []string, error) {
	if strings.TrimSpace(rawRequested) == "" {
		selected := make([]embeddedSkill, 0, len(embeddedSkills))
		selected = append(selected, embeddedSkills...)
		return selected, []string{"all"}, nil
	}

	byName := make(map[string]embeddedSkill, len(embeddedSkills))
	for _, skill := range embeddedSkills {
		byName[skill.Name] = skill
	}

	requestedOrder := make([]string, 0)
	seen := make(map[string]struct{})
	for _, token := range strings.Split(rawRequested, ",") {
		name := strings.TrimSpace(token)
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		requestedOrder = append(requestedOrder, name)
	}
	if len(requestedOrder) == 0 {
		return nil, nil, fmt.Errorf("-skills must include at least one non-empty skill name")
	}
	if len(requestedOrder) == 1 && requestedOrder[0] == "all" {
		selected := make([]embeddedSkill, 0, len(embeddedSkills))
		selected = append(selected, embeddedSkills...)
		return selected, []string{"all"}, nil
	}
	for _, name := range requestedOrder {
		if name == "all" {
			return nil, requestedOrder, fmt.Errorf("-skills=all cannot be combined with specific skill names")
		}
	}

	selected := make([]embeddedSkill, 0, len(requestedOrder))
	unknown := make([]string, 0)
	for _, name := range requestedOrder {
		skill, ok := byName[name]
		if !ok {
			unknown = append(unknown, name)
			continue
		}
		selected = append(selected, skill)
	}
	if len(unknown) > 0 {
		knownNames := make([]string, 0, len(embeddedSkills))
		for _, skill := range embeddedSkills {
			knownNames = append(knownNames, skill.Name)
		}
		return nil, requestedOrder, fmt.Errorf("unknown skill name(s): %s (available: %s)", strings.Join(unknown, ", "), strings.Join(knownNames, ", "))
	}
	return selected, requestedOrder, nil
}

func ensureSkillsDestination(destination string, dryRun bool) error {
	info, err := os.Stat(destination)
	if err == nil {
		if !info.IsDir() {
			return fmt.Errorf("skills destination %q exists and is not a directory", destination)
		}
		return nil
	}
	if !os.IsNotExist(err) {
		return fmt.Errorf("stat skills destination %q: %w", destination, err)
	}
	if dryRun {
		return nil
	}
	if err := os.MkdirAll(destination, 0o755); err != nil {
		return fmt.Errorf("create skills destination %q: %w", destination, err)
	}
	return nil
}

func installEmbeddedSkill(skill embeddedSkill, destination string, force bool, dryRun bool) (skillsInstallItem, error) {
	item := skillsInstallItem{
		Name:      skill.Name,
		Path:      filepath.Join(destination, skill.Name),
		FileCount: len(skill.Files),
	}

	if info, err := os.Stat(item.Path); err == nil {
		if !info.IsDir() {
			return item, fmt.Errorf("skill destination %q exists and is not a directory", item.Path)
		}
		if !force {
			item.Status = "skipped_exists"
			item.FileCount = 0
			return item, nil
		}
		if dryRun {
			item.Status = "would_overwrite"
			return item, nil
		}
		if err := os.RemoveAll(item.Path); err != nil {
			return item, fmt.Errorf("remove existing skill directory %q: %w", item.Path, err)
		}
		if err := os.MkdirAll(item.Path, 0o755); err != nil {
			return item, fmt.Errorf("recreate skill directory %q: %w", item.Path, err)
		}
		written, err := writeEmbeddedSkillFiles(skill, item.Path)
		if err != nil {
			return item, err
		}
		item.Status = "overwritten"
		item.FileCount = written
		return item, nil
	} else if !os.IsNotExist(err) {
		return item, fmt.Errorf("stat skill destination %q: %w", item.Path, err)
	}

	if dryRun {
		item.Status = "would_install"
		return item, nil
	}
	if err := os.MkdirAll(item.Path, 0o755); err != nil {
		return item, fmt.Errorf("create skill directory %q: %w", item.Path, err)
	}
	written, err := writeEmbeddedSkillFiles(skill, item.Path)
	if err != nil {
		return item, err
	}
	item.Status = "installed"
	item.FileCount = written
	return item, nil
}

func writeEmbeddedSkillFiles(skill embeddedSkill, destination string) (int, error) {
	skillSourceRoot := path.Join(embeddedSkillsBaseDir, skill.Name)
	written := 0
	for _, relPath := range skill.Files {
		normalizedRelPath := strings.TrimSpace(relPath)
		if normalizedRelPath == "" || normalizedRelPath == "." {
			continue
		}
		sourcePath := path.Join(skillSourceRoot, normalizedRelPath)
		payload, err := fs.ReadFile(embeddedSkillsFS, sourcePath)
		if err != nil {
			return written, fmt.Errorf("read embedded skill file %q: %w", sourcePath, err)
		}
		targetPath := filepath.Join(destination, filepath.FromSlash(normalizedRelPath))
		if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
			return written, fmt.Errorf("create skill file parent directory %q: %w", filepath.Dir(targetPath), err)
		}
		mode := fs.FileMode(0o644)
		if info, err := fs.Stat(embeddedSkillsFS, sourcePath); err == nil {
			if perms := info.Mode().Perm(); perms != 0 {
				mode = perms
			}
		}
		if err := os.WriteFile(targetPath, payload, mode); err != nil {
			return written, fmt.Errorf("write skill file %q: %w", targetPath, err)
		}
		written++
	}
	return written, nil
}
