package main

import (
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"
)

const (
	projectBinaryName = "forge"
	projectModulePath = "github.com/tionis/forge"
)

func main() {
	if err := executeCLI(os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

func executeCLI(args []string) error {
	// Compatibility mode:
	// - `forge .`
	// - `forge -algos blake3 /path`
	// continue to behave like hash mode.
	if shouldUseHashCompatibilityMode(args) {
		return runHashCommand(args)
	}

	root := newRootCommand()
	root.SetArgs(args)
	return root.Execute()
}

func shouldUseHashCompatibilityMode(args []string) bool {
	if len(args) == 0 {
		return true
	}

	switch args[0] {
	case "hash", "snapshot", "help", "completion", "-h", "--help":
		return false
	}

	if len(args[0]) > 0 && args[0][0] == '-' {
		return true
	}

	return true
}

func newRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:           projectBinaryName,
		Short:         "Forge is a multi-tool CLI for filesystem workflows.",
		Long:          fmt.Sprintf("Forge is a multi-tool CLI for filesystem workflows.\nModule: %s", projectModulePath),
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.AddCommand(newHashCommand())
	root.AddCommand(newSnapshotCommand())
	root.AddCommand(newCompletionCommand(root))
	return root
}

func newHashCommand() *cobra.Command {
	return &cobra.Command{
		Use:                "hash [options] [path]",
		Aliases:            []string{"tag"},
		Short:              "Hash files and cache digests in xattrs.",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runHashCommand(args)
		},
	}
}

func newSnapshotCommand() *cobra.Command {
	snapshotCmd := &cobra.Command{
		Use:                "snapshot",
		Aliases:            []string{"snap"},
		Short:              "Create, inspect, and diff filesystem snapshots.",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSnapshotCreateCommand(args)
		},
	}

	snapshotCmd.AddCommand(&cobra.Command{
		Use:                "create [options] [path]",
		Short:              "Create a snapshot pointer for a filesystem path.",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSnapshotCreateCommand(args)
		},
	})
	snapshotCmd.AddCommand(&cobra.Command{
		Use:                "history [options] [path]",
		Short:              "List snapshots for a path.",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSnapshotHistoryCommand(args)
		},
	})
	snapshotCmd.AddCommand(&cobra.Command{
		Use:                "diff [options] [path]",
		Short:              "Show differences between two snapshots.",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSnapshotDiffCommand(args)
		},
	})

	return snapshotCmd
}

func newCompletionCommand(root *cobra.Command) *cobra.Command {
	return &cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "Generate shell completion scripts.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			switch args[0] {
			case "bash":
				return root.GenBashCompletionV2(os.Stdout, true)
			case "zsh":
				return root.GenZshCompletion(os.Stdout)
			case "fish":
				return root.GenFishCompletion(os.Stdout, true)
			case "powershell":
				return root.GenPowerShellCompletionWithDesc(os.Stdout)
			default:
				return fmt.Errorf("unsupported shell %q", args[0])
			}
		},
	}
}
