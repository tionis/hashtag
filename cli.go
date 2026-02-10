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

	exitCodeFailure         = 1
	exitCodePartialWarnings = 2
)

type cliExitError struct {
	code  int
	cause error
}

func (e cliExitError) Error() string {
	if e.cause == nil {
		return ""
	}
	return e.cause.Error()
}

func (e cliExitError) Unwrap() error {
	return e.cause
}

func (e cliExitError) ExitCode() int {
	return e.code
}

func newCLIExitError(code int, cause error) error {
	if cause == nil {
		return nil
	}
	return cliExitError{code: code, cause: cause}
}

func resolveCLIExitCode(err error) int {
	if err == nil {
		return 0
	}
	if coder, ok := err.(interface{ ExitCode() int }); ok {
		code := coder.ExitCode()
		if code > 0 {
			return code
		}
	}
	return exitCodeFailure
}

func main() {
	if err := executeCLI(os.Args[1:]); err != nil {
		log.Print(err)
		os.Exit(resolveCLIExitCode(err))
	}
}

func executeCLI(args []string) error {
	root := newRootCommand()
	root.SetArgs(args)
	return root.Execute()
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
	root.AddCommand(newDupesCommand())
	root.AddCommand(newSnapshotCommand())
	root.AddCommand(newHashmapCommand())
	root.AddCommand(newTagsCommand())
	root.AddCommand(newRemoteCommand())
	root.AddCommand(newBlobCommand())
	root.AddCommand(newVectorCommand())
	root.AddCommand(newCompletionCommand(root))
	return root
}

func newHashCommand() *cobra.Command {
	return &cobra.Command{
		Use:                "hash [options] [path]",
		Short:              "Hash files and cache digests in xattrs.",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runHashCommand(args)
		},
	}
}

func newDupesCommand() *cobra.Command {
	return &cobra.Command{
		Use:                "dupes [options] [path]",
		Short:              "Find duplicate files by content.",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDupesCommand(args)
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
	snapshotCmd.AddCommand(&cobra.Command{
		Use:                "inspect [options]",
		Short:              "Inspect entries and tags for a tree hash.",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSnapshotInspectCommand(args)
		},
	})
	snapshotCmd.AddCommand(&cobra.Command{
		Use:                "query [options]",
		Short:              "Query tree entries by required tags.",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSnapshotQueryCommand(args)
		},
	})
	snapshotCmd.AddCommand(&cobra.Command{
		Use:                "remote [options] <remote:path>",
		Short:              "Create a snapshot pointer for an rclone remote target.",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSnapshotRemoteCommand(args)
		},
	})

	return snapshotCmd
}

func newHashmapCommand() *cobra.Command {
	hashmapCmd := &cobra.Command{
		Use:                "hashmap",
		Short:              "Manage mappings between BLAKE3 and other file digests.",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	hashmapCmd.AddCommand(&cobra.Command{
		Use:                "ingest [options] [path]",
		Short:              "Scan files and ingest checksum xattr mappings.",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runHashmapIngestCommand(args)
		},
	})
	hashmapCmd.AddCommand(&cobra.Command{
		Use:                "lookup [options]",
		Short:              "Lookup BLAKE3 by external algorithm digest.",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runHashmapLookupCommand(args)
		},
	})
	hashmapCmd.AddCommand(&cobra.Command{
		Use:                "show [options]",
		Short:              "Show known algorithm digests for a BLAKE3 digest.",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runHashmapShowCommand(args)
		},
	})

	return hashmapCmd
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

func newBlobCommand() *cobra.Command {
	blobCmd := &cobra.Command{
		Use:                "blob",
		Short:              "Manage convergent blobs with plaintext local cache and encrypted remote storage.",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	blobCmd.AddCommand(&cobra.Command{
		Use:                "put [options] <path>",
		Short:              "Encrypt a file into a deterministic blob and cache it locally.",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runBlobPutCommand(args)
		},
	})
	blobCmd.AddCommand(&cobra.Command{
		Use:                "get [options]",
		Short:              "Fetch and decrypt a blob by CID or OID.",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runBlobGetCommand(args)
		},
	})
	blobCmd.AddCommand(&cobra.Command{
		Use:                "ls [options]",
		Short:              "List known blob mappings from the local metadata DB.",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runBlobListCommand(args)
		},
	})
	blobCmd.AddCommand(&cobra.Command{
		Use:                "rm [options]",
		Aliases:            []string{"delete", "del"},
		Short:              "Remove blob data from local cache and optionally remote backend.",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runBlobRemoveCommand(args)
		},
	})
	blobCmd.AddCommand(&cobra.Command{
		Use:                "gc [options]",
		Short:              "Garbage collect local blob cache/metadata from local reference roots.",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runBlobGCCommand(args)
		},
	})

	return blobCmd
}

func newRemoteCommand() *cobra.Command {
	remoteCmd := &cobra.Command{
		Use:                "remote",
		Short:              "Manage global remote backend configuration.",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	configCmd := &cobra.Command{
		Use:                "config",
		Short:              "Manage global remote config object in S3.",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	configCmd.AddCommand(&cobra.Command{
		Use:                "init [options]",
		Short:              "Initialize or update the global remote config object.",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRemoteConfigInitCommand(args)
		},
	})
	configCmd.AddCommand(&cobra.Command{
		Use:                "show [options]",
		Short:              "Show the global remote config object.",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRemoteConfigShowCommand(args)
		},
	})
	remoteCmd.AddCommand(configCmd)

	return remoteCmd
}

func newVectorCommand() *cobra.Command {
	vectorCmd := &cobra.Command{
		Use:                "vector",
		Short:              "Run vector embedding service and ingestion workflows.",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	vectorCmd.AddCommand(&cobra.Command{
		Use:                "serve",
		Short:              "Run the VectorForge coordinator service.",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runVectorServeCommand(args)
		},
	})

	vectorCmd.AddCommand(&cobra.Command{
		Use:                "ingest [options]",
		Short:              "Scan local files and upload missing embedding jobs.",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runVectorIngestCommand(args)
		},
	})
	vectorCmd.AddCommand(&cobra.Command{
		Use:                "lease-status [options]",
		Short:              "Show remote writer lease state for vector replication.",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runVectorLeaseStatusCommand(args)
		},
	})

	return vectorCmd
}

func newTagsCommand() *cobra.Command {
	tagsCmd := &cobra.Command{
		Use:                "tags",
		Short:              "Manage user.xdg.tags on files.",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	tagsCmd.AddCommand(&cobra.Command{
		Use:                "get [options] [path]",
		Short:              "Show normalized tags for a path.",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTagsGetCommand(args)
		},
	})
	tagsCmd.AddCommand(&cobra.Command{
		Use:                "set [options] [path]",
		Short:              "Replace tags on a path with the provided set.",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTagsSetCommand(args)
		},
	})
	tagsCmd.AddCommand(&cobra.Command{
		Use:                "add [options] [path]",
		Short:              "Add tags to a path.",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTagsAddCommand(args)
		},
	})
	tagsCmd.AddCommand(&cobra.Command{
		Use:                "remove [options] [path]",
		Short:              "Remove tags from a path.",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTagsRemoveCommand(args)
		},
	})
	tagsCmd.AddCommand(&cobra.Command{
		Use:                "clear [options] [path]",
		Short:              "Clear all tags on a path.",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTagsClearCommand(args)
		},
	})

	return tagsCmd
}
