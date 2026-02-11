package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/tionis/forge/internal/forgeconfig"
	"github.com/tionis/forge/internal/vectorforge"
)

type effectivePathsOutput struct {
	DataDir          string `json:"data_dir"`
	CacheDir         string `json:"cache_dir"`
	SnapshotDB       string `json:"snapshot_db"`
	BlobDB           string `json:"blob_db"`
	BlobCache        string `json:"blob_cache"`
	RemoteDB         string `json:"remote_db"`
	RefsDB           string `json:"refs_db"`
	VectorEmbedDB    string `json:"vector_embed_db"`
	VectorQueueDB    string `json:"vector_queue_db"`
	VectorTempDir    string `json:"vector_temp_dir"`
	VectorHydratedDB string `json:"vector_hydrated_db"`
}

type effectiveVectorRuntimeOutput struct {
	ListenAddr            string `json:"listen_addr,omitempty"`
	ImageWorkerURL        string `json:"image_worker_url,omitempty"`
	TextWorkerURL         string `json:"text_worker_url,omitempty"`
	WorkerConcurrency     int    `json:"worker_concurrency,omitempty"`
	LookupChunkSize       int    `json:"lookup_chunk_size,omitempty"`
	QueueAckTimeoutMS     int64  `json:"queue_ack_timeout_ms,omitempty"`
	MaxPendingJobs        int    `json:"max_pending_jobs,omitempty"`
	MaxJobAttempts        int    `json:"max_job_attempts,omitempty"`
	ReplicaRestoreOnStart bool   `json:"replica_restore_on_start,omitempty"`
	Error                 string `json:"error,omitempty"`
}

type effectiveRemoteOutput struct {
	BootstrapPresent   bool   `json:"bootstrap_present"`
	BootstrapError     string `json:"bootstrap_error,omitempty"`
	Bucket             string `json:"bucket,omitempty"`
	Region             string `json:"region,omitempty"`
	EndpointURL        string `json:"endpoint_url,omitempty"`
	ForcePathStyle     bool   `json:"force_path_style,omitempty"`
	ConfigKey          string `json:"config_key,omitempty"`
	ConfigLoaded       bool   `json:"config_loaded"`
	ConfigLoadError    string `json:"config_load_error,omitempty"`
	ETag               string `json:"etag,omitempty"`
	DocumentVersion    int64  `json:"document_version,omitempty"`
	SignerFingerprint  string `json:"signer_fingerprint,omitempty"`
	PayloadHash        string `json:"payload_hash,omitempty"`
	ExpiresAtUTC       string `json:"expires_at_utc,omitempty"`
	CacheTTLSeconds    int    `json:"cache_ttl_seconds,omitempty"`
	ObjectPrefix       string `json:"object_prefix,omitempty"`
	BlobPrefix         string `json:"blob_prefix,omitempty"`
	CapabilityIfNone   bool   `json:"capability_if_none_match,omitempty"`
	CapabilityIfMatch  bool   `json:"capability_if_match,omitempty"`
	CapabilityChecksum bool   `json:"capability_response_checksums,omitempty"`
	TrustNodeCount     int    `json:"trust_node_count,omitempty"`
}

type effectiveConfigOutput struct {
	Paths         effectivePathsOutput         `json:"paths"`
	VectorRuntime effectiveVectorRuntimeOutput `json:"vector_runtime"`
	Remote        effectiveRemoteOutput        `json:"remote"`
}

func runConfigShowCommand(args []string) error {
	fs := flag.NewFlagSet("config show", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s config show [options]\n\n", os.Args[0])
		fmt.Fprintln(fs.Output(), "Show effective Forge configuration derived from env, defaults, and signed remote config.")
		fmt.Fprintln(fs.Output(), "\nOptions:")
		fs.PrintDefaults()
	}

	effective := fs.Bool("effective", true, "Show effective resolved configuration values")
	outputMode := fs.String("output", outputModeAuto, "Output mode: auto|pretty|kv|json")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments: %s", strings.Join(fs.Args(), " "))
	}
	if !*effective {
		return fmt.Errorf("only -effective=true is supported")
	}

	resolvedOutputMode, err := resolvePrettyKVJSONOutputMode(*outputMode)
	if err != nil {
		return err
	}

	output := effectiveConfigOutput{
		Paths: effectivePathsOutput{
			DataDir:          forgeconfig.DataDir(),
			CacheDir:         forgeconfig.CacheDir(),
			SnapshotDB:       forgeconfig.SnapshotDBPath(),
			BlobDB:           forgeconfig.BlobDBPath(),
			BlobCache:        forgeconfig.BlobCacheDir(),
			RemoteDB:         forgeconfig.RemoteDBPath(),
			RefsDB:           forgeconfig.RefsDBPath(),
			VectorEmbedDB:    forgeconfig.VectorEmbedDBPath(),
			VectorQueueDB:    forgeconfig.VectorQueueDBPath(),
			VectorTempDir:    forgeconfig.VectorTempDir(),
			VectorHydratedDB: forgeconfig.VectorHydratedDBPath(),
		},
	}

	vectorCfg, vectorErr := vectorforge.LoadConfig()
	if vectorErr != nil {
		output.VectorRuntime.Error = vectorErr.Error()
	} else {
		output.VectorRuntime = effectiveVectorRuntimeOutput{
			ListenAddr:            vectorCfg.ListenAddr,
			ImageWorkerURL:        vectorCfg.ImageWorkerURL,
			TextWorkerURL:         vectorCfg.TextWorkerURL,
			WorkerConcurrency:     vectorCfg.WorkerConcurrency,
			LookupChunkSize:       vectorCfg.LookupChunkSize,
			QueueAckTimeoutMS:     vectorCfg.QueueAckTimeout.Milliseconds(),
			MaxPendingJobs:        vectorCfg.MaxPendingJobs,
			MaxJobAttempts:        vectorCfg.MaxJobAttempts,
			ReplicaRestoreOnStart: vectorCfg.ReplicaRestoreOnStart,
		}
	}

	bootstrap, bootstrapErr := loadRemoteS3BootstrapFromEnv()
	if bootstrapErr != nil {
		output.Remote.BootstrapPresent = false
		output.Remote.BootstrapError = bootstrapErr.Error()
	} else {
		output.Remote.BootstrapPresent = true
		output.Remote.Bucket = bootstrap.Bucket
		output.Remote.Region = bootstrap.Region
		output.Remote.EndpointURL = bootstrap.EndpointURL
		output.Remote.ForcePathStyle = bootstrap.ForcePathStyle
		output.Remote.ConfigKey = bootstrap.ConfigKey

		remoteResult, loadErr := loadRemoteGlobalConfigWithCacheDetails(context.Background(), bootstrap, nil)
		if loadErr != nil {
			output.Remote.ConfigLoaded = false
			output.Remote.ConfigLoadError = loadErr.Error()
		} else {
			output.Remote.ConfigLoaded = true
			output.Remote.ETag = remoteResult.ETag
			output.Remote.DocumentVersion = remoteResult.Trust.Version
			output.Remote.SignerFingerprint = remoteResult.Trust.SignerFingerprint
			output.Remote.PayloadHash = remoteResult.Trust.PayloadHash
			output.Remote.ExpiresAtUTC = remoteResult.Trust.ExpiresAtUTC
			output.Remote.CacheTTLSeconds = remoteResult.Config.Cache.RemoteConfigTTLSeconds
			output.Remote.ObjectPrefix = remoteResult.Config.S3.ObjectPrefix
			output.Remote.BlobPrefix = remoteResult.Config.S3.BlobPrefix
			output.Remote.CapabilityIfNone = remoteResult.Config.S3.Capabilities.ConditionalIfNoneMatch
			output.Remote.CapabilityIfMatch = remoteResult.Config.S3.Capabilities.ConditionalIfMatch
			output.Remote.CapabilityChecksum = remoteResult.Config.S3.Capabilities.ResponseChecksums
			output.Remote.TrustNodeCount = len(remoteResult.Config.Trust.Nodes)
		}
	}

	return renderEffectiveConfigOutput(resolvedOutputMode, output)
}

func renderEffectiveConfigOutput(mode string, output effectiveConfigOutput) error {
	switch mode {
	case outputModeKV:
		fmt.Printf("paths.data_dir=%s\n", output.Paths.DataDir)
		fmt.Printf("paths.cache_dir=%s\n", output.Paths.CacheDir)
		fmt.Printf("paths.snapshot_db=%s\n", output.Paths.SnapshotDB)
		fmt.Printf("paths.blob_db=%s\n", output.Paths.BlobDB)
		fmt.Printf("paths.blob_cache=%s\n", output.Paths.BlobCache)
		fmt.Printf("paths.remote_db=%s\n", output.Paths.RemoteDB)
		fmt.Printf("paths.refs_db=%s\n", output.Paths.RefsDB)
		fmt.Printf("paths.vector_embed_db=%s\n", output.Paths.VectorEmbedDB)
		fmt.Printf("paths.vector_queue_db=%s\n", output.Paths.VectorQueueDB)
		fmt.Printf("paths.vector_temp_dir=%s\n", output.Paths.VectorTempDir)
		fmt.Printf("paths.vector_hydrated_db=%s\n", output.Paths.VectorHydratedDB)

		fmt.Printf("vector_runtime.error=%s\n", output.VectorRuntime.Error)
		fmt.Printf("vector_runtime.listen_addr=%s\n", output.VectorRuntime.ListenAddr)
		fmt.Printf("vector_runtime.image_worker_url=%s\n", output.VectorRuntime.ImageWorkerURL)
		fmt.Printf("vector_runtime.text_worker_url=%s\n", output.VectorRuntime.TextWorkerURL)
		fmt.Printf("vector_runtime.worker_concurrency=%d\n", output.VectorRuntime.WorkerConcurrency)
		fmt.Printf("vector_runtime.lookup_chunk_size=%d\n", output.VectorRuntime.LookupChunkSize)
		fmt.Printf("vector_runtime.queue_ack_timeout_ms=%d\n", output.VectorRuntime.QueueAckTimeoutMS)
		fmt.Printf("vector_runtime.max_pending_jobs=%d\n", output.VectorRuntime.MaxPendingJobs)
		fmt.Printf("vector_runtime.max_job_attempts=%d\n", output.VectorRuntime.MaxJobAttempts)
		fmt.Printf("vector_runtime.replica_restore_on_start=%t\n", output.VectorRuntime.ReplicaRestoreOnStart)

		fmt.Printf("remote.bootstrap_present=%t\n", output.Remote.BootstrapPresent)
		fmt.Printf("remote.bootstrap_error=%s\n", output.Remote.BootstrapError)
		fmt.Printf("remote.bucket=%s\n", output.Remote.Bucket)
		fmt.Printf("remote.region=%s\n", output.Remote.Region)
		fmt.Printf("remote.endpoint_url=%s\n", output.Remote.EndpointURL)
		fmt.Printf("remote.force_path_style=%t\n", output.Remote.ForcePathStyle)
		fmt.Printf("remote.config_key=%s\n", output.Remote.ConfigKey)
		fmt.Printf("remote.config_loaded=%t\n", output.Remote.ConfigLoaded)
		fmt.Printf("remote.config_load_error=%s\n", output.Remote.ConfigLoadError)
		fmt.Printf("remote.etag=%s\n", output.Remote.ETag)
		fmt.Printf("remote.document_version=%d\n", output.Remote.DocumentVersion)
		fmt.Printf("remote.signer_fingerprint=%s\n", output.Remote.SignerFingerprint)
		fmt.Printf("remote.payload_hash=%s\n", output.Remote.PayloadHash)
		fmt.Printf("remote.expires_at_utc=%s\n", output.Remote.ExpiresAtUTC)
		fmt.Printf("remote.cache_ttl_seconds=%d\n", output.Remote.CacheTTLSeconds)
		fmt.Printf("remote.object_prefix=%s\n", output.Remote.ObjectPrefix)
		fmt.Printf("remote.blob_prefix=%s\n", output.Remote.BlobPrefix)
		fmt.Printf("remote.capability_if_none_match=%t\n", output.Remote.CapabilityIfNone)
		fmt.Printf("remote.capability_if_match=%t\n", output.Remote.CapabilityIfMatch)
		fmt.Printf("remote.capability_response_checksums=%t\n", output.Remote.CapabilityChecksum)
		fmt.Printf("remote.trust_node_count=%d\n", output.Remote.TrustNodeCount)
		return nil
	case outputModeJSON:
		return printJSON(output)
	case outputModePretty:
		printPrettyTitle("Effective Config")
		printPrettySection("Paths")
		printPrettyFields([]outputField{
			{Label: "Data Dir", Value: output.Paths.DataDir},
			{Label: "Cache Dir", Value: output.Paths.CacheDir},
			{Label: "Snapshot DB", Value: output.Paths.SnapshotDB},
			{Label: "Blob DB", Value: output.Paths.BlobDB},
			{Label: "Blob Cache", Value: output.Paths.BlobCache},
			{Label: "Remote DB", Value: output.Paths.RemoteDB},
			{Label: "Refs DB", Value: output.Paths.RefsDB},
			{Label: "Vector Embed DB", Value: output.Paths.VectorEmbedDB},
			{Label: "Vector Queue DB", Value: output.Paths.VectorQueueDB},
			{Label: "Vector Temp Dir", Value: output.Paths.VectorTempDir},
			{Label: "Vector Hydrated DB", Value: output.Paths.VectorHydratedDB},
		})

		printPrettySection("Vector Runtime")
		printPrettyFields([]outputField{
			{Label: "Error", Value: output.VectorRuntime.Error},
			{Label: "Listen Addr", Value: output.VectorRuntime.ListenAddr},
			{Label: "Image Worker URL", Value: output.VectorRuntime.ImageWorkerURL},
			{Label: "Text Worker URL", Value: output.VectorRuntime.TextWorkerURL},
			{Label: "Worker Concurrency", Value: strconv.Itoa(output.VectorRuntime.WorkerConcurrency)},
			{Label: "Lookup Chunk Size", Value: strconv.Itoa(output.VectorRuntime.LookupChunkSize)},
			{Label: "Queue Ack Timeout (ms)", Value: strconv.FormatInt(output.VectorRuntime.QueueAckTimeoutMS, 10)},
			{Label: "Max Pending Jobs", Value: strconv.Itoa(output.VectorRuntime.MaxPendingJobs)},
			{Label: "Max Job Attempts", Value: strconv.Itoa(output.VectorRuntime.MaxJobAttempts)},
			{Label: "Replica Restore On Start", Value: strconv.FormatBool(output.VectorRuntime.ReplicaRestoreOnStart)},
		})

		printPrettySection("Remote")
		printPrettyFields([]outputField{
			{Label: "Bootstrap Present", Value: strconv.FormatBool(output.Remote.BootstrapPresent)},
			{Label: "Bootstrap Error", Value: output.Remote.BootstrapError},
			{Label: "Bucket", Value: output.Remote.Bucket},
			{Label: "Region", Value: output.Remote.Region},
			{Label: "Endpoint URL", Value: output.Remote.EndpointURL},
			{Label: "Force Path Style", Value: strconv.FormatBool(output.Remote.ForcePathStyle)},
			{Label: "Config Key", Value: output.Remote.ConfigKey},
			{Label: "Config Loaded", Value: strconv.FormatBool(output.Remote.ConfigLoaded)},
			{Label: "Config Load Error", Value: output.Remote.ConfigLoadError},
			{Label: "ETag", Value: output.Remote.ETag},
			{Label: "Document Version", Value: strconv.FormatInt(output.Remote.DocumentVersion, 10)},
			{Label: "Signer Fingerprint", Value: output.Remote.SignerFingerprint},
			{Label: "Payload Hash", Value: output.Remote.PayloadHash},
			{Label: "Expires At", Value: output.Remote.ExpiresAtUTC},
			{Label: "Cache TTL (s)", Value: strconv.Itoa(output.Remote.CacheTTLSeconds)},
			{Label: "Object Prefix", Value: output.Remote.ObjectPrefix},
			{Label: "Blob Prefix", Value: output.Remote.BlobPrefix},
			{Label: "Capability If-None-Match", Value: strconv.FormatBool(output.Remote.CapabilityIfNone)},
			{Label: "Capability If-Match", Value: strconv.FormatBool(output.Remote.CapabilityIfMatch)},
			{Label: "Capability Response Checksums", Value: strconv.FormatBool(output.Remote.CapabilityChecksum)},
			{Label: "Trust Nodes", Value: strconv.Itoa(output.Remote.TrustNodeCount)},
		})
		return nil
	default:
		return fmt.Errorf("unsupported output mode %q", mode)
	}
}
