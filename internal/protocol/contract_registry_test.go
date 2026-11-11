package protocol

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

type contractRegistry struct {
	SchemaVersion int                `json:"schemaVersion"`
	Boundaries    []contractBoundary `json:"boundaries"`
}

type contractBoundary struct {
	Boundary              string   `json:"boundary"`
	Owner                 string   `json:"owner"`
	Producer              string   `json:"producer"`
	Artifact              string   `json:"artifact"`
	Version               string   `json:"version"`
	ActiveArtifactVersion string   `json:"activeArtifactVersion"`
	Consumers             []string `json:"consumers"`
	ConformanceTest       string   `json:"conformanceTest"`
}

func TestContractRegistryPinsRelayProtocolArtifacts(t *testing.T) {
	registry := loadContractRegistry(t)
	if registry.SchemaVersion != 1 {
		t.Fatalf("schemaVersion = %d, want 1", registry.SchemaVersion)
	}
	boundary := findContractBoundary(t, registry, "relay-core-tunnel")
	if boundary.Owner != "beamfall-relay" || boundary.Producer != "beamfall-relay" {
		t.Fatalf("owner/producer = %q/%q, want beamfall-relay", boundary.Owner, boundary.Producer)
	}
	for _, artifact := range []string{
		"contracts/protocol/v1/schema.json",
		"contracts/protocol/v1/vectors.json",
	} {
		if !strings.Contains(boundary.Artifact, artifact) {
			t.Fatalf("artifact %q missing from %q", artifact, boundary.Artifact)
		}
		if _, err := os.Stat(filepath.Join(repoRoot(t), artifact)); err != nil {
			t.Fatalf("artifact %s: %v", artifact, err)
		}
	}
	wantVersion := strconv.Itoa(loadVectors(t).SchemaVersion)
	if boundary.Version != wantVersion || boundary.ActiveArtifactVersion != wantVersion {
		t.Fatalf("version/active = %q/%q, want %q", boundary.Version, boundary.ActiveArtifactVersion, wantVersion)
	}
	for _, consumer := range []string{"beamfall", "beamfall-relay"} {
		if !contains(boundary.Consumers, consumer) {
			t.Fatalf("consumer %q missing from %v", consumer, boundary.Consumers)
		}
	}
	if boundary.ConformanceTest != "internal/protocol/conformance_test.go" {
		t.Fatalf("conformanceTest = %q", boundary.ConformanceTest)
	}
}

func loadContractRegistry(t *testing.T) contractRegistry {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot(t), "contracts", "registry.json"))
	if err != nil {
		t.Fatalf("load contracts/registry.json: %v", err)
	}
	var registry contractRegistry
	if err := json.Unmarshal(data, &registry); err != nil {
		t.Fatalf("parse contracts/registry.json: %v", err)
	}
	return registry
}

func findContractBoundary(t *testing.T, registry contractRegistry, name string) contractBoundary {
	t.Helper()
	for _, boundary := range registry.Boundaries {
		if boundary.Boundary == name {
			return boundary
		}
	}
	t.Fatalf("missing boundary %q", name)
	return contractBoundary{}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(file), "..", "..")
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
