package relaytoken

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

const (
	inTreeModulePath = "github.com/beamfall/relay/relaytoken"
	inTreeReplace    = "./relaytoken"
)

type provenanceManifest struct {
	SchemaVersion int `json:"schema_version"`
	Destination   struct {
		ModulePath  string `json:"module_path"`
		RootReplace string `json:"root_replace"`
	} `json:"destination"`
	Source struct {
		Repository       string `json:"repository"`
		Path             string `json:"path"`
		SnapshotCommit   string `json:"snapshot_commit"`
		LastChangeCommit string `json:"last_change_commit"`
		TreeGitOID       string `json:"tree_git_oid"`
		License          string `json:"license"`
		LicensePath      string `json:"license_path"`
		LicenseSHA256    string `json:"license_sha256"`
	} `json:"source"`
	DestinationLicense struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
		// Relicense records an owner relicense of the transferred files. When set,
		// the destination licence may differ from the source licence.
		Relicense *struct {
			SPDX     string `json:"spdx"`
			Decision string `json:"decision"`
		} `json:"relicense,omitempty"`
	} `json:"destination_license"`
	Files []struct {
		Path              string `json:"path"`
		SourceSHA256      string `json:"source_sha256"`
		DestinationSHA256 string `json:"destination_sha256"`
		Transformation    string `json:"transformation"`
	} `json:"files"`
}

func TestTransferProvenance(t *testing.T) {
	root := moduleRoot(t)
	manifest := readProvenance(t, root)

	if manifest.SchemaVersion != 2 {
		t.Fatalf("schema version = %d, want 2", manifest.SchemaVersion)
	}
	if manifest.Destination.ModulePath != inTreeModulePath {
		t.Fatalf("module path = %q, want %q", manifest.Destination.ModulePath, inTreeModulePath)
	}
	if manifest.Destination.RootReplace != inTreeReplace {
		t.Fatalf("root replace = %q, want %q", manifest.Destination.RootReplace, inTreeReplace)
	}

	requireSourceIdentity(t, manifest)
	requireTransferredFiles(t, root, manifest)
	requireModuleDeclaration(t, root)
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve module root")
	}
	return filepath.Dir(file)
}

func readProvenance(t *testing.T, root string) provenanceManifest {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join(root, "PROVENANCE.json"))
	if err != nil {
		t.Fatalf("read provenance manifest: %v", err)
	}
	var manifest provenanceManifest
	decoder := json.NewDecoder(strings.NewReader(string(contents)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		t.Fatalf("decode provenance manifest: %v", err)
	}
	return manifest
}

func requireSourceIdentity(t *testing.T, manifest provenanceManifest) {
	t.Helper()
	fullSHA := regexp.MustCompile(`^[0-9a-f]{40}$`)
	if manifest.Source.Repository != "https://github.com/Beamfall/cloud" {
		t.Errorf("source repository = %q", manifest.Source.Repository)
	}
	if manifest.Source.Path != "relaytoken" {
		t.Errorf("source path = %q", manifest.Source.Path)
	}
	for name, value := range map[string]string{
		"snapshot commit":    manifest.Source.SnapshotCommit,
		"last change commit": manifest.Source.LastChangeCommit,
		"tree git oid":       manifest.Source.TreeGitOID,
	} {
		if !fullSHA.MatchString(value) {
			t.Errorf("%s = %q, want full lowercase Git object ID", name, value)
		}
	}
	if manifest.Source.License == "" || manifest.Source.LicensePath == "" {
		t.Error("source license identity is incomplete")
	}
	if relicense := manifest.DestinationLicense.Relicense; relicense != nil {
		if relicense.SPDX == "" || relicense.Decision == "" {
			t.Error("destination relicense must name an SPDX identifier and the owner decision")
		}
	} else if manifest.Source.LicenseSHA256 != manifest.DestinationLicense.SHA256 {
		t.Error("destination license does not preserve source license checksum")
	}
}

func requireTransferredFiles(t *testing.T, root string, manifest provenanceManifest) {
	t.Helper()
	required := map[string]bool{
		"canonical_parity_test.go": false,
		"fuzz_test.go":             false,
		"go.mod":                   false,
		"relaytoken.go":            false,
		"roundtrip_test.go":        false,
		"testdata/fuzz/FuzzDecodeToken/kat-empty":        false,
		"testdata/fuzz/FuzzDecodeToken/kat-four-parts":   false,
		"testdata/fuzz/FuzzDecodeToken/kat-random-bytes": false,
		"testdata/fuzz/FuzzDecodeToken/kat-two-parts":    false,
	}
	seen := make(map[string]struct{}, len(manifest.Files))
	for _, file := range manifest.Files {
		if _, ok := required[file.Path]; !ok {
			t.Errorf("unexpected transferred path %q", file.Path)
			continue
		}
		if _, duplicate := seen[file.Path]; duplicate {
			t.Errorf("duplicate transferred path %q", file.Path)
			continue
		}
		seen[file.Path] = struct{}{}
		required[file.Path] = true
		requireFileDigest(t, root, file.Path, file.DestinationSHA256)
		if file.Transformation == "none" && file.SourceSHA256 != file.DestinationSHA256 {
			t.Errorf("%s claims no transformation but source and destination checksums differ", file.Path)
		}
	}
	for path, found := range required {
		if !found {
			t.Errorf("provenance omits transferred path %q", path)
		}
	}
	requireFileDigest(t, root, manifest.DestinationLicense.Path, manifest.DestinationLicense.SHA256)
}

func requireFileDigest(t *testing.T, root, path, want string) {
	t.Helper()
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(want) {
		t.Errorf("%s checksum = %q, want lowercase SHA-256", path, want)
		return
	}
	contents, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
	if err != nil {
		t.Errorf("read %s: %v", path, err)
		return
	}
	sum := sha256.Sum256(contents)
	if got := hex.EncodeToString(sum[:]); got != want {
		t.Errorf("%s checksum = %s, want %s", path, got, want)
	}
}

func requireModuleDeclaration(t *testing.T, root string) {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	if !strings.HasPrefix(string(contents), "module "+inTreeModulePath+"\n") {
		t.Fatalf("go.mod does not declare %s", inTreeModulePath)
	}
	if strings.Contains(string(contents), "replace ") {
		t.Fatal("nested relaytoken module must not contain replace directives")
	}
}
