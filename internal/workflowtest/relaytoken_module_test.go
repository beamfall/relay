package workflowtest

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	relaytokenModule      = "github.com/beamfall/relay/relaytoken"
	relaytokenRequirement = relaytokenModule + " v0.0.0"
	relaytokenReplacement = "replace " + relaytokenModule + " => ./relaytoken"
)

var credentialFreeWorkflows = []string{
	".github/workflows/gate.yml",
	".github/workflows/release.yml",
	".github/workflows/fuzz-nightly.yml",
	".github/workflows/vuln-nightly.yml",
	".github/workflows/soak-scheduled.yml",
	".github/workflows/relay-core-e2e-nightly.yml",
}

func TestRelaytokenModuleResolvesInTree(t *testing.T) {
	rootGoMod := readRepoFile(t, "go.mod")
	nestedGoMod := readRepoFile(t, "relaytoken/go.mod")
	if err := relaytokenModuleError(rootGoMod, nestedGoMod); err != nil {
		t.Fatal(err)
	}
}

func TestRelaytokenModuleRejectsNonHermeticFixtures(t *testing.T) {
	rootGoMod := readRepoFile(t, "go.mod")
	nestedGoMod := readRepoFile(t, "relaytoken/go.mod")
	fixtures := map[string]string{
		"floating sibling": strings.Replace(
			rootGoMod,
			"./relaytoken",
			"../beamfall-cloud/relaytoken",
			1,
		),
		"network resolved": strings.Replace(rootGoMod, relaytokenReplacement+"\n", "", 1),
		"Cloud module": strings.ReplaceAll(
			rootGoMod,
			relaytokenModule,
			"github.com/beamfall/cloud/relaytoken",
		),
		"additional replacement": rootGoMod + "\nreplace example.com/external => ../external\n",
	}
	for name, fixture := range fixtures {
		t.Run(name, func(t *testing.T) {
			if err := relaytokenModuleError(fixture, nestedGoMod); err == nil {
				t.Fatal("non-hermetic module fixture accepted")
			}
		})
	}
}

func TestRelaytokenOfflineResolutionHasNegativeControl(t *testing.T) {
	t.Run("in-tree replacement builds", func(t *testing.T) {
		fixture := newRelaytokenFixture(t, relaytokenReplacement+"\n")
		if output, err := runOfflineGoTest(t, fixture); err != nil {
			t.Fatalf("in-tree relaytoken failed offline: %v: %s", err, output)
		}
	})

	t.Run("network resolution fails", func(t *testing.T) {
		fixture := newRelaytokenFixture(t, "")
		if output, err := runOfflineGoTest(t, fixture); err == nil {
			t.Fatalf("network-resolved relaytoken unexpectedly built offline: %s", output)
		}
	})
}

func TestBuildWorkflowsNeedNoCloudCredential(t *testing.T) {
	for _, path := range credentialFreeWorkflows {
		t.Run(path, func(t *testing.T) {
			contents := readRepoFile(t, path)
			// Every checkout must drop its token, including checkouts of other repositories.
			checkouts := strings.Count(contents, "uses: actions/checkout@")
			if checkouts < strings.Count(contents, "name: Checkout relay") || checkouts == 0 {
				t.Errorf("%s has %d checkouts, fewer than its Relay checkouts", path, checkouts)
			}
			if credentiallessCheckouts := strings.Count(contents, "persist-credentials: false"); credentiallessCheckouts != checkouts {
				t.Errorf("%s has %d credential-free checkouts, want %d", path, credentiallessCheckouts, checkouts)
			}
			for _, forbidden := range []string{
				"CLOUD_REPO_PAT",
				"repository: Beamfall/cloud",
				"beamfall-cloud",
				"cloud-repo.sha",
				"verify-cloud-checkout",
				"github.com/beamfall/cloud/relaytoken",
				"../beamfall-cloud",
				"GOPRIVATE",
				"GONOSUMDB",
				"GONOSUMCHECK",
			} {
				if strings.Contains(contents, forbidden) {
					t.Errorf("%s retains Cloud dependency %q", path, forbidden)
				}
			}
		})
	}
}

func TestGateAndReleaseExerciseHermeticBuild(t *testing.T) {
	makefile := readRepoFile(t, "Makefile")
	for _, required := range []string{
		"gate: gofmt-check build vet relaytoken-check hermetic-check ",
		"GOTOOLCHAIN=local GOPROXY=off GOVCS='*:off' GOENV=off",
		"hermetic-check requires a clean committed tree",
		"clean_go off go build ./...",
		"clean_go off go vet ./...",
		"clean_go off go test ./...",
		"DOCKER_CONFIG=\"$$docker_config\" DOCKER_HOST=\"$$docker_host\" $$buildx build --pull \\\n\t\t--output \"type=docker,dest=$$release_tar,rewrite-timestamp=true\"",
		"--tag beamfall-relay:gate .",
	} {
		if !strings.Contains(makefile, required) {
			t.Errorf("Makefile omits hermetic gate fragment %q", required)
		}
	}
	for _, forbidden := range []string{"GOPRIVATE", "GONOSUMDB", "GONOSUMCHECK"} {
		if strings.Contains(makefile, forbidden) {
			t.Errorf("Makefile uses checksum/privacy bypass %q", forbidden)
		}
	}

	dockerfile := readRepoFile(t, "Dockerfile")
	for _, required := range []string{
		"ARG GO_VERSION=1.26.10",
		"FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-bookworm@sha256:5de7c99eb78ca5e515a4c340235d0955ec5964a5071c492c15503d7c267da473 AS build",
		"ENV GOTOOLCHAIN=local",
		"COPY relaytoken ./relaytoken",
		"RUN go mod download && go mod verify",
		"RUN GOPROXY=off GOVCS='*:off' GOENV=off",
	} {
		requireContainsOnce(t, dockerfile, required)
	}
	if copyIndex, downloadIndex := strings.Index(dockerfile, "COPY relaytoken ./relaytoken"), strings.Index(dockerfile, "RUN go mod download"); copyIndex < 0 || copyIndex > downloadIndex {
		t.Fatal("Dockerfile must copy the in-tree relaytoken module before downloading dependencies")
	}
	for _, forbidden := range []string{"beamfall-cloud", "beamfall-relay/"} {
		if strings.Contains(dockerfile, forbidden) {
			t.Errorf("Dockerfile retains workspace-context path %q", forbidden)
		}
	}

	release := readRepoFile(t, ".github/workflows/release.yml")
	requireContainsOnce(t, release, "          context: .")
	gate := readRepoFile(t, ".github/workflows/gate.yml")
	requireContainsOnce(t, gate, "uses: docker/setup-buildx-action@")
}

func relaytokenModuleError(rootGoMod, nestedGoMod string) error {
	if strings.Contains(rootGoMod, "github.com/beamfall/cloud/relaytoken") {
		return fmt.Errorf("go.mod retains the Cloud relaytoken module")
	}
	if strings.Count(rootGoMod, relaytokenRequirement) != 1 {
		return fmt.Errorf("go.mod must require %q exactly once", relaytokenRequirement)
	}
	if strings.Count(rootGoMod, relaytokenReplacement) != 1 {
		return fmt.Errorf("go.mod must contain %q exactly once", relaytokenReplacement)
	}
	if strings.Count(rootGoMod, "replace ") != 1 {
		return fmt.Errorf("go.mod contains a replacement outside the in-tree relaytoken boundary")
	}
	if strings.Contains(rootGoMod, "../") {
		return fmt.Errorf("go.mod contains a replacement outside the repository")
	}
	if strings.Count(nestedGoMod, "module "+relaytokenModule+"\n") != 1 {
		return fmt.Errorf("relaytoken/go.mod must declare %s", relaytokenModule)
	}
	return nil
}

func newRelaytokenFixture(t *testing.T, replacement string) string {
	t.Helper()
	root := t.TempDir()
	writeFixtureFile(t, filepath.Join(root, "go.mod"), "module example.com/hermetic-fixture\n\ngo 1.26.6\n\nrequire "+relaytokenRequirement+"\n\n"+replacement)
	writeFixtureFile(t, filepath.Join(root, "fixture.go"), "package fixture\n\nimport \""+relaytokenModule+"\"\n\nconst tokenType = relaytoken.TokenType\n")
	writeFixtureFile(t, filepath.Join(root, "relaytoken", "go.mod"), readRepoFile(t, "relaytoken/go.mod"))
	writeFixtureFile(t, filepath.Join(root, "relaytoken", "relaytoken.go"), readRepoFile(t, "relaytoken/relaytoken.go"))
	return root
}

func runOfflineGoTest(t *testing.T, fixture string) (string, error) {
	t.Helper()
	command := exec.Command("go", "test", "-mod=mod", "./...")
	command.Dir = fixture
	command.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + t.TempDir(),
		"TMPDIR=" + t.TempDir(),
		"GOCACHE=" + filepath.Join(t.TempDir(), "go-build"),
		"GOMODCACHE=" + filepath.Join(t.TempDir(), "go-mod"),
		"GOPROXY=off",
		"GOVCS=*:off",
		"GOENV=off",
		"GOWORK=off",
		"GOTOOLCHAIN=local",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_TERMINAL_PROMPT=0",
		"CGO_ENABLED=0",
	}
	output, err := command.CombinedOutput()
	return string(output), err
}

func writeFixtureFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
}
