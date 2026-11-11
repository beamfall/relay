package workflowtest

import (
	"fmt"
	"os"
	"os/exec"
	pathpkg "path"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestFuzzNightlyProtectsEveryTarget(t *testing.T) {
	workflow := readRepoFile(t, ".github/workflows/fuzz-nightly.yml")
	requireProtectedScanner(t, workflow, "fuzz", `go test -fuzz=${{ matrix.target.name }}`)
	requireBoundedJobTimeout(t, workflow, "fuzz", 15)

	for _, target := range []string{"FuzzReadFrame", "FuzzParseClientHelloRecord", "FuzzHMACVerifyV2"} {
		requireContainsOnce(t, workflow, "name: "+target)
	}
}

func TestVulnerabilityNightlyProtectsEveryScanner(t *testing.T) {
	workflow := readRepoFile(t, ".github/workflows/vuln-nightly.yml")
	for job, scanner := range map[string]string{
		"govulncheck":      "govulncheck ./...",
		"license-tripwire": "go-licenses check ./...",
	} {
		requireProtectedScanner(t, workflow, job, scanner)
	}
}

func TestNightlyWorkflowGuardsRejectUnsafeFixtures(t *testing.T) {
	fuzz := readRepoFile(t, ".github/workflows/fuzz-nightly.yml")

	t.Run("missing fuzz timeout", func(t *testing.T) {
		fixture := strings.Replace(fuzz, "    timeout-minutes: 15\n", "", 1)
		requireGuardFailure(t, boundedJobTimeoutError(fixture, "fuzz", 15))
	})
	t.Run("excessive fuzz timeout", func(t *testing.T) {
		fixture := strings.Replace(fuzz, "    timeout-minutes: 15\n", "    timeout-minutes: 120\n", 1)
		requireGuardFailure(t, boundedJobTimeoutError(fixture, "fuzz", 15))
	})

	const scanner = `go test -fuzz=${{ matrix.target.name }} -fuzztime=60s ${{ matrix.target.pkg }}`
	fixtures := map[string]string{
		"scanner or true":  strings.Replace(fuzz, scanner, scanner+" || true", 1),
		"scanner or no-op": strings.Replace(fuzz, scanner, scanner+" || :", 1),
		"disabled errexit": strings.Replace(
			fuzz,
			"        run: "+scanner,
			"        run: |\n          set +e\n          "+scanner,
			1,
		),
	}
	for name, fixture := range fixtures {
		t.Run(name, func(t *testing.T) {
			requireGuardFailure(t, protectedScannerError(fixture, "fuzz", `go test -fuzz=${{ matrix.target.name }}`))
		})
	}

	t.Run("scanner and no-op with trailing success", func(t *testing.T) {
		fixture := strings.Replace(fuzz, scanner, scanner+" && :\n          true", 1)
		command := exec.Command("bash", "-e", "-o", "pipefail", "-c", "false && :\ntrue")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("negative fixture must demonstrate Bash failure masking: %v: %s", err, output)
		}
		requireGuardFailure(t, protectedScannerError(fixture, "fuzz", `go test -fuzz=${{ matrix.target.name }}`))
	})

	t.Run("background scanner with trailing success", func(t *testing.T) {
		fixture := strings.Replace(fuzz, scanner, scanner+" &\n          true", 1)
		command := exec.Command("bash", "-e", "-o", "pipefail", "-c", "false & true")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("negative fixture must demonstrate detached Bash failure masking: %v: %s", err, output)
		}
		requireGuardFailure(t, protectedScannerError(fixture, "fuzz", `go test -fuzz=${{ matrix.target.name }}`))
	})
}

func TestWorkflowsResolveGoVersionFromCheckout(t *testing.T) {
	var paths []string
	for _, pattern := range []string{"*.yml", "*.yaml"} {
		matches, err := filepath.Glob(filepath.Join(repoRoot(t), ".github", "workflows", pattern))
		if err != nil {
			t.Fatal(err)
		}
		paths = append(paths, matches...)
	}
	for _, path := range paths {
		path := path
		t.Run(filepath.Base(path), func(t *testing.T) {
			contents, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := workflowGoVersionError(string(contents)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestWorkflowGoVersionGuardsRejectUnsafeFixtures(t *testing.T) {
	gate := readRepoFile(t, ".github/workflows/gate.yml")
	nightly := readRepoFile(t, ".github/workflows/relay-core-e2e-nightly.yml")
	fixtures := map[string]string{
		"literal version":      strings.Replace(gate, "go-version-file: go.mod", `go-version: "1.26.6"`, 1),
		"missing version file": strings.Replace(gate, "          go-version-file: go.mod\n", "", 1),
		"root checkout with nested path": strings.Replace(
			gate,
			"go-version-file: go.mod",
			"go-version-file: beamfall-relay/go.mod",
			1,
		),
		"nested checkout with root path": strings.Replace(
			nightly,
			"go-version-file: beamfall-relay/go.mod",
			"go-version-file: go.mod",
			1,
		),
	}
	for name, fixture := range fixtures {
		t.Run(name, func(t *testing.T) {
			requireGuardFailure(t, workflowGoVersionError(fixture))
		})
	}
}

type workflowStep struct {
	job             string
	uses            string
	checkoutPath    string
	repository      string
	goVersionFile   string
	run             string
	condition       string
	continueOnError string
}

func requireProtectedScanner(t *testing.T, workflow, job, scanner string) {
	t.Helper()
	if err := protectedScannerError(workflow, job, scanner); err != nil {
		t.Fatal(err)
	}
}

func protectedScannerError(workflow, job, scanner string) error {
	var matches []workflowStep
	for _, step := range parseWorkflowSteps(workflow) {
		if step.job == job && commandIndex(step.run, scanner) >= 0 {
			matches = append(matches, step)
		}
	}
	if len(matches) != 1 {
		return fmt.Errorf("job %q has %d executable scanner steps containing %q, want 1", job, len(matches), scanner)
	}

	step := matches[0]
	if hasFailureSuppression(step.run) {
		return fmt.Errorf("job %q scanner step contains shell failure suppression", job)
	}
	if step.continueOnError != "" && step.continueOnError != "false" {
		return fmt.Errorf("job %q scanner step bypasses failure with continue-on-error: %s", job, step.continueOnError)
	}
	if strings.Contains(step.condition, "always()") {
		return fmt.Errorf("job %q scanner step bypasses failure with if: %s", job, step.condition)
	}
	return nil
}

func parseWorkflowSteps(workflow string) []workflowStep {
	var steps []workflowStep
	var current *workflowStep
	job := ""
	inJobs := false
	inRun := false

	flush := func() {
		if current != nil {
			steps = append(steps, *current)
			current = nil
		}
		inRun = false
	}

	for _, line := range strings.Split(workflow, "\n") {
		indent := len(line) - len(strings.TrimLeft(line, " "))
		trimmed := strings.TrimSpace(line)
		if indent == 0 && trimmed == "jobs:" {
			inJobs = true
			continue
		}
		if !inJobs || trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if indent == 2 && strings.HasSuffix(trimmed, ":") {
			flush()
			job = strings.TrimSuffix(trimmed, ":")
			continue
		}
		if indent == 6 && strings.HasPrefix(trimmed, "- ") {
			flush()
			current = &workflowStep{job: job}
			continue
		}
		if current == nil {
			continue
		}
		if inRun && indent > 8 {
			current.run += strings.TrimSpace(line) + "\n"
			continue
		}
		inRun = false
		if indent != 8 && indent != 10 {
			continue
		}

		key, value, ok := strings.Cut(trimmed, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch key {
		case "uses":
			current.uses = value
		case "path":
			current.checkoutPath = value
		case "repository":
			current.repository = value
		case "go-version-file":
			current.goVersionFile = value
		case "run":
			if value == "|" || value == ">" {
				inRun = true
			} else {
				current.run = value + "\n"
			}
		case "if":
			current.condition = value
		case "continue-on-error":
			current.continueOnError = value
		}
	}
	flush()
	return steps
}

func workflowGoVersionError(workflow string) error {
	steps := parseWorkflowSteps(workflow)
	checkoutPaths := make(map[string]string)
	for _, line := range strings.Split(workflow, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "go-version:") {
			return fmt.Errorf("workflow pins a literal go-version")
		}
	}
	for _, step := range steps {
		if strings.HasPrefix(step.uses, "actions/checkout@") && step.repository == "" {
			checkoutPaths[step.job] = step.checkoutPath
		}
	}

	for _, step := range steps {
		if !strings.HasPrefix(step.uses, "actions/setup-go@") {
			continue
		}
		checkoutPath, ok := checkoutPaths[step.job]
		if !ok {
			return fmt.Errorf("job %q sets up Go without checking out the repository", step.job)
		}
		expected := pathpkg.Join(checkoutPath, "go.mod")
		if step.goVersionFile != expected {
			return fmt.Errorf("job %q go-version-file is %q, want %q relative to checkout path", step.job, step.goVersionFile, expected)
		}
	}
	return nil
}

func requireBoundedJobTimeout(t *testing.T, workflow, job string, maximum int) {
	t.Helper()
	if err := boundedJobTimeoutError(workflow, job, maximum); err != nil {
		t.Fatal(err)
	}
}

func boundedJobTimeoutError(workflow, job string, maximum int) error {
	body, err := workflowJobBody(workflow, job)
	if err != nil {
		return err
	}
	values := jobScalarValues(body, "timeout-minutes")
	if len(values) != 1 {
		return fmt.Errorf("job %q has %d timeout-minutes values, want 1", job, len(values))
	}
	minutes, err := strconv.Atoi(strings.Trim(values[0], `'"`))
	if err != nil || minutes < 1 || minutes > maximum {
		return fmt.Errorf("job %q timeout-minutes must be between 1 and %d, got %q", job, maximum, values[0])
	}
	return nil
}

func workflowJobBody(workflow, wanted string) (string, error) {
	var body strings.Builder
	inJobs := false
	inWanted := false
	found := 0

	for _, line := range strings.Split(workflow, "\n") {
		indent := len(line) - len(strings.TrimLeft(line, " "))
		trimmed := strings.TrimSpace(line)
		if indent == 0 && trimmed == "jobs:" {
			inJobs = true
			continue
		}
		if !inJobs {
			continue
		}
		if indent == 2 && strings.HasSuffix(trimmed, ":") {
			name := strings.TrimSuffix(trimmed, ":")
			inWanted = name == wanted
			if inWanted {
				found++
			}
			continue
		}
		if inWanted {
			body.WriteString(line)
			body.WriteByte('\n')
		}
	}
	if found != 1 {
		return "", fmt.Errorf("workflow has %d jobs named %q, want 1", found, wanted)
	}
	return body.String(), nil
}

func jobScalarValues(body, key string) []string {
	var values []string
	for _, line := range strings.Split(body, "\n") {
		indent := len(line) - len(strings.TrimLeft(line, " "))
		trimmed := strings.TrimSpace(line)
		if indent != 4 || !strings.HasPrefix(trimmed, key+":") {
			continue
		}
		values = append(values, strings.TrimSpace(strings.TrimPrefix(trimmed, key+":")))
	}
	return values
}

func requireGuardFailure(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("unsafe workflow fixture unexpectedly passed")
	}
}

func commandIndex(run, command string) int {
	for index, line := range strings.Split(run, "\n") {
		line = strings.TrimSpace(line)
		if line == command || strings.HasPrefix(line, command) {
			return index
		}
	}
	return -1
}

func hasFailureSuppression(run string) bool {
	for _, line := range strings.Split(run, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "||") || strings.Contains(line, "&") || line == "set +e" || strings.HasPrefix(line, "set +e ") || line == "set +o errexit" || strings.HasPrefix(line, "set +o errexit ") {
			return true
		}
	}
	return false
}

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func readRepoFile(t *testing.T, name string) string {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join(repoRoot(t), name))
	if err != nil {
		t.Fatal(err)
	}
	return string(contents)
}

func requireContainsOnce(t *testing.T, text, fragment string) {
	t.Helper()
	if count := strings.Count(text, fragment); count != 1 {
		t.Fatalf("%q occurs %d times, want 1", fragment, count)
	}
}
