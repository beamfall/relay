package workflowtest

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

var (
	goDirectiveRE       = regexp.MustCompile(`(?m)^go (\d+)\.(\d+)(?:\.(\d+))?\s*$`)
	dockerfileGoArgRE   = regexp.MustCompile(`(?m)^ARG GO_VERSION=(\d+)\.(\d+)(?:\.(\d+))?\s*$`)
	dockerfileGoImageRE = regexp.MustCompile(`(?m)^FROM --platform=\$BUILDPLATFORM golang:\$\{GO_VERSION\}-bookworm@sha256:[0-9a-f]{64} AS build$`)
)

func parseGoVersion(t *testing.T, label string, m []string) [3]int {
	t.Helper()
	if m == nil {
		t.Fatalf("%s: no Go version found", label)
	}
	var v [3]int
	for i := 0; i < 3; i++ {
		if m[i+1] != "" {
			n, err := strconv.Atoi(m[i+1])
			if err != nil {
				t.Fatalf("%s: %v", label, err)
			}
			v[i] = n
		}
	}
	return v
}

func goVersionLess(a, b [3]int) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// The release image builds with GOTOOLCHAIN=local, so its pinned Go release
// must satisfy every go directive in the tree or the docker build fails only
// at the last gate target.
func TestDockerfileGoVersionSatisfiesGoModDirectives(t *testing.T) {
	dockerfile := readRepoFile(t, "Dockerfile")
	image := parseGoVersion(t, "Dockerfile ARG GO_VERSION", dockerfileGoArgRE.FindStringSubmatch(dockerfile))
	if !dockerfileGoImageRE.MatchString(dockerfile) {
		t.Error("Dockerfile build stage must be the digest-pinned golang:${GO_VERSION}-bookworm image")
	}
	for _, name := range []string{"go.mod", "relaytoken/go.mod"} {
		required := parseGoVersion(t, name, goDirectiveRE.FindStringSubmatch(readRepoFile(t, name)))
		if goVersionLess(image, required) {
			t.Errorf("Dockerfile GO_VERSION %s is older than %s directive %s (GOTOOLCHAIN=local)",
				fmtGo(image), name, fmtGo(required))
		}
	}
}

func TestGoVersionComparisonRejectsOlderImage(t *testing.T) {
	older := parseGoVersion(t, "older", dockerfileGoArgRE.FindStringSubmatch("ARG GO_VERSION=1.26.6\n"))
	need := parseGoVersion(t, "need", goDirectiveRE.FindStringSubmatch("go 1.26.10\n"))
	if !goVersionLess(older, need) {
		t.Fatal("1.26.6 must be older than 1.26.10")
	}
	if goVersionLess(need, need) || strings.Contains(fmtGo(need), " ") {
		t.Fatal("equal versions must satisfy")
	}
}

func fmtGo(v [3]int) string { return fmt.Sprintf("%d.%d.%d", v[0], v[1], v[2]) }
