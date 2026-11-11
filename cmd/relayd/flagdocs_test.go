package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"
)

// operatorGuidePath is relative to this package directory (cmd/relayd).
const operatorGuidePath = "../../docs/operator-self-hosted-relay.md"

// flagUsageLine matches a Go flag package usage line, e.g. "  -public-addr string"
// or "  -admin-allow-public". Flag names always start a line with exactly two
// spaces then a single dash (the flag package's Usage never emits "--").
var flagUsageLine = regexp.MustCompile(`(?m)^  -([A-Za-z][A-Za-z0-9-]*)`)

// TestFlagDocsCoverAllRelaydFlags builds the real relayd binary and parses the
// --help output of the top-level command and both subcommands, the same way an
// operator would discover flags, then fails listing any flag name that does not
// literally appear as "--flagname" in docs/operator-self-hosted-relay.md. This
// is a subprocess test rather than an in-process one because every flag relayd
// accepts is registered inside func main() (and the two subcommand runners),
// which this ticket's Allowed Paths do not permit refactoring into an
// injectable, in-process-testable form.
func TestFlagDocsCoverAllRelaydFlags(t *testing.T) {
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go toolchain not found in PATH")
	}

	binPath := filepath.Join(t.TempDir(), "relayd")
	build := exec.Command(goTool, "build", "-o", binPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build ./cmd/relayd: %v\n%s", err, out)
	}

	guide, err := os.ReadFile(operatorGuidePath)
	if err != nil {
		t.Fatalf("read operator guide %s: %v", operatorGuidePath, err)
	}

	cases := []struct {
		name string
		args []string
	}{
		{"top-level", []string{"--help"}},
		{"cache-serve", []string{"cache-serve", "--help"}},
		{"cache-supervise", []string{"cache-supervise", "--help"}},
	}

	var missing []string
	for _, c := range cases {
		flags := helpFlagNames(t, binPath, c.args)
		if len(flags) == 0 {
			t.Fatalf("%s --help produced no parseable flag lines; the usage format may have changed", c.name)
		}
		for _, flagName := range flags {
			if !bytes.Contains(guide, []byte("--"+flagName)) {
				missing = append(missing, c.name+" --"+flagName)
			}
		}
	}

	if len(missing) > 0 {
		t.Fatalf("flags accepted by the relayd binary but missing from %s:\n  %s",
			operatorGuidePath, joinLines(missing))
	}
}

// helpFlagNames runs the built binary with args (expected to end in --help,
// which the flag package answers with usage text on stderr and a 0 exit code)
// and returns every flag name it declares.
func helpFlagNames(t *testing.T, binPath string, args []string) []string {
	t.Helper()
	cmd := exec.Command(binPath, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", binPath, args, err, out)
	}
	matches := flagUsageLine.FindAllSubmatch(out, -1)
	names := make([]string, 0, len(matches))
	for _, m := range matches {
		names = append(names, string(m[1]))
	}
	return names
}

func joinLines(lines []string) string {
	out := ""
	for i, l := range lines {
		if i > 0 {
			out += "\n  "
		}
		out += l
	}
	return out
}
