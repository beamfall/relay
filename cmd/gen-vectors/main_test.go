package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// goldenFiles names the committed file of every -set, as the Makefile's
// VECTOR_SETS does.
var goldenFiles = map[string]string{
	"frames":        "vectors.json",
	"hmac-token-v2": "hmac-token-v2-vectors.json",
}

// TestCommittedVectorsMatchGenerator is the in-package twin of
// `make verify-vectors`: each committed golden must equal the generator output
// byte for byte.
func TestCommittedVectorsMatchGenerator(t *testing.T) {
	if len(goldenFiles) != len(vectorSets) {
		t.Fatalf("goldenFiles lists %d sets, vectorSets has %d", len(goldenFiles), len(vectorSets))
	}
	for set, name := range goldenFiles {
		got, err := render(set)
		if err != nil {
			t.Fatalf("render %s: %v", set, err)
		}
		want, err := os.ReadFile(filepath.Join("..", "..", "contracts", "protocol", "v1", name))
		if err != nil {
			t.Fatalf("read committed %s: %v", name, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("-set %s output differs from committed %s; run `make gen-vectors`", set, name)
		}
	}
}

func TestRenderRejectsUnknownSet(t *testing.T) {
	if _, err := render("no-such-set"); err == nil {
		t.Fatal("render accepted an unknown set name")
	}
}
