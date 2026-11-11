package relaytoken

import (
	"bytes"
	"testing"
)

// canonicalParityFixtures pins the exact inputs and expected canonical-JSON
// bytes shared with internal/entitlement/canonical_parity_test.go in the
// beamfall-cloud module. marshalCanonical/canonicalJSON are byte-identical
// copies (this module is zero-dep and can't import internal/entitlement;
// AUDIT-CLOUD-14 / RT-03 / C12-05). If either copy is edited without the
// other, its own copy of this fixture table will fail here or there,
// catching silent drift. Keep the two literals identical.
var canonicalParityFixtures = []struct {
	name string
	in   any
	want string
}{
	{
		name: "empty object",
		in:   map[string]any{},
		want: `{}`,
	},
	{
		name: "unordered keys sort lexically",
		in:   map[string]any{"b": 1.0, "a": 2.0, "c": 3.0},
		want: `{"a":2,"b":1,"c":3}`,
	},
	{
		name: "nested object and array",
		in: map[string]any{
			"z": []any{1.0, "two", false, nil},
			"a": map[string]any{"nested": true},
		},
		want: `{"a":{"nested":true},"z":[1,"two",false,null]}`,
	},
	{
		name: "string escaping",
		in:   map[string]any{"k": "a\"b\\c\nd"},
		want: `{"k":"a\"b\\c\nd"}`,
	},
	{
		name: "empty array",
		in:   []any{},
		want: `[]`,
	},
}

// TestCanonicalJSONParityFixtures feeds the shared fixture table into this
// module's canonicalJSON and asserts byte-identical output against the
// golden bytes pinned above (AUDIT-CLOUD-14). The same table, with the same
// expected bytes, is asserted independently against internal/entitlement's
// copy in canonical_parity_test.go there — so a divergent edit to either
// copy fails its own test without needing a cross-module import.
func TestCanonicalJSONParityFixtures(t *testing.T) {
	for _, tc := range canonicalParityFixtures {
		t.Run(tc.name, func(t *testing.T) {
			got, err := canonicalJSON(tc.in)
			if err != nil {
				t.Fatalf("canonicalJSON(%#v): %v", tc.in, err)
			}
			if !bytes.Equal(got, []byte(tc.want)) {
				t.Fatalf("canonicalJSON(%#v) = %s, want %s", tc.in, got, tc.want)
			}
		})
	}
}
