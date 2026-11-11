package config

import "testing"

func TestBoolEnvOrDefault(t *testing.T) {
	if got, err := BoolEnvOrDefault("", true); err != nil || got != true {
		t.Fatalf("empty -> fallback: got %v err %v, want true", got, err)
	}
	if got, err := BoolEnvOrDefault("false", true); err != nil || got != false {
		t.Fatalf("\"false\" -> false: got %v err %v", got, err)
	}
	if got, err := BoolEnvOrDefault("1", false); err != nil || got != true {
		t.Fatalf("\"1\" -> true: got %v err %v", got, err)
	}
	if _, err := BoolEnvOrDefault("notabool", false); err == nil {
		t.Fatal("invalid bool should error")
	}
}

func TestIntEnvOrDefault(t *testing.T) {
	if got, err := IntEnvOrDefault("", 30); err != nil || got != 30 {
		t.Fatalf("empty -> fallback: got %d err %v, want 30", got, err)
	}
	if got, err := IntEnvOrDefault("7", 30); err != nil || got != 7 {
		t.Fatalf("\"7\" -> 7: got %d err %v", got, err)
	}
	if _, err := IntEnvOrDefault("nope", 30); err == nil {
		t.Fatal("invalid int should error")
	}
}

func TestInt64EnvOrDefault(t *testing.T) {
	if got, err := Int64EnvOrDefault("", 1<<40); err != nil || got != 1<<40 {
		t.Fatalf("empty -> fallback: got %d err %v, want %d", got, err, int64(1<<40))
	}
	if got, err := Int64EnvOrDefault("1099511627776", 0); err != nil || got != 1<<40 {
		t.Fatalf("parsed value: got %d err %v, want %d", got, err, int64(1<<40))
	}
	if _, err := Int64EnvOrDefault("12.5", 0); err == nil {
		t.Fatal("invalid int64 should error")
	}
}

func TestEnvOrDefault(t *testing.T) {
	if got := EnvOrDefault("set", "fallback"); got != "set" {
		t.Fatalf("non-empty value: got %q, want \"set\"", got)
	}
	if got := EnvOrDefault("", "fallback"); got != "fallback" {
		t.Fatalf("empty value: got %q, want \"fallback\"", got)
	}
}

func TestSplitCSV(t *testing.T) {
	cases := []struct {
		input string
		want  []string
	}{
		{"relay.example.com", []string{"relay.example.com"}},
		{"a.example.com,b.example.com", []string{"a.example.com", "b.example.com"}},
		{" a.example.com , b.example.com ", []string{"a.example.com", "b.example.com"}},
		{"", nil},
		{",,,", nil},
		{"a.example.com,,b.example.com", []string{"a.example.com", "b.example.com"}},
	}
	for _, tc := range cases {
		got := SplitCSV(tc.input)
		if len(got) != len(tc.want) {
			t.Errorf("SplitCSV(%q) = %v (len %d), want %v (len %d)", tc.input, got, len(got), tc.want, len(tc.want))
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("SplitCSV(%q)[%d] = %q, want %q", tc.input, i, got[i], tc.want[i])
			}
		}
	}
}
