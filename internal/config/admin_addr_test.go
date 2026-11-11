package config

import "testing"

func TestAdminExposureCheck(t *testing.T) {
	cases := []struct {
		name        string
		addr        string
		allowPublic bool
		wantErr     bool
		wantWarn    bool
	}{
		{"disabled", "", false, false, false},
		{"loopback v4", "127.0.0.1:9080", false, false, false},
		{"loopback v4 alt", "127.0.0.2:9080", false, false, false},
		{"loopback v6", "[::1]:9080", false, false, false},
		{"private 10/8", "10.0.0.5:9080", false, false, false},
		{"private 172.16/12", "172.16.4.9:9080", false, false, false},
		{"private 192.168/16", "192.168.1.10:9080", false, false, false},
		{"private ULA v6", "[fd00::1]:9080", false, false, false},
		{"all interfaces empty host", ":9080", false, true, false},
		{"public v4", "203.0.113.10:9080", false, true, false},
		{"public v6", "[2001:db8::1]:9080", false, true, false},
		{"hostname", "admin.example.com:9080", false, false, true},
		{"unparseable", "not-a-host-port", false, false, true},
		{"all interfaces empty host, opt-in", ":9080", true, false, false},
		{"public v4, opt-in", "203.0.113.10:9080", true, false, false},
		{"public v6, opt-in", "[2001:db8::1]:9080", true, false, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			warning, err := AdminExposureCheck(tc.addr, tc.allowPublic)
			if tc.wantErr && err == nil {
				t.Fatalf("addr %q allowPublic=%v: expected an error, got none", tc.addr, tc.allowPublic)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("addr %q allowPublic=%v: expected no error, got %v", tc.addr, tc.allowPublic, err)
			}
			if tc.wantWarn && warning == "" {
				t.Fatalf("addr %q allowPublic=%v: expected a warning, got none", tc.addr, tc.allowPublic)
			}
			if !tc.wantWarn && warning != "" {
				t.Fatalf("addr %q allowPublic=%v: expected no warning, got %q", tc.addr, tc.allowPublic, warning)
			}
		})
	}
}
