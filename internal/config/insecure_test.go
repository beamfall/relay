package config

import (
	"strings"
	"testing"
)

func TestGuardInsecureSkipVerify(t *testing.T) {
	// Insecure not requested: env is irrelevant, never an error.
	if err := GuardInsecureSkipVerify(false, ""); err != nil {
		t.Fatalf("insecure=false, no dev env: unexpected error %v", err)
	}
	if err := GuardInsecureSkipVerify(false, "1"); err != nil {
		t.Fatalf("insecure=false, dev env set: unexpected error %v", err)
	}

	// Insecure requested without the dev-mode unlock: must be refused loudly.
	err := GuardInsecureSkipVerify(true, "")
	if err == nil {
		t.Fatal("insecure=true without BEAMFALL_RELAY_DEV=1 must be refused")
	}
	if !strings.Contains(err.Error(), DevModeEnv) {
		t.Fatalf("refusal error should name %s, got %q", DevModeEnv, err.Error())
	}

	// A non-"1" value does not unlock (e.g. "true", "0", "yes").
	for _, v := range []string{"0", "true", "yes", "2", " 1"} {
		if err := GuardInsecureSkipVerify(true, v); err == nil {
			t.Fatalf("insecure=true with BEAMFALL_RELAY_DEV=%q must still be refused", v)
		}
	}

	// Explicit dev-mode unlock permits the insecure switch.
	if err := GuardInsecureSkipVerify(true, "1"); err != nil {
		t.Fatalf("insecure=true with BEAMFALL_RELAY_DEV=1: unexpected error %v", err)
	}
}
