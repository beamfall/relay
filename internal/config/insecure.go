package config

import "fmt"

// DevModeEnv is the environment variable that must be explicitly set to "1" to
// unlock developer-only switches such as --insecure-skip-verify. Production and
// release deployments must never set it.
const DevModeEnv = "BEAMFALL_RELAY_DEV"

// GuardInsecureSkipVerify enforces a structural gate around the carrier TLS
// verification downgrade switch. The --insecure-skip-verify flag is a
// local-testing-only escape hatch (see RV-RELAY-006); leaving its safety solely
// to the flag staying default-false lets a copied test invocation or a
// misconfigured systemd unit silently run production carrier TLS with
// verification disabled.
//
// When insecure is requested, this requires the developer-mode environment
// variable (BEAMFALL_RELAY_DEV=1) to be set; otherwise it returns a loud error
// so the process refuses to start rather than dialing the carrier without
// verification. When insecure is not requested, the env var is irrelevant and
// no error is returned.
func GuardInsecureSkipVerify(insecure bool, devModeEnv string) error {
	if !insecure {
		return nil
	}
	if devModeEnv == "1" {
		return nil
	}
	return fmt.Errorf("--insecure-skip-verify is a local-testing-only switch and is refused in production: set %s=1 to enable it (never set this in a release/systemd deployment)", DevModeEnv)
}
