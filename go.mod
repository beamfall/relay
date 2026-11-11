module github.com/beamfall/relay

go 1.26.10

require (
	github.com/alicebob/miniredis/v2 v2.38.0
	github.com/beamfall/relay/relaytoken v0.0.0
	github.com/hashicorp/yamux v0.1.2
	github.com/prometheus/client_golang v1.25.0
	github.com/quic-go/quic-go v0.60.0
	github.com/redis/go-redis/v9 v9.21.0
	go.opentelemetry.io/otel v1.44.0
	go.opentelemetry.io/otel/sdk v1.44.0
	go.opentelemetry.io/otel/trace v1.44.0
	golang.org/x/sys v0.48.0
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/prometheus/client_model v0.6.3 // indirect
	github.com/prometheus/common v0.72.0 // indirect
	github.com/prometheus/procfs v0.22.0 // indirect
	github.com/yuin/gopher-lua v1.1.1 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/otel/metric v1.44.0 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/net v0.59.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)

replace github.com/beamfall/relay/relaytoken => ./relaytoken
