# syntax=docker/dockerfile:1.7

ARG GO_VERSION=1.26.10

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-bookworm@sha256:5de7c99eb78ca5e515a4c340235d0955ec5964a5071c492c15503d7c267da473 AS build
ENV GOTOOLCHAIN=local
WORKDIR /src

COPY go.mod go.sum ./
COPY relaytoken ./relaytoken
RUN go mod download && go mod verify

COPY cmd ./cmd
COPY internal ./internal

ARG TARGETOS
ARG TARGETARCH
RUN GOPROXY=off GOVCS='*:off' GOENV=off \
	CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
	go build -trimpath -ldflags="-s -w" -o /out/relayd ./cmd/relayd && \
	CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
	go build -trimpath -ldflags="-s -w" -o /out/tunnel-client ./cmd/tunnel-client && \
	CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
	go build -trimpath -ldflags="-s -w" -o /out/relay-healthcheck ./cmd/relay-healthcheck && \
	install -d -m 0700 /out/relayd-state

FROM gcr.io/distroless/static-debian12:nonroot@sha256:d093aa3e30dbadd3efe1310db061a14da60299baff8450a17fe0ccc514a16639

COPY --from=build /out/relayd /usr/local/bin/relayd
COPY --from=build /out/tunnel-client /usr/local/bin/tunnel-client
COPY --from=build /out/relay-healthcheck /usr/local/bin/relay-healthcheck
COPY --from=build --chown=nonroot:nonroot --chmod=0700 /out/relayd-state /var/lib/beamfall-relay

EXPOSE 8443 9443 9080
VOLUME ["/var/lib/beamfall-relay"]
USER nonroot:nonroot
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["/usr/local/bin/relay-healthcheck"]
ENTRYPOINT ["/usr/local/bin/relayd"]
