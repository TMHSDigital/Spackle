# syntax=docker/dockerfile:1

# Build stage. The Go toolchain image is pinned by tag here and by digest in
# the release workflow's provenance attestation.
FROM --platform=$BUILDPLATFORM golang:1.27 AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown
WORKDIR /src
COPY go.mod go.su[m] ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
    -ldflags "-s -w \
      -X github.com/TMHSDigital/spackle/internal/version.Version=${VERSION} \
      -X github.com/TMHSDigital/spackle/internal/version.Commit=${COMMIT} \
      -X github.com/TMHSDigital/spackle/internal/version.Date=${DATE}" \
    -o /out/spackle ./cmd/spackle

# Runtime stage: distroless, static, non-root. No shell, no package manager.
FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.title="spackle" \
      org.opencontainers.image.description="Agentic security and debugging for systems you own or are authorized to test" \
      org.opencontainers.image.source="https://github.com/TMHSDigital/Spackle" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /out/spackle /usr/local/bin/spackle
USER nonroot:nonroot
WORKDIR /work
# No EXPOSE: Spackle does not listen on any port.
ENTRYPOINT ["/usr/local/bin/spackle"]
CMD ["help"]
