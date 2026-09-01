# notify-svc container image (fixture estate; never actually built).
#
# Base images are pinned to exact version tags; CI additionally locks
# each tag to a digest at build time and fails if the digest drifts.
# The runtime stage is distroless and runs as the nonroot user.

# ---- build stage ----------------------------------------------------------
FROM golang:1.22.4-bookworm AS build

WORKDIR /src

# Cache module downloads separately from source changes.
COPY apps/notify-svc/go.mod ./
RUN go mod download

COPY apps/notify-svc/ ./

# Static binary: no cgo, no libc dependency in the runtime image.
ENV CGO_ENABLED=0
RUN go build -trimpath -ldflags="-s -w" -o /out/notify-svc .

# ---- runtime stage --------------------------------------------------------
# Distroless: no shell, no package manager, nonroot by default. The
# explicit USER line keeps the invariant even if the base tag changes.
FROM gcr.io/distroless/static-debian12:nonroot

LABEL org.opencontainers.image.title="notify-svc" \
      org.opencontainers.image.vendor="example.invalid" \
      org.opencontainers.image.source="https://git.example.invalid/demo/fixture-estate"

COPY --from=build /out/notify-svc /usr/local/bin/notify-svc

USER nonroot:nonroot

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/notify-svc"]
