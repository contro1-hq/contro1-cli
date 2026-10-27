# Contro1 private connector, as a container.
#
# Build from the cli/ directory:
#   docker build -f packaging/private-connector/Dockerfile --build-arg VERSION=0.3.0 -t contro1/private-connector .
#
# Provision once (the setup JSON from Contro1 goes on stdin, nothing is baked in):
#   docker volume create contro1-connector
#   docker run --rm -i -v contro1-connector:/var/lib/contro1-private-connector \
#     contro1/private-connector private-connector provision < setup.json
#
# Run:
#   docker run -d --name contro1-connector --restart unless-stopped \
#     -v contro1-connector:/var/lib/contro1-private-connector contro1/private-connector
#
# The container needs outbound HTTPS to Contro1 (or proxy_url in the setup) and
# a route to the local API. It opens no port.

FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/contro1 . \
 && mkdir -p /out/state && chown 65532:65532 /out/state && chmod 0700 /out/state

# No shell, no package manager; runs as an unprivileged user.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/contro1 /usr/local/bin/contro1
COPY --from=build --chown=65532:65532 /out/state /var/lib/contro1-private-connector
VOLUME ["/var/lib/contro1-private-connector"]
USER 65532:65532
ENV CONTRO1_CONNECTOR_LOG=stdout
ENTRYPOINT ["/usr/local/bin/contro1"]
CMD ["private-connector", "serve"]
