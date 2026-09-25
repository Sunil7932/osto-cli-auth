# Build stage: compile a static binary so the runtime image can stay tiny.
FROM golang:1.22-alpine AS build

WORKDIR /src

# Dependencies first, so editing source does not invalidate the module cache.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build \
        -trimpath \
        -ldflags "-s -w -X main.version=${VERSION}" \
        -o /out/authcli ./cmd/authcli

# Runtime stage.
FROM alpine:3.20

# ca-certificates for outbound TLS, tzdata so timestamps render in the
# operator's timezone instead of plain UTC.
RUN apk add --no-cache ca-certificates tzdata \
    && adduser -D -u 10001 -h /home/authcli authcli \
    && mkdir -p /home/authcli/history \
    && chown -R authcli:authcli /home/authcli

COPY --from=build /out/authcli /usr/local/bin/authcli

USER authcli
WORKDIR /home/authcli

# Kept on a volume in compose so shell history survives container restarts.
ENV CLI_HISTORY_FILE=/home/authcli/history/.authcli_history

ENTRYPOINT ["authcli"]
