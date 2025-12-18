FROM golang:1.25.4-alpine AS builder

ARG VERSION=unknown
ARG COMMIT_HASH=unknown

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY main.go ./
COPY internal internal/
COPY pkg pkg/
COPY cmd cmd/

RUN CGO_ENABLED=0 GOOS=linux \
    go build \
    -ldflags="-w -s \
      -X github.com/darmiel/talmi/internal/buildinfo.Version=${VERSION} \
      -X github.com/darmiel/talmi/internal/buildinfo.CommitHash=${COMMIT_HASH}" \
    -o talmi .

FROM gcr.io/distroless/static:nonroot

WORKDIR /
COPY --from=builder /app/talmi /talmi

USER 65532:65532

ENTRYPOINT ["/talmi"]
CMD ["serve", "--addr", ":8080", "--config", "/etc/talmi/talmi.yaml"]
