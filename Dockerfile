FROM golang:1.25.4-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY main.go ./
COPY internal internal/
COPY pkg pkg/
COPY cmd cmd/

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o talmi .

FROM gcr.io/distroless/static:nonroot

WORKDIR /
COPY --from=builder /app/talmi /talmi

USER 65532:65532

ENTRYPOINT ["/talmi"]
CMD ["serve", "--addr", ":8080", "--config", "/etc/talmi/talmi.yaml"]
