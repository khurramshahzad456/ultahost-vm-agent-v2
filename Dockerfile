
FROM golang:1.24-alpine3.21 AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o run-agent ./cmd/agent/main.go


FROM alpine:3.21

WORKDIR /root
COPY --from=builder /app/run-agent .
COPY run-agent.env .
RUN apk add --no-cache ca-certificates

EXPOSE 8080
CMD ["./run-agent"]
