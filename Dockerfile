# 1. Use the official Go image as the builder
FROM golang:1.24-bookworm AS builder

# 2. Set the working directory inside the container
WORKDIR /src

# 3. Copy your go.mod and go.sum (Don't ignore these!)
COPY go.mod go.sum ./

# 4. Download dependencies
RUN go mod download

# 5. Copy the rest of the source code
COPY . .

# 6. Compile the binary (static build for minimal final image)
RUN CGO_ENABLED=1 go build -ldflags="-s -w" -o /out/rduck-web ./cmd/rduck-web

# 7. Minimal runtime image with CA certs for TLS
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/rduck-web /usr/local/bin/rduck-web
EXPOSE 8443
ENTRYPOINT ["rduck-web"]
