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

# 6. Compile the binary
RUN CGO_ENABLED=1 go build -o /out/rduck-web ./cmd/rduck-web

# 7. Export only the compiled binary as the final stage
FROM scratch AS binary
COPY --from=builder /out/rduck-web /