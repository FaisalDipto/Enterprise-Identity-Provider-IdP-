# ==================================
# STAGE 1: Tge Builder
# ==================================
FROM golang:1.26-alpine AS builder

# Set the working directory inside the container
WORKDIR /app

# Copy the module files first to cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of your IDP source code
COPY . .

# Build the Go binary (statically linked for Alpine)
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o idp-server main.go

# ==================================
# STAGE 2: The Production Image
# ==================================
FROM alpine:latest
# Install CA certificates just in case we need to make external HTTPS calls
RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Copy the compiled binary from the builder stage
COPY --from=builder /app/idp-server .

# Copy your keys and environment variables
COPY --from=builder /app/public.pem .
COPY --from=builder /app/private.pem .
COPY --from=builder /app/.env .

# Expose port 8080 to the Docker network
EXPOSE 8080

# Command to boot the IDP
CMD ["./idp-server"]
