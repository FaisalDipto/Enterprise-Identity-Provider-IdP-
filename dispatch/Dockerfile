# STAGE 1: The Builder
FROM golang:1.26-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build the Dispatch binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o dispatch-server main.go

# STAGE 2: The Production Image
FROM alpine:latest
RUN apk --no-cache add ca-certificates

WORKDIR /root/

COPY --from=builder /app/dispatch-server .
COPY --from=builder /app/public.pem .

# Expose port 8081 for the Dispatch Service
EXPOSE 8081

CMD [ "./dispatch-server" ]