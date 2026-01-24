# Builder stage
FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY . .
RUN go mod download
# Build API
RUN go build -o main ./cmd/api
# Build Worker
RUN go build -o worker ./cmd/worker
# Build Control CLI (Optioneel, handig voor in container)
RUN go build -o control ./cmd/control

# Final stage
FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/main .
COPY --from=builder /app/worker .
COPY --from=builder /app/control .
# Copy migrations if needed
COPY migrations ./migrations 

# Default command is API, maar kan overschreven worden door docker-compose
CMD ["./main"]
