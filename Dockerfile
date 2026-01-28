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
# Build Migrate (NIEUW - voor auto-migrations)
RUN go build -o migrate ./cmd/migrate
# Build Email Worker
RUN go build -o emailworker ./cmd/emailworker

# Final stage
FROM alpine:latest
WORKDIR /app

# Install ca-certificates voor HTTPS calls
RUN apk --no-cache add ca-certificates

COPY --from=builder /app/main .
COPY --from=builder /app/worker .
COPY --from=builder /app/control .
COPY --from=builder /app/migrate .
COPY --from=builder /app/emailworker .

# Copy migrations directory (nodig voor migrate tool)
COPY migrations ./migrations 

# Copy entrypoint script en maak executable
COPY docker-entrypoint.sh .
RUN chmod +x docker-entrypoint.sh

# Default command is entrypoint (runs migrations + API)
ENTRYPOINT ["./docker-entrypoint.sh"]
