#!/bin/sh
set -e

echo "🚀 LaventeCare Auth Systems - Starting..."

# Check if DATABASE_URL is set
if [ -z "$DATABASE_URL" ]; then
  echo "❌ ERROR: DATABASE_URL is not set"
  exit 1
fi

# Run database migrations
echo "📦 Running database migrations..."
if ./migrate; then
  echo "✅ Migrations completed successfully"
else
  echo "❌ Migration failed"
  exit 1
fi

# Start the API server
echo "🌐 Starting API server on port ${PORT:-8080}..."
exec ./main
