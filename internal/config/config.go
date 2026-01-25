package config

import (
	"os"
	"strconv"
)

// Config holds all application configuration.
type Config struct {
	AllowPublicRegistration bool
	DatabaseURL             string
	ConvexWebhookURL        string // URL to Convex gatekeeper endpoint
	ConvexDeployKey         string // Deploy key for authentication
	// Add other app-level configs here
}

// Load reads configuration from environment variables.
func Load() Config {
	return Config{
		AllowPublicRegistration: getEnvAsBool("ALLOW_PUBLIC_REGISTRATION", false),
		DatabaseURL:             os.Getenv("DATABASE_URL"),
		ConvexWebhookURL:        os.Getenv("CONVEX_WEBHOOK_URL"),
		ConvexDeployKey:         os.Getenv("CONVEX_DEPLOY_KEY"),
	}
}

// Helper to read boolean env vars
func getEnvAsBool(name string, defaultVal bool) bool {
	valStr := os.Getenv(name)
	if valStr == "" {
		return defaultVal
	}
	val, err := strconv.ParseBool(valStr)
	if err != nil {
		return defaultVal
	}
	return val
}
