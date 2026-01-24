package config

import (
	"os"
	"strconv"
)

// Config holds all application configuration.
type Config struct {
	AllowPublicRegistration bool
	DatabaseURL             string
	// Add other app-level configs here
}

// Load reads configuration from environment variables.
func Load() Config {
	return Config{
		AllowPublicRegistration: getEnvAsBool("ALLOW_PUBLIC_REGISTRATION", false),
		DatabaseURL:             os.Getenv("DATABASE_URL"),
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
