package logger

import (
	"log/slog"
	"os"
)

// Setup configures the global logger based on the environment.
// It returns the logger instance, but also sets it as the default global logger.
func Setup(env string) *slog.Logger {
	var handler slog.Handler

	opts := &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}

	if env == "production" {
		// JSON for machine parsing (Datadog, Splunk, etc.)
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		// Text for human readability in development
		opts.Level = slog.LevelDebug
		handler = slog.NewTextHandler(os.Stdout, opts)
	}

	logger := slog.New(handler)
	slog.SetDefault(logger)

	return logger
}
