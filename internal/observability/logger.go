package observability

import (
	"log/slog"
	"os"
)

func NewLogger(component, version string) *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		AddSource: true,
		Level:     slog.LevelInfo,
	})).With(
		slog.String("component", component),
		slog.String("version", version),
	)
}

func WithLoggerDefaults(logger *slog.Logger, component, version string) *slog.Logger {
	if logger == nil {
		return NewLogger(component, version)
	}
	return logger.With(
		slog.String("component", component),
		slog.String("version", version),
	)
}
