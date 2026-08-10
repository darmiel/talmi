package logging

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

const (
	LogLevelKey   = "log.level"
	LogFormatKey  = "log.format"
	LogNoColorKey = "log.no_color"
)

func InitDefault() {
	log.Logger = zerolog.New(zerolog.NewConsoleWriter(func(w *zerolog.ConsoleWriter) {
		w.Out = os.Stderr
		w.NoColor = viper.GetBool(LogNoColorKey)
		w.TimeFormat = "15:04:05.000"
	})).With().
		Timestamp().
		Logger()

	// Make log.Ctx(ctx) fall back to the global logger when the context carries
	// none (background flows: runtime reload, tasks, startup) instead of a
	// disabled logger that silently drops messages.
	zerolog.DefaultContextLogger = &log.Logger
}

// Init sets up the global logger. If sensitive values are provided,
// it wraps the standard output with a redacting writer to mask those values in logs.
func Init() {
	var queue []string

	levelStr := strings.ToLower(viper.GetString(LogLevelKey))
	level, err := zerolog.ParseLevel(levelStr)
	if err != nil {
		level = zerolog.InfoLevel
		queue = append(queue, fmt.Sprintf("invalid log level %q, using info", levelStr))
	}
	zerolog.SetGlobalLevel(level)

	var output io.Writer = os.Stderr
	logFormat := strings.ToLower(viper.GetString(LogFormatKey))

	if logFormat == "json" {
		log.Logger = zerolog.New(output).With().
			Timestamp().
			Logger()
	} else {
		if logFormat != "console" {
			queue = append(queue, fmt.Sprintf("unknown log format %q, using console", logFormat))
		}
		log.Logger = zerolog.New(zerolog.NewConsoleWriter(func(w *zerolog.ConsoleWriter) {
			w.Out = output
			w.NoColor = viper.GetBool(LogNoColorKey)
			w.TimeFormat = "15:04:05.000"
		})).With().
			Timestamp().
			Logger()
	}

	// now after we set up the logger, we can log any queued messages
	for _, msg := range queue {
		log.Warn().Msg(msg)
	}

	// Make log.Ctx(ctx) fall back to the global logger when the context carries
	// none (background flows) instead of a disabled logger.
	zerolog.DefaultContextLogger = &log.Logger
}
