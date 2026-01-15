package logging

import "github.com/rs/zerolog"

// InternalLogger is an interface used by e.g. tasks and fetchers for logging.
// I don't like it either, but it allows decoupling from specific logging implementations,
// for example when storing task logs.
// I don't like it either, we can refactor later! :)
type InternalLogger interface {
	Info(format string, args ...any)
	Warn(format string, args ...any)
	Error(format string, args ...any)
}

var _ InternalLogger = (*ZLogger)(nil)

type ZLogger struct {
	ZLog zerolog.Logger
}

func NewZLogger(zlog zerolog.Logger) ZLogger {
	return ZLogger{ZLog: zlog}
}

func (l ZLogger) Info(format string, args ...any) {
	l.ZLog.Info().Msgf(format, args...)
}

func (l ZLogger) Warn(format string, args ...any) {
	l.ZLog.Warn().Msgf(format, args...)
}

func (l ZLogger) Error(format string, args ...any) {
	l.ZLog.Error().Msgf(format, args...)
}

var _ InternalLogger = (*MultiLogger)(nil)

type MultiLogger struct {
	Loggers []InternalLogger
}

func NewMultiLogger(loggers ...InternalLogger) MultiLogger {
	return MultiLogger{Loggers: loggers}
}

func (l MultiLogger) Info(format string, args ...any) {
	for _, logger := range l.Loggers {
		logger.Info(format, args...)
	}
}

func (l MultiLogger) Warn(format string, args ...any) {
	for _, logger := range l.Loggers {
		logger.Warn(format, args...)
	}
}

func (l MultiLogger) Error(format string, args ...any) {
	for _, logger := range l.Loggers {
		logger.Error(format, args...)
	}
}
