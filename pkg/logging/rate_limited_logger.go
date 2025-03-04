package logging

import (
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"golang.org/x/time/rate"
)

// RateLimitedLogger wraps a zap.SugaredLogger that supports rate limiting.
type RateLimitedLogger struct {
	Logger       Logger
	frequency    float64
	burst        int
	rateLimiters *lru.Cache[string, *rate.Limiter]
}

// NewRateLimitLogger returns a rate limited logger
func NewRateLimitLogger(l Logger, size int, logLines int, interval time.Duration, burst int) *RateLimitedLogger {
	cache, err := lru.New[string, *rate.Limiter](size)
	if err != nil {
		l.Errorf("unable to create rate limiter cache for logger in module %q: %v", CurrentModule().name, err)
		return nil
	}
	return &RateLimitedLogger{
		l,
		float64(logLines) / interval.Seconds(),
		burst,
		cache,
	}
}

// ErrorL logs a templated error message if allowed by the rate limiter corresponding to the identifier
func (rl *RateLimitedLogger) ErrorL(limiter string, template string, args ...interface{}) {
	if rl.allowLog(limiter) {
		rl.Errorf(template, args...)
	}
}

// Error logs the consecutive interfaces
func (rl *RateLimitedLogger) Error(args ...interface{}) {
	rl.Logger.Error(args...)
}

// Errorf logs the input template filled with argument data
func (rl *RateLimitedLogger) Errorf(template string, args ...interface{}) {
	rl.Logger.Errorf(template, args...)
}

// Errorw logs the input message and keyValues
func (rl *RateLimitedLogger) Errorw(msg string, keysAndValues ...interface{}) {
	rl.Logger.Errorw(msg, keysAndValues...)
}

// WarnL logs a templated warn message if allowed by the rate limiter corresponding to the identifier
func (rl *RateLimitedLogger) WarnL(limiter string, template string, args ...interface{}) {
	if rl.allowLog(limiter) {
		rl.Warnf(template, args...)
	}
}

// Warn logs the consecutive interfaces
func (rl *RateLimitedLogger) Warn(args ...interface{}) {
	rl.Logger.Warn(args...)
}

// Warnf logs the input template filled with argument data
func (rl *RateLimitedLogger) Warnf(template string, args ...interface{}) {
	rl.Logger.Warnf(template, args...)
}

// Warnw logs the input message and keyValues
func (rl *RateLimitedLogger) Warnw(msg string, keysAndValues ...interface{}) {
	rl.Logger.Warnw(msg, keysAndValues...)
}

// InfoL logs a templated info message if allowed by the rate limiter corresponding to the identifier
func (rl *RateLimitedLogger) InfoL(limiter string, template string, args ...interface{}) {
	if rl.allowLog(limiter) {
		rl.Infof(template, args...)
	}
}

// Info logs the consecutive interfaces
func (rl *RateLimitedLogger) Info(args ...interface{}) {
	rl.Logger.Info(args...)
}

// Infof logs the input template filled with argument data
func (rl *RateLimitedLogger) Infof(template string, args ...interface{}) {
	rl.Logger.Infof(template, args...)
}

// Infow logs the input message and keyValues
func (rl *RateLimitedLogger) Infow(msg string, keysAndValues ...interface{}) {
	rl.Logger.Infow(msg, keysAndValues...)
}

// DebugL logs a templated debug message if allowed by the rate limiter corresponding to the identifier
func (rl *RateLimitedLogger) DebugL(limiter string, template string, args ...interface{}) {
	if rl.allowLog(limiter) {
		rl.Debugf(template, args...)
	}
}

// Debug logs the consecutive interfaces
func (rl *RateLimitedLogger) Debug(args ...interface{}) {
	rl.Logger.Debug(args...)
}

// Debugf logs the input template filled with argument data
func (rl *RateLimitedLogger) Debugf(template string, args ...interface{}) {
	rl.Logger.Debugf(template, args...)
}

// Debugw logs the input message and keyValues
func (rl *RateLimitedLogger) Debugw(msg string, keysAndValues ...interface{}) {
	rl.Logger.Debugw(msg, keysAndValues...)
}

func (rl *RateLimitedLogger) allowLog(limiter string) bool {
	_, _ = rl.rateLimiters.ContainsOrAdd(limiter, rate.NewLimiter(rate.Limit(rl.frequency), rl.burst))

	if lim, ok := rl.rateLimiters.Get(limiter); ok {
		return lim.Allow()
	}
	return false
}
