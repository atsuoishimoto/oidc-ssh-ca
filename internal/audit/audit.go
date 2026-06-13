// Package audit emits the structured audit log. Every issuance decision
// — issued or denied — produces exactly one event on stdout as JSON via
// log/slog. Internal error details belong here, never in HTTP responses.
package audit

import (
	"log/slog"
	"os"
)

// Event names.
const (
	EventIssued = "certificate_issued"
	EventDenied = "certificate_denied"
)

// Logger wraps slog with the two audit events.
type Logger struct {
	log *slog.Logger
}

// New creates a JSON audit logger writing to stdout.
func New() *Logger {
	return &Logger{log: slog.New(slog.NewJSONHandler(os.Stdout, nil))}
}

// NewWithHandler creates a logger with a custom handler (tests).
func NewWithHandler(h slog.Handler) *Logger {
	return &Logger{log: slog.New(h)}
}

// Issued records a successful issuance.
func (l *Logger) Issued(requestID string, attrs ...any) {
	args := append([]any{"event", EventIssued, "request_id", requestID}, attrs...)
	l.log.Info(EventIssued, args...)
}

// Denied records a denial with a stable reason code and detail. The
// detail is for the operator only and is never returned to the caller.
func (l *Logger) Denied(requestID, reason, detail string, attrs ...any) {
	args := append([]any{
		"event", EventDenied,
		"request_id", requestID,
		"reason", reason,
		"detail", detail,
	}, attrs...)
	l.log.Warn(EventDenied, args...)
}

// Error records a server-side error unrelated to a specific decision
// (e.g. a failed policy reload).
func (l *Logger) Error(msg string, attrs ...any) {
	l.log.Error(msg, attrs...)
}

// Info records operational events (startup, reload).
func (l *Logger) Info(msg string, attrs ...any) {
	l.log.Info(msg, attrs...)
}

// Warn records an operational condition that is allowed but weakens a
// default safeguard (e.g. a permission check disabled by an operator).
func (l *Logger) Warn(msg string, attrs ...any) {
	l.log.Warn(msg, attrs...)
}
