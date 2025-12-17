package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/darmiel/talmi/internal/core"
)

var _ core.Auditor = (*FileAuditor)(nil)

// FileAuditor is an auditor that writes audit logs to a file in JSON format.
type FileAuditor struct {
	mu      sync.Mutex
	file    *os.File
	encoder *json.Encoder
}

func NewFileAuditor(filePath string) (*FileAuditor, error) {
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("opening audit log file: %w", err)
	}
	return &FileAuditor{
		file:    file,
		encoder: json.NewEncoder(file),
	}, nil
}

func (f *FileAuditor) Log(entry core.AuditEntry) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if err := f.encoder.Encode(entry); err != nil {
		return fmt.Errorf("writing audit log entry: %w", err)
	}
	return nil
}

func (f *FileAuditor) GetRecent(limit int) ([]core.AuditEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	// on high throughput, reopening the file is probably not a good idea,
	// but when you use it in production, you probably* have a proper audit backend.
	// *probably = "hopefully"
	file, err := os.Open(f.file.Name())
	if err != nil {
		return nil, fmt.Errorf("opening audit log file for reading: %w", err)
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	var entries []core.AuditEntry
	decoder := json.NewDecoder(file)
	for decoder.More() {
		var entry core.AuditEntry
		if err := decoder.Decode(&entry); err != nil {
			return nil, fmt.Errorf("decoding audit log entry: %w", err)
		}
		entries = append(entries, entry)
	}

	// now we read it all, now reverse and limit
	count := len(entries)
	if count == 0 {
		return entries, nil // well nothing to do
	}

	start := count - limit
	if start < 0 {
		start = 0
	}

	recent := make([]core.AuditEntry, 0, limit)
	//for i := count - 1; i >= start; i-- {
	for i := start; i < count; i++ {
		recent = append(recent, entries[i])
	}

	return recent, nil
}

func (f *FileAuditor) Find(filter func(entry core.AuditEntry) bool, limit int) ([]core.AuditEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	// see above
	file, err := os.Open(f.file.Name())
	if err != nil {
		return nil, fmt.Errorf("opening audit log file for reading: %w", err)
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	var matches []core.AuditEntry

	decoder := json.NewDecoder(file)
	for decoder.More() {
		var entry core.AuditEntry
		if err := decoder.Decode(&entry); err != nil {
			return nil, fmt.Errorf("decoding audit log entry: %w", err)
		}
		if filter(entry) {
			matches = append(matches, entry)
		}
	}

	if len(matches) > limit {
		matches = matches[len(matches)-limit:]
	}

	return matches, nil
}

func (f *FileAuditor) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.file.Close()
}
