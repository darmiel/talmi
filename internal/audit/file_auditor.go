package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/darmiel/talmi/internal/core"
)

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

func (f *FileAuditor) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.file.Close()
}
