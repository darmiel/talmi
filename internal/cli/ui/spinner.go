package ui

import (
	"fmt"
	"io"
	"sync"
	"time"
)

var spinnerFrames = []rune{'|', '/', '-', '\\'}

// Spinner renders an animated status line to a writer. When disabled (non-TTY
// or JSON mode) every method is a no-op. It is safe to Stop more than once.
type Spinner struct {
	w       io.Writer
	enabled bool

	mu      sync.Mutex
	done    chan struct{}
	wg      sync.WaitGroup
	stopped bool
}

func NewSpinner(w io.Writer, enabled bool) *Spinner {
	return &Spinner{
		w:       w,
		enabled: enabled,
	}
}

func (s *Spinner) Start(msg string) {
	if !s.enabled {
		return
	}
	s.done = make(chan struct{})
	s.wg.Add(1)

	go func() {
		defer s.wg.Done()

		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()

		frameIndex := 0
		for {
			select {
			case <-s.done:
				return
			case <-ticker.C:
				_, _ = fmt.Fprintf(s.w, "\r%c %s", spinnerFrames[frameIndex], msg)
				frameIndex = (frameIndex + 1) % len(spinnerFrames)
			}
		}
	}()
}

func (s *Spinner) Stop(final string) {
	if !s.enabled {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.stopped {
		return
	}
	s.stopped = true
	close(s.done)
	s.wg.Wait()

	if final == "" {
		_, _ = fmt.Fprint(s.w, "\r\x1b[K")
		return
	}
	_, _ = fmt.Fprintf(s.w, "\r\x1b[K%s\n", final)
}
