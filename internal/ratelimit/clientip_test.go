package ratelimit

import (
	"net/http"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClientIP(t *testing.T) {
	t.Parallel()

	trusted10 := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}

	tests := []struct {
		name    string
		remote  string
		xff     string // "" means no header
		trusted []netip.Prefix
		want    string
	}{
		{
			name:    "untrusted peer ignores spoofed xff",
			remote:  "203.0.113.9:1234",
			xff:     "1.2.3.4",
			trusted: trusted10,
			want:    "203.0.113.9",
		},
		{
			name:    "no xff returns peer",
			remote:  "203.0.113.9:1234",
			trusted: trusted10,
			want:    "203.0.113.9",
		},
		{
			name:    "trusted peer takes single client hop",
			remote:  "10.0.0.1:5000",
			xff:     "203.0.113.7",
			trusted: trusted10,
			want:    "203.0.113.7",
		},
		{
			name:    "trusted peer picks rightmost untrusted hop in chain",
			remote:  "10.0.0.6:5000",
			xff:     "203.0.113.7, 10.0.0.5, 10.0.0.6",
			trusted: trusted10,
			want:    "203.0.113.7",
		},
		{
			name:    "all hops trusted falls back to leftmost",
			remote:  "10.0.0.6:5000",
			xff:     "10.0.0.4, 10.0.0.5",
			trusted: trusted10,
			want:    "10.0.0.4",
		},
		{
			name:    "trusted peer with only malformed xff falls back to peer",
			remote:  "10.0.0.1:5000",
			xff:     "garbage",
			trusted: trusted10,
			want:    "10.0.0.1",
		},
		{
			name:    "trusted peer skips malformed hop for valid untrusted one",
			remote:  "10.0.0.1:5000",
			xff:     "garbage, 203.0.113.7",
			trusted: trusted10,
			want:    "203.0.113.7",
		},
		{
			name:    "empty trusted list always uses peer",
			remote:  "203.0.113.9:1234",
			xff:     "1.2.3.4",
			trusted: nil,
			want:    "203.0.113.9",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req, err := http.NewRequest(http.MethodGet, "/", nil)
			assert.NoError(t, err)
			req.RemoteAddr = tt.remote
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}
			assert.Equal(t, tt.want, ClientIP(req, tt.trusted))
		})
	}
}
