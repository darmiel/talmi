package ratelimit

import (
	"net/http"
	"net/netip"
	"strings"
)

// ClientIP derives the real client address.
func ClientIP(r *http.Request, trusted []netip.Prefix) string {
	peer := peerAddr(r.RemoteAddr)
	if !peer.IsValid() || !InPrefixes(peer, trusted) {
		return addrString(peer, r.RemoteAddr)
	}

	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return addrString(peer, r.RemoteAddr)
	}

	hops := parseHops(xff)
	if len(hops) == 0 {
		return addrString(peer, r.RemoteAddr)
	}

	// rightmost hop that is NOT trusted is the client IP
	for i := len(hops) - 1; i >= 0; i-- {
		if !InPrefixes(hops[i], trusted) {
			return hops[i].String()
		}
	}
	// all hops trusted :O best guess is probably the leftmost hop
	return hops[0].String()
}

func peerAddr(remote string) netip.Addr {
	if ap, err := netip.ParseAddrPort(remote); err == nil {
		return ap.Addr()
	}
	if a, err := netip.ParseAddr(remote); err == nil {
		return a
	}
	return netip.Addr{}
}

func addrString(a netip.Addr, raw string) string {
	if a.IsValid() {
		return a.String()
	}
	return raw
}

// parseHops splits an XFF header into the valid IPs it contains in order.
func parseHops(xff string) []netip.Addr {
	parts := strings.Split(xff, ",")
	hops := make([]netip.Addr, 0, len(parts))
	for _, p := range parts {
		if a, err := netip.ParseAddr(strings.TrimSpace(p)); err == nil {
			hops = append(hops, a)
		}
	}
	return hops
}

// InPrefixes reports whether a is contained in any of the prefixes.
func InPrefixes(a netip.Addr, prefixes []netip.Prefix) bool {
	for _, p := range prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
