package helpers

import (
	"net"
	"net/http"
	"strings"
)

// GetRealIP extracts the client's real IP address, trusting X-Forwarded-For
// headers only if configured (or assuming behind a proxy like Nginx/Traefik).
// "Anti-Gravity": We prefer X-Forwarded-For over RemoteAddr if present and valid.
// Security Warning: Spoofing is possible if the specific proxy is not stripping these headers.
// We assume the infrastructure (Nginx/Traefik/Cloudflare) sanctifies these headers.
func GetRealIP(r *http.Request) net.IP {
	// 1. Try X-Forwarded-For (Standard)
	// Format: client, proxy1, proxy2
	xForwardedFor := r.Header.Get("X-Forwarded-For")
	if xForwardedFor != "" {
		// Taking the first IP in the list (Client IP)
		parts := strings.Split(xForwardedFor, ",")
		for _, p := range parts {
			ipStr := strings.TrimSpace(p)
			if ip := net.ParseIP(ipStr); ip != nil {
				return ip
			}
		}
	}

	// 2. Try X-Real-IP (Nginx/Alternative)
	xRealIP := r.Header.Get("X-Real-IP")
	if xRealIP != "" {
		if ip := net.ParseIP(strings.TrimSpace(xRealIP)); ip != nil {
			return ip
		}
	}

	// 3. Fallback to RemoteAddr
	// Remove port if present (ipv4:port or [ipv6]:port)
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		if ip := net.ParseIP(host); ip != nil {
			return ip
		}
	}

	// Fallback if SplitHostPort fails (e.g. no port)
	return net.ParseIP(r.RemoteAddr)
}
