package middleware

import (
	"log/slog"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// IPRateLimiter holds the rate limiters for each visitor.
type IPRateLimiter struct {
	ips    sync.Map
	mu     sync.Mutex
	config LimiterConfig
}

type LimiterConfig struct {
	RPS   rate.Limit
	Burst int
}

// NewIPRateLimiter creates a custom rate limiter.
func NewIPRateLimiter(rps rate.Limit, burst int) *IPRateLimiter {
	i := &IPRateLimiter{
		config: LimiterConfig{
			RPS:   rps,
			Burst: burst,
		},
	}

	// Background cleanup of old IPs could be added here to prevent memory leaks
	go i.cleanupLoop()

	return i
}

// GetLimiter returns the rate limiter for the provided IP address.
func (i *IPRateLimiter) GetLimiter(ip string) *rate.Limiter {
	limiter, exists := i.ips.Load(ip)
	if !exists {
		// Create new limiter
		newLimiter := rate.NewLimiter(i.config.RPS, i.config.Burst)
		i.ips.Store(ip, newLimiter)
		return newLimiter
	}
	return limiter.(*rate.Limiter)
}

func (i *IPRateLimiter) cleanupLoop() {
	for {
		time.Sleep(10 * time.Minute)
		// Simplistic cleanup: clear map. In production, use LRU or last-seen timestamp.
		// For now, we trust the "Anti-Gravity" robustness of the server restarts.
		// A full wipe is acceptable for a dev/staging MVP.
		i.ips.Range(func(key, value interface{}) bool {
			i.ips.Delete(key)
			return true
		})
	}
}

// RateLimitMiddleware enforces the rate limit per IP.
func (i *IPRateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		// If behind proxy (e.g. Nginx/Cloudflare), use X-Forwarded-For (handled by chi middleware.RealIP upstream)

		limiter := i.GetLimiter(ip)
		if !limiter.Allow() {
			slog.Warn("Rate Limit Exceeded", "ip", ip, "path", r.URL.Path)
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}
