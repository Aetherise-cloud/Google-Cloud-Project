package auth

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type rateBucket struct {
	tokens     float64
	lastRefill time.Time
}

// IPRateLimiter implements a token bucket rate limiter per client IP.
type IPRateLimiter struct {
	mu       sync.Mutex
	capacity float64
	rate     float64 // tokens per second
	buckets  map[string]*rateBucket
}

// NewIPRateLimiter creates a rate limiter with specified max capacity and refill rate per minute.
func NewIPRateLimiter(capacity, perMinute float64) *IPRateLimiter {
	return &IPRateLimiter{
		capacity: capacity,
		rate:     perMinute / 60.0,
		buckets:  make(map[string]*rateBucket),
	}
}

// Allow checks if a request from the client IP is allowed.
func (rl *IPRateLimiter) Allow(r *http.Request) bool {
	ip := extractClientIP(r)

	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	b, ok := rl.buckets[ip]
	if !ok {
		rl.buckets[ip] = &rateBucket{
			tokens:     rl.capacity - 1,
			lastRefill: now,
		}
		return true
	}

	elapsed := now.Sub(b.lastRefill).Seconds()
	b.tokens += elapsed * rl.rate
	if b.tokens > rl.capacity {
		b.tokens = rl.capacity
	}
	b.lastRefill = now

	if b.tokens >= 1.0 {
		b.tokens -= 1.0
		return true
	}

	return false
}

func extractClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}
