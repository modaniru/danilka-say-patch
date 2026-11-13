package httpapi

import (
	"math"
	"sync"
	"time"
)

type LimiterOptions struct {
	Limit    int
	Period   time.Duration
	MaxUsers int
	Now      func() time.Time
}

type limitEntry struct {
	Count int
	Until time.Time
}

// RateLimiter bounds successful authenticated requests per subject, as well as
// the total memory used by subjects with active fixed windows.
type RateLimiter struct {
	mu    sync.Mutex
	opts  LimiterOptions
	users map[string]limitEntry
}

func NewRateLimiter(opts LimiterOptions) *RateLimiter {
	if opts.Limit <= 0 {
		opts.Limit = 60
	}
	if opts.Period <= 0 {
		opts.Period = time.Minute
	}
	if opts.MaxUsers <= 0 {
		opts.MaxUsers = 10000
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &RateLimiter{opts: opts, users: make(map[string]limitEntry)}
}

// Take returns zero for an allowed request, otherwise Retry-After in seconds.
func (l *RateLimiter) Take(subject string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.opts.Now()
	entry, exists := l.users[subject]
	if !exists || !now.Before(entry.Until) {
		if len(l.users) >= l.opts.MaxUsers {
			for id, state := range l.users {
				if !now.Before(state.Until) {
					delete(l.users, id)
				}
			}
			if _, exists := l.users[subject]; !exists && len(l.users) >= l.opts.MaxUsers {
				return retrySeconds(l.opts.Period)
			}
		}
		entry = limitEntry{Until: now.Add(l.opts.Period)}
	}
	if entry.Count >= l.opts.Limit {
		return retrySeconds(entry.Until.Sub(now))
	}
	entry.Count++
	l.users[subject] = entry
	return 0
}

func retrySeconds(duration time.Duration) int { return max(1, int(math.Ceil(duration.Seconds()))) }
