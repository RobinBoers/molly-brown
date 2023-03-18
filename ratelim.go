package main

import (
	"sync"
	"time"
)

type RateLimiter struct {
	mu sync.Mutex
	bucket map[string]int
	rate int
	burst int
}

func newRateLimiter(rate int, burst int) RateLimiter {
	var rl = new(RateLimiter)
	rl.bucket = make(map[string]int)
	rl.rate = rate
	rl.burst = burst
	// Leak periodically
	go func () {
		for(true) {
			rl.mu.Lock()
			for addr, drips := range rl.bucket {
				if drips <= rate {
					delete(rl.bucket, addr)
				} else {
					rl.bucket[addr] = drips - rl.rate
				}
			}
			rl.mu.Unlock()
			time.Sleep(time.Second)
		}
	}()
	return *rl
}

func  (rl *RateLimiter) Allowed(addr string) (int, bool) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	drips, present := rl.bucket[addr]
	if !present {
		rl.bucket[addr] = 1
		return 1, true
	}
	drips += 1
	rl.bucket[addr] = drips
	return drips, drips < rl.burst
}

