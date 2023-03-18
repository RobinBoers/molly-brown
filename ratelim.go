package main

import (
	"log"
	"sync"
	"time"
)

type RateLimiter struct {
	mu sync.Mutex
	bucket map[string]int
	bans map[string]time.Time
	rate int
	softLimit int
	hardLimit int
}

func newRateLimiter(rate int, softLimit int, hardLimit int) RateLimiter {
	var rl = new(RateLimiter)
	rl.bucket = make(map[string]int)
	rl.bans = make(map[string]time.Time)
	rl.rate = rate
	rl.softLimit = softLimit
	rl.hardLimit = hardLimit

	// Leak periodically
	go func () {
		for(true) {
			rl.mu.Lock()
			// Leak the buckets
			for addr, drips := range rl.bucket {
				if drips <= rate {
					delete(rl.bucket, addr)
				} else {
					rl.bucket[addr] = drips - rl.rate
				}
			}
			// Expire bans
			now := time.Now()
			for addr, expiry := range rl.bans {
				if now.After(expiry) {
					delete(rl.bans, addr)
				}
			}

			// Wait
			rl.mu.Unlock()
			time.Sleep(time.Second)
		}
	}()
	return *rl
}

func  (rl *RateLimiter) softLimited(addr string) (int, bool) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	drips, present := rl.bucket[addr]
	if !present {
		rl.bucket[addr] = 1
		return 1, false
	}
	drips += 1
	rl.bucket[addr] = drips
	if drips > rl.hardLimit {
		now := time.Now()
		expiry := now.Add(time.Hour)
		rl.bans[addr] = expiry
		log.Println("Banning " + addr + "for 1 hour due to ignoring rate limiting.")
	}
	return drips, drips > rl.softLimit
}

func  (rl *RateLimiter) hardLimited(addr string) bool {
	_, present := rl.bans[addr]
	return present
}
