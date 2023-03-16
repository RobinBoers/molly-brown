package main

import (
	"fmt"
	"sync"
	"time"
)

type RateLimiter struct {
	mu sync.Mutex
	bucket map[string]int
	capacity int
	rate int
}

func newRateLimiter(capacity int, rate int) RateLimiter {
	var rl = new(RateLimiter)
	rl.bucket = make(map[string]int)
	rl.capacity = capacity
	rl.rate = rate
	// Leak periodically
	go func () {
		for(true) {
			fmt.Println(rl.bucket)
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

func  (rl *RateLimiter) Allowed(addr string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	drips, present := rl.bucket[addr]
	if !present {
		rl.bucket[addr] = 1
		return true
	}
	if drips == rl.capacity {
		return false
	}
	rl.bucket[addr] = drips + 1
	return true
}

