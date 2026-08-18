package ratelimit

import (
	"context"
	"hash/fnv"
	"sync"
	"time"
)

const defaultShards = 16

type MemoryOptions struct {
	Sweep   time.Duration // how often to sweep expired buckets, 0 = disabled
	IdleTTL time.Duration // evict buckets untouched for this long, 0 = default
	Now     func() time.Time
}

const defaultIdleTTL = 10 * time.Minute

var _ Limiter = (*MemoryLimiter)(nil)

type MemoryLimiter struct {
	shards  []*memoryShard
	idleTTL time.Duration
	now     func() time.Time

	quit chan struct{}
	wg   sync.WaitGroup
	once sync.Once
}

type memoryShard struct {
	mu      sync.Mutex
	entries map[string]*memoryEntry
}

type memoryEntry struct {
	bucket *bucket
	seen   time.Time
}

func NewMemoryLimiter(opts MemoryOptions) *MemoryLimiter {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	idle := opts.IdleTTL
	if idle <= 0 {
		idle = defaultIdleTTL
	}
	m := &MemoryLimiter{
		shards:  make([]*memoryShard, defaultShards),
		idleTTL: idle,
		now:     now,
		quit:    make(chan struct{}),
	}
	for i := range m.shards {
		m.shards[i] = &memoryShard{
			entries: make(map[string]*memoryEntry),
		}
	}
	if opts.Sweep > 0 {
		m.wg.Add(1)
		go m.sweeper(opts.Sweep)
	}
	return m
}

func (m *MemoryLimiter) shardFor(k string) *memoryShard {
	h := fnv.New32a()
	_, _ = h.Write([]byte(k))
	return m.shards[h.Sum32()%uint32(len(m.shards))]
}

func mapKey(key Key) string {
	return key.Layer + "\x00" + key.ID
}

// entry resolves or creates the bucket for key inside its shard.
func (s *memoryShard) entry(key Key, now func() time.Time) *memoryEntry {
	mk := mapKey(key)
	e, ok := s.entries[mk]
	if !ok {
		e = &memoryEntry{
			bucket: newBucket(float64(key.Profile.Capacity), key.Profile.RefillPerSec, now),
		}
		s.entries[mk] = e
	}
	return e
}

func (m *MemoryLimiter) Admit(_ context.Context, key Key) (Decision, error) {
	s := m.shardFor(mapKey(key))
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.entry(key, m.now)
	e.seen = m.now()
	return e.bucket.snapshot(), nil
}

func (m *MemoryLimiter) Charge(_ context.Context, key Key, cost int) error {
	s := m.shardFor(mapKey(key))
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.entry(key, m.now)
	e.seen = m.now()
	e.bucket.charge(float64(cost))
	return nil
}

func (m *MemoryLimiter) count() int {
	n := 0
	for _, s := range m.shards {
		s.mu.Lock()
		n += len(s.entries)
		s.mu.Unlock()
	}
	return n
}

func (m *MemoryLimiter) sweep() {
	cutoff := m.now().Add(-m.idleTTL)
	for _, s := range m.shards {
		s.mu.Lock()
		for k, e := range s.entries {
			if e.seen.Before(cutoff) {
				delete(s.entries, k)
			}
		}
		s.mu.Unlock()
	}
}

func (m *MemoryLimiter) sweeper(interval time.Duration) {
	defer m.wg.Done()
	t := time.NewTicker(interval)
	for {
		select {
		case <-m.quit:
			return
		case <-t.C:
			m.sweep()
		}
	}
}

func (m *MemoryLimiter) Close() error {
	m.once.Do(func() {
		close(m.quit)
	})
	m.wg.Wait()
	return nil
}
