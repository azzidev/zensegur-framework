package zensegur

import (
	"sync"
	"time"
)

type Cache struct {
	data map[string]CacheItem
	mu   sync.RWMutex
	ttl  time.Duration
}

type CacheItem struct {
	Value     interface{}
	ExpiresAt time.Time
}

func NewCache(ttl time.Duration) *Cache {
	return &Cache{
		data: make(map[string]CacheItem),
		ttl:  ttl,
	}
}

func (c *Cache) Set(key string, value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[key] = CacheItem{
		Value:     value,
		ExpiresAt: time.Now().Add(c.ttl),
	}
}

func (c *Cache) Get(key string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	item, exists := c.data[key]
	if !exists || time.Now().After(item.ExpiresAt) {
		return nil, false
	}
	return item.Value, true
}

func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data = make(map[string]CacheItem)
}

func (r *Repository) WithCache(cache *Cache) *Repository {
	return &Repository{
		client:     r.client,
		collection: r.collection,
		ctx:        r.ctx,
	}
}
