package zensegur

import (
	"sync"
	"time"
)

type Cache struct {
	items map[string]cacheItem
	mu    sync.RWMutex
}

type cacheItem struct {
	value      interface{}
	expiration int64
}

func NewCache(defaultExpiration time.Duration) *Cache {
	cache := &Cache{
		items: make(map[string]cacheItem),
	}
	
	go cache.startGC(defaultExpiration)
	
	return cache
}

func (c *Cache) Set(key string, value interface{}) {
	c.SetWithExpiration(key, value, 5*time.Minute)
}

func (c *Cache) SetWithExpiration(key string, value interface{}, duration time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	c.items[key] = cacheItem{
		value:      value,
		expiration: time.Now().Add(duration).UnixNano(),
	}
}

func (c *Cache) Get(key string) interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	item, found := c.items[key]
	if !found {
		return nil
	}
	
	if time.Now().UnixNano() > item.expiration {
		return nil
	}
	
	return item.value
}

func (c *Cache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	if key == "*" {
		c.items = make(map[string]cacheItem)
		return
	}
	
	if len(key) > 0 && key[len(key)-1] == '*' {
		prefix := key[:len(key)-1]
		for k := range c.items {
			if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
				delete(c.items, k)
			}
		}
		return
	}
	
	delete(c.items, key)
}

func (c *Cache) startGC(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	
	for {
		<-ticker.C
		c.deleteExpired()
	}
}

func (c *Cache) deleteExpired() {
	now := time.Now().UnixNano()
	
	c.mu.Lock()
	defer c.mu.Unlock()
	
	for k, v := range c.items {
		if now > v.expiration {
			delete(c.items, k)
		}
	}
}