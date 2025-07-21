package zensframework

import (
	"github.com/redis/go-redis/v9"
)

func newRedisClient(opts *redis.Options) *redis.Client {
	return redis.NewClient(opts)
}
