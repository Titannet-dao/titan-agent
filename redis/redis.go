package redis

import (
	"github.com/redis/go-redis/v9"
)

type Redis struct {
	client *redis.Client
}

func NewRedis(addr string) *Redis {
	if len(addr) == 0 {
		panic("Redis addr can not empty")
	}

	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: "", // no password set
		DB:       0,  // use default DB
	})

	return &Redis{client: client}
}

const (
	RedisKeyApp         = "titan:agent:app:%s"
	RedisKeyNode        = "titan:agent:node:%s"
	RedisKeyNodeAppList = "titan:agent:nodeAppList:%s"
	RedisKeyNodeApp     = "titan:agent:nodeApp:%s:%s"

	RedisKeyNodeRegist        = "titan:agent:nodeRegist"
	RedisKeyNodeOnlineDuration = "titan:agent:nodeOnlineDuration:%s"
)
