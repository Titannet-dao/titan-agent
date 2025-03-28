package redis

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

type Redis struct {
	client *redis.Client
}

func NewRedis(addr, pass string) *Redis {
	if len(addr) == 0 {
		panic("Redis addr can not empty")
	}

	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: pass, // no password set
		DB:       0,    // use default DB
	})

	return &Redis{client: client}
}

const (
	RedisKeyApp                  = "titan:agent:app:%s"
	RedisKeyNode                 = "titan:agent:node:%s"
	RedisKeyZsNodeLastActiveTime = "titan:agent:nodeLastActiveTime"

	RedisKeyNodeAppList = "titan:agent:nodeAppList:%s"
	RedisKeyNodeApp     = "titan:agent:nodeApp:%s:%s"

	RedisKeyNodeRegist         = "titan:agent:nodeRegist"
	RedisKeyNodeOnlineDuration = "titan:agent:nodeOnlineDuration:%s"

	RedisKeySNNode = "titan:agent:sn:node:%s"

	RedisKeySNWhitList = "titan:agent:sn:whiteList"

	RedisKeyNodeOnlineDurationByDate = "titan:agent:onlineDurationDate:%s:%s"
)

func (r *Redis) Ping(ctx context.Context) error {
	reidsCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	if _, err := r.client.Ping(reidsCtx).Result(); err != nil {
		return err
	}
	return nil
}
