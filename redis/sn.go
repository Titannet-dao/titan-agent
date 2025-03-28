package redis

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	SNPrefix            = "TNT"
	RedisSNIncrIDKeyApp = "titan:agent:sn:id:%s"
)

func (r *Redis) GetSNNextID(ctx context.Context) (string, error) {
	dateTime := time.Now().Format("20060102")
	keyName := fmt.Sprintf("%s:%s", RedisSNIncrIDKeyApp, dateTime)
	val, err := r.client.Get(ctx, keyName).Int64()

	if err == redis.Nil {
		val = 10000
		nextDay := time.Now().Add(24 * time.Hour)
		expireTime := time.Date(nextDay.Year(), nextDay.Month(), nextDay.Day(), 0, 0, 0, 0, nextDay.Location())
		err = r.client.Set(ctx, keyName, val, time.Until(expireTime)).Err()
		if err != nil {
			return "", err
		}
	} else if err != nil {
		return "", err
	}

	newVal, err := r.client.Incr(ctx, keyName).Result()
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s%s%d", SNPrefix, dateTime, newVal), nil
}

// CheckExist 检测序列号是否在白名单中. 只要有一个在,则返回true
func (r *Redis) CheckExist(ctx context.Context, sns []string) (bool, error) {
	for _, sn := range sns {
		ok, err := r.client.SIsMember(ctx, RedisKeySNWhitList, sn).Result()
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}

	return false, nil
}

// AddBoxSNs 添加盒子序列号到Redis的白名单中
func (r *Redis) AddBoxSNs(ctx context.Context, sns []string) error {
	return r.client.SAdd(ctx, RedisKeySNWhitList, sns).Err()
}

var BoxSNPattern = regexp.MustCompile(`^TT(\d{4})(\d{2})(\d{2})([A-Za-z0-9]{10})$`) // TT202502011LJLFSVLE8
