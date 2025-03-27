package redis

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

type Node struct {
	ID                  string `redis:"id"`
	UUID                string `redis:"uuid"`
	AndroidID           string `redis:"androidId"`
	AndroidSerialNumber string `redis:"androidSerialNumber"`

	OS              string `redis:"os"`
	Platform        string `redis:"platform"`
	PlatformVersion string `redis:"platformVersion"`
	Arch            string `redis:"arch"`
	BootTime        int64  `redis:"bootTime"`

	Macs string `redis:"macs"`

	CPUModuleName string  `redis:"cpuModuleName"`
	CPUCores      int     `redis:"cpuCores"`
	CPUMhz        float64 `redis:"cpuMhz"`
	CPUUsage      float64 `redis:"cpuUsage"`

	Gpu string `redis:"gpu"`

	TotalMemory     int64  `redis:"totalMemory"`
	UsedMemory      int64  `redis:"usedMemory"`
	AvailableMemory int64  `redis:"availableMemory"`
	MemoryModel     string `redis:"memoryModel"`

	NetIRate float64 `redis:"netIRate"`
	NetORate float64 `redis:"netORate"`

	Baseboard string `redis:"baseboard"`

	TotalDisk int64  `redis:"totalDisk"`
	FreeDisk  int64  `redis:"freeDisk"`
	DiskModel string `redis:"diskModel"`

	LastActivityTime time.Time `redis:"lastActivityTime"`

	// Controller *Controller

	IP string `redis:"ip"`

	// AppList []*App

	// WorkingDir string
	Version string `redis:"version"`
	Channel string `redis:"channel"`

	ServiceState int `redis:"serviceState"`
}

var InitStateAfterFetchingClientIDMap = map[string]int{
	"pedge":      BizStatusCodeResourceWaitAudit,
	"niulinkant": BizStatusCodeResourceWaitAudit,
	"painet":     BizStatusCodeWaitAudit,

	"vmbox:":       BizStateReservedRunning,
	"emc-titan-l2": BizStateReservedRunning,
}

func GetStateBeforeInit(locationMatch, resourceMatch bool) int {
	if !locationMatch {
		return BizStatusCodeAreaUnsupport
	}
	if !resourceMatch && locationMatch {
		return BizStatusCodeNoTask
	}

	// locationMatch && areaMatch
	return BizStateIniting
}

const (
	BizStatusCodeWaitAudit         = 0  // 资源审核中 正在审核资源中，预计5-20分钟，审核通过后将会自动部署。 (七牛云)
	BizStatusCodeResourceWaitAudit = 2  // 资源审核中 正在审核资源中，预计12-24小时，审核通过后会自动部署 (派享)
	BizStatusCodeAreaUnsupport     = 5  // 部署失败-区域未开放 资源所在地尚未开放需求，请更换地区参与。
	BizStatusCodeNoTask            = 7  // 部署失败-无任务 当前地区无对应设备的资源需求，请更换地区或设备参与.
	BizStateIniting                = 11 // 环境准备中
	BizStatusCodeErr               = 12 // 错误 (获取bizid失败, multipass失败)

	// AgentServer state reserved
	BizStateReservedRunning = 100

	BizStatusRunning = "running"
)

func (r *Redis) SetNode(ctx context.Context, n *Node) error {
	if n == nil {
		return fmt.Errorf("Redis.SetNode: node can not empty")
	}

	if len(n.ID) == 0 {
		return fmt.Errorf("Redis.SetNode: node ID can not empty")
	}

	if len(n.AndroidSerialNumber) > 0 {
		if err := r.client.Set(ctx, fmt.Sprintf(RedisKeySNNode, n.AndroidSerialNumber), n.ID, 0).Err(); err != nil {
			return err
		}
	}

	key := fmt.Sprintf(RedisKeyNode, n.ID)
	err := r.client.HSet(ctx, key, n).Err()
	if err != nil {
		return err
	}

	err = r.client.ZAdd(ctx, RedisKeyZsNodeLastActiveTime, redis.Z{
		Score:  float64(n.LastActivityTime.Unix()),
		Member: n.ID,
	}).Err()
	if err != nil {
		return err
	}
	return nil
}

func (redis *Redis) GetNode(ctx context.Context, nodeID string) (*Node, error) {
	if len(nodeID) == 0 {
		return nil, fmt.Errorf("Redis.GetNode: nodeID can not empty")
	}

	key := fmt.Sprintf(RedisKeyNode, nodeID)
	res := redis.client.HGetAll(ctx, key)
	if res.Err() != nil {
		return nil, res.Err()
	}

	var n Node
	if err := res.Scan(&n); err != nil {
		return nil, err
	}

	return &n, nil
}

func (r *Redis) GetNodesAfter(ctx context.Context, t int64) ([]string, error) {
	return r.client.ZRangeByScore(ctx, RedisKeyZsNodeLastActiveTime, &redis.ZRangeBy{
		Min: fmt.Sprintf("%d", t),
		Max: fmt.Sprintf("%d", 4070908800), // 2099-01-01 00:00:00
	}).Result()

}

func (r *Redis) GetNodeList(ctx context.Context, lastActiveTime time.Time, nodeid string) ([]*Node, error) {

	var (
		cursor uint64
		ret    []*Node
	)

	nodeLike := fmt.Sprintf("%s*", nodeid)
	nodeKeyPattern := strings.Replace(RedisKeyNode, "%s", nodeLike, -1)
	for {
		keys, nextCursor, err := r.client.Scan(ctx, cursor, nodeKeyPattern, 100).Result()
		if err != nil {
			fmt.Println("Error scanning keys:", err)
			break
		}

		for _, key := range keys {
			res := r.client.HGetAll(ctx, key)
			if res.Err() != nil {
				// return nil, res.Err()
				log.Printf("Error HGetAll: %v", res.Err())
				continue
			}

			var n Node
			if err := res.Scan(&n); err != nil {
				// return nil, err
				log.Printf("Error scan node: %v", err)
				continue
			}

			if n.LastActivityTime.After(lastActiveTime) {
				ret = append(ret, &n)
			}

		}

		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	return ret, nil
}

func (r *Redis) IncrNodeOnlineDuration(ctx context.Context, nodeid string, seconds int) error {
	if len(nodeid) == 0 {
		return fmt.Errorf("Redis.IncrNodeOnlineDuration: nodeID can not empty")
	}
	if seconds <= 0 {
		return fmt.Errorf("Redis.IncrNodeOnlineDuration: seconds can not less than or equal to zero")
	}
	totalOnlineKey := fmt.Sprintf(RedisKeyNodeOnlineDuration, nodeid)
	if err := r.client.IncrBy(ctx, totalOnlineKey, int64(seconds)).Err(); err != nil {
		return err
	}

	todayOnlineKey := fmt.Sprintf(RedisKeyNodeOnlineDurationByDate, nodeid, time.Now().Format("20060102"))
	return r.client.IncrBy(ctx, todayOnlineKey, int64(seconds)).Err()
}

func (r *Redis) GetNodeOnlineDuration(ctx context.Context, nodeid string) (int64, error) {
	if len(nodeid) == 0 {
		return 0, fmt.Errorf("Redis.GetNodeOnlineDuration: nodeID can not empty")
	}
	key := fmt.Sprintf(RedisKeyNodeOnlineDuration, nodeid)
	return r.client.Get(ctx, key).Int64()
}

func (r *Redis) GetNodeOnlineDurationStastics(ctx context.Context, nodeid string) ([]map[string]int64, error) {
	if nodeid == "" {
		return nil, fmt.Errorf("Redis.GetNodeOnlineDurationStastics: nodeID can not empty")
	}
	var (
		cursor uint64
		ret    []map[string]int64
	)

	nodeKeyPattern := fmt.Sprintf(RedisKeyNodeOnlineDurationByDate, nodeid, "*")

	for {
		keys, nextCursor, err := r.client.Scan(ctx, cursor, nodeKeyPattern, 100).Result()
		if err != nil {
			fmt.Println("Error scanning keys:", err)
			break
		}

		for _, key := range keys {
			res := r.client.Get(ctx, key)
			if res.Err() != nil {
				log.Printf("Error get key %s: %v", key, res.Err())
				continue
			}

			keyArr := strings.Split(key, ":")
			date := keyArr[len(keyArr)-1]

			var n int64
			if err := res.Scan(&n); err != nil {
				log.Printf("Error scan n: %v", err)
				continue
			}

			// todo fix online duration overflow
			if n >= 86400 {
				n = 86400
			}

			ret = append(ret, map[string]int64{
				date: n,
			})
		}

		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	return ret, nil
}

func (r *Redis) GetNodeOnlineDurationByDate(ctx context.Context, nodeid string, date string) (string, error) {
	nodeKeyPattern := fmt.Sprintf(RedisKeyNodeOnlineDurationByDate, nodeid, date)
	res, err := r.client.Get(ctx, nodeKeyPattern).Result()
	if err != nil && err != redis.Nil {
		return "0", err
	}
	if err == redis.Nil {
		return "0", nil
	}
	return res, nil

}

// func(r *Redis)