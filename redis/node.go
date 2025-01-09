package redis

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"
)

type Node struct {
	ID   string `redis:"id"`
	UUID string `redis:"uuid"`
	// AndroidID           string
	// AndroidSerialNumber string

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
	Channel string `redis:"channel"`
}

func (redis *Redis) SetNode(ctx context.Context, n *Node) error {
	if n == nil {
		return fmt.Errorf("Redis.SetNode: node can not empty")
	}

	if len(n.ID) == 0 {
		return fmt.Errorf("Redis.SetNode: node ID can not empty")
	}

	key := fmt.Sprintf(RedisKeyNode, n.ID)
	err := redis.client.HSet(ctx, key, n).Err()
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

func (r *Redis) GetNodeList(ctx context.Context, lastActiveTime time.Time) ([]*Node, error) {

	var (
		cursor uint64
		ret    []*Node
	)

	nodeKeyPattern := strings.Replace(RedisKeyNode, "%s", "*", -1)
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

func (r *Redis) IncrNodeOnlineDuration(ctx context.Context, nodeid string, minutes int) error {
	if len(nodeid) == 0 {
		return fmt.Errorf("Redis.IncrNodeOnlineDuration: nodeID can not empty")
	}
	if minutes <= 0 {
		return fmt.Errorf("Redis.IncrNodeOnlineDuration: minutes can not less than or equal to zero")
	}
	key := fmt.Sprintf(RedisKeyNodeOnlineDuration, nodeid)
	return r.client.IncrBy(ctx, key, int64(minutes)).Err()
}

func (r *Redis) GetNodeOnlineDuration(ctx context.Context, nodeid string) (int64, error) {
	if len(nodeid) == 0 {
		return 0, fmt.Errorf("Redis.GetNodeOnlineDuration: nodeID can not empty")
	}
	key := fmt.Sprintf(RedisKeyNodeOnlineDuration, nodeid)
	return r.client.Get(ctx, key).Int64()
}
