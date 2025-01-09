package redis

import (
	"context"
	"encoding/json"
	"fmt"
)

type NodeRegistInfo struct {
	NodeID string

	PublicKey   string
	CreatedTime int64
}

func (r *Redis) NodeRegist(ctx context.Context, node *NodeRegistInfo) error {
	data, err := json.Marshal(node)
	if err != nil {
		return err
	}
	return r.client.HSet(ctx, RedisKeyNodeRegist, node.NodeID, data).Err()
}

func (r *Redis) GetNodeRegistInfo(ctx context.Context, nodeID string) (*NodeRegistInfo, error) {
	if len(nodeID) == 0 {
		return nil, fmt.Errorf("Redis.GetNode: nodeID can not empty")
	}

	res := r.client.HGet(ctx, RedisKeyNodeRegist, nodeID)
	if res.Err() != nil {
		return nil, res.Err()
	}

	var n NodeRegistInfo
	jsonData, err := res.Result()
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal([]byte(jsonData), &n); err != nil {
		return nil, err
	}

	return &n, nil
}

func (r *Redis) UpdateNodePublickKey(ctx context.Context, nodeID string, publicKey string) error {
	regInfo, err := r.GetNodeRegistInfo(ctx, nodeID)
	if err != nil {
		return err
	}
	regInfo.PublicKey = publicKey
	return r.NodeRegist(ctx, regInfo)
}
