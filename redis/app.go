package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

// App descript the info of app, Does not belong to any node
type App struct {
	AppName string `redis:"appName"`
	// relative app dir
	AppDir     string `redis:"appDir"`
	ScriptName string `redis:"scriptName"`
	ScriptMD5  string `redis:"scriptMD5"`
	Version    string `redis:"version"`
	ScriptURL  string `redis:"scriptURL"`
}

// NodeApp Information that is unique to the node
// Metric includes the app's operational status, as well as unique information
type NodeApp struct {
	AppName          string       `redis:"appName"`
	MD5              string       `redis:"md5"`
	Metric           MetricString `redis:"metric"`
	LastActivityTime time.Time    `redis:"lastActivityTime"`
}

type MetricString string

func (m MetricString) GetClientID() string {
	var metric NodeAppBaseMetrics
	json.Unmarshal([]byte(m), &metric)
	return metric.ClientID
}

func (m *MetricString) UnmarshalJSON(data []byte) error {
	*m = MetricString(data)
	return nil
}

func (m MetricString) MarshalJSON() ([]byte, error) {
	return []byte(m), nil
}

func (m MetricString) MarshalBinary() ([]byte, error) {
	return []byte(m), nil
}

type NodeAppBaseMetrics struct {
	ClientID string `json:"client_id"` // third-party unique id
	Status   string `json:"status"`
	Err      string `json:"err"`
}

func (redis *Redis) SetApp(ctx context.Context, app *App) error {
	if app == nil {
		return fmt.Errorf("Redis.SetApp: app can not empty")
	}

	if len(app.AppName) == 0 {
		return fmt.Errorf("Redis.SetApp: app name can not empty")
	}

	key := fmt.Sprintf(RedisKeyApp, app.AppName)
	err := redis.client.HSet(ctx, key, app).Err()
	if err != nil {
		return err
	}

	return nil
}

func (redis *Redis) SetApps(ctx context.Context, apps []*App) error {
	pipe := redis.client.Pipeline()
	for _, app := range apps {
		key := fmt.Sprintf(RedisKeyApp, app.AppName)
		pipe.HSet(ctx, key, app).Err()
	}

	_, err := pipe.Exec(ctx)
	if err != nil {
		return err
	}

	return nil
}

func (redis *Redis) GetApp(ctx context.Context, appName string) (*App, error) {
	if len(appName) == 0 {
		return nil, fmt.Errorf("Redis.GetApp: nodeID can not empty")
	}

	key := fmt.Sprintf(RedisKeyApp, appName)
	res := redis.client.HGetAll(ctx, key)
	if res.Err() != nil {
		return nil, res.Err()
	}

	var app App
	if err := res.Scan(&app); err != nil {
		return nil, err
	}

	return &app, nil
}

func (redis *Redis) GetApps(ctx context.Context, appNames []string) ([]*App, error) {
	pipe := redis.client.Pipeline()

	var cmds []*goredis.MapStringStringCmd
	for _, appName := range appNames {
		key := fmt.Sprintf(RedisKeyApp, appName)
		cmd := pipe.HGetAll(ctx, key)
		cmds = append(cmds, cmd)
	}

	_, err := pipe.Exec(ctx)
	if err != nil {
		return nil, err
	}

	apps := make([]*App, 0, len(cmds))
	for _, cmd := range cmds {
		var app App
		if err := cmd.Scan(&app); err != nil {
			return nil, err
		}
		apps = append(apps, &app)
	}

	return apps, nil
}

func (redis *Redis) SetNodeApp(ctx context.Context, nodeID string, nApp *NodeApp) error {
	if len(nodeID) == 0 {
		return fmt.Errorf("Redis.SetNodeApp: node id can not empty")
	}
	if nApp == nil {
		return fmt.Errorf("Redis.SetNodeApp: node app can not empty")
	}

	if len(nApp.AppName) == 0 {
		return fmt.Errorf("Redis.SetNodeApp: node app name can not empty")
	}

	nApp.LastActivityTime = time.Now()

	key := fmt.Sprintf(RedisKeyNodeApp, nodeID, nApp.AppName)
	err := redis.client.HSet(ctx, key, nApp).Err()
	if err != nil {
		return err
	}

	return nil
}

func (redis *Redis) SetNodeApps(ctx context.Context, nodeID string, nodeApps []*NodeApp) error {
	if len(nodeID) == 0 {
		log.Printf("Redis.SetNodeApp: node id can not empty")
		return nil
	}

	pipe := redis.client.Pipeline()

	tn := time.Now()
	for _, app := range nodeApps {
		key := fmt.Sprintf(RedisKeyNodeApp, nodeID, app.AppName)
		app.LastActivityTime = tn
		pipe.HSet(ctx, key, app).Err()
	}

	_, err := pipe.Exec(ctx)
	if err != nil {
		return err
	}

	return nil
}

func (redis *Redis) GetNodeApp(ctx context.Context, nodeID, appName string) (*NodeApp, error) {
	if len(nodeID) == 0 {
		return nil, fmt.Errorf("Redis.GetNodeApp: nodeID can not empty")
	}

	if len(appName) == 0 {
		return nil, fmt.Errorf("Redis.GetNodeApp: node app name can not empty")
	}

	key := fmt.Sprintf(RedisKeyNodeApp, nodeID, appName)
	res := redis.client.HGetAll(ctx, key)
	if res.Err() != nil {
		return nil, res.Err()
	}

	var nApp NodeApp
	if err := res.Scan(&nApp); err != nil {
		return nil, err
	}

	return &nApp, nil
}

func (redis *Redis) GetNodeApps(ctx context.Context, nodeID string, appNames []string) ([]*NodeApp, error) {
	if len(nodeID) == 0 {
		return nil, fmt.Errorf("Redis.GetNodeApp: nodeID can not empty")
	}

	pipe := redis.client.Pipeline()

	var cmds []*goredis.MapStringStringCmd
	for _, appName := range appNames {
		key := fmt.Sprintf(RedisKeyNodeApp, nodeID, appName)
		cmd := pipe.HGetAll(ctx, key)
		cmds = append(cmds, cmd)
	}

	_, err := pipe.Exec(ctx)
	if err != nil {
		return nil, err
	}

	apps := make([]*NodeApp, 0, len(cmds))
	for _, cmd := range cmds {
		var app NodeApp
		if err := cmd.Scan(&app); err != nil {
			return nil, err
		}
		apps = append(apps, &app)
	}

	return apps, nil
}

func (redis *Redis) AddNodeAppsToList(ctx context.Context, nodeID string, appNames []string) error {
	if len(nodeID) == 0 {
		// return fmt.Errorf("Redis.AddNodeApps: node id can not empty")
		return nil
	}

	if len(appNames) == 0 {
		// return fmt.Errorf("Redis.AddNodeApps: node apps name can not empty")
		return nil
	}

	key := fmt.Sprintf(RedisKeyNodeAppList, nodeID)
	err := redis.client.SAdd(ctx, key, appNames).Err()
	if err != nil {
		return err
	}

	return nil
}

func (redis *Redis) DeleteNodeApps(ctx context.Context, nodeID string, appNames []string) error {
	if len(nodeID) == 0 {
		log.Println("Redis.DeleteNodeApp: node id can not empty")
		return nil
	}

	if len(appNames) == 0 {
		log.Println("Redis.DeleteNodeApp: node apps name can not empty")
		return nil
	}

	pipe := redis.client.Pipeline()

	key1 := fmt.Sprintf(RedisKeyNodeAppList, nodeID)
	pipe.SRem(ctx, key1, appNames).Err()

	for _, appName := range appNames {
		key2 := fmt.Sprintf(RedisKeyNodeApp, nodeID, appName)
		pipe.Del(context.Background(), key2)
	}

	_, err := pipe.Exec(ctx)
	if err != nil {
		return err
	}

	return nil
}

func (redis *Redis) GetNodeAppList(ctx context.Context, nodeID string) ([]string, error) {
	if len(nodeID) == 0 {
		return nil, fmt.Errorf("Redis.GetNodeAppList: nodeID can not empty")
	}

	key := fmt.Sprintf(RedisKeyNodeAppList, nodeID)
	appNames, err := redis.client.SMembers(ctx, key).Result()
	if err != nil {
		return nil, err
	}

	return appNames, nil
}

type NodeAppExtra struct {
	NodeApp
	NodeID string
}

func (r *Redis) GetAllAppInfos(ctx context.Context, lastActiveTime time.Time) ([]*NodeAppExtra, error) {

	var (
		cursor uint64
		ret    []*NodeAppExtra
	)

	nodeAppKeyPattern := strings.Replace(RedisKeyNodeApp, "%s:%s", "*", -1)
	for {
		keys, nextCursor, err := r.client.Scan(ctx, cursor, nodeAppKeyPattern, 100).Result()
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

			var n NodeAppExtra
			if err := res.Scan(&n.NodeApp); err != nil {
				// return nil, err
				log.Printf("Error scan node: %v", err)
				continue
			}

			//titan:agent:nodeApp:%s:%s
			n.NodeID = strings.Split(key, ":")[3]

			// fmt.Println(n)

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
