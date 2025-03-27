package redis

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

const (
	redisAddr = "127.0.0.1:6379"
)

func TestNode(t *testing.T) {
	t.Logf("TestNode")

	redis := NewRedis(redisAddr, "")

	node := Node{
		ID:       uuid.NewString(),
		OS:       "windows",
		Platform: "10.01",
	}
	err := redis.SetNode(context.Background(), &node)
	if err != nil {
		t.Fatal("set node err:", err.Error())
	}

	n, err := redis.GetNode(context.Background(), node.ID)
	if err != nil {
		t.Fatal("set node err:", err.Error())
	}

	t.Logf("node:%#v", *n)
}

func TestApp1(t *testing.T) {
	t.Logf("TestApp")

	redis := NewRedis(redisAddr, "")

	app := App{
		AppName: "titan-l2",
		// relative app dir
		AppDir:     "/opt/titan/apps/titan-l2",
		ScriptName: "titan-l2.lua",
		ScriptMD5:  "585f384ec97532e9822b7863ddeb958a",
		Version:    "0.0.1",
		ScriptURL:  "https://agent.titannet.io/titan-l2.lua",
	}
	err := redis.SetApp(context.Background(), &app)
	if err != nil {
		t.Fatal("set app err:", err.Error())
	}

	titanL2App, err := redis.GetApp(context.Background(), app.AppName)
	if err != nil {
		t.Fatal("get app err:", err.Error())
	}

	t.Logf("app: %#v", titanL2App)
}

func TestApps(t *testing.T) {
	t.Logf("TestApps")

	redis := NewRedis(redisAddr, "")

	app1 := App{
		AppName: "titan-l2",
		// relative app dir
		AppDir:     "/opt/titan/apps/titan-l2",
		ScriptName: "titan-l2.lua",
		ScriptMD5:  "585f384ec97532e9822b7863ddeb958a",
		Version:    "0.0.1",
		ScriptURL:  "https://agent.titannet.io/titan-l2.lua",
	}

	app2 := App{
		AppName: "titan-l1",
		// relative app dir
		AppDir:     "/opt/titan/apps/titan-l1",
		ScriptName: "titan-l1.lua",
		ScriptMD5:  "585f384ec97532e9822b7863ddeb958a",
		Version:    "0.0.1",
		ScriptURL:  "https://agent.titannet.io/titan-l1.lua",
	}
	err := redis.SetApps(context.Background(), []*App{&app1, &app2})
	if err != nil {
		t.Fatal("set app err:", err.Error())
	}

	apps, err := redis.GetApps(context.Background(), []string{app1.AppName, app2.AppName})
	if err != nil {
		t.Fatal("get app err:", err.Error())
	}

	t.Log("apps:")
	for _, app := range apps {
		t.Logf("%#v", app)
	}
}

func TestNodeApp(t *testing.T) {
	t.Logf("TestNodeApp")

	redis := NewRedis(redisAddr, "")

	app := NodeApp{
		AppName: "titan-l2",
		MD5:     "585f384ec97532e9822b7863ddeb958a",
		Metric:  "abc",
	}

	nodeID := uuid.NewString()

	err := redis.SetNodeApp(context.Background(), nodeID, &app)
	if err != nil {
		t.Fatal("set app err:", err.Error())
	}

	titanL2App, err := redis.GetNodeApp(context.Background(), nodeID, app.AppName)
	if err != nil {
		t.Fatal("get app err:", err.Error())
	}

	t.Logf("app: %#v", titanL2App)
}

func TestNodeApps(t *testing.T) {
	t.Logf("TestNodeApps")

	redis := NewRedis(redisAddr, "")

	app1 := NodeApp{
		AppName: "titan-l2",
		MD5:     "585f384ec97532e9822b7863ddeb958a",
		Metric:  "abc",
	}

	app2 := NodeApp{
		AppName: "titan-l1",
		MD5:     "585f384ec97532e9822b7863ddeb958a",
		Metric:  "abc",
	}

	nodeID := uuid.NewString()

	err := redis.SetNodeApps(context.Background(), nodeID, []*NodeApp{&app1, &app2})
	if err != nil {
		t.Fatal("set app err:", err.Error())
	}

	nodeApps, err := redis.GetNodeApps(context.Background(), nodeID, []string{app1.AppName, app2.AppName})
	if err != nil {
		t.Fatal("get app err:", err.Error())
	}

	t.Log("node apps:")
	for _, nodeApp := range nodeApps {
		t.Logf("%#v", nodeApp)
	}
}

func TestNodeAppList(t *testing.T) {
	t.Logf("TestNodeApps")

	redis := NewRedis(redisAddr, "")

	nodeID := uuid.NewString()

	err := redis.AddNodeAppsToList(context.Background(), nodeID, []string{"titan-l1", "titan-l2"})
	if err != nil {
		t.Fatal("set app err:", err.Error())
	}

	appList, err := redis.GetNodeAppList(context.Background(), nodeID)
	if err != nil {
		t.Fatal("get app err:", err.Error())
	}

	t.Logf("appList:%#v", appList)
}

func TestDeleteNodeAppList(t *testing.T) {
	t.Logf("TestNodeApps")

	redis := NewRedis(redisAddr, "")

	nodeID := "52b67296-940c-434e-85f3-16df4aa9c6ed"

	err := redis.DeleteNodeApps(context.Background(), nodeID, []string{"titan-l1", "titan-l2"})
	if err != nil {
		t.Fatal("delete app list err:", err.Error())
	}

}