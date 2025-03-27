package server

import (
	"agent/common"
	titanrsa "agent/common/rsa"
	"agent/redis"
	"agent/redis/metrics"
	"errors"
	"math"
	"strconv"
	"sync"

	"bufio"
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"crypto/rsa"

	"github.com/gbrlsnchs/jwt/v3"

	log "github.com/sirupsen/logrus"
)

type ServerHandler struct {
	config *Config
	devMgr *DevMgr
	redis  *redis.Redis
	auth   *auth
	// authenticate func
}

// type tokenPayload struct {
// }

type auth struct {
	apiSecret *jwt.HMACSHA
}

func (a *auth) proxy(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		token = strings.TrimPrefix(token, "Bearer ")

		if token == "" {
			token = r.URL.Query().Get("token")
		}
    
		if token == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		var payload common.JwtPayload
		if _, err := jwt.Verify([]byte(token), a.apiSecret, &payload); err != nil {
			log.Errorf("jwt.Verify: %v", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		r = r.WithContext(context.WithValue(r.Context(), "payload", payload))

		// curlCmd, err := RequestToCurl(r)
		// if err == nil {
		// 	log.Infof("RequestToCurl: %s", curlCmd)
		// }

		next(w, r)
	}
}

func RequestToCurl(req *http.Request) (string, error) {
	var curlCmd strings.Builder

	curlCmd.WriteString("curl -X ")
	curlCmd.WriteString(req.Method)

	for key, values := range req.Header {
		for _, value := range values {
			curlCmd.WriteString(fmt.Sprintf(" -H '%s: %s'", key, value))
		}
	}

	if req.Body != nil {
		bodyBytes, err := io.ReadAll(req.Body)
		if err != nil {
			return "", fmt.Errorf("failed to read request body: %w", err)
		}

		req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

		if len(bodyBytes) > 0 {
			curlCmd.WriteString(fmt.Sprintf(" -d '%s'", string(bodyBytes)))
		}
	}

	curlCmd.WriteString(fmt.Sprintf(" '%s'", req.URL.String()))

	return curlCmd.String(), nil
}

func parseTokenFromRequestContext(ctx context.Context) (*common.JwtPayload, error) {
	payload, ok := ctx.Value("payload").(common.JwtPayload)
	if !ok {
		return nil, fmt.Errorf("no payload in context")
	}
	return &payload, nil
}

func (a *auth) sign(p common.JwtPayload) ([]byte, error) {
	return jwt.Sign(p, a.apiSecret)
}

func newServerHandler(config *Config, devMgr *DevMgr, redis *redis.Redis, authApiSecret *jwt.HMACSHA) *ServerHandler {
	return &ServerHandler{config: config, devMgr: devMgr, redis: redis, auth: &auth{apiSecret: authApiSecret}}
}

func (h *ServerHandler) handleGetLuaConfig(w http.ResponseWriter, r *http.Request) {
	h.handleLuaUpdate(w, r)
}

func (h *ServerHandler) handleLuaUpdate(w http.ResponseWriter, r *http.Request) {
	log.Infof("handleLuaUpdate, queryString %s\n", r.URL.RawQuery)

	d := NewDeviceFromURLQuery(r.URL.Query())
	if d != nil {
		recordRawIP(d.UUID, r)
		ip := getClientIP(r)
		if ip != "" {
			d.IP = ip
		}

		h.devMgr.updateAgent(&Agent{*d})
	}

	os := r.URL.Query().Get("os")
	uuid := r.URL.Query().Get("uuid")

	var testScripName string
	testNode := h.config.TestNodes[uuid]
	if testNode != nil {
		testScripName = testNode.LuaScript
	}

	// log.Printf("testNode %#v", testNode)
	var file *FileConfig = nil
	for _, f := range h.config.LuaFileList {
		if len(testScripName) > 0 {
			if f.Name == testScripName {
				file = f
				break
			}
		} else if f.OS == os {
			file = f
			break
		}
	}

	if file == nil {
		resultError(w, http.StatusBadRequest, fmt.Sprintf("can not find the os %s script", os))
		return
	}

	buf, err := json.Marshal(file)
	if err != nil {
		resultError(w, http.StatusBadRequest, err.Error())
		return
	}

	w.Write(buf)
}

func (h *ServerHandler) handleGetControllerConfig(w http.ResponseWriter, r *http.Request) {
	log.Infof("handleGetControllerConfig, queryString %s\n", r.URL.RawQuery)
	// version := r.URL.Query().Get("version")
	os := r.URL.Query().Get("os")
	uuid := r.URL.Query().Get("uuid")
	arch := r.URL.Query().Get("arch")
	isBox, _ := strconv.ParseBool(r.URL.Query().Get("isBox"))

	var testControllerName string
	testNode := h.config.TestNodes[uuid]
	if testNode != nil {
		testControllerName = testNode.Controller
	}

	var file *FileConfig = nil
	var bestMatchFile *FileConfig = nil

	for _, f := range h.config.ControllerFileList {
		if len(testControllerName) > 0 {
			if f.Name == testControllerName {
				file = f
				break
			}
		}
		if f.OS == os {
			// common version
			if f.Tag == "" && file == nil {
				file = f
				// arch match version
			} else if f.Tag != "" && arch != "" && strings.Contains(f.Tag, arch) {
				bestMatchFile = f
				break
			} else if isBox && f.Tag == "box" {
				bestMatchFile = f
				break
			}
		}
	}

	var finalFile *FileConfig = file
	if bestMatchFile != nil {
		finalFile = bestMatchFile
	}

	if finalFile == nil {
		resultError(w, http.StatusBadRequest, fmt.Sprintf("can not find the os %s", os))
		return
	}

	buf, err := json.Marshal(finalFile)
	if err != nil {
		resultError(w, http.StatusBadRequest, err.Error())
		return
	}

	w.Write(buf)
}

var TestWssshApp = AppConfig{
	AppName:    "wsssh-unix",
	AppDir:     "wsssh",
	ScriptName: "wsssh-unix.lua",
	ScriptURL:  "https://pcdn.titannet.io/test4/script/wsssh-unix.lua",
	ScriptMD5:  "16f9a27fd021ee6c5972168b4f1059f8",
}

var TestNodeList = []string{
	"73b09cbf-fda9-4a59-93e8-db76ad273d6c",
}

func mergeTestApps(nodeid string, apps *[]*AppConfig) {
	for _, v := range TestNodeList {
		if v == nodeid {
			*apps = append(*apps, &TestWssshApp)
			break
		}
	}
}

func replaceIfTestApp(nodeid string, apps *[]*AppConfig) {
	for _, v := range TestNodeList {
		if v == nodeid {
			apps = &[]*AppConfig{&TestWssshApp}
			break
		}
	}
}
func (h *ServerHandler) handleGetAppsConfig(w http.ResponseWriter, r *http.Request) {
	log.Infof("handleGetAppsConfig, queryString %s\n", r.URL.RawQuery)
	payload, err := parseTokenFromRequestContext(r.Context())
	if err != nil {
		log.Infof("ServerHandler.handleGetAppsConfig parseTokenFromRequestContext: %v", err)
		resultError(w, http.StatusUnauthorized, err.Error())
		return
	}

	d := NewDeviceFromURLQuery(r.URL.Query())


	uuid := r.URL.Query().Get("uuid")
	channel := r.URL.Query().Get("channel")

	var testApps []string
	testNode := h.config.TestNodes[uuid]
	if testNode != nil {
		testApps = testNode.Apps
	}

	appList := make([]*AppConfig, 0, len(h.config.AppList))
	for _, app := range h.config.AppList {
		var locationMatch, resourceMatch bool

		// test case
		if len(testApps) > 0 {
			if h.isTestApp(app.AppName, testApps) {
				appList = append(appList, app)
			}
			continue
		} else if len(channel) > 0 {
			// specify channel case
			// todo channel的arch适配
			locationMatch = h.isMatchLocationApp(r, app.ReqLocations)
			resourceMatch = h.isAppMatchChannel(app.AppName, channel)
			if locationMatch && resourceMatch {
				appList = append(appList, app)
			}

			continue
		} else {
			// common case
			locationMatch = h.isMatchLocationApp(r, app.ReqLocations)
			resourceMatch = h.isResourceMatchApp(r, app.ReqResources)
			if locationMatch && resourceMatch {
				appList = append(appList, app)
			}
			continue
		}
	}

	// |--------|---------|--------|
	// |        | 资源满足 |资源不满足|
	// |--------|---------|--------|
	// | 区域满足|  ✅     | 无任务  |
	// |--------|---------|--------|
	// |区域不满足|区域未开放|区域未开放|
	// |--------|---------|--------|
	var initState int = 0
	for _, app := range h.config.AppList {
		var locationMatch, resourceMatch bool

		// test case
		if len(testApps) > 0 {
			if h.isTestApp(app.AppName, testApps) {
				initState = redis.BizStateIniting
				break
			}
		} else if len(channel) > 0 {
			// specify channel case
			// todo channel的arch适配
			locationMatch = h.isMatchLocationApp(r, app.ReqLocations)
			resourceMatch = h.isAppMatchChannel(app.AppName, channel)
			initState = redis.GetStateBeforeInit(locationMatch, resourceMatch)
			if locationMatch && resourceMatch {
				break
			}
		} else {
			// common case
			locationMatch = h.isMatchLocationApp(r, app.ReqLocations)
			resourceMatch = h.isResourceMatchApp(r, app.ReqResources)
			initState = redis.GetStateBeforeInit(locationMatch, resourceMatch)
			if locationMatch && resourceMatch {
				break
			}
		}
	}

	// mergeTestApps(payload.NodeID, &appList)
	replaceIfTestApp(payload.NodeID, &appList)

	appListStr, _ := json.Marshal(appList)
	log.Infof("GetAppList node: %s, os: %s, channel: %s, apps: %s", payload.NodeID, r.URL.Query().Get("os"), channel, appListStr)

	node, _ := h.redis.GetNode(context.Background(), payload.NodeID)
	var serviceState int

	// 已经跑起来 到了审核阶段 并且获取到的是初始化阶段 就不应该发生变化
	if !(node != nil && (node.ServiceState == redis.BizStatusCodeWaitAudit || node.ServiceState == redis.BizStatusCodeResourceWaitAudit) && initState == redis.BizStateIniting) {
		serviceState = initState
	} else {
		serviceState = node.ServiceState
	}

	w.Header().Set("ServiceState", strconv.Itoa(serviceState))
	w.Header().Set("InitState", strconv.Itoa(initState))

	recordRawIP(payload.NodeID, r)
	ip := getClientIP(r)
	if ip != "" {
		node.IP = ip
		d.IP = ip
	}

	// h.redis.SetNode()
	// h.devMgr.device
	h.devMgr.updateNodeFromDevice(r.Context(), payload.NodeID, d, serviceState)
	// h.devMgr.updateController(&Controller{Device: *d, NodeID: payload.NodeID}, serviceState)

	var appNames []string
	for _, app := range appList {
		appNames = append(appNames, app.AppName)
	}

	if err := h.redis.AddNodeAppsToList(context.Background(), payload.NodeID, appNames); err != nil {
		log.Errorf("ServerHandler.handleGetAppsConfig AddNodeAppsToList: %v", err)
		resultError(w, http.StatusBadRequest, err.Error())
		return
	}

	buf, err := json.Marshal(appList)
	if err != nil {
		resultError(w, http.StatusBadRequest, err.Error())
		return
	}
	w.Write(buf)
}

func (h *ServerHandler) isResourceMatchApp(r *http.Request, reqResources []string) bool {
	os, cpu, memoryMB, diskGB, arch := getResource(r)
	for _, reqResourceName := range reqResources {
		reqRes := h.config.Resources[reqResourceName]
		if reqRes == nil {
			continue
		}

		// arch未定义是通用, 或者包含
		if reqRes.Arch != "" && !strings.Contains(reqRes.Arch, arch) {
			continue
		}

		if reqRes.OS == os && cpu >= reqRes.MinCPU && memoryMB >= reqRes.MinMemoryMB && diskGB >= reqRes.MinDiskGB {
			return true
		}
	}
	return false
}

func (h *ServerHandler) isIPMatchLocationApp(ip string, reqLocations []string) bool {
	if reqLocations == nil {
		return true
	}

	country, err := getLocationCountry(ip)
	if err != nil {
		log.Errorf("isMatchLocationApp: %v", err)
		return false
	}

	for _, reqLoc := range reqLocations {
		if reqLoc == country {
			return true
		}
	}

	return false
}

func (h *ServerHandler) isMatchLocationApp(r *http.Request, reqLocations []string) bool {
	if reqLocations == nil {
		return true
	}

	payload, _ := parseTokenFromRequestContext(r.Context())
	recordRawIP(payload.NodeID, r)

	clientIP := getClientIP(r)
	if clientIP == "" {
		return false
	}
	country, err := getLocationCountry(clientIP)
	if err != nil {
		log.Errorf("isMatchLocationApp: %v", err)
		return false
	}

	for _, reqLoc := range reqLocations {
		if reqLoc == country {
			return true
		}
	}

	return false
}

var ipMapRaw = sync.Map{}

func recordRawIP(nodeid string, r *http.Request) {
	if nodeid == "" {
		return
	}
	var ipRecords = make(map[string][]string)
	ipRecords["X-Original-Forwarded-For"] = append(ipRecords["X-Original-Forwarded-For"], r.Header.Get("X-Original-Forwarded-For"))
	ipRecords["X-Real-IP"] = append(ipRecords["X-Real-IP"], r.Header.Get("X-Real-IP"))
	ipRecords["RemoteAddr"] = append(ipRecords["RemoteAddr"], r.RemoteAddr)
	ipRecords["X-Forwarded-For"] = append(ipRecords["X-Forwarded-For"], r.Header.Get("X-Forwarded-For"))
	ipRecords["X-Remote-Addr"] = append(ipRecords["X-Remote-Addr"], r.Header.Get("X-Remote-Addr"))
	ipMapRaw.Store(nodeid, ipRecords)
}

func (h *ServerHandler) handleLoadNodeIP(w http.ResponseWriter, r *http.Request) {
	c, _ := ipMapRaw.Load(r.URL.Query().Get("node_id"))
	json.NewEncoder(w).Encode(c)
	// json.NewEncoder(w).Encode()
}

func getClientIP(r *http.Request) string {

	ip := getValidIPFromHeader(r.Header.Get("X-Original-Forwarded-For"))
	if ip != "" {
		return ip
	}

	ip = getValidIPFromHeader(r.Header.Get("X-Forwarded-For"))
	if ip != "" {
		return ip
	}

	ip = getValidIPFromHeader(r.Header.Get("X-Remote-Addr"))
	if ip != "" {
		return ip
	}

	ip = r.Header.Get("X-Real-IP")
	if ip != "" && !isPrivateIP(ip) {
		return ip
	}

	ip, _, _ = net.SplitHostPort(r.RemoteAddr)

	if ip != "" && !isPrivateIP(ip) {
		return ip
	}

	return ""
}

func getValidIPFromHeader(header string) string {
	for _, ip := range strings.Split(header, ",") {
		ip = strings.TrimSpace(ip)
		if ip != "" && !isPrivateIP(ip) {
			return ip
		}
	}
	return ""
}

func isPrivateIP(ipstr string) bool {
	ip := net.ParseIP(ipstr)
	if ip == nil {
		return false
	}

	if ip.To4() != nil {
		ip = ip.To4()

		switch {
		case ip[0] == 10:
			// 10.0.0.0 To 10.255.255.255
			return true
		case ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31:
			// 172.16.0.0 To 172.31.255.255
			return true
		case ip[0] == 192 && ip[1] == 168:
			// 192.168.0.0 To 192.168.255.255
			return true
		}
	}

	return false
}

func getLocationCountry(ip string) (string, error) {
	resp, err := http.Get(fmt.Sprintf("https://api-test1.container1.titannet.io/api/v2/location?ip=%s", ip))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	location := struct {
		Data struct {
			Country string `json:"country"`
		} `json:"data"`
	}{}

	err = json.Unmarshal(bodyBytes, &location)
	if err != nil {
		return "", err
	}

	return location.Data.Country, nil
}

func (h *ServerHandler) isTestApp(appName string, testAppNames []string) bool {
	if len(testAppNames) == 0 {
		return false
	}

	for _, testAppName := range testAppNames {
		if appName == testAppName {
			return true
		}
	}

	return false
}

func (h *ServerHandler) isAppMatchChannel(appName string, channel string) bool {
	apps := h.config.ChannelApps[channel]
	if len(apps) == 0 {
		return false
	}

	// log.Info("isAppMatchChannel apps", apps, "current app", appName)
	for _, app := range apps {
		if appName == app {
			return true
		}
	}

	return false
}

func (h *ServerHandler) handleAgentList(w http.ResponseWriter, r *http.Request) {
	log.Infof("handleAgentList, queryString %s\n", r.URL.RawQuery)

	agents := h.devMgr.getAgents()

	result := struct {
		Total  int      `json:"total"`
		Agents []*Agent `json:"agents"`
	}{
		Total:  len(agents),
		Agents: agents,
	}

	formattedJSON, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		http.Error(w, "Failed to format JSON", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(formattedJSON)
}

func (h *ServerHandler) handleControllerList(w http.ResponseWriter, r *http.Request) {
	log.Infof("handleControllerList, queryString %s\n", r.URL.RawQuery)

	controllers := h.devMgr.getControllers()

	result := struct {
		Total       int           `json:"total"`
		Controllers []*Controller `json:"controllers"`
	}{
		Total:       len(controllers),
		Controllers: controllers,
	}

	formattedJSON, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		http.Error(w, "Failed to format JSON", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(formattedJSON)
}

func (h *ServerHandler) handleGetAppList(w http.ResponseWriter, r *http.Request) {
	uuid := r.URL.Query().Get("id")

	apps, err := h.redis.GetNodeAppList(context.Background(), uuid)
	if err != nil {
		apiResultErr(w, err.Error())
		return
	}

	result := APIResult{Data: apps}
	buf, err := json.Marshal(result)
	if err != nil {
		log.Error("ServerHandler.handleGetAppList, Marshal: ", err.Error())
		return
	}

	if _, err := w.Write(buf); err != nil {
		log.Error("ServerHandler.handleGetAppList, Write: ", err.Error())
	}

}

func (h *ServerHandler) handleGetAppInfo(w http.ResponseWriter, r *http.Request) {
	uuid := r.URL.Query().Get("id")
	appName := r.URL.Query().Get("app")

	// TODO: convert id to uuid format
	// TODO：check app if exist

	app, err := h.redis.GetNodeApp(context.Background(), uuid, appName)
	if err != nil {
		apiResultErr(w, err.Error())
		return
	}

	res := struct {
		AppName string `json:"appName"`
		NodeID  string `json:"nodeID"`
	}{}

	// app.Metric.UnmarshalJSON()

	// err = json.Unmarshal([]byte(app.Metric), &res)
	// if err != nil {
	// 	apiResultErr(w, err.Error())
	// 	return
	// }


	if app.AppName == "titan-l2" && len(res.NodeID) == 0 {
		apiResultErr(w, "titan-l2 not exist")
		return
	}

	res.AppName = app.AppName

	result := APIResult{Data: res}
	buf, err := json.Marshal(result)
	if err != nil {
		log.Error("ServerHandler.handleGetAppList, Marshal: ", err.Error())
		return
	}

	if _, err := w.Write(buf); err != nil {
		log.Error("ServerHandler.handleGetAppList, Write: ", err.Error())
	}
}

type NodeWebInfo struct {
	*redis.Node
	State          int   // 0 exception, 1 online, 2 offline
	OnlineDuration int64 // online minutes
	OnlineRate     float64
	CGroup         int // 0 unchecked, 1 enable, 2 disable
	CGroupOut      string
}

const (
	NodeStateException = 0
	NodeStateOnline    = 1
	NodeStateOffline   = 2
)

func (h *ServerHandler) handleGetNodeList(w http.ResponseWriter, r *http.Request) {
	lastActivityTime := r.URL.Query().Get("last_activity_time")
	lastActivityTimeInt, _ := strconv.Atoi(lastActivityTime)

	// latTime, err := time.Parse(time.RFC3339, lastActivityTime)
	// if err != nil {
	// 	apiResultErr(w, "invalid last_activity_time timeformat")
	// 	return
	// }

	// latTime := time.Unix(int64(lastActivityTimeInt), 0)

	nodesArr, err := h.redis.GetNodesAfter(r.Context(), int64(lastActivityTimeInt))
	if err != nil {
		apiResultErr(w, fmt.Sprintf("find node list failed: %s", err.Error()))
		return
	}

	// nodes, err := h.redis.GetNodeList(context.Background(), latTime, nodeid)
	// if err != nil {
	// 	apiResultErr(w, fmt.Sprintf("find node list failed: %s", err.Error()))
	// 	return
	// }

	// var ret = make([]*NodeWebInfo, len(nodesA))
	var ret []*NodeWebInfo
	for _, nodeid := range nodesArr {
		node, err := h.redis.GetNode(r.Context(), nodeid)
		if err != nil {
			log.Errorf("ServerHandler.handleGetNodeList, GetNode: %s", err.Error())
			continue
		}
		var n = &NodeWebInfo{Node: node}

		if time.Since(node.LastActivityTime) > offlineTime {
			n.State = NodeStateOffline
		} else {
			n.State = NodeStateOnline
		}
		n.OnlineDuration, _ = h.redis.GetNodeOnlineDuration(r.Context(), node.ID)
		rinfo, _ := h.redis.GetNodeRegistInfo(r.Context(), node.ID)
		if rinfo != nil {
			n.OnlineRate = float64(n.OnlineDuration) / float64(time.Since(time.Unix(rinfo.CreatedTime, 0)).Seconds())
		}

		calUsage(node)

		// handle vps channel
		if node.Channel == "vps" {
			n.CGroup, n.CGroupOut = h.redis.CheckVPSCGroupInfo(r.Context(), node.ID, h.config.ChannelApps["vps"][0])
		}

		ret = append(ret, n)
	}

	result := APIResult{Data: ret}
	buf, err := json.Marshal(result)
	if err != nil {
		log.Error("ServerHandler.handleGetNodeList, Marshal: ", err.Error())
		return
	}

	if _, err := w.Write(buf); err != nil {
		log.Error("ServerHandler.handleGetNodeList, Write: ", err.Error())
	}
}

type NodeAppWebInfo struct {
	// *redis.NodeApp

	LastActivityTime time.Time
	NodeID           string
	AppName          string
	Channel          string
	Tag              string
	ClientID         string
	Status           int
	Err              string
}

func (h *ServerHandler) handleGetAllNodesAppInfosList(w http.ResponseWriter, r *http.Request) {

	lastActivityTime := r.URL.Query().Get("last_activity_time")
	nodeid := r.URL.Query().Get("node_id")
	tag := r.URL.Query().Get("tag")
	clientid := r.URL.Query().Get("client_id")
	appname := r.URL.Query().Get("app_name")

	lastActivityTimeInt, _ := strconv.Atoi(lastActivityTime)

	latTime := time.Unix(int64(lastActivityTimeInt), 0)

	nodeApps, err := h.redis.GetAllAppInfos(r.Context(), latTime, redis.AppInfoFileter{
		NodeID: nodeid, Tag: tag, ClientID: clientid, AppName: appname,
	})
	if err != nil {
		apiResultErr(w, fmt.Sprintf("find apps list failed: %s", err.Error()))
		return
	}

	channelRefMap := make(map[string]string)
	for channel, appNames := range h.config.ChannelApps {
		for _, appName := range appNames {
			channelRefMap[appName] = channel
		}
	}

	tagRefMap := make(map[string]string)
	for _, app := range h.config.AppList {
		tagRefMap[app.AppName] = app.Tag
	}

	var ret []*NodeAppWebInfo = make([]*NodeAppWebInfo, len(nodeApps))

	for i, nodeApp := range nodeApps {
		ret[i] = &NodeAppWebInfo{
			AppName:          nodeApp.AppName,
			LastActivityTime: nodeApp.LastActivityTime,
			NodeID:           nodeApp.NodeID,
			Channel:          channelRefMap[nodeApp.AppName],
			ClientID:         metrics.GetClientID(nodeApp.Metric, tagRefMap[nodeApp.AppName]),
			Tag:              tagRefMap[nodeApp.AppName],
		}
	}

	result := APIResult{Data: ret}
	buf, err := json.Marshal(result)
	if err != nil {
		log.Error("ServerHandler.handleGetAllNodesAppInfosList, Marshal: ", err.Error())
		return
	}

	if _, err := w.Write(buf); err != nil {
		log.Error("ServerHandler.handleGetAllNodesAppInfosList, Write: ", err.Error())
	}
}

type signVerifyRequest struct {
	NodeId  string `json:"nodeId"`
	Sign    string `json:"sign"`
	Content string `json:"content"`
}

func (h *ServerHandler) handleSignVerify(w http.ResponseWriter, r *http.Request) {
	var req signVerifyRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		apiResultErr(w, err.Error())
		return
	}

	if req.NodeId == "" || req.Sign == "" || req.Content == "" {
		apiResultErr(w, "params can not be empty")
		return
	}

	node, err := h.redis.GetNodeRegistInfo(context.Background(), req.NodeId)
	if err != nil {
		apiResultErr(w, fmt.Sprintf("node %s not exist", req.NodeId))
		return
	}

	pubKey, err := titanrsa.Pem2PublicKey([]byte(node.PublicKey))
	if err != nil {
		apiResultErr(w, fmt.Sprintf("load public key failed: %s", err.Error()))
		return
	}

	hash := crypto.SHA256.New()
	_, err = hash.Write([]byte(req.Content))
	if err != nil {
		apiResultErr(w, fmt.Sprintf("hash write failed: %s", err.Error()))
		return
	}
	sum := hash.Sum(nil)

	sign, err := hex.DecodeString(req.Sign)

	if err != nil {
		apiResultErr(w, fmt.Sprintf("hex decode sign failed: %s", err.Error()))
		return
	}

	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, sum, sign); err != nil {
		apiResultErr(w, fmt.Sprintf("verify sign failed: %s", err.Error()))
		return
	}

	if err := json.NewEncoder(w).Encode(APIResult{Data: "success"}); err != nil {
		log.Error("ServerHandler.handleSignVerify, Encode: ", err.Error())
	}
}

func (h *ServerHandler) handleGetNodeInfo(w http.ResponseWriter, r *http.Request) {
	nodeid := r.URL.Query().Get("node_id")
	sn := r.URL.Query().Get("sn")
	if nodeid == "" && sn == "" {
		http.Error(w, "node_id or sn parameter required", http.StatusBadRequest)
		return
	}

	var (
		nodeInfo *redis.Node
		appInfo  []*redis.NodeAppExtra
		err      error
	)
	if nodeid != "" {
		nodeInfo, appInfo, err = h.getNodeInfoByNodeID(r.Context(), nodeid)
	}

	if sn != "" {
		nodeInfo, appInfo, err = h.getNodeInfoByAppSN(r.Context(), sn)
	}

	if err != nil {
		rsp := APIResult{ErrMsg: err.Error(), Data: nil}
		json.NewEncoder(w).Encode(rsp)
		return
	}

	type NodeInfoRet struct {
		NodeInfo        NodeWebInfo           `json:"node"`
		AppInfo         []*redis.NodeAppExtra `json:"apps"`
		OnlineStatstics []map[string]int64    `json:"onlineStatistics"`
	}

	nodeinfo := NodeWebInfo{
		Node: nodeInfo,
	}
	if time.Since(nodeinfo.LastActivityTime) > offlineTime {
		nodeinfo.State = NodeStateOffline
	} else {
		nodeinfo.State = NodeStateOnline
	}
	nodeinfo.OnlineDuration, _ = h.redis.GetNodeOnlineDuration(r.Context(), nodeinfo.ID)

	calUsage(nodeinfo.Node)

	rinfo, _ := h.redis.GetNodeRegistInfo(r.Context(), nodeinfo.ID)
	if rinfo != nil {
		nodeinfo.OnlineRate = float64(nodeinfo.OnlineDuration) / float64(time.Since(time.Unix(rinfo.CreatedTime, 0)).Seconds())
	}
	onlineStatistics, err := h.redis.GetNodeOnlineDurationStastics(r.Context(), nodeinfo.ID)
	if err != nil {
		log.Errorf("GetNodeInfoByNodeID.GetNodeOnlineDurationStastics: %v", err)
	}

	ret := APIResult{Data: NodeInfoRet{NodeInfo: nodeinfo, AppInfo: appInfo, OnlineStatstics: onlineStatistics}}
	json.NewEncoder(w).Encode(ret)
}

func (h *ServerHandler) getNodeInfoByNodeID(ctx context.Context, nodeid string) (*redis.Node, []*redis.NodeAppExtra, error) {
	nodeInfo, err := h.redis.GetNode(ctx, nodeid)
	if err != nil {
		log.Errorf("GetNodeInfoByNodeID.GetNode: %v", err)
	}

	// appInfo, err := h.redis.GetAllAppInfos(ctx, time.Unix(0, 0), redis.AppInfoFileter{NodeID: nodeid})
	// if err != nil {
	// 	log.Errorf("GetNodeInfoByNodeID.GetAllAppInfos: %v", err)
	// }

	appInfo, err := h.redis.GetAppinfosByNodeID(ctx, nodeid)
	if err != nil {
		log.Errorf("GetNodeInfoByNodeID.GetAllAppInfos: %v", err)
	}

	return nodeInfo, appInfo, nil
}

func (h *ServerHandler) getNodeInfoByAppSN(ctx context.Context, sn string) (*redis.Node, []*redis.NodeAppExtra, error) {

	nodeid, err := h.redis.GetNodeIDBySN(ctx, sn)
	if err != nil {
		log.Errorf("GetNodeIDBySN(%s) error(%v)", sn, err)
		return nil, nil, err
	}

	if nodeid == "" {
		return nil, nil, errors.New("nodeid is empty")
	}

	return h.getNodeInfoByNodeID(ctx, nodeid)

}

func (h *ServerHandler) handlePushAppInfo(w http.ResponseWriter, r *http.Request) {

	// payload, err := parseTokenFromRequestContext(r.Context())
	// if err != nil {
	// 	resultError(w, http.StatusUnauthorized, err.Error())
	// 	return
	// }

	var (
		uuid      = r.URL.Query().Get("uuid")
		appName   = r.URL.Query().Get("appName")
		client_id = r.URL.Query().Get("client_id")
	)

	if client_id == "" {
		resultError(w, http.StatusBadRequest, "business_id or client_id cannot be empty")
		return
	}

	_, err := h.redis.GetApp(r.Context(), appName)
	if err != nil {
		resultError(w, http.StatusBadRequest, fmt.Sprintf("failed to find app %s, cause: %s", appName, err.Error()))
		return
	}

	// h.redis.GetNodeApps(r.Context(), payload.NodeID)

	b, err := io.ReadAll(r.Body)
	if err != nil {
		log.Error("CustomHandler.handleAppInfo read body failed: ", err.Error())
		resultError(w, http.StatusBadRequest, err.Error())
		return
	}

	if len(b) == 0 {
		log.Error("CustomHandler.handleAppInfo read body is empty")
		resultError(w, http.StatusBadRequest, "body is empty")
		return
	}

	scanner := bufio.NewScanner(bytes.NewReader(b))

	// Scan and print each line
	for scanner.Scan() {
		line := scanner.Text()
		fmt.Println(line)
	}
	log.Infof("uuid:%s, appName:%s\n", uuid, appName)

	// Check for any errors
	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading bytes:", err)
	}

	// TODO: add exterInfo to app

}

func (h *ServerHandler) handlePushMetrics(w http.ResponseWriter, r *http.Request) {
	payload, _ := parseTokenFromRequestContext(r.Context())
	// uuid := r.URL.Query().Get("uuid")

	b, err := io.ReadAll(r.Body)
	if err != nil {
		log.Error("ServerHandler.handlePushMetrics read body failed: ", err.Error())
		resultError(w, http.StatusBadRequest, err.Error())
		return
	}

	if len(b) == 0 {
		log.Error("ServerHandler.handlePushMetrics read body is empty")
		resultError(w, http.StatusBadRequest, "body is empty")
		return
	}

	apps := make([]*App, 0)
	err = json.Unmarshal(b, &apps)
	if err != nil {
		log.Error("ServerHandler.handlePushMetrics Unmarshal failed:", err.Error())
		resultError(w, http.StatusBadRequest, err.Error())
		return
	}
	log.Infof("[PushMetrics] NodeID:%s, apps: %v, body: %s", payload.NodeID, apps, string(b))

	if err := h.updateNodeApps(payload.NodeID, apps); err != nil {
		log.Error("ServerHandler.handlePushMetrics update nodes app failed:", err.Error())
	}

	node, err := h.redis.GetNode(r.Context(), payload.NodeID)
	if err != nil {
		log.Error("ServerHandler.handlePushMetrics get node failed:", err.Error())
		resultError(w, http.StatusBadRequest, err.Error())
		return
	}

	// c := h.devMgr.getController(payload.NodeID)
	// if c == nil {
	// 	log.Errorf("ServerHandler.handlePushMetrics controller %s not exist", payload.NodeID)
	// 	resultError(w, http.StatusBadRequest, fmt.Sprintf("controller %s not exist", payload.NodeID))
	// 	return
	// }

	recordRawIP(payload.NodeID, r)
	ip := getClientIP(r)
	if ip != "" {
		node.IP = ip
	}

	for _, app := range apps {
		if app.Metric == "" {
			continue
		}
		m := metrics.NewMetricsString(app.Metric, app.Tag)
		status, errStr := m.GetStatus()
		clientid := m.GetClientID()
		if clientid != "" {
			// h.devMgr.updateController(c, redis.InitStateAfterFetchingClientIDMap[app.Tag])
			h.devMgr.updateNode(r.Context(), payload.NodeID, node, redis.InitStateAfterFetchingClientIDMap[app.Tag])

			// h.devMgr.updateNodeFromDevice()
			// 只要有一个app运行成功 就running
			break
		}

		if status == "running" {
			// h.devMgr.updateController(c, redis.BizStateIniting)
			h.devMgr.updateNode(r.Context(), payload.NodeID, node, redis.BizStateIniting)
		}

		if errStr != "running" && errStr != "" {
			h.devMgr.updateNode(r.Context(), payload.NodeID, node, redis.BizStatusCodeErr)
			// h.devMgr.updateController(c, redis.BizStatusCodeErr)
		}
	}

	// c.AppList = apps
}

//------- logic changed --------------------
// 1. 拉取旧app的metric
// 2. 如果当前的app没有metric,则保留旧的metric
// 3. 删除所有旧的app
// 4. 保存当前的所有app

// ------- 覆盖全部的指标信息 ------------------
func (h *ServerHandler) updateNodeApps(nodeID string, apps []*App) error {
	nodeApps := make([]*redis.NodeApp, 0, len(apps))
	for _, app := range apps {
		if app.AppName != "" {
			nodeApps = append(nodeApps, &redis.NodeApp{AppName: app.AppName, MD5: app.ScriptMD5, Metric: app.Metric})
		}
	}
	// appNames, err := h.redis.GetNodeAppList(context.Background(), nodeID)
	// if err != nil {
	// 	return err
	// }

	// oldApps, err := h.redis.GetNodeApps(context.Background(), nodeID, appNames)
	// if err != nil {
	// 	return err
	// }

	// oldAppMap := make(map[string]*redis.NodeApp)
	// for _, app := range oldApps {
	// 	oldAppMap[app.AppName] = app
	// }

	// for _, app := range nodeApps {
	// 	if oldApp := oldAppMap[app.AppName]; oldApp != nil {
	// 		if len(app.Metric) != 0 && len(oldApp.Metric) != 0 {
	// 			app.Metric = oldApp.Metric
	// 		}
	// 	}
	// }

	// if err = h.redis.DeleteNodeApps(context.Background(), nodeID, appNames); err != nil {
	// 	return err
	// }

	if err := h.redis.SetNodeApps(context.Background(), nodeID, nodeApps); err != nil {
		return err
	}

	return nil
}

func (h *ServerHandler) HandleNodeRegist(w http.ResponseWriter, r *http.Request) {
	var (
		nodeid = r.URL.Query().Get("node_id")
		pubKey = r.URL.Query().Get("pub_key")
	)

	pubKeyBytes, err := base64.URLEncoding.DecodeString(pubKey)
	if err != nil {
		http.Error(w, "Failed to decode public key from base64", http.StatusBadRequest)
		return
	}

	if len(nodeid) == 0 {
		resultError(w, http.StatusBadRequest, "no id in query string")
		return
	}

	if _, err := titanrsa.Pem2PublicKey(pubKeyBytes); err != nil {
		resultError(w, http.StatusBadRequest, "pub_key is invalid: "+err.Error())
		return
	}

	registedInfo, err := h.redis.GetNodeRegistInfo(r.Context(), nodeid)
	if err == nil {
		if registedInfo.PublicKey != string(pubKeyBytes) {
			if err := h.redis.UpdateNodePublickKey(r.Context(), nodeid, string(pubKeyBytes)); err != nil {
				resultError(w, http.StatusBadRequest, err.Error())
			}
		}
		return
	}

	regInfo := &redis.NodeRegistInfo{
		NodeID:      nodeid,
		PublicKey:   string(pubKeyBytes),
		CreatedTime: time.Now().Unix(),
	}

	if err := h.redis.NodeRegist(r.Context(), regInfo); err != nil {
		resultError(w, http.StatusBadRequest, err.Error())
		return
	}
}

func (h *ServerHandler) HandleNodeLogin(w http.ResponseWriter, r *http.Request) {
	var (
		nodeid = r.URL.Query().Get("node_id")
		sign   = r.URL.Query().Get("sign")
	)

	if len(nodeid) == 0 {
		resultError(w, http.StatusBadRequest, "no id in query string")
		return
	}

	if len(sign) == 0 {
		resultError(w, http.StatusBadRequest, "no sign in query string")
		return
	}

	// node, err := h.redis.GetNode(r.Context(), nodeid)
	// if err != nil {
	// 	resultError(w, http.StatusBadRequest, err.Error())
	// 	return
	// }

	nodeRegistInfo, err := h.redis.GetNodeRegistInfo(r.Context(), nodeid)
	if err != nil {
		resultError(w, http.StatusBadRequest, err.Error())
		return
	}
	pem := nodeRegistInfo.PublicKey

	publicKey, err := titanrsa.Pem2PublicKey([]byte(pem))
	if err != nil {
		resultError(w, http.StatusBadRequest, fmt.Sprintf("pem to public key failed: %s", err.Error()))
	}

	signBuf, err := hex.DecodeString(sign)
	if err != nil {
		resultError(w, http.StatusBadRequest, fmt.Sprintf("hex decode sign failed: %s", err.Error()))
		return
	}

	rsa := titanrsa.New(crypto.SHA256, crypto.SHA256.New())
	if err := rsa.VerifySign(publicKey, signBuf, []byte(nodeid)); err != nil {
		resultError(w, http.StatusBadRequest, fmt.Sprintf("verify sign failed: %s", err.Error()))
		return
	}

	payload := common.JwtPayload{
		NodeID: nodeid,
	}

	w.Header().Set("Web-Server", h.config.WebServer)

	tk, err := h.auth.sign(payload)
	if err != nil {
		resultError(w, http.StatusBadRequest, fmt.Sprintf("sign jwt token failed: %s", err.Error()))
		return
	}

	w.Write([]byte(tk))
}

func (h *ServerHandler) HandleNodeKeepalive(w http.ResponseWriter, r *http.Request) {
	payload, ok := r.Context().Value("payload").(*common.JwtPayload)
	if !ok {
		resultError(w, http.StatusBadRequest, "no payload in context")
		return
	}

	node, err := h.redis.GetNode(r.Context(), payload.NodeID)
	if err != nil {
		log.Errorf("find node %s failed: %s", payload.NodeID, err.Error())
		resultError(w, http.StatusBadRequest, err.Error())
		return
	}

	node.LastActivityTime = time.Now()
	if err := h.redis.SetNode(r.Context(), node); err != nil {
		resultError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := h.redis.IncrNodeOnlineDuration(context.Background(), payload.NodeID, int(offlineTime.Minutes())); err != nil {
		resultError(w, http.StatusBadRequest, err.Error())
		return
	}
}

func (h *ServerHandler) HandleNextId(w http.ResponseWriter, r *http.Request) {
	nextId, err := h.redis.GetSNNextID(r.Context())
	if err != nil {
		resultError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := json.NewEncoder(w).Encode(APIResult{Data: map[string]string{
		"sn": nextId,
	}}); err != nil {
		log.Error("ServerHandler.handleSignVerify, Encode: ", err.Error())
	}
}

func (h *ServerHandler) HealthCheck(w http.ResponseWriter, r *http.Request) {

	// 1. check redis
	if err := h.redis.Ping(r.Context()); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	// 2. xxx

	w.WriteHeader(http.StatusOK)
}

func (h *ServerHandler) handleOnlineDurationByDate(w http.ResponseWriter, r *http.Request) {
	date := r.URL.Query().Get("date")
	if date == "" {
		resultError(w, http.StatusBadRequest, "date is required")
		return
	}

	list, err := h.redis.GetNodeList(r.Context(), time.Unix(0, 0), "")
	if err != nil {
		apiResultErr(w, err.Error())
		return
	}
	var ret [][]string

	for _, node := range list {
		v, err := h.redis.GetNodeOnlineDurationByDate(r.Context(), node.ID, date)
		if err != nil {
			apiResultErr(w, fmt.Sprintf("failed to get online duration for node %s: %v", node.ID, err))
			return
		}

		ret = append(ret, []string{node.ID, date, v})
	}

	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", `attachment; filename="online_duration.csv"`)
	csvw := csv.NewWriter(w)
	csvw.WriteAll(ret)
	csvw.Flush()
}

func resultError(w http.ResponseWriter, statusCode int, errMsg string) {
	w.WriteHeader(statusCode)
	w.Write([]byte(errMsg))
}

func apiResultErr(w http.ResponseWriter, errMsg string) {
	result := APIResult{ErrCode: APIErrCode, ErrMsg: errMsg}
	buf, err := json.Marshal(result)
	if err != nil {
		log.Error("apiResult, Marshal: ", err.Error())
		return
	}

	if _, err := w.Write(buf); err != nil {
		log.Error("apiResult, Write: ", err.Error())
	}
}

func calUsage(node *redis.Node) {
	if node.CPUCores == 0 && node.CPUUsage > 1 {
		_, node.CPUUsage = math.Modf(node.CPUUsage)
		return
	}
	node.CPUUsage = node.CPUUsage / float64(node.CPUCores)
	if node.CPUUsage > 1 {
		_, node.CPUUsage = math.Modf(node.CPUUsage)
	}
}

// cpu/number memory/MB disk/GB
func getResource(r *http.Request) (os string, cpu int, memory int64, disk int64, arch string) {
	os = r.URL.Query().Get("os")

	cpuStr := r.URL.Query().Get("cpu")
	memoryStr := r.URL.Query().Get("memory")
	diskStr := r.URL.Query().Get("disk")

	cpu = stringToInt(cpuStr)

	memoryBytes := stringToInt64(memoryStr)
	memory = memoryBytes / (1024 * 1024)

	diskBytes := stringToInt64(diskStr)
	disk = diskBytes / (1024 * 1024 * 1024)
	arch = r.URL.Query().Get("arch")
	return
}

func getReadIP(r *http.Request) string {
	realIP := r.Header.Get("X-Real-IP")
	if len(realIP) == 0 {
		realIP, _, _ = net.SplitHostPort(r.RemoteAddr)
	}
	return realIP
}
