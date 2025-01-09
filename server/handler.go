package server

import (
	"agent/common"
	titanrsa "agent/common/rsa"
	"agent/redis"
	"strconv"

	"bufio"
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
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
		d.IP = getReadIP(r)
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
		} else if f.OS == os {
			file = f
			if strings.Contains(f.Tag, arch) {
				bestMatchFile = f
			}
			break
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

func (h *ServerHandler) handleGetAppsConfig(w http.ResponseWriter, r *http.Request) {
	log.Infof("handleGetAppsConfig, queryString %s\n", r.URL.RawQuery)
	payload, err := parseTokenFromRequestContext(r.Context())
	if err != nil {
		log.Infof("ServerHandler.handleGetAppsConfig parseTokenFromRequestContext: %v", err)
		resultError(w, http.StatusUnauthorized, err.Error())
		return
	}

	d := NewDeviceFromURLQuery(r.URL.Query())
	d.IP = getReadIP(r)
	h.devMgr.updateController(&Controller{Device: *d, NodeID: payload.NodeID})

	uuid := r.URL.Query().Get("uuid")
	channel := r.URL.Query().Get("channel")

	var testApps []string
	testNode := h.config.TestNodes[uuid]
	if testNode != nil {
		testApps = testNode.Apps
	}

	appList := make([]*AppConfig, 0, len(h.config.AppList))

	for _, app := range h.config.AppList {
		if len(testApps) > 0 {
			if h.isTestApp(app.AppName, testApps) {
				appList = append(appList, app)
			}
		} else if len(channel) > 0 {
			// TODO handle channel
			if h.isAppMatchChannel(app.AppName, channel) {
				appList = append(appList, app)
			}
			// log.Infof("ServerHandler.handleGetAppsConfig channel %s", channel)
		} else if h.isResourceMatchApp(r, app.ReqResources) {
			appList = append(appList, app)
		}
	}

	log.Infof("GetAppList node: %s, os: %s, channel: %s, apps: %v", payload.NodeID, r.URL.Query().Get("os"), channel, appList)

	if len(appList) == 0 {
		log.Infof("ServerHandler.handleGetAppsConfig len(appList) == 0, uuid:%s, os:%s", r.URL.Query().Get("uuid"), r.URL.Query().Get("os"))
	}

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
	os, cpu, memoryMB, diskGB := getResource(r)
	for _, reqResourceName := range reqResources {
		reqRes := h.config.Resources[reqResourceName]
		if reqRes == nil {
			continue
		}

		if reqRes.OS == os && cpu >= reqRes.MinCPU && memoryMB >= reqRes.MinMemoryMB && diskGB >= reqRes.MinDiskGB {
			return true
		}
	}
	return false
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

	err = json.Unmarshal([]byte(app.Metric), &res)
	if err != nil {
		apiResultErr(w, err.Error())
		return
	}

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

	latTime := time.Unix(int64(lastActivityTimeInt), 0)

	nodes, err := h.redis.GetNodeList(context.Background(), latTime)
	if err != nil {
		apiResultErr(w, fmt.Sprintf("find node list failed: %s", err.Error()))
		return
	}

	var ret = make([]*NodeWebInfo, len(nodes))
	for i, node := range nodes {
		ret[i] = &NodeWebInfo{Node: node}
		if time.Since(node.LastActivityTime) > offlineTime {
			ret[i].State = NodeStateOffline
		} else {
			ret[i].State = NodeStateOnline
		}
		ret[i].OnlineDuration, _ = h.redis.GetNodeOnlineDuration(r.Context(), node.ID)
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
	ClientID         string
	Tag              string
}

func (h *ServerHandler) handleGetAllNodesAppInfosList(w http.ResponseWriter, r *http.Request) {

	lastActivityTime := r.URL.Query().Get("last_activity_time")
	lastActivityTimeInt, _ := strconv.Atoi(lastActivityTime)

	latTime := time.Unix(int64(lastActivityTimeInt), 0)

	nodeApps, err := h.redis.GetAllAppInfos(r.Context(), latTime)
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
			ClientID:         nodeApp.Metric.GetClientID(),
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

	log.Infof("[PushMetrics] NodeID:%s, apps: %v", payload.NodeID, apps)

	if err := h.updateNodeApps(payload.NodeID, apps); err != nil {
		log.Error("ServerHandler.handlePushMetrics update nodes app failed:", err.Error())
	}

	c := h.devMgr.getController(payload.NodeID)
	if c == nil {
		log.Errorf("ServerHandler.handlePushMetrics controller %s not exist", payload.NodeID)
		resultError(w, http.StatusBadRequest, fmt.Sprintf("controller %s not exist", payload.NodeID))
		return
	}
	c.AppList = apps
}

// 1. 拉取旧app的metric
// 2. 如果当前的app没有metric,则保留旧的metric
// 3. 删除所有旧的app
// 4. 保存当前的所有app
func (h *ServerHandler) updateNodeApps(nodeID string, apps []*App) error {
	nodeApps := make([]*redis.NodeApp, 0, len(apps))
	for _, app := range apps {
		nodeApps = append(nodeApps, &redis.NodeApp{AppName: app.AppName, MD5: app.ScriptMD5, Metric: redis.MetricString(app.Metric)})
	}
	appNames, err := h.redis.GetNodeAppList(context.Background(), nodeID)
	if err != nil {
		return err
	}

	oldApps, err := h.redis.GetNodeApps(context.Background(), nodeID, appNames)
	if err != nil {
		return err
	}

	oldAppMap := make(map[string]*redis.NodeApp)
	for _, app := range oldApps {
		oldAppMap[app.AppName] = app
	}

	for _, app := range nodeApps {
		if oldApp := oldAppMap[app.AppName]; oldApp != nil {
			if len(app.Metric) == 0 && len(oldApp.Metric) != 0 {
				app.Metric = oldApp.Metric
			}
		}
	}

	if err = h.redis.DeleteNodeApps(context.Background(), nodeID, appNames); err != nil {
		return err
	}

	if err = h.redis.SetNodeApps(context.Background(), nodeID, nodeApps); err != nil {
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
		resultError(w, http.StatusBadRequest, "pub_key is invalid"+err.Error())
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

// cpu/number memory/MB disk/GB
func getResource(r *http.Request) (os string, cpu int, memory int64, disk int64) {
	os = r.URL.Query().Get("os")

	cpuStr := r.URL.Query().Get("cpu")
	memoryStr := r.URL.Query().Get("memory")
	diskStr := r.URL.Query().Get("disk")

	cpu = stringToInt(cpuStr)

	memoryBytes := stringToInt64(memoryStr)
	memory = memoryBytes / (1024 * 1024)

	diskBytes := stringToInt64(diskStr)
	disk = diskBytes / (1024 * 1024 * 1024)
	return
}

func getReadIP(r *http.Request) string {
	realIP := r.Header.Get("X-Real-IP")
	if len(realIP) == 0 {
		realIP, _, _ = net.SplitHostPort(r.RemoteAddr)
	}
	return realIP
}
