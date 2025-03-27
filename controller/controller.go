package controller

import (
	"agent/agent"
	titanrsa "agent/common/rsa"
	"bytes"
	"context"
	"crypto"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"reflect"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	Version             = "0.1.1"
	httpTimeout         = 10 * time.Second
	pushMetricsInterval = 120 * time.Second
)

type ConrollerArgs struct {
	WorkingDir           string
	ScriptUpdateInterval int
	ServerURL            string
	RelAppsDir           string
	AppConfigsFileName   string
	Channel              string

	WebServerUrl string
	KEY          string
}

type App struct {
	appConfig *AppConfig
	app       *Application
}

type AppMetric struct {
	AppConfig
	Metric string `json:"metric"`
}

type Controller struct {
	baseInfo      *agent.BaseInfo
	args          *ConrollerArgs
	appConfigs    []*AppConfig
	appConfigsMD5 string
	apps          map[string]*App
	metricCh      chan AppMetric
	appMetrics    map[string]string

	//
	Config *Config
	token  string
	// client *http.Client
}

func New(args *ConrollerArgs) (*Controller, error) {
	config, err := InitConfig(args.WorkingDir)
	if err != nil {
		return nil, err
	}

	appsDir := path.Join(args.WorkingDir, args.RelAppsDir)
	err = os.MkdirAll(appsDir, os.ModePerm)
	if err != nil {
		return nil, err
	}

	controllerInfo := agent.ControllerInfo{
		WorkingDir:      args.WorkingDir,
		Version:         Version,
		ServerURL:       args.ServerURL,
		ScriptInvterval: args.ScriptUpdateInterval,
		Channel:         args.Channel,
	}

	info := agent.NewBaseInfo(nil, &agent.AppInfo{ControllerInfo: controllerInfo})

	c := &Controller{
		apps:       make(map[string]*App),
		args:       args,
		baseInfo:   info,
		appMetrics: make(map[string]string),
		metricCh:   make(chan AppMetric, 64),
		Config:     config,
	}

	if err := c.regist(context.Background()); err != nil {
		return nil, fmt.Errorf("[Regist error] %s", err.Error())
	}
	log.Info("Node regist success")

	token, err := c.login(context.Background())
	if err != nil {
		return nil, fmt.Errorf("[Login error] %s", err.Error())
	}
	log.Info("Node login success")
	c.token = token

	if !info.IsBox() {
		if err := c.registBindInfo(context.Background()); err != nil {
			return nil, fmt.Errorf("[Bind Error]: %s", err.Error())
		}
		log.Info("Node bind success")
	} else {
		log.Info("Box Node, skip bind")
	}

	return c, nil
}

func (c *Controller) registBindInfo(ctx context.Context) error {
	titanRsa := titanrsa.New(crypto.SHA256, crypto.SHA256.New())
	sign, err := titanRsa.Sign(c.Config.PrivateKey, []byte(c.args.KEY))
	if err != nil {
		return fmt.Errorf("failed to sign key: %s", err.Error())
	}

	type BindReq struct {
		Key    string `json:"key"`
		NodeID string `json:"node_id"`
		Sign   string `json:"sign"`
	}

	bindReq := BindReq{
		Key:    c.args.KEY,
		NodeID: c.Config.AgentID,
		Sign:   hex.EncodeToString(sign),
	}

	buf, err := json.Marshal(bindReq)
	if err != nil {
		return fmt.Errorf("failed to marshal bind request: %s", err.Error())
	}
  
	webUrl := c.baseInfo.GetWebServer()
	if webUrl != "" {
		webUrl += "/api/network/bind_node"
	} else {
		webUrl = c.args.WebServerUrl
	}

	resp, err := http.Post(webUrl, "application/json", bytes.NewReader(buf))
	if err != nil {
		return fmt.Errorf("failed to post bind req to web-server: %s", err.Error())
	}

	if resp.StatusCode != http.StatusOK {
		buf, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read response body: %s", err.Error())
		}
		return fmt.Errorf("bind failed, status code %d, response body: %s", resp.StatusCode, string(buf))
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %s", err.Error())
	}

	type Resp struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
	}
	rsp := Resp{}
	if err := json.Unmarshal(respBody, &rsp); err != nil {
		return fmt.Errorf("failed to unmarshal response body: %s", err.Error())
	}

	if rsp.Code != 0 {
		return fmt.Errorf("bind failed, code: %d, msg: %s", rsp.Code, rsp.Msg)
	}
	return nil
}

func (c *Controller) login(ctx context.Context) (string, error) {
	rsa := titanrsa.New(crypto.SHA256, crypto.SHA256.New())
	sign, err := rsa.Sign(c.Config.PrivateKey, []byte(c.Config.AgentID))
	if err != nil {
		return "", err
	}

	url := fmt.Sprintf("%s%s?node_id=%s&sign=%s", c.args.ServerURL, "/node/login", c.Config.AgentID, hex.EncodeToString(sign))

	ctx, cancel := context.WithTimeout(ctx, httpTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("regist status code: %d, msg: %s, url: %s", resp.StatusCode, string(body), url)
	}

	c.baseInfo.SetWebServer(resp.Header.Get("Web-Server"))

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil

}

func (c *Controller) regist(ctx context.Context) error {

	encodedPubKey := base64.URLEncoding.EncodeToString(titanrsa.PublicKey2Pem(&c.Config.PrivateKey.PublicKey))

	url := fmt.Sprintf("%s%s?node_id=%s&pub_key=%s", c.args.ServerURL, "/node/regist", c.Config.AgentID, url.QueryEscape(encodedPubKey))

	ctx, cancel := context.WithTimeout(ctx, httpTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("regist status code: %d, msg: %s, url: %s", resp.StatusCode, string(body), url)
	}

	_, err = io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// log.Infof("Controller.regist body:%s", string(body))

	return nil

}

func (c *Controller) Run(ctx context.Context) error {
	c.loadLocal()
	c.updateAppsFromServer()
	c.newApps()

	go c.handleMetric(ctx)

	go c.collectTraffic(ctx)

	scriptUpdateinterval := time.Second * time.Duration(c.args.ScriptUpdateInterval)
	ticker := time.NewTicker(scriptUpdateinterval)
	defer ticker.Stop()

	appUpdateTime := time.Now()
	for {
		select {
		case <-ticker.C:
			elapsed := time.Since(appUpdateTime)
			if elapsed > scriptUpdateinterval {
				isUpdate, err := c.updateAppsFromServer()
				if err != nil {
					log.Infof("Controller.Run updateAppsFromServer %s", err.Error())
				} else if isUpdate {
					log.Infof("Controller.Run updateAppsFromServer renew apps")
					c.renewApps()
				} else {
					log.Infof("Controller.Run updateAppsFromServer no apps change")
				}
				appUpdateTime = time.Now()
			}
		case <-ctx.Done():
			c.onStop()
			return nil
		}

	}

}

func (c *Controller) handleMetric(ctx context.Context) {
	ticker := time.NewTicker(pushMetricsInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// send metric to server
			metrics := make(map[string]string)
			for appName, metric := range c.appMetrics {
				metrics[appName] = metric
			}

			go func() {
				if err := c.pushMetrics(metrics); err != nil {
					log.Error("handleMetric pushMetrics failed:", err.Error())
				}
			}()

		case metric := <-c.metricCh:
			c.appMetrics[metric.AppName] = metric.Metric

		case <-ctx.Done():
			log.Info("handleMetric exist")
			return
		}
	}
}

// ./controller run --working-dir=./devctr --server-url=http://localhost:8080 --web-url=http://google.com --key=xxxxxx

func (c *Controller) pushMetrics(metrics map[string]string) error {
	// if len(metrics) == 0 {
	// 	return nil
	// }
	if len(c.apps) == 0 {
		return nil
	}

	appMetrics := make([]*AppMetric, 0, len(c.apps))
	for _, app := range c.apps {
		metric := metrics[app.appConfig.AppName]
		appMetrics = append(appMetrics, &AppMetric{AppConfig: *app.appConfig, Metric: metric})
	}

	buf, err := json.Marshal(appMetrics)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s%s?uuid=%s", c.args.ServerURL, "/push/metrics", c.baseInfo.UUID())

	ctx, cancel := context.WithTimeout(context.Background(), httpTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, bytes.NewReader(buf))
	if err != nil {
		return err
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", c.token))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("getScriptInfoFromServer status code: %d, msg: %s, url: %s", resp.StatusCode, string(body), url)
	}

	// log.Infof("push metrics")

	return nil
}

func (c *Controller) pushMetric(metric AppMetric) {
	c.metricCh <- metric
}

func (c *Controller) loadLocal() {
	appConfigs, err := c.loadLocalAppConfigs()
	if err != nil {
		log.Errorf("Controller.loadLocal load apps config:%v", err)
		return
	}

	c.appConfigsMD5 = c.configMD5(appConfigs)
	c.appConfigs = appConfigs
}

func (c *Controller) configMD5(appConfigs []*AppConfig) string {
	b, err := json.Marshal(appConfigs)
	if err != nil {
		log.Errorf("Controller.configMD5 Marshal:%s", err.Error())
		return ""
	}

	return fmt.Sprintf("%x", md5.Sum(b))
}

func (c *Controller) newApps() {
	if len(c.appConfigs) == 0 {
		return
	}

	for _, appConfig := range c.appConfigs {
		app, err := NewApplication(&AppArguments{ControllerArgs: c.args, AppConfig: appConfig}, c)
		if err != nil {
			log.Errorf("Controller.newApps NewApplication failed:%s", err.Error())
			continue
		}
		c.apps[appConfig.AppName] = &App{appConfig: appConfig, app: app}

		go app.Run()
	}

}

func (c *Controller) renewApps() {
	if len(c.appConfigs) == 0 {
		return
	}

	appConfigMap := make(map[string]*AppConfig)
	for _, appConfig := range c.appConfigs {
		appConfigMap[appConfig.AppName] = appConfig
	}

	removeApps := make([]*App, 0, len(c.apps))
	for _, app := range c.apps {
		appConfig, ok := appConfigMap[app.appConfig.AppName]
		if !ok {
			removeApps = append(removeApps, app)
			continue
		}

		if c.isAppConfigChange(app.appConfig, appConfig) {
			removeApps = append(removeApps, app)
		}
	}

	// remove apps
	for _, app := range removeApps {
		app.app.Stop()
		delete(c.apps, app.appConfig.AppName)
	}

	// new apps
	for _, appConfig := range c.appConfigs {
		_, ok := c.apps[appConfig.AppName]
		if !ok {
			app, err := NewApplication(&AppArguments{ControllerArgs: c.args, AppConfig: appConfig}, c)
			if err != nil {
				log.Errorf("Controller.newApps NewApplication failed:%s", err.Error())
				continue
			}
			c.apps[appConfig.AppName] = &App{appConfig: appConfig, app: app}

			go app.Run()
		}
	}

}

func (c *Controller) loadLocalAppConfigs() ([]*AppConfig, error) {
	configFilePath := path.Join(c.args.WorkingDir, c.args.RelAppsDir, c.args.AppConfigsFileName)
	b, err := os.ReadFile(configFilePath)
	if err != nil {
		return nil, err
	}

	appsConfig := make([]*AppConfig, 0)
	err = json.Unmarshal(b, &appsConfig)
	if err != nil {
		return nil, err
	}

	return appsConfig, nil
}

// updateAppsFromServer just get apps from server and save on local
func (c *Controller) updateAppsFromServer() (bool, error) {
	// load config from server
	appConfigs, err := c.getAppConfigsFromServer()
	if err != nil {
		return false, err
	}

	// Filtering invalid configurations
	newAppConfigs := make([]*AppConfig, 0, len(appConfigs))
	appConfigMap := make(map[string]*AppConfig)
	for _, appConfig := range appConfigs {
		// if appConfig.AppDir == "" || appConfig.AppName == "" || appConfig.
		if _, ok := appConfigMap[appConfig.AppName]; ok {
			continue
		}
		appConfigMap[appConfig.AppName] = appConfig
		newAppConfigs = append(newAppConfigs, appConfig)
	}

	if !c.isAppsConfigChange(newAppConfigs) {
		return false, nil
	}

	for _, appConfig := range newAppConfigs {
		scriptContent, err := c.getScriptFromServer(appConfig.ScriptURL)
		if err != nil {
			log.Errorf("Controller.updateAppConfigAndScriptFromServer getScriptFromServer faile %v", err.Error())
			return false, err
		}

		newMD5 := fmt.Sprintf("%x", md5.Sum(scriptContent))
		if newMD5 != appConfig.ScriptMD5 {
			log.Errorf("Controller.updateAppConfigAndScriptFromServer script md5 not match, AppName: %s. server md5: %s. download md5: %s", appConfig.AppName, appConfig.ScriptMD5, newMD5)
			return false, err
		}

		err = c.saveScript(scriptContent, appConfig)
		if err != nil {
			log.Errorf("Controller.updateAppConfigAndScriptFromServer saveScript faile %v", err.Error())
			return false, err
		}

	}

	// remove excess apps
	for _, appConfig := range c.appConfigs {
		if _, ok := appConfigMap[appConfig.AppName]; !ok {
			if err = c.removeAppDir(appConfig); err != nil {
				log.Errorf("Controller.updateAppConfigAndScriptFromServer removeAppDir %s", err.Error())
				return false, err
			}
		}
	}

	if err = c.saveAppConfigs(newAppConfigs); err != nil {
		log.Errorf("Controller.updateAppConfigAndScriptFromServer saveAppConfigs faile %v", err.Error())
		return false, err
	}

	c.appConfigsMD5 = c.configMD5(newAppConfigs) 
	c.appConfigs = newAppConfigs

	return true, nil
}

func (c *Controller) isAppsConfigChange(newAppConfigs []*AppConfig) bool {
	if len(c.apps) != len(newAppConfigs) {
		return true
	}

	for _, appConfig := range newAppConfigs {
		app, ok := c.apps[appConfig.AppName]
		if !ok {
			return true
		}

		if c.isAppConfigChange(app.appConfig, appConfig) {
			return true
		}
	}

	return false
}

func (c *Controller) isAppConfigChange(appConfig1 *AppConfig, appConfig2 *AppConfig) bool {

	return !reflect.DeepEqual(appConfig1, appConfig2)
	// // 两者均为nil 则没有变化
	// if appConfig1 == nil && appConfig2 == nil {
	// 	return false
	// }

	// // 如果一个是nil 另一个不是 则有变化
	// if appConfig1 == nil || appConfig2 == nil {
	// 	return true
	// }

	// b1, err := json.Marshal(appConfig1)
	// if err != nil {
	// 	return true
	// }

	// b2, err := json.Marshal(appConfig2)
	// if err != nil {
	// 	return true
	// }

	// config1MD5 := fmt.Sprintf("%x", md5.Sum(b1))
	// config2MD5 := fmt.Sprintf("%x", md5.Sum(b2))

	// return config1MD5 != config2MD5

}

func (c *Controller) getAppConfigsFromServer() ([]*AppConfig, error) {
	queryString := c.baseInfo.ToURLQuery()

	url := fmt.Sprintf("%s%s?%s", c.args.ServerURL, "/config/apps", queryString.Encode())

	ctx, cancel := context.WithTimeout(context.Background(), httpTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", c.token))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("getScriptInfoFromServer status code: %d, msg: %s, url: %s", resp.StatusCode, string(body), url)
	}

	// Read and handle the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	appsConfigs := make([]*AppConfig, 0)
	err = json.Unmarshal(body, &appsConfigs)
	if err != nil {
		return nil, err
	}
	return appsConfigs, nil
}

func (c *Controller) getScriptFromServer(url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), httpTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("getScriptInfoFromServer status code: %d, msg: %s, url: %s", resp.StatusCode, string(body), url)
	}

	// Read and handle the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return body, nil
}

func (c *Controller) saveScript(content []byte, appConfig *AppConfig) error {
	appDir := path.Join(c.args.WorkingDir, c.args.RelAppsDir, appConfig.AppDir)
	err := os.MkdirAll(appDir, os.ModePerm)
	if err != nil {
		return err
	}

	filePath := path.Join(appDir, appConfig.ScriptName)
	f, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Write(content)
	return err
}

func (c *Controller) saveAppConfigs(appConfigs []*AppConfig) error {
	appsDir := path.Join(c.args.WorkingDir, c.args.RelAppsDir)
	err := os.MkdirAll(appsDir, os.ModePerm)
	if err != nil {
		return err
	}

	filePath := path.Join(appsDir, c.args.AppConfigsFileName)
	f, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	b, err := json.Marshal(appConfigs)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	return err
}

func (c *Controller) removeAppDir(appConfig *AppConfig) error {
	appDir := path.Join(c.args.WorkingDir, c.args.RelAppsDir, appConfig.AppDir)
	return os.RemoveAll(appDir)
}

func (c *Controller) onStop() {
	c.stopAllApps()

	log.Infof("Controller.onStop abc")
}

func (c *Controller) stopAllApps() {
	for _, app := range c.apps {
		app.app.Stop()
	}

}

func (c *Controller) collectTraffic(ctx context.Context) {
	statsChan, err := agent.MonitorNetworkStats(ctx, 1*time.Minute)
	if err != nil {
		log.Errorf("collect network stats error: %v", err)
		return
	}

	for {
		select {
		case <-ctx.Done():
			log.Info("collectTraffic quit")
			return
		case stats := <-statsChan:
			c.baseInfo.SetTraffice(stats)
			c.baseInfo.SetCpuUsage(agent.GetCpuRealtimeUsage())
		}
	}
}
