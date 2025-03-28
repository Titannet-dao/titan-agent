package agent

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	version     = "0.1.1"
	httpTimeout = 10 * time.Second
)

type AgentArguments struct {
	WorkingDir     string
	ScriptFileName string

	ScriptInvterval int

	ServerURL string
	Channel   string
	Key       string
}

type Agent struct {
	agentVersion string

	args *AgentArguments

	baseInfo *BaseInfo
	script   *Script

	scriptFileMD5     string
	scriptFileContent []byte
}

type UpdateConfig struct {
	MD5 string `json:"md5"`
	URL string `json:"url"`
}

func New(args *AgentArguments) (*Agent, error) {
	agentInfo := AgentInfo{
		WorkingDir:      args.WorkingDir,
		Version:         version,
		ServerURL:       args.ServerURL,
		ScriptFileName:  args.ScriptFileName,
		ScriptInvterval: args.ScriptInvterval,
		Channel:         args.Channel,
		ControllerKey:   args.Key,
	}
	agent := &Agent{
		agentVersion: version,
		args:         args,
		baseInfo:     NewBaseInfo(&agentInfo, nil),
	}

	// err := os.MkdirAll(args.WorkingDir, os.ModePerm)
	// if err != nil {
	// 	return nil, err
	// }

	return agent, nil
}

func (a *Agent) Version() string {
	return a.agentVersion
}

func (a *Agent) Run(ctx context.Context) error {
	a.loadLocal()
	a.updateScriptFromServer()
	a.renewScript()

	scriptUpdateinterval := time.Second * time.Duration(a.args.ScriptInvterval)
	ticker := time.NewTicker(scriptUpdateinterval)
	scriptUpdateTime := time.Now()
	loop := true
	defer ticker.Stop()

	for loop {
		script := a.currentScript()
		select {
		case ev := <-script.Events():
			script.HandleEvent(ev)
		case <-ticker.C:
			elapsed := time.Since(scriptUpdateTime)
			if elapsed > scriptUpdateinterval {
				a.updateScriptFromServer()

				if a.scriptFileMD5 != script.fileMD5 {
					a.renewScript()
				}

				scriptUpdateTime = time.Now()
			}
		case <-ctx.Done():
			script.Stop()
			log.Info("ctx done, Run() will quit")
			loop = false
		}
	}

	return nil
}

func (a *Agent) updateScriptFromServer() {
	log.Info("updateScriptFromServer")
	updateConfig, err := a.getUpdateConfigFromServer()
	if err != nil {
		log.Errorf("updateScriptFromServer get update config: %s", err.Error())
		return
	}
	if a.scriptFileMD5 == updateConfig.MD5 {
		return
	}

	buf, err := a.getScriptFromServer(updateConfig.URL)
	if err != nil {
		log.Errorf("updateScriptFromServer get script:%s", err.Error())
		return
	}

	newFileMD5 := fmt.Sprintf("%x", md5.Sum(buf))
	if newFileMD5 != updateConfig.MD5 {
		log.Errorf("Server script file md5 not match, new: %s, old: %s", newFileMD5, updateConfig.MD5)
		return
	}

	a.scriptFileContent = buf
	a.scriptFileMD5 = updateConfig.MD5
	a.updateScriptFile(buf)

	log.Info("update script file, md5 ", updateConfig.MD5)
}

func (a *Agent) currentScript() *Script {
	return a.script
}

func (a *Agent) renewScript() {
	oldScript := a.script
	if oldScript != nil {
		oldScript.Stop()
	}

	newScript := NewScript(a.baseInfo, a.scriptFileMD5, a.scriptFileContent)
	newScript.Start()

	a.script = newScript
}

func (a *Agent) loadLocal() {
	p := path.Join(a.args.WorkingDir, a.args.ScriptFileName)
	b, err := os.ReadFile(p)
	if err != nil {
		log.Errorf("loadLocal ReadFile file failed:%v", err)
		return
	}

	a.scriptFileContent = b
	a.scriptFileMD5 = fmt.Sprintf("%x", md5.Sum(b))
}

func (a *Agent) getUpdateConfigFromServer() (*UpdateConfig, error) {
	devInfoQuery := a.baseInfo.ToURLQuery()

	url := fmt.Sprintf("%s/update/lua?%s", a.args.ServerURL, devInfoQuery.Encode())

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

	updateConfig := &UpdateConfig{}
	err = json.Unmarshal(body, updateConfig)
	if err != nil {
		return nil, nil
	}
	return updateConfig, nil
}

func (a *Agent) getScriptFromServer(url string) ([]byte, error) {
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
		return nil, fmt.Errorf("getScriptFromServer status code: %d, msg: %s, url: %s", resp.StatusCode, string(body), url)
	}

	// Read and handle the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return body, nil
}

func (a *Agent) updateScriptFile(scriptContent []byte) error {
	err := os.MkdirAll(a.args.WorkingDir, os.ModePerm)
	if err != nil {
		return err
	}

	filePath := path.Join(a.args.WorkingDir, a.args.ScriptFileName)
	f, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Write(scriptContent)
	return err
}
