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
	ServerURL      string
	Channel        string
	Key            string
}

type Agent struct {
	agentVersion string
	args         *AgentArguments
	baseInfo     *BaseInfo
	script       *Script
	scriptFileMD5 string
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

	// Create a working directory if it doesn't exist
	if err := os.MkdirAll(args.WorkingDir, os.ModePerm); err != nil {
		return nil, fmt.Errorf("failed to create working directory: %v", err)
	}

	return agent, nil
}

func (a *Agent) Version() string {
	return a.agentVersion
}

func (a *Agent) Run(ctx context.Context) error {
	// Load the local script and update it from the server
	if err := a.loadLocal(); err != nil {
		return err
	}
	a.updateScriptFromServer()
	a.renewScript()

	scriptUpdateinterval := time.Duration(a.args.ScriptInvterval) * time.Second
	ticker := time.NewTicker(scriptUpdateinterval)
	defer ticker.Stop()

	scriptUpdateTime := time.Now()

	for {
		select {
		case ev := <-a.currentScript().Events():
			a.currentScript().HandleEvent(ev)
		case <-ticker.C:
			if time.Since(scriptUpdateTime) > scriptUpdateinterval {
				a.updateScriptFromServer()
				if a.scriptFileMD5 != a.script.fileMD5 {
					a.renewScript()
				}
				scriptUpdateTime = time.Now()
			}
		case <-ctx.Done():
			a.currentScript().Stop()
			log.Info("ctx done, Run() will quit")
			return nil
		}
	}
}

func (a *Agent) updateScriptFromServer() {
	log.Info("Checking for script updates from server...")

	updateConfig, err := a.getUpdateConfigFromServer()
	if err != nil {
		log.Errorf("Failed to get update config: %v", err)
		return
	}

	if a.scriptFileMD5 == updateConfig.MD5 {
		log.Info("Script is up-to-date")
		return
	}

	buf, err := a.getScriptFromServer(updateConfig.URL)
	if err != nil {
		log.Errorf("Failed to get script: %v", err)
		return
	}

	newFileMD5 := fmt.Sprintf("%x", md5.Sum(buf))
	if newFileMD5 != updateConfig.MD5 {
		log.Errorf("MD5 mismatch for the script from server")
		return
	}

	a.scriptFileContent = buf
	a.scriptFileMD5 = updateConfig.MD5
	if err := a.updateScriptFile(buf); err != nil {
		log.Errorf("Failed to update script file: %v", err)
	}
	log.Info("Script updated successfully")
}

func (a *Agent) currentScript() *Script {
	return a.script
}

func (a *Agent) renewScript() {
	if oldScript := a.script; oldScript != nil {
		oldScript.Stop()
	}

	newScript := NewScript(a.baseInfo, a.scriptFileMD5, a.scriptFileContent)
	newScript.Start()
	a.script = newScript
}

func (a *Agent) loadLocal() error {
	filePath := path.Join(a.args.WorkingDir, a.args.ScriptFileName)
	content, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to load local script: %v", err)
	}

	a.scriptFileContent = content
	a.scriptFileMD5 = fmt.Sprintf("%x", md5.Sum(content))
	return nil
}

func (a *Agent) getUpdateConfigFromServer() (*UpdateConfig, error) {
	devInfoQuery := a.baseInfo.ToURLQuery()
	url := fmt.Sprintf("%s/update/lua?%s", a.args.ServerURL, devInfoQuery.Encode())

	return a.getResponse(url, &UpdateConfig{})
}

func (a *Agent) getScriptFromServer(url string) ([]byte, error) {
	body, err := a.getResponse(url, nil)
	if err != nil {
		return nil, err
	}
	return body, nil
}

func (a *Agent) getResponse(url string, responseBody interface{}) ([]byte, error) {
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

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP request failed with status %d: %s", resp.StatusCode, string(body))
	}

	if responseBody != nil {
		if err := json.NewDecoder(resp.Body).Decode(responseBody); err != nil {
			return nil, fmt.Errorf("failed to parse response body: %v", err)
		}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}

func (a *Agent) updateScriptFile(scriptContent []byte) error {
	if err := os.MkdirAll(a.args.WorkingDir, os.ModePerm); err != nil {
		return fmt.Errorf("failed to create directory: %v", err)
	}

	filePath := path.Join(a.args.WorkingDir, a.args.ScriptFileName)
	f, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to open script file: %v", err)
	}
	defer f.Close()

	_, err = f.Write(scriptContent)
	return err
}
