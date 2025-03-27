package server

import (
	titanrsa "agent/common/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type Config struct {
	ListenOn          string            `json:"listenOn" yaml:"listenOn"`
	DefaultLuaScript  string            `json:"defaultLuaScript" yaml:"defaultLuaScript"`
	DefaultController map[string]string `json:"defaultController" yaml:"defaultController"`
	DefaultApp        map[string]string `json:"defaultApp" yaml:"defaultApp"`

	LuaFileList        []*FileConfig        `json:"luaFileList" yaml:"luaFileList"`
	ControllerFileList []*FileConfig        `json:"controllerFileList" yaml:"controllerFileList"`
	AppList            []*AppConfig         `json:"appList" yaml:"appList"`
	Resources          map[string]*Resource `json:"resources" yaml:"resources"`
	NodeTags           map[string][]string  `json:"nodeTags" yaml:"nodeTags"`
	TestNodes          map[string]*TestApp  `json:"testNodes" yaml:"testNodes"`
	ChannelApps        map[string][]string  `json:"channelApps" yaml:"channelApps"`

	RedisAddr  string `json:"redisAddr" yaml:"redisAddr"`
	RedisPass  string `json:"redisPass" yaml:"redisPass"`
	PrivateKey string `json:"privateKey" yaml:"privateKey"`

	WebServer string `json:"webServer" yaml:"webServer"`
}

type FileConfig struct {
	Name    string `json:"name" yaml:"name"`
	Version string `json:"version" yaml:"version"`
	MD5     string `json:"md5" yaml:"md5"`
	URL     string `json:"url" yaml:"url"`
	OS      string `json:"os" yaml:"os"`
	Tag     string `json:"tag" yaml:"tag"`
}

type AppConfig struct {
	AppName      string   `json:"appName" yaml:"appName"`
	AppDir       string   `json:"appDir" yaml:"appDir"` // relative app dir
	ScriptName   string   `json:"scriptName" yaml:"scriptName"`
	AppVersion   string   `json:"appVersion" yaml:"appVersion"`
	ScriptMD5    string   `json:"scriptMD5" yaml:"scriptMD5"`
	ScriptURL    string   `json:"scriptURL" yaml:"scriptURL"`
	ReqResources []string `json:"reqResources" yaml:"reqResources"`
	ReqLocations []string `json:"reqLocations" yaml:"reqLocations"`
	Tag          string   `json:"tag" yaml:"tag"`
}

type Resource struct {
	Name        string `json:"name" yaml:"name"`
	OS          string `json:"os" yaml:"os"`
	Arch        string `json:"arch" yaml:"arch"`
	MinCPU      int    `json:"minCPU" yaml:"minCPU"`
	MinMemoryMB int64  `json:"minMemoryMB" yaml:"minMemoryMB"`
	MinDiskGB   int64  `json:"minDiskGB" yaml:"minDiskGB"`
}

type TestApp struct {
	LuaScript  string   `json:"luaScript" yaml:"luaScript"`
	Controller string   `json:"controller" yaml:"controller"`
	Apps       []string `json:"apps" yaml:"apps"`
}

func ParseConfig(filePath string) (*Config, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	ext := filepath.Ext(filePath)
	var config Config

	switch ext {
	case ".json":
		if err := json.NewDecoder(f).Decode(&config); err != nil {
			return nil, fmt.Errorf("failed to parse JSON: %w", err)
		}
	case ".yaml", ".yml":
		if err := yaml.NewDecoder(f).Decode(&config); err != nil {
			return nil, fmt.Errorf("failed to parse YAML: %w", err)
		}
	default:
		return nil, errors.New("unsupported file format: must be .json, .yaml, or .yml")
	}

	changed := false
	if config.PrivateKey == "" {
		bits := 1024
		priKey, err := titanrsa.GeneratePrivateKey(bits)
		if err != nil {
			return nil, fmt.Errorf("failed to generate private key: %w", err)
		}
		priKeyPem := titanrsa.PrivateKey2Pem(priKey)
		config.PrivateKey = string(priKeyPem)
		changed = true
	}

	if changed {
		buf, err := marshalConfig(filePath, &config)
		if err != nil {
			return nil, err
		}
		err = os.WriteFile(filePath, buf, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to write updated config: %w", err)
		}
	}

	return &config, nil
}

func marshalConfig(filePath string, config *Config) ([]byte, error) {
	ext := filepath.Ext(filePath)
	switch ext {
	case ".json":
		return json.MarshalIndent(config, "", "  ")
	case ".yaml", ".yml":
		return yaml.Marshal(config)
	default:
		return nil, errors.New("unsupported file format for saving: must be .json, .yaml, or .yml")
	}
}
