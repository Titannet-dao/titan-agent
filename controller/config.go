package controller

import (
	titanrsa "agent/common/rsa"
	"crypto/rsa"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

type Config struct {
	AgentID    string
	PrivateKey *rsa.PrivateKey
}

const (
	agtConfigPath = ".titanagent"
	agtIdFile     = "agent_id"
	agtPrivateKey = "private.key"
	agtCert       = "cert.pem"
)

func InitConfig(workDir string) (*Config, error) {
	var (
		ret = new(Config)
		err error
	)

	ret.AgentID, err = loadAgentID(workDir)
	if err != nil {
		return nil, fmt.Errorf("failed to load AgentID: %w", err)
	}

	log.Infof("AgentID: %s", ret.AgentID)

	ret.PrivateKey, err = loadPrivateKey(workDir)
	if err != nil {
		return nil, fmt.Errorf("failed to load PrivateKey: %w", err)
	}

	return ret, nil
}

func loadAgentID(workDir string) (string, error) {
	idPath := filepath.Join(workDir, agtConfigPath, agtIdFile)

	if _, err := os.Stat(idPath); os.IsNotExist(err) {
		agentID := uuid.NewString()
		if err := createAndWriteFile(idPath, []byte(agentID)); err != nil {
			return "", err
		}
		return agentID, nil
	}

	bytes, err := os.ReadFile(idPath)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(bytes)), nil
}

func loadPrivateKey(workDir string) (*rsa.PrivateKey, error) {
	keyPath := filepath.Join(workDir, agtConfigPath, agtPrivateKey)

	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		bits := 1024
		priKey, err := titanrsa.GeneratePrivateKey(bits)
		if err != nil {
			return nil, err
		}
		priKeyPem := titanrsa.PrivateKey2Pem(priKey)
		if err := createAndWriteFile(keyPath, priKeyPem); err != nil {
			return nil, err
		}
		return priKey, nil
	}

	bytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	priKey, err := titanrsa.Pem2PrivateKey(bytes)
	return priKey, err
}

func createAndWriteFile(filePath string, data []byte) error {
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directories for %s: %w", filePath, err)
	}

	f, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", filePath, err)
	}
	defer f.Close()

	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("failed to write to file %s: %w", filePath, err)
	}
	return nil
}
