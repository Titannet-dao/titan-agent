package agent

import (
	"archive/zip"
	"bufio"
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/bodgit/sevenzip"
	lua "github.com/yuin/gopher-lua"
)

const ExecTimeout = 10

type AgentModule struct {
	baseInfo *lua.LTable
}

func newAgentModule(devInfo *lua.LTable) *AgentModule {
	am := &AgentModule{baseInfo: devInfo}

	return am
}

func (am *AgentModule) loader(L *lua.LState) int {
	// register functions to the table
	var exports = map[string]lua.LGFunction{
		"fileMD5":        am.fileMD5,
		"info":           am.info,
		"extract7z":      am.extract7z,
		"extractZip":     am.extractZip,
		"copyDir":        am.copyDir,
		"removeAll":      am.removeAll,
		"execWithDetach": am.execWithDetach,
		"chmod":          am.chmod,
		"exec":           am.exec,
		"runBashCmd":     am.runBashCmd,
	}

	mod := L.SetFuncs(L.NewTable(), exports)

	// returns the module
	L.Push(mod)
	return 1
}

func (ag *AgentModule) fileMD5(L *lua.LState) int {
	filePath := L.CheckString(1)
	if len(filePath) == 0 {
		L.Push(lua.LNil)
		L.Push(lua.LString("File path can not empty"))
		return 2
	}

	md5, err := fileMD5(filePath)
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(fmt.Sprintf("%s", err)))
		return 2
	}

	L.Push(lua.LString(md5))
	return 1
}

func fileMD5(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := md5.New()

	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	md5Bytes := hash.Sum(nil)
	return hex.EncodeToString(md5Bytes), nil
}

func (am *AgentModule) info(L *lua.LState) int {
	if am.baseInfo != nil {
		L.Push(am.baseInfo)
		return 1
	}

	return 0
	// t := am.agent.devInfo.ToLuaTable(L)
	// t.RawSet(lua.LString("workingDir"), lua.LString(am.agent.args.WorkingDir))
	// t.RawSet(lua.LString("version"), lua.LString(am.agent.Version()))
	// t.RawSet(lua.LString("serverURL"), lua.LString(am.agent.args.ServerURL))
	// t.RawSet(lua.LString("scriptFileName"), lua.LString(am.agent.args.ScriptFileName))
	// t.RawSet(lua.LString("scriptInvterval"), lua.LNumber(am.agent.args.ScriptInvterval))

	// L.Push(t)
	// return 1
}

func (am *AgentModule) extract7z(L *lua.LState) int {
	filePath := L.CheckString(1)
	outputDir := L.OptString(2, filepath.Dir(filePath))

	err := extract7z(filePath, outputDir)
	if err != nil {
		L.Push(lua.LString(err.Error()))
	} else {
		L.Push(lua.LNil)
	}
	return 1

}

func extract7z(archive string, outputDir string) error {
	err := os.MkdirAll(outputDir, os.ModePerm)
	if err != nil {
		return err
	}

	r, err := sevenzip.OpenReader(archive)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		if err = extract7zFile(f, outputDir); err != nil {
			return err
		}
	}

	return nil
}

func extract7zFile(file *sevenzip.File, outputDir string) error {
	rc, err := file.Open()
	if err != nil {
		return err
	}
	defer rc.Close()

	if file.FileInfo().IsDir() {
		os.MkdirAll(outputDir+"/"+file.Name, os.ModePerm)
		return nil
	}
	// Extract the file

	outFile, err := os.Create(outputDir + "/" + file.Name)
	if err != nil {
		return err
	}
	defer outFile.Close()

	_, err = io.Copy(outFile, rc)
	return err
}

func (am *AgentModule) extractZip(L *lua.LState) int {
	filePath := L.CheckString(1)
	outputDir := L.OptString(2, filepath.Dir(filePath))

	err := extractZip(filePath, outputDir)
	if err != nil {
		L.Push(lua.LString(err.Error()))
	} else {
		L.Push(lua.LNil)
	}
	return 1
}

func extractZip(filePath, outputDir string) error {
	err := os.MkdirAll(outputDir, os.ModePerm)
	if err != nil {
		return err
	}

	zipFile, err := zip.OpenReader(filePath)
	if err != nil {
		return err
	}
	defer zipFile.Close()

	// Extract each file in the ZIP archive
	for _, f := range zipFile.File {
		if err = extractZipFile(f, outputDir); err != nil {
			return err
		}
	}
	return nil
}

func extractZipFile(file *zip.File, outputDir string) error {
	rc, err := file.Open()
	if err != nil {
		return err
	}
	defer rc.Close()

	if file.FileInfo().IsDir() {
		os.MkdirAll(outputDir+"/"+file.Name, os.ModePerm)
		return nil
	}
	// Extract the file

	outFile, err := os.Create(outputDir + "/" + file.Name)
	if err != nil {
		return err
	}
	defer outFile.Close()

	_, err = io.Copy(outFile, rc)
	return err
}

func (am *AgentModule) copyDir(L *lua.LState) int {
	srcDir := L.ToString(1)
	dstDir := L.ToString(2)

	err := copyDir(srcDir, dstDir)
	if err != nil {
		L.Push(lua.LString(fmt.Sprintf("Error copying directory: %s", err.Error())))
	} else {
		L.Push(lua.LNil)
	}
	return 1
}

func copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	return err
}

func copyDir(srcDir, dstDir string) error {
	return filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() {
			relPath, err := filepath.Rel(srcDir, path)
			if err != nil {
				return err
			}
			dstPath := filepath.Join(dstDir, relPath)
			if err := os.MkdirAll(filepath.Dir(dstPath), os.ModePerm); err != nil {
				return err
			}

			if err := copyFile(path, dstPath); err != nil {
				return err
			}
		}
		return nil
	})
}

func (am *AgentModule) removeAll(L *lua.LState) int {
	err := os.RemoveAll(L.CheckString(1))
	if err != nil {
		L.Push(lua.LString(err.Error()))
		return 1
	} else {
		L.Push(lua.LNil)
		return 1
	}
}

func (am *AgentModule) execWithDetach(L *lua.LState) int {
	command := L.CheckString(1)
	envStr := L.CheckString(2)

	args := strings.Split(command, " ")
	newArgs := make([]string, 0, len(args))
	for _, arg := range args {
		arg = strings.TrimSpace(arg)
		if len(arg) != 0 {
			newArgs = append(newArgs, arg)
		}
	}

	if len(newArgs) == 0 {
		L.Push(lua.LString("args can not emtpy"))
		return 1
	}

	var env = []string{}
	if len(envStr) > 0 {
		env = strings.Split(envStr, " ")
	}

	var cmd *exec.Cmd
	if len(newArgs) > 1 {
		cmd = exec.Command(newArgs[0], newArgs[1:]...)
	} else {
		cmd = exec.Command(newArgs[0])
	}

	cmd.Env = env
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		L.Push(lua.LString(err.Error()))
		return 1
	}

	if err := cmd.Process.Release(); err != nil {
		L.Push(lua.LString(err.Error()))
		return 1
	}

	return 0
}

func (am *AgentModule) chmod(L *lua.LState) int {
	filePath := L.CheckString(1)
	modeStr := L.CheckString(2)

	// conver to octor
	mode, err := strconv.ParseInt(modeStr, 8, 64)
	if err != nil {
		L.Push(lua.LString(fmt.Sprintf("Error parsing mode: %v", err)))
		return 1
	}

	err = os.Chmod(filePath, fs.FileMode(mode))
	if err != nil {
		L.Push(lua.LString(err.Error()))
		return 1
	}

	return 0
}

// Exec lua cmd.exec(command) return ({status=0, stdout="", stderr=""}, err)
func (am *AgentModule) exec(L *lua.LState) int {
	command := L.CheckString(1)
	timeout := time.Duration(L.OptInt64(2, ExecTimeout)) * time.Second
	needPrint := L.OptBool(3, false)
	envs := L.OptString(4, "")

	args := strings.Split(command, " ")
	newArgs := make([]string, 0, len(args))
	for _, arg := range args {
		arg = strings.TrimSpace(arg)
		if len(arg) != 0 {
			newArgs = append(newArgs, arg)
		}
	}

	if len(newArgs) == 0 {
		L.Push(lua.LNil)
		L.Push(lua.LString("args cannot be empty"))
		return 2
	}

	var cmd *exec.Cmd

	if len(newArgs) > 1 {
		cmd = exec.Command(newArgs[0], newArgs[1:]...)
	} else {
		cmd = exec.Command(newArgs[0])
	}

	if envs != "" {
		cmd.Env = append(cmd.Env, strings.Split(envs, " ")...)
	}

	parentEnv := os.Environ()
	cmd.Env = append(cmd.Env, parentEnv...)

	stdoutPipe, _ := cmd.StdoutPipe()
	stderrPipe, _ := cmd.StderrPipe()

	stdoutBuffer := bytes.Buffer{}
	stderrBuffer := bytes.Buffer{}

	go func() {
		reader := bufio.NewReader(stdoutPipe)
		for {
			line, err := reader.ReadString('\n')
			if len(line) > 0 {
				stdoutBuffer.WriteString(line)
				if needPrint {
					fmt.Print(line) // Print to console or log
				}
			}
			if err != nil {
				break
			}
		}
	}()

	go func() {
		reader := bufio.NewReader(stderrPipe)
		for {
			line, err := reader.ReadString('\n')
			if len(line) > 0 {
				stderrBuffer.WriteString(line)
				if needPrint {
					fmt.Print(line) // Print to console or log
				}
			}
			if err != nil {
				break
			}
		}
	}()

	if err := cmd.Start(); err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))
		return 2
	}

	done := make(chan error)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case <-time.After(timeout):
		_ = cmd.Process.Kill()
		L.Push(lua.LNil)
		L.Push(lua.LString("execute timeout"))
		return 2
	case err := <-done:
		result := L.NewTable()
		L.SetField(result, "stdout", lua.LString(stdoutBuffer.String()))
		L.SetField(result, "stderr", lua.LString(stderrBuffer.String()))
		L.SetField(result, "status", lua.LNumber(-1))

		if err != nil {
			if exiterr, ok := err.(*exec.ExitError); ok {
				if status, ok := exiterr.Sys().(syscall.WaitStatus); ok {
					L.SetField(result, "status", lua.LNumber(int64(status.ExitStatus())))
				}
			}
		} else {
			L.SetField(result, "status", lua.LNumber(0))
		}

		L.Push(result)
		return 1
	}
}

func (am *AgentModule) runBashCmd(L *lua.LState) int {
	command := L.CheckString(1)
	timeout := time.Duration(L.OptInt64(2, ExecTimeout)) * time.Second
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "linux", "darwin", "android":
		cmd = exec.Command("/bin/sh", "-c", command)
	case "windows":
		cmd = exec.Command("cmd.exe", "/C", command)
	default:
		L.Push(lua.LNil)
		L.Push(lua.LString(`unsupported os`))
		return 2
	}

	parentEnv := os.Environ()
	cmd.Env = append(cmd.Env, parentEnv...)

	stdout, stderr := bytes.Buffer{}, bytes.Buffer{}
	cmd.Stderr = &stderr
	cmd.Stdout = &stdout

	if err := cmd.Start(); err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))
		return 2
	}

	done := make(chan error)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case <-time.After(timeout):
		go cmd.Process.Kill()
		L.Push(lua.LNil)
		L.Push(lua.LString(`execute timeout`))
		return 2
	case err := <-done:
		result := L.NewTable()
		L.SetField(result, "stdout", lua.LString(stdout.String()))
		L.SetField(result, "stderr", lua.LString(stderr.String()))
		L.SetField(result, "status", lua.LNumber(-1))

		if err != nil {
			if exiterr, ok := err.(*exec.ExitError); ok {
				if status, ok := exiterr.Sys().(syscall.WaitStatus); ok {
					L.SetField(result, "status", lua.LNumber(int64(status.ExitStatus())))
				}
			}
		} else {
			L.SetField(result, "status", lua.LNumber(0))
		}
		L.Push(result)
		return 1
	}
}
