package agent

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	log "github.com/sirupsen/logrus"
	lua "github.com/yuin/gopher-lua"
)

type ProcessEvent struct {
	name string
}

func (pe *ProcessEvent) evtType() string {
	return "process"
}

type Process struct {
	name string
	cmd  *exec.Cmd
}

type ProcessModule struct {
	owner      *Script
	processMap map[string]*Process
}

func newProcessModule(s *Script) *ProcessModule {
	pm := &ProcessModule{
		owner:      s,
		processMap: make(map[string]*Process),
	}

	return pm
}

func (pm *ProcessModule) loader(L *lua.LState) int {
	// register functions to the table
	var exports = map[string]lua.LGFunction{
		"createProcess": pm.createProcessStub,
		"killProcess":   pm.killProcessStub,
		"listProcess":   pm.listProcessStub,
		"getProcess":    pm.getProcessStub,
	}

	mod := L.SetFuncs(L.NewTable(), exports)

	// returns the module
	L.Push(mod)
	return 1
}

func (pm *ProcessModule) createProcessStub(L *lua.LState) int {
	name := L.ToString(1)
	command := L.ToString(2)
	envStr := L.ToString(3)

	log.Infof("createProcessStub name:%s", name)
	// log.Infof("createProcessStub command:%s\n, envStr:%s", command, envStr)

	if len(name) < 1 {
		L.Push(lua.LString("Must set process name"))
		return 1
	}

	_, exist := pm.processMap[name]
	if exist {
		L.Push(lua.LString(fmt.Sprintf("Process %s already exist", name)))
		return 1
	}

	env := pm.parseEnv(envStr)
	cmd, err := pm.createProcess(command, env)
	if err != nil {
		L.Push(lua.LString(err.Error()))
		return 1
	}

	err = cmd.Start()
	if err != nil {
		L.Push(lua.LString(err.Error()))
		return 1
	}

	process := &Process{
		name: name,
		cmd:  cmd,
	}

	go pm.waitProcess(process)

	pm.processMap[name] = process

	return 0
}

func (tm *ProcessModule) parseEnv(envStr string) []string {
	if len(envStr) == 0 {
		return []string{}
	}
	return strings.Split(envStr, " ")
}

// killProcessStub not wait Process stop
// Process.Wait() will wait in other goroutine
// if start same name process, must wait process to stop complete
func (tm *ProcessModule) killProcessStub(L *lua.LState) int {
	name := L.ToString(1)
	process, exist := tm.processMap[name]
	if !exist {
		return 0
	}

	process.cmd.Process.Kill()

	// delete(tm.processMap, name)

	return 0
}

func (pm *ProcessModule) listProcessStub(L *lua.LState) int {
	if len(pm.processMap) == 0 {
		return 0
	}

	t := L.NewTable()
	for _, v := range pm.processMap {
		process := L.NewTable()
		process.RawSet(lua.LString("name"), lua.LString(v.name))
		process.RawSet(lua.LString("pid"), lua.LNumber(v.cmd.Process.Pid))
		t.Append(process)
	}

	L.Push(t)
	return 1
}

func (pm *ProcessModule) getProcessStub(L *lua.LState) int {
	if len(pm.processMap) == 0 {
		return 0
	}

	name := L.ToString(1)
	process := pm.processMap[name]
	if process != nil {
		t := L.NewTable()
		t.RawSet(lua.LString("name"), lua.LString(process.name))
		t.RawSet(lua.LString("pid"), lua.LNumber(process.cmd.Process.Pid))
		L.Push(t)
		return 1
	}

	return 0
}

func (pm *ProcessModule) waitProcess(process *Process) {
	err := process.cmd.Wait()
	if err != nil {
		log.Errorf("wait process %s, err:%v", process.name, err)
	}

	pm.owner.pushEvt(&ProcessEvent{name: process.name})
}

func (pm *ProcessModule) delete(name string) {
	delete(pm.processMap, name)
}

func (pm *ProcessModule) clear() {
	for _, v := range pm.processMap {
		v.cmd.Process.Kill()
	}

	pm.processMap = make(map[string]*Process)
}

func (tm *ProcessModule) createProcess(command string, env []string) (*exec.Cmd, error) {
	args := strings.Split(command, " ")
	newArgs := make([]string, 0, len(args))
	for _, arg := range args {
		arg = strings.TrimSpace(arg)
		if len(arg) != 0 {
			newArgs = append(newArgs, arg)
		}
	}

	if len(newArgs) == 0 {
		return nil, fmt.Errorf("args can not emtpy")
	}

	var cmd *exec.Cmd
	if len(newArgs) > 1 {
		cmd = exec.Command(newArgs[0], newArgs[1:]...)
	} else {
		cmd = exec.Command(newArgs[0])
	}

	parentEnv := os.Environ()
	cmd.Env = append(parentEnv, env...)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd, nil
}
