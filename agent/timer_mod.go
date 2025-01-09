package agent

import (
	"context"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
	lua "github.com/yuin/gopher-lua"
)

type TimerEvent struct {
	tag      string
	callback string
}

func (te *TimerEvent) evtType() string {
	return "timer"
}

type Timer struct {
	tag      string
	callback string
	interval int

	ctxCancelFn context.CancelFunc
}

type TimerModule struct {
	owner *Script

	timerMap map[string]*Timer
}

func newTimerModule(s *Script) *TimerModule {
	tm := &TimerModule{
		owner:    s,
		timerMap: make(map[string]*Timer),
	}

	return tm
}

func (tm *TimerModule) loader(L *lua.LState) int {
	// register functions to the table
	var exports = map[string]lua.LGFunction{
		"createTimer": tm.createTimerStub,
		"deleteTimer": tm.deleteTimerStub,
	}

	mod := L.SetFuncs(L.NewTable(), exports)

	// returns the module
	L.Push(mod)
	return 1
}

func (tm *TimerModule) createTimerStub(L *lua.LState) int {
	// extract tag, interval, callback-name
	tag := L.ToString(1)
	interval := L.ToInt(2)
	callback := L.ToString(3)

	log.Infof("createTimerStub tag:%s, interval:%d, callback:%s", tag, interval, callback)

	if !tm.owner.hasLuaFunction(callback) {
		L.Push(lua.LString(fmt.Sprintf("callback function %s not exist", callback)))
		return 1
	}

	if len(tag) < 1 {
		L.Push(lua.LString("tag can not empty"))
		return 1
	}

	if interval <= 0 {
		L.Push(lua.LString("interval can not <= 0"))
		return 1
	}

	_, exist := tm.timerMap[tag]
	if exist {
		L.Push(lua.LString(fmt.Sprintf("timer %s already exist", tag)))
		return 1
	}

	ctx, ctxCancelFn := context.WithCancel(context.Background())
	timer := &Timer{
		tag:         tag,
		callback:    callback,
		interval:    interval,
		ctxCancelFn: ctxCancelFn,
	}

	go tm.serveTimer(timer, ctx)

	tm.timerMap[tag] = timer

	return 0
}

func (tm *TimerModule) deleteTimerStub(L *lua.LState) int {
	// extract tag
	tag := L.ToString(1)
	timer, exist := tm.timerMap[tag]
	if !exist {
		return 0
	}

	timer.ctxCancelFn()

	delete(tm.timerMap, tag)

	return 0
}

func (tm *TimerModule) clear() {
	for _, v := range tm.timerMap {
		v.ctxCancelFn()
	}

	tm.timerMap = make(map[string]*Timer)
}

func (tm *TimerModule) serveTimer(timer *Timer, ctx context.Context) {
	loop := true
	interval := time.Second * time.Duration(timer.interval)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for loop {
		select {
		case <-ticker.C:
			ev := &TimerEvent{
				tag:      timer.tag,
				callback: timer.callback,
			}

			tm.owner.pushEvt(ev)
		case <-ctx.Done():
			loop = false
		}
	}
}

func (tm *TimerModule) hasTimer(tag string) bool {
	_, ok := tm.timerMap[tag]
	return ok
}
