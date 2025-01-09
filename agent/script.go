package agent

import (
	log "github.com/sirupsen/logrus"
	libs "github.com/vadv/gopher-lua-libs"
	lua "github.com/yuin/gopher-lua"
)

type ScriptEvent interface {
	evtType() string
}

type Script struct {
	baseInfo *BaseInfo
	fileMD5  string

	eventsChan chan ScriptEvent

	state *lua.LState

	modTable *lua.LTable

	timerModule *TimerModule

	downloadModule *DownloadModule

	processModule *ProcessModule

	metricModule *MetricModule
}

func (s *Script) Events() <-chan ScriptEvent {
	return s.eventsChan
}

func (s *Script) pushEvt(evt ScriptEvent) {
	s.eventsChan <- evt
}

func (s *Script) Metric() <-chan string {
	if s.metricModule != nil {
		return s.metricModule.metric()
	}

	return nil
}

func (s *Script) HandleEvent(evt ScriptEvent) {
	switch evt.evtType() {
	case "timer":
		e := evt.(*TimerEvent)
		if e != nil && s.timerModule.hasTimer(e.tag) {
			s.callModFunction1(e.callback, lua.LString(e.tag))
		}
	case "download":
		e := evt.(*DownloadEvent)
		if e != nil {
			s.downloadModule.delete(e.tag)
			t := s.state.NewTable()
			t.RawSet(lua.LString("tag"), lua.LString(e.tag))
			t.RawSet(lua.LString("filePath"), lua.LString(e.filePath))
			t.RawSet(lua.LString("md5"), lua.LString(e.md5))
			t.RawSet(lua.LString("err"), lua.LString(e.err))
			s.callModFunction1(e.callback, t)
		}
	case "process":
		e := evt.(*ProcessEvent)
		if e != nil {
			s.processModule.delete(e.name)
		}

	}
}

func NewScript(baseInfo *BaseInfo, scriptFileMD5 string, fileContent []byte) *Script {
	s := &Script{
		baseInfo:   baseInfo,
		fileMD5:    scriptFileMD5,
		eventsChan: make(chan ScriptEvent, 64),
	}

	s.state = lua.NewState()

	if len(fileContent) > 0 {
		s.load(fileContent)
	}

	return s
}

func (s *Script) Start() {
	ls := s.state
	s.timerModule = newTimerModule(s)
	ls.PreloadModule("timer", s.timerModule.loader)

	s.downloadModule = newDownloaderModule(s)
	ls.PreloadModule("downloader", s.downloadModule.loader)

	s.processModule = newProcessModule(s)
	ls.PreloadModule("process", s.processModule.loader)

	s.metricModule = newMetricModule()
	ls.PreloadModule("metric", s.metricModule.loader)

	ls.PreloadModule("agent", newAgentModule(s.baseInfo.ToLuaTable(ls)).loader)

	libs.Preload(ls)

	if s.modTable != nil {
		// exec 'start' funciton in lua mod
		s.callModFunction0("start")
	}
}

func (s *Script) hasLuaFunction(funcName string) bool {
	if s.modTable != nil {
		fn := s.state.GetField(s.modTable, funcName)
		return fn != nil
	}

	return false
}

func (s *Script) callModFunction0(funcName string) {
	ls := s.state
	fn := ls.GetField(s.modTable, funcName)
	if fn != nil {
		ls.Push(fn)
		err := ls.PCall(0, lua.MultRet, nil)
		if err != nil {
			log.Errorf("callModFunction0 %s failed:%v", funcName, err)
		}
	}
}

func (s *Script) callModFunction1(funcName string, param0 lua.LValue) {
	ls := s.state
	fn := ls.GetField(s.modTable, funcName)
	if fn != nil {
		ls.Push(fn)
		ls.Push(param0)
		err := ls.PCall(1, lua.MultRet, nil)
		if err != nil {
			log.Errorf("callModFunction1 %s failed:%v", funcName, err)
		}
	}
}

func (s *Script) Stop() {
	ls := s.state
	if s.modTable != nil {
		// exec 'stop' funciton in lua mod
		s.callModFunction0("stop")
	}

	ls.Close()
	s.state = nil
	s.modTable = nil
	s.timerModule.clear()
	s.timerModule = nil
	s.downloadModule.clear()
	s.downloadModule = nil
	s.processModule.clear()
	s.processModule = nil
}

func (s *Script) load(fileContent []byte) {
	ls := s.state
	fn, err := ls.LoadString(string(fileContent))
	if err != nil {
		log.Errorf("lstate load string failed:%v", err)
		return
	}

	ls.Push(fn)
	err = ls.PCall(0, lua.MultRet, nil)
	if err != nil {
		log.Errorf("lstate PCall failed:%v", err)
		return
	}

	s.modTable = ls.ToTable(-1)
}
