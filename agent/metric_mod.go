package agent

import (
	lua "github.com/yuin/gopher-lua"
)

type MetricModule struct {
	value chan string
}

func newMetricModule() *MetricModule {
	dm := &MetricModule{
		value: make(chan string, 2),
		// downloaderMap: make(map[string]*Downloader),
	}

	return dm
}

func (mm *MetricModule) loader(L *lua.LState) int {
	// register functions to the table
	var exports = map[string]lua.LGFunction{
		"send": mm.sendMetricStub,
	}

	mod := L.SetFuncs(L.NewTable(), exports)

	// returns the module
	L.Push(mod)
	return 1
}

func (mm *MetricModule) sendMetricStub(L *lua.LState) int {
	metric := L.CheckString(1)

	mm.clearMetric()
	mm.sendMetric(metric)
	return 0
}

// clearMetric avoid blocking channels
func (mm *MetricModule) clearMetric() {
	for {
		select {
		case <-mm.value:
		default:
			return
		}
	}
}

func (mm *MetricModule) sendMetric(value string) {
	mm.value <- value
}

func (mm *MetricModule) metric() chan string {
	return mm.value
}
