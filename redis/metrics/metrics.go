package metrics

import (
	"strings"
)

type MetricsI interface {
	GetClientID() string
	GetStatus() (string, string)
	UnmarshalJSON(data []byte) error
	MarshalJSON() ([]byte, error)
	MarshalBinary() ([]byte, error)
}

var FactoryMap = map[string]func(s string) MetricsI{
	"vmbox": func(s string) MetricsI {
		ss := VMBoxMetricString(s)
		return &ss
	},
	"vmboxes": func(s string) MetricsI {
		ss := VMBoxMetricString(s)
		return &ss
	},
	"titanl2": func(s string) MetricsI {
		ss := TitanL2MetricString(s)
		return &ss
	},
	"vps": func(s string) MetricsI {
		ss := VPSMetricString(s)
		return &ss
	},
}

func NewMetricsString(s string, factory string) MetricsI {
	fm := strings.ToLower(factory)
	if factory != "" {
		if factfun, ok := FactoryMap[fm]; ok {
			return factfun(s)
		}
	}
	ss := MetricString(s)
	return &ss
}

// type nodeAppHelper struct {
// 	AppName          string    `redis:"appName"`
// 	MD5              string    `redis:"md5"`
// 	Metric           string    `redis:"metric"`
// 	LastActivityTime time.Time `redis:"lastActivityTime"`
// }

// func (nh *nodeAppHelper) scan(n *NodeApp) error {
// 	n.AppName = nh.AppName
// 	n.MD5 = nh.MD5
// 	n.Metric = NewMetricsString(nh.Metric, n.AppName).ToStruct()
// 	n.LastActivityTime = nh.LastActivityTime

// }

func GetClientID(m string, appName string) string {
	metric := NewMetricsString(m, appName)
	if metric != nil {
		return metric.GetClientID()
	}
	return ""
}
