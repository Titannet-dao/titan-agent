package redis

import (
	"encoding/json"
	"log"
	"strings"
)

type MetricsI interface {
	GetClientID() string
	UnmarshalJSON(data []byte) error
	MarshalJSON() ([]byte, error)
	MarshalBinary() ([]byte, error)
	Len() int
	// ToStruct() interface{}
}

type VMBoxMetricString string

// type VMBoxMetrics []VMBoxMetric

type VMBoxMetric struct {
	ClientID  string `json:"client_id"` // third-party unique id
	Status    string `json:"status"`
	CDNVendor string `json:"cdn_vendor"`
	VMName    string `json:"vm_name"`
}

func (m VMBoxMetricString) GetClientID() string {
	var metric VMBoxMetric
	if err := json.Unmarshal([]byte(m), &metric); err != nil {
		log.Printf("Error unmarshaling VMBoxMetrics MetricString: %v", err)
		return ""
	}

	return metric.ClientID
}

func (m *VMBoxMetricString) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	*m = VMBoxMetricString(s)
	return nil
}

func (m VMBoxMetricString) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(m))
}

func (m VMBoxMetricString) MarshalBinary() ([]byte, error) {
	return json.Marshal(string(m))
}

func (m VMBoxMetricString) Len() int {
	return len(m)
}

// func (m VMBoxMetricString) ToStruct() interface{} {
// 	var metric VMBoxMetrics
// 	if err := json.Unmarshal([]byte(m), &metric); err != nil {
// 		log.Printf("Error unmarshaling VMBoxMetrics MetricString: %v", err)
// 		return nil
// 	}
// 	return metric
// }

type MetricString string

type NodeAppBaseMetrics struct {
	ClientID string `json:"client_id"` // third-party unique id
	Status   string `json:"status"`
	Err      string `json:"err"`
}

func (m MetricString) GetClientID() string {
	var metric NodeAppBaseMetrics
	if err := json.Unmarshal([]byte(m), &metric); err != nil {
		log.Printf("Error unmarshaling NodeAppBaseMetrics MetricString: %v", err)
		return ""
	}
	return metric.ClientID
}

func (m *MetricString) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	*m = MetricString(s)
	return nil
}

func (m MetricString) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(m))
}

func (m MetricString) MarshalBinary() ([]byte, error) {
	return json.Marshal(string(m))
}

func (m MetricString) Len() int {
	return len(m)
}

// func (m MetricString) ToStruct() interface{} {
// 	var metric NodeAppBaseMetrics
// 	if err := json.Unmarshal([]byte(m), &metric); err != nil {
// 		log.Printf("Error unmarshaling MetricString: %v", err)
// 		return nil
// 	}
// 	return metric
// }

var FactoryMap = map[string]func(s string) MetricsI{
	"vmbox": func(s string) MetricsI {
		ss := VMBoxMetricString(s)
		return &ss
	},
	"vmboxes": func(s string) MetricsI {
		ss := VMBoxMetricString(s)
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
