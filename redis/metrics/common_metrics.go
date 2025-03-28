package metrics

import (
	"encoding/json"
	"log"
)

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

func (n MetricString) GetStatus() (string, string) {
	var metric NodeAppBaseMetrics
	if err := json.Unmarshal([]byte(n), &metric); err != nil {
		log.Printf("Error unmarshaling NodeAppBaseMetrics MetricString: %v", err)
		return "", ""
	}
	return metric.Status, metric.Err
}
