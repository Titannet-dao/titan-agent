package metrics

import (
	"encoding/json"
	"log"
)

type VMBoxMetricString string

// type VMBoxMetrics []VMBoxMetric

type VMBoxMetric struct {
	ClientID  string `json:"client_id"` // third-party unique id
	Status    string `json:"status"`
	CDNVendor string `json:"cdn_vendor"`
	VMName    string `json:"vm_name"`
	Err       string `json:"err"`
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

func (n VMBoxMetricString) GetStatus() (string, string) {
	var metric VMBoxMetric
	if err := json.Unmarshal([]byte(n), &metric); err != nil {
		log.Printf("Error unmarshaling NodeAppBaseMetrics MetricString: %v", err)
		return "", ""
	}
	return metric.Status, metric.Err
}
