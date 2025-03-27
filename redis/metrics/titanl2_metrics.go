package metrics

import (
	"encoding/json"
	"log"
)

type TitanL2MetricString string

/*
*
node id: e_3d811888-f36e-4aba-9445-acb6af558800
name: e_3d811888
internal_ip: 172.27.97.232
system version: 0.1.20+git.32c9b88+api1.0.0
disk usage: 62.1757 %
disk space: 98.25GiB
titan disk usage: 0B
titan disk space: 5GiB
fsType: not implement
mac:
download bandwidth: 0B
upload bandwidth: 0B
netflow upload: 0B
netflow download: 0B
cpu percent: 3.23 %
*/

type TitanL2Metrics struct {
	Status string `json:"status"`
	Err    string `json:"err"`
	// NodeInfo string `json:"nodeInfo"`
	NodeInfo string `json:"nodeInfo"`
	NodeID   string `json:"node_id"`
}

type titanL2Metrics struct {
	NodeID            string `line:"0"`
	Name              string `line:"1"`
	InternalIP        string `line:"2"`
	SystemVersion     string `line:"3"`
	DiskUsage         string `line:"4"`
	DiskSpace         string `line:"5"`
	TitanDiskUsage    string `line:"6"`
	TitanDiskSpace    string `line:"7"`
	FsType            string `line:"8"`
	Mac               string `line:"9"`
	DownloadBandwidth string `line:"10"`
	UploadBandwidth   string `line:"11"`
	NetflowUpload     string `line:"12"`
	NetflowDownload   string `line:"13"`
	CpuPercent        string `line:"14"`
}

func (m TitanL2MetricString) GetClientID() string {
	// return m.readRaw().NodeID
	var metric TitanL2Metrics
	if err := json.Unmarshal([]byte(m), &metric); err != nil {
		log.Printf("Error unmarshaling TitanL2Metrics MetricString: %v", err)
		return ""
	}
	return metric.NodeID
}

// func (m TitanL2MetricString) readRaw() TitanL2Metrics {
// 	lines := strings.Split(string(m), "\n")
// 	var out TitanL2Metrics

// 	for _, line := range lines {
// 		line = strings.TrimSpace(line)
// 		if line == "" {
// 			continue
// 		}

// 		parts := strings.SplitN(line, ":", 2)
// 		if len(parts) != 2 {
// 			continue
// 		}
// 		key := strings.TrimSpace(parts[0])
// 		val := strings.TrimSpace(parts[1])

// 		switch strings.ToLower(key) {
// 		case "node id":
// 			out.NodeID = val
// 		case "name":
// 			out.Name = val
// 		case "internal_ip":
// 			out.InternalIP = val
// 		case "system version":
// 			out.SystemVersion = val
// 		case "disk usage":
// 			out.DiskUsage = val
// 		case "disk space":
// 			out.DiskSpace = val
// 		case "titan disk usage":
// 			out.TitanDiskUsage = val
// 		case "titan disk space":
// 			out.TitanDiskSpace = val
// 		case "fstype":
// 			out.FsType = val
// 		case "mac":
// 			out.Mac = val
// 		case "download bandwidth":
// 			out.DownloadBandwidth = val
// 		case "upload bandwidth":
// 			out.UploadBandwidth = val
// 		case "netflow upload":
// 			out.NetflowUpload = val
// 		case "netflow download":
// 			out.NetflowDownload = val
// 		case "cpu percent":
// 			out.CpuPercent = val
// 		default:

// 		}
// 	}
// 	return out
// }

func (m *TitanL2MetricString) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	*m = TitanL2MetricString(s)
	return nil
}

func (m TitanL2MetricString) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(m))
}

func (m TitanL2MetricString) MarshalBinary() ([]byte, error) {
	return json.Marshal(string(m))
}

func (n TitanL2MetricString) GetStatus() (string, string) {
	var metric TitanL2Metrics
	if err := json.Unmarshal([]byte(n), &metric); err != nil {
		log.Printf("Error unmarshaling NodeAppBaseMetrics MetricString: %v", err)
		return "", ""
	}
	return metric.Status, metric.Err
}
