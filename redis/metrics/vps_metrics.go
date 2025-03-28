package metrics

import (
	"bufio"
	"encoding/json"
	"log"
	"regexp"
	"strings"
)

type VPSMetricString string

type VPSMetric struct {
	ClientID string `json:"client_id"` // third-party unique id
	Status   string `json:"status"`
	Err      string `json:"err"`
	Cgourp   string `json:"cgroup"`
}

func (m VPSMetricString) GetClientID() string {
	var metric VPSMetric
	if err := json.Unmarshal([]byte(m), &metric); err != nil {
		log.Printf("Error unmarshaling VMBoxMetrics MetricString: %v", err)
		return ""
	}

	return metric.ClientID
}

func (m *VPSMetricString) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	*m = VPSMetricString(s)
	return nil
}

func (m VPSMetricString) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(m))
}

func (m VPSMetricString) MarshalBinary() ([]byte, error) {
	return json.Marshal(string(m))
}

func (n VPSMetricString) GetStatus() (string, string) {
	var metric VPSMetric
	if err := json.Unmarshal([]byte(n), &metric); err != nil {
		log.Printf("Error unmarshaling NodeAppBaseMetrics MetricString: %v", err)
		return "", ""
	}
	return metric.Status, metric.Err
}

func (n VPSMetricString) EnableCgroup() (bool, string, error) {
	var metric VPSMetric
	if err := json.Unmarshal([]byte(n), &metric); err != nil {
		log.Printf("Error unmarshaling NodeAppBaseMetrics MetricString: %v", err)
		return false, metric.Cgourp, err
	}

	return checkEnableCgroup1(metric.Cgourp), metric.Cgourp, nil
}

func checkEnableCgroup1(s string) bool {
	/*
		tmpfs on /sys/fs/cgroup type tmpfs (ro,nosuid,nodev,noexec,mode=755)
		cgroup on /sys/fs/cgroup/unified type cgroup2 (rw,nosuid,nodev,noexec,relatime,nsdelegate)
		cgroup on /sys/fs/cgroup/systemd type cgroup (rw,nosuid,nodev,noexec,relatime,xattr,name=systemd)
		cgroup on /sys/fs/cgroup/net_cls,net_prio type cgroup (rw,nosuid,nodev,noexec,relatime,net_cls,net_prio)
		cgroup on /sys/fs/cgroup/memory type cgroup (rw,nosuid,nodev,noexec,relatime,memory)
		cgroup on /sys/fs/cgroup/perf_event type cgroup (rw,nosuid,nodev,noexec,relatime,perf_event)
		cgroup on /sys/fs/cgroup/cpu,cpuacct type cgroup (rw,nosuid,nodev,noexec,relatime,cpu,cpuacct)
		cgroup on /sys/fs/cgroup/devices type cgroup (rw,nosuid,nodev,noexec,relatime,devices)
		cgroup on /sys/fs/cgroup/cpuset type cgroup (rw,nosuid,nodev,noexec,relatime,cpuset)
		cgroup on /sys/fs/cgroup/rdma type cgroup (rw,nosuid,nodev,noexec,relatime,rdma)
		cgroup on /sys/fs/cgroup/pids type cgroup (rw,nosuid,nodev,noexec,relatime,pids)
		cgroup on /sys/fs/cgroup/freezer type cgroup (rw,nosuid,nodev,noexec,relatime,freezer)
		cgroup on /sys/fs/cgroup/hugetlb type cgroup (rw,nosuid,nodev,noexec,relatime,hugetlb)
		cgroup on /sys/fs/cgroup/blkio type cgroup (rw,nosuid,nodev,noexec,relatime,blkio)
	*/
	re := regexp.MustCompile(`^\S+ on (/sys/fs/cgroup/.+) type cgroup .*?\brw\b`)

	scanner := bufio.NewScanner(strings.NewReader(s))
	for scanner.Scan() {
		if re.MatchString(scanner.Text()) {
			return true
		}
	}
	return false
}
