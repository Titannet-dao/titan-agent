package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
)

type NetworkStats struct {
	Ibytes uint64
	Obytes uint64
}

type NetworkStatsRate struct {
	IRate float64 // Bytes per second received
	ORate float64 // Bytes per second sent
}

func MonitorNetworkStats(ctx context.Context, interval time.Duration) (<-chan NetworkStatsRate, error) {
	outputChan := make(chan NetworkStatsRate)

	go func() {
		defer close(outputChan)
		var previousStats NetworkStats
		var err error

		previousStats, err = getNetworkStats()
		if err != nil {
			fmt.Printf("Error fetching initial stats: %v\n", err)
			return
		}

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				currentStats, err := getNetworkStats()
				if err != nil {
					fmt.Printf("Error fetching network stats: %v\n", err)
					continue
				}

				ibytesDiff := currentStats.Ibytes - previousStats.Ibytes
				obytesDiff := currentStats.Obytes - previousStats.Obytes

				seconds := interval.Seconds()
				outputChan <- NetworkStatsRate{
					IRate: float64(ibytesDiff) / seconds,
					ORate: float64(obytesDiff) / seconds,
				}

				previousStats = currentStats

			case <-ctx.Done():
				return
			}
		}
	}()

	return outputChan, nil
}

func getNetworkStats() (NetworkStats, error) {
	switch runtime.GOOS {
	case "darwin":
		return getNetworkStatsMacOS()
	case "linux", "android":
		return getNetworkStatsLinux()
	case "windows":
		return getNetworkStatsWindows()
	default:
		return NetworkStats{}, fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

func getNetworkStatsLinux() (NetworkStats, error) {
	output, err := exec.Command("cat", "/proc/net/dev").Output()
	if err != nil {
		return NetworkStats{}, err
	}

	lines := strings.Split(string(output), "\n")
	var totalStats NetworkStats

	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 10 || !strings.Contains(line, ":") {
			continue
		}

		ibytes, _ := strconv.ParseUint(fields[1], 10, 64) // Bytes received
		obytes, _ := strconv.ParseUint(fields[9], 10, 64) // Bytes sent

		totalStats.Ibytes += ibytes
		totalStats.Obytes += obytes
	}

	return totalStats, nil
}

func getNetworkStatsMacOS() (NetworkStats, error) {
	cmd := exec.Command("netstat", "-ib")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return NetworkStats{}, err
	}

	return parseNetstatOutput(out.String())
}

func parseNetstatOutput(output string) (NetworkStats, error) {
	lines := strings.Split(output, "\n")
	var totalStats NetworkStats
	seen := make(map[string]bool)

	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}

		interfaceName := fields[0]
		if seen[interfaceName] || strings.HasPrefix(interfaceName, "utun") || strings.HasPrefix(interfaceName, "vmnet") {
			continue // Skip duplicate or virtual interfaces
		}
		seen[interfaceName] = true

		ibytes, _ := strconv.ParseUint(fields[6], 10, 64) // Bytes received
		obytes, _ := strconv.ParseUint(fields[9], 10, 64) // Bytes sent

		totalStats.Ibytes += ibytes
		totalStats.Obytes += obytes
	}

	return totalStats, nil
}

func getNetworkStatsWindows() (NetworkStats, error) {
	cmd := exec.Command("powershell", "-Command", `
	Get-Counter -Counter "\Network Interface(*)\Bytes Received/sec", "\Network Interface(*)\Bytes Sent/sec" |
	Select-Object -ExpandProperty CounterSamples |
	ConvertTo-Json
	`)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return NetworkStats{}, err
	}

	type CounterSample struct {
		Path         string  `json:"Path"`
		InstanceName string  `json:"InstanceName"`
		CookedValue  float64 `json:"CookedValue"`
	}

	var samples []CounterSample
	if err := json.Unmarshal(out.Bytes(), &samples); err != nil {
		return NetworkStats{}, fmt.Errorf("json unmarshal error: %v", err)
	}

	var totalStats NetworkStats
	for _, s := range samples {
		if strings.Contains(strings.ToLower(s.Path), "bytes received/sec") {
			totalStats.Ibytes += uint64(s.CookedValue)
		} else if strings.Contains(strings.ToLower(s.Path), "bytes sent/sec") {
			totalStats.Obytes += uint64(s.CookedValue)
		}
	}

	return totalStats, nil
}

func parseWindowsOutput(output string) (NetworkStats, error) {
	lines := strings.Split(output, "\n")
	var totalStats NetworkStats

	for _, line := range lines {
		if !strings.Contains(line, "\\Network Interface") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return NetworkStats{}, err
		}

		if strings.Contains(fields[0], "Bytes Received/sec") {
			totalStats.Ibytes += value
		} else if strings.Contains(fields[0], "Bytes Sent/sec") {
			totalStats.Obytes += value
		}
	}

	return totalStats, nil
}

func GetCpuRealtimeUsage() float64 {
	usages, _ := cpu.Percent(time.Second, false)
	return calAvg(usages)
}
