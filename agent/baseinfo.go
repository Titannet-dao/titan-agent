package agent

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/jaypipes/ghw"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
	lua "github.com/yuin/gopher-lua"
	"golang.org/x/exp/constraints"
)

// Used by agent
type AgentInfo struct {
	WorkingDir      string
	Version         string
	ServerURL       string
	ScriptFileName  string
	ScriptInvterval int
	Channel         string
	ControllerKey   string
}

// Used by controller
type ControllerInfo struct {
	WorkingDir      string
	Version         string
	ServerURL       string
	ScriptInvterval int
	Channel         string
}

type AppInfo struct {
	ControllerInfo
	AppRootDir string
	AppDir     string
}

type BaseInfo struct {
	hostName        string
	os              string
	platform        string
	platformVersion string
	bootTime        int64
	arch            string

	macs string

	cpuModuleName string
	cpuCores      int
	cpuMhz        float64
	cpuUsage      float64

	gpu string

	totalMemory     int64
	usedMemory      int64
	availableMemory int64
	memoryModel     string

	netIRate float64
	netORate float64

	baseboard string

	uuid                string
	androidID           string
	androidSerialNumber string

	totalDisk int64
	freeDisk  int64
	diskModel string

	agentInfo *AgentInfo

	appInfo *AppInfo
}

func NewBaseInfo(agentInfo *AgentInfo, appInfo *AppInfo) *BaseInfo {
	info, err := host.Info()
	if err != nil {
		log.Printf("Get host info failed: %v", err)
	}

	baseInfo := &BaseInfo{agentInfo: agentInfo, appInfo: appInfo}
	// host info
	if info != nil {
		baseInfo.hostName = info.Hostname
		baseInfo.os = info.OS
		baseInfo.platform = info.Platform
		baseInfo.platformVersion = info.PlatformVersion
		baseInfo.bootTime = int64(info.BootTime)
		baseInfo.arch = info.KernelArch
	}

	var macs = ""
	interfaces, err := net.Interfaces()
	if err != nil {
		log.Printf("Get interfaces failed: %v", err)
	}
	for _, interf := range interfaces {
		macs += fmt.Sprintf("%s:%s,", interf.Name, interf.HardwareAddr)
	}
	baseInfo.macs = strings.TrimSuffix(macs, ",")

	// cpu info
	cpuInfo, err := cpu.Info()
	if err == nil && len(cpuInfo) > 0 {
		baseInfo.cpuModuleName = cpuInfo[0].ModelName
		baseInfo.cpuMhz = cpuInfo[0].Mhz
		baseInfo.cpuCores = int(cpuInfo[0].Cores)
		if baseInfo.cpuCores == 1 {
			baseInfo.cpuCores = len(cpuInfo)
		}
	}

	// gpu
	gpuInfo, err := ghw.GPU()
	if err != nil {
		log.Printf("Get GPU info failed: %v", err)
	}
	if gpuInfo != nil && len(gpuInfo.GraphicsCards) > 0 {
		last := gpuInfo.GraphicsCards[len(gpuInfo.GraphicsCards)-1]
		if last.DeviceInfo != nil && last.DeviceInfo.Vendor != nil && last.DeviceInfo.Product != nil {
			baseInfo.gpu = fmt.Sprintf("%s, %s", last.DeviceInfo.Vendor.ID, last.DeviceInfo.Product.Name)
		}
	}

	// memory info
	memory, err := mem.VirtualMemory()
	if err != nil {
		log.Printf("Get memory info failed: %v", err)
	}
	if memory != nil {
		baseInfo.totalMemory = int64(memory.Total)
		baseInfo.usedMemory = int64(memory.Used)
		baseInfo.availableMemory = int64(memory.Available)
	}

	// ram info
	m, err := ghw.Memory()
	if err != nil {
		log.Printf("Get memory info failed: %v", err)
	}
	if m != nil && len(m.Modules) > 0 {
		baseInfo.memoryModel = m.Modules[0].Vendor
	}

	// blk info
	blk, err := ghw.Block()
	if err != nil {
		log.Printf("Get disk info failed: %v", err)
	}
	if blk != nil && len(blk.Disks) > 0 {
		var disks []string
		for _, d := range blk.Disks {
			disks = append(disks, d.Model)
		}
		baseInfo.diskModel = strings.Join(disks, ", ")
	}

	baseboard, err := ghw.Baseboard()
	if err != nil {
		log.Printf("Get baseboard info failed: %v", err)
	}
	if baseboard != nil {
		baseInfo.baseboard = fmt.Sprintf("Vendor:%s,Product:%s", baseboard.Vendor, baseboard.Product)
	}

	baseInfo.getAndroidID()
	baseInfo.getUUID()
	baseInfo.getAndroidSerialNumber()
	baseInfo.getDiskUsage()
	return baseInfo
}

func (baseInfo *BaseInfo) getAndroidID() {
	if runtime.GOOS != "linux" && runtime.GOOS != "android" {
		return
	}

	androidID, err := runCmd("settings get secure android_id")
	if err != nil {
		return
	}

	baseInfo.androidID = androidID
}

func (baseInfo *BaseInfo) getUUID() {
	// get windows uuid
	if runtime.GOOS == "windows" {
		uuid, err := getWindowsUUID()
		if err == nil {
			baseInfo.uuid = uuid
		} else {
			fmt.Println("getUUID failed:", err.Error())
		}
		return
	}

	if runtime.GOOS == "linux" {
		// get androi,linux,darwin uuid
		machineID, err := runCmd("cat /etc/machine-id")
		if err == nil {
			baseInfo.uuid = formatToUUID(machineID)
		} else {
			fmt.Println("getUUID failed:", err.Error())
		}

		return
	}

	if runtime.GOOS == "android" {
		androidID, err := runCmd("settings get secure android_id")
		if err == nil {
			baseInfo.uuid = generateUUIDFromString(androidID)
		} else {
			fmt.Println("getUUID failed:", err.Error())
		}
		return
	}

	// TODO add darwin

}

func (baseInfo *BaseInfo) getAndroidSerialNumber() {
	if runtime.GOOS != "linux" && runtime.GOOS != "android" {
		return
	}

	serialno, err := runCmd("getprop ro.serialno")
	if err != nil {
		return
	}

	baseInfo.androidSerialNumber = serialno
}

func getWindowsUUID() (string, error) {
	cmd := exec.Command("c:/Windows/System32/wbem/wmic.exe", "csproduct", "get", "uuid")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	result := strings.TrimSpace(string(output))
	lines := strings.Split(result, "\n")
	if len(lines) > 1 {

		return strings.TrimSpace(lines[1]), nil
	}

	return "", fmt.Errorf("UUID not found")
}

func formatToUUID(id string) string {
	if len(id) <= 20 {
		return id
	}

	return fmt.Sprintf("%s-%s-%s-%s-%s", id[0:8], id[8:12], id[12:16], id[16:20], id[20:])
}

func generateUUIDFromString(s string) string {
	hash := sha256.Sum256([]byte(s))
	hashHex := hex.EncodeToString(hash[:])
	return fmt.Sprintf("%s-%s-%s-%s-%s", hashHex[0:8], hashHex[8:12], hashHex[12:16], hashHex[16:20], hashHex[20:32])
}

func runCmd(command string) (string, error) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux", "darwin", "android":
		cmd = exec.Command("/bin/sh", "-c", command)
	case "windows":
		cmd = exec.Command("cmd.exe", "/C", command)
	default:
		return "", fmt.Errorf("unsupported os")
	}

	stdout, stderr := bytes.Buffer{}, bytes.Buffer{}
	cmd.Stderr = &stderr
	cmd.Stdout = &stdout

	if err := cmd.Start(); err != nil {
		return "", err
	}

	done := make(chan error)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case <-time.After(3 * time.Second):
		cmd.Process.Kill()
		return "", fmt.Errorf("timeout")
	case err := <-done:
		if err != nil {
			return "", fmt.Errorf("%s,%s", err.Error(), stderr.String())
		}
		if len(stderr.String()) > 0 {
			fmt.Println(stderr)
		}
		return strings.Trim(stdout.String(), "\n"), nil
	}
}

func (baseInfo *BaseInfo) getDiskUsage() {
	var workingDir string
	if baseInfo.agentInfo != nil && len(baseInfo.agentInfo.WorkingDir) > 0 {
		workingDir = baseInfo.agentInfo.WorkingDir
	} else if baseInfo.appInfo != nil && len(baseInfo.appInfo.WorkingDir) > 0 {
		workingDir = baseInfo.appInfo.WorkingDir
	}

	if len(workingDir) > 0 {
		usage, err := disk.Usage(workingDir)
		if err == nil {
			baseInfo.totalDisk = int64(usage.Total)
			baseInfo.freeDisk = int64(usage.Free)
		}
	}
}

func (baseInfo *BaseInfo) ToURLQuery() url.Values {
	query := url.Values{}
	query.Add("hostname", baseInfo.hostName)
	query.Add("os", baseInfo.os)
	query.Add("platform", baseInfo.platform)
	query.Add("platformVersion", baseInfo.platformVersion)
	query.Add("bootTime", fmt.Sprintf("%d", baseInfo.bootTime))
	query.Add("arch", baseInfo.arch)

	query.Add("macs", baseInfo.macs)

	query.Add("cpuModuleName", baseInfo.cpuModuleName)
	query.Add("cpuCores", fmt.Sprintf("%d", baseInfo.cpuCores))
	query.Add("cpuMhz", fmt.Sprintf("%f", baseInfo.cpuMhz))
	query.Add("cpuUsage", fmt.Sprintf("%f", baseInfo.cpuUsage))

	query.Add("gpu", baseInfo.gpu)

	query.Add("totalmemory", fmt.Sprintf("%d", baseInfo.totalMemory))
	query.Add("usedMemory", fmt.Sprintf("%d", baseInfo.usedMemory))
	query.Add("availableMemory", fmt.Sprintf("%d", baseInfo.availableMemory))
	query.Add("memoryModel", baseInfo.memoryModel)

	query.Add("netIRate", fmt.Sprintf("%f", baseInfo.netIRate))
	query.Add("netORate", fmt.Sprintf("%f", baseInfo.netORate))

	query.Add("baseboard", baseInfo.baseboard)

	query.Add("uuid", baseInfo.uuid)
	query.Add("androidID", baseInfo.androidID)
	query.Add("androidSerialNumber", baseInfo.androidSerialNumber)

	query.Add("totalDisk", fmt.Sprintf("%d", baseInfo.totalDisk))
	query.Add("freeDisk", fmt.Sprintf("%d", baseInfo.freeDisk))
	query.Add("diskModel", baseInfo.diskModel)

	if baseInfo.agentInfo != nil {
		query.Add("version", baseInfo.agentInfo.Version)
		query.Add("channel", baseInfo.agentInfo.Channel)
		query.Add("workingDir", baseInfo.agentInfo.WorkingDir)
	}

	if baseInfo.appInfo != nil {
		query.Add("version", baseInfo.appInfo.Version)
		query.Add("channel", baseInfo.appInfo.Channel)
		query.Add("workingDir", baseInfo.appInfo.WorkingDir)
	}

	return query
}

func (baseInfo *BaseInfo) ToLuaTable(L *lua.LState) *lua.LTable {
	t := L.NewTable()
	t.RawSet(lua.LString("hostname"), lua.LString(baseInfo.hostName))
	t.RawSet(lua.LString("os"), lua.LString(baseInfo.os))
	t.RawSet(lua.LString("platform"), lua.LString(baseInfo.platform))
	t.RawSet(lua.LString("platformVersion"), lua.LString(baseInfo.platformVersion))
	t.RawSet(lua.LString("bootTime"), lua.LNumber(baseInfo.bootTime))
	t.RawSet(lua.LString("arch"), lua.LString(baseInfo.arch))

	t.RawSet(lua.LString("macs"), lua.LString(baseInfo.macs))

	t.RawSet(lua.LString("cpuModuleName"), lua.LString(baseInfo.cpuModuleName))
	t.RawSet(lua.LString("cpuCores"), lua.LNumber(baseInfo.cpuCores))
	t.RawSet(lua.LString("cpuMhz"), lua.LNumber(baseInfo.cpuMhz))
	t.RawSet(lua.LString("cpuUsage"), lua.LNumber(baseInfo.cpuUsage))

	t.RawSet(lua.LString("gpu"), lua.LString(baseInfo.gpu))

	t.RawSet(lua.LString("totalmemory"), lua.LNumber(baseInfo.totalMemory))
	t.RawSet(lua.LString("usedMemory"), lua.LNumber(baseInfo.usedMemory))
	t.RawSet(lua.LString("availableMemory"), lua.LNumber(baseInfo.availableMemory))
	t.RawSet(lua.LString("memoryModel"), lua.LString(baseInfo.memoryModel))

	t.RawSet(lua.LString("netIRate"), lua.LNumber(baseInfo.netIRate))
	t.RawSet(lua.LString("netORate"), lua.LNumber(baseInfo.netORate))

	t.RawSet(lua.LString("baseboard"), lua.LString(baseInfo.baseboard))

	t.RawSet(lua.LString("uuid"), lua.LString(baseInfo.uuid))
	t.RawSet(lua.LString("androidID"), lua.LString(baseInfo.androidID))
	t.RawSet(lua.LString("androidSerialNumber"), lua.LString(baseInfo.androidSerialNumber))

	t.RawSet(lua.LString("totalDisk"), lua.LNumber(baseInfo.totalDisk))
	t.RawSet(lua.LString("freeDisk"), lua.LNumber(baseInfo.freeDisk))
	t.RawSet(lua.LString("diskModel"), lua.LString(baseInfo.diskModel))

	if baseInfo.agentInfo != nil {
		t.RawSet(lua.LString("workingDir"), lua.LString(baseInfo.agentInfo.WorkingDir))
		t.RawSet(lua.LString("version"), lua.LString(baseInfo.agentInfo.Version))
		t.RawSet(lua.LString("serverURL"), lua.LString(baseInfo.agentInfo.ServerURL))
		t.RawSet(lua.LString("scriptFileName"), lua.LString(baseInfo.agentInfo.ScriptFileName))
		t.RawSet(lua.LString("scriptInvterval"), lua.LNumber(baseInfo.agentInfo.ScriptInvterval))
		t.RawSet(lua.LString("channel"), lua.LString(baseInfo.agentInfo.Channel))
		t.RawSet(lua.LString("key"), lua.LString(baseInfo.agentInfo.ControllerKey))
	}

	if baseInfo.appInfo != nil {
		t.RawSet(lua.LString("workingDir"), lua.LString(baseInfo.appInfo.WorkingDir))
		t.RawSet(lua.LString("version"), lua.LString(baseInfo.appInfo.Version))
		t.RawSet(lua.LString("serverURL"), lua.LString(baseInfo.appInfo.ServerURL))
		t.RawSet(lua.LString("scriptInvterval"), lua.LNumber(baseInfo.appInfo.ScriptInvterval))
		t.RawSet(lua.LString("appRootDir"), lua.LString(baseInfo.appInfo.AppRootDir))
		t.RawSet(lua.LString("appDir"), lua.LString(baseInfo.appInfo.AppDir))
		t.RawSet(lua.LString("channel"), lua.LString(baseInfo.appInfo.Channel))
	}

	return t
}

func (baseInfo *BaseInfo) UUID() string {
	return baseInfo.uuid
}

func (baseInfo *BaseInfo) SetTraffice(n NetworkStatsRate) {
	baseInfo.netIRate = n.IRate
	baseInfo.netORate = n.ORate
}

func (b *BaseInfo) SetCpuUsage(cpuUsage float64) {
	b.cpuUsage = cpuUsage
}

func calAvg[T constraints.Integer | constraints.Float](arr []T) float64 {
	if len(arr) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range arr {
		sum += float64(v)
	}
	return sum / float64(len(arr))
}
