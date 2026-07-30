// Package system provides access to Linux system metrics such as CPU, memory,
// disk usage, network interface statistics, and server uptime.
package system

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// Metrics holds a snapshot of system resource usage.
type Metrics struct {
	UptimeSeconds float64            `json:"uptime_seconds"`
	CPUPercent    float64            `json:"cpu_percent"`
	MemTotal      uint64             `json:"mem_total_bytes"`
	MemUsed       uint64             `json:"mem_used_bytes"`
	MemPercent    float64            `json:"mem_percent"`
	DiskTotal     uint64             `json:"disk_total_bytes"`
	DiskUsed      uint64             `json:"disk_used_bytes"`
	DiskPercent   float64            `json:"disk_percent"`
	Interfaces    []InterfaceMetrics `json:"interfaces"`
	LoadAvg       [3]float64         `json:"load_avg"`
}

// InterfaceMetrics holds traffic counters for a network interface.
type InterfaceMetrics struct {
	Name      string             `json:"name"`
	Alias     string             `json:"alias,omitempty"`
	Addresses []InterfaceAddress `json:"addresses,omitempty"`
	RxBytes   uint64             `json:"rx_bytes"`
	TxBytes   uint64             `json:"tx_bytes"`
	RxPackets uint64             `json:"rx_packets"`
	TxPackets uint64             `json:"tx_packets"`
	RxErrors  uint64             `json:"rx_errors"`
	TxErrors  uint64             `json:"tx_errors"`
	RxDropped uint64             `json:"rx_dropped"`
	TxDropped uint64             `json:"tx_dropped"`
}

// InterfaceAddress represents an IP address configured on an interface.
type InterfaceAddress struct {
	Family string `json:"family"`
	IP     string `json:"ip"`
	Subnet string `json:"subnet"`
	CIDR   string `json:"cidr"`
}

// Collector collects system metrics.
type Collector struct {
	prevCPUStat cpuStat
}

// NewCollector creates a new Collector.
func NewCollector() *Collector {
	c := &Collector{}
	c.prevCPUStat, _ = readCPUStat()
	return c
}

// Collect gathers a snapshot of system metrics.
func (c *Collector) Collect() (*Metrics, error) {
	m := &Metrics{}

	m.UptimeSeconds = readUptime()
	m.LoadAvg = readLoadAvg()

	// CPU
	cur, err := readCPUStat()
	if err == nil {
		m.CPUPercent = calcCPUPercent(c.prevCPUStat, cur)
		c.prevCPUStat = cur
	}

	// Memory
	memInfo, err := readMemInfo()
	if err == nil {
		m.MemTotal = memInfo["MemTotal"] * 1024
		free := memInfo["MemFree"] * 1024
		buffers := memInfo["Buffers"] * 1024
		cached := memInfo["Cached"] * 1024
		m.MemUsed = m.MemTotal - free - buffers - cached
		if m.MemTotal > 0 {
			m.MemPercent = float64(m.MemUsed) / float64(m.MemTotal) * 100
		}
	}

	// Disk (root filesystem)
	disk, err := diskUsage("/")
	if err == nil {
		m.DiskTotal = disk.total
		m.DiskUsed = disk.used
		if disk.total > 0 {
			m.DiskPercent = float64(disk.used) / float64(disk.total) * 100
		}
	}

	// Network interfaces
	m.Interfaces, _ = readNetDev()

	return m, nil
}

// ─── uptime ──────────────────────────────────────────────────────────────────

func readUptime() float64 {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0
	}
	v, _ := strconv.ParseFloat(fields[0], 64)
	return v
}

// ReadBootID returns the kernel's boot_id — a UUID that stays stable for the
// entire lifetime of the current kernel boot and changes on every real
// reboot. Unlike /proc/uptime (which only tells you how long the KERNEL has
// been up), comparing successive boot_ids is how callers distinguish "the
// machine actually rebooted" from "just this process restarted" (e.g. a
// `systemctl restart` from a package upgrade).
func ReadBootID() (string, error) {
	data, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// ─── load average ────────────────────────────────────────────────────────────

func readLoadAvg() [3]float64 {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return [3]float64{}
	}
	fields := strings.Fields(string(data))
	var la [3]float64
	for i := 0; i < 3 && i < len(fields); i++ {
		la[i], _ = strconv.ParseFloat(fields[i], 64)
	}
	return la
}

// ─── CPU ─────────────────────────────────────────────────────────────────────

type cpuStat struct {
	user, nice, system, idle, iowait, irq, softirq, steal uint64
	ts                                                    time.Time
}

func (s cpuStat) total() uint64 {
	return s.user + s.nice + s.system + s.idle + s.iowait + s.irq + s.softirq + s.steal
}

func (s cpuStat) busy() uint64 {
	return s.user + s.nice + s.system + s.irq + s.softirq + s.steal
}

func readCPUStat() (cpuStat, error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return cpuStat{}, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 8 {
			break
		}
		parse := func(s string) uint64 {
			v, _ := strconv.ParseUint(s, 10, 64)
			return v
		}
		return cpuStat{
			user:    parse(fields[1]),
			nice:    parse(fields[2]),
			system:  parse(fields[3]),
			idle:    parse(fields[4]),
			iowait:  parse(fields[5]),
			irq:     parse(fields[6]),
			softirq: parse(fields[7]),
			steal:   safeField(fields, 8),
			ts:      time.Now(),
		}, nil
	}
	return cpuStat{}, fmt.Errorf("cpu line not found in /proc/stat")
}

func safeField(fields []string, idx int) uint64 {
	if idx >= len(fields) {
		return 0
	}
	v, _ := strconv.ParseUint(fields[idx], 10, 64)
	return v
}

func calcCPUPercent(prev, cur cpuStat) float64 {
	totalDiff := float64(cur.total()) - float64(prev.total())
	busyDiff := float64(cur.busy()) - float64(prev.busy())
	if totalDiff <= 0 {
		return 0
	}
	return busyDiff / totalDiff * 100
}

// ─── Memory ──────────────────────────────────────────────────────────────────

func readMemInfo() (map[string]uint64, error) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	info := make(map[string]uint64)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		valStr := strings.TrimSpace(parts[1])
		valStr = strings.TrimSuffix(valStr, " kB")
		valStr = strings.TrimSpace(valStr)
		v, _ := strconv.ParseUint(valStr, 10, 64)
		info[key] = v
	}
	return info, scanner.Err()
}

// ─── Disk ─────────────────────────────────────────────────────────────────────

type diskInfo struct {
	total, used, free uint64
}

func diskUsage(path string) (diskInfo, error) {
	var stat diskInfo
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return stat, fmt.Errorf("not a directory: %s", path)
	}
	// Read /proc/mounts and /proc/diskstats is complex; use statfs via syscall.
	// For portability use a simple df-equivalent via reading /proc/mounts.
	// We'll use the syscall package which works on Linux.
	return diskUsageSyscall(path)
}

// ─── Network ─────────────────────────────────────────────────────────────────

func readNetDev() ([]InterfaceMetrics, error) {
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var ifaces []InterfaceMetrics
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		if lineNum <= 2 {
			continue // Skip header lines
		}
		line := strings.TrimSpace(scanner.Text())
		colonIdx := strings.Index(line, ":")
		if colonIdx < 0 {
			continue
		}
		name := strings.TrimSpace(line[:colonIdx])
		fields := strings.Fields(line[colonIdx+1:])
		if len(fields) < 16 {
			continue
		}
		parse := func(s string) uint64 {
			v, _ := strconv.ParseUint(s, 10, 64)
			return v
		}
		ifaces = append(ifaces, InterfaceMetrics{
			Name:      name,
			RxBytes:   parse(fields[0]),
			RxPackets: parse(fields[1]),
			RxErrors:  parse(fields[2]),
			RxDropped: parse(fields[3]),
			TxBytes:   parse(fields[8]),
			TxPackets: parse(fields[9]),
			TxErrors:  parse(fields[10]),
			TxDropped: parse(fields[11]),
		})
	}
	if err := scanner.Err(); err != nil {
		return ifaces, err
	}

	ifaceList, err := net.Interfaces()
	if err != nil {
		return ifaces, nil
	}

	addrByName := make(map[string][]InterfaceAddress, len(ifaceList))
	for _, iface := range ifaceList {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet.IP == nil {
				continue
			}
			ip := ipNet.IP.String()
			maskSize, _ := ipNet.Mask.Size()
			family := "ipv4"
			if ipNet.IP.To4() == nil {
				family = "ipv6"
			}
			addrByName[iface.Name] = append(addrByName[iface.Name], InterfaceAddress{
				Family: family,
				IP:     ip,
				Subnet: fmt.Sprintf("/%d", maskSize),
				CIDR:   ipNet.String(),
			})
		}
	}

	for i := range ifaces {
		ifaces[i].Addresses = addrByName[ifaces[i].Name]
	}

	return ifaces, nil
}

// UptimeString returns a human-readable uptime string.
func UptimeString(seconds float64) string {
	d := time.Duration(seconds) * time.Second
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60
	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	return fmt.Sprintf("%dm", minutes)
}
