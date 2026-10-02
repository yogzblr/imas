// Package facts collects system information on the sprout side.
package facts

import (
	"net"
	"os"
	"runtime"
	"sync/atomic"
)

// SystemFacts holds auto-collected system properties.
type SystemFacts struct {
	OS          string         `json:"os"`
	Arch        string         `json:"arch"`
	Hostname    string         `json:"hostname"`
	GoVersion   string         `json:"go_version"`
	NumCPU      int            `json:"num_cpu"`
	IPAddresses []string       `json:"ip_addresses"`
	KernelArch  string         `json:"kernel_arch"`
	SproutID    string         `json:"sprout_id,omitempty"`
	Hardware    *HardwareFacts `json:"hardware,omitempty"`
	// SproutVersion is the running sprout's release tag (cmd/sprout's
	// main.Tag, "v<version>"; SetSproutVersion). A fleet update rollout's
	// wave passes only once each sprout reports its new version here
	// (design doc §2.3). Empty for a build without a release tag.
	SproutVersion string `json:"sprout_version,omitempty"`
}

// sproutVersion is what Collect reports as SproutVersion.
var sproutVersion atomic.Pointer[string]

// SetSproutVersion records the running sprout's release tag for Collect
// to report. cmd/sprout calls it once at startup.
func SetSproutVersion(tag string) { sproutVersion.Store(&tag) }

// Collect gathers system facts from the local machine.
func Collect() SystemFacts {
	hostname, _ := os.Hostname()
	sf := SystemFacts{
		OS:          runtime.GOOS,
		Arch:        runtime.GOARCH,
		Hostname:    hostname,
		GoVersion:   runtime.Version(),
		NumCPU:      runtime.NumCPU(),
		IPAddresses: localIPs(),
		KernelArch:  runtime.GOARCH,
	}
	if hw := CollectHardware(); !hw.IsZero() {
		sf.Hardware = &hw
	}
	if v := sproutVersion.Load(); v != nil {
		sf.SproutVersion = *v
	}
	return sf
}

// localIPs returns all non-loopback unicast IP addresses.
func localIPs() []string {
	var ips []string
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ips
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok || ipNet.IP == nil {
			continue
		}
		if ipNet.IP.IsLoopback() || ipNet.IP.IsLinkLocalUnicast() || ipNet.IP.IsLinkLocalMulticast() {
			continue
		}
		ips = append(ips, ipNet.IP.String())
	}
	return ips
}
