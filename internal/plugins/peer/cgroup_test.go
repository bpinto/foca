package peer

import (
	"strings"
	"testing"
)

func TestContainerIDFromCgroup(t *testing.T) {
	id := strings.Repeat("0123456789abcdef", 4)
	other := strings.Repeat("fedcba9876543210", 4)
	for _, c := range []struct{ name, cgroup, want string }{
		{"docker, systemd, v2", "0::/system.slice/docker-" + id + ".scope\n", id},
		{"docker, cgroupfs, v1", "12:memory:/docker/" + id + "\n11:cpu,cpuacct:/docker/" + id + "\n1:name=systemd:/docker/" + id + "\n", id},
		{"rootless podman", "0::/user.slice/user-1000.slice/user@1000.service/user.slice/libpod-" + id + ".scope/container\n", id},
		{"podman, cgroupfs", "0::/libpod_parent/libpod-" + id + "\n", id},
		{"containerd under Kubernetes", "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1234.slice/cri-containerd-" + id + ".scope\n", id},
		{"CRI-O", "0::/kubepods.slice/kubepods-pod1234.slice/crio-" + id + ".scope\n", id},
		{"Kubernetes, cgroupfs", "0::/kubepods/burstable/pod1234/" + id + "\n", id},
		{"nested: the outer container", "0::/docker/" + id + "/docker/" + other + "\n", id},
		{"conmon is not the container", "0::/machine.slice/libpod-conmon-" + id + ".scope\n", ""},
		{"a host process", "0::/user.slice/user-1000.slice/session-2.scope\n", ""},
		{"a short id", "0::/docker/" + id[:12] + "\n", ""},
		{"upper-case hex", "0::/system.slice/docker-" + strings.ToUpper(id) + ".scope\n", ""},
		{"an id not under a runtime", "0::/user.slice/" + id + "\n", ""},
		{"hierarchies disagree", "12:memory:/docker/" + id + "\n11:cpu:/docker/" + other + "\n", ""},
		{"empty", "", ""},
	} {
		if got := containerID([]byte(c.cgroup)); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}
