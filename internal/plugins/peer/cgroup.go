package peer

import (
	"bytes"
	"regexp"
	"strings"
)

// Container runtimes name a container's cgroup after its id. These are the
// shapes docker, podman, containerd and CRI-O use, with systemd or cgroupfs
// managing cgroups. Only full 64-digit ids count.
var (
	// docker-<id>.scope, libpod-<id>.scope, crio-<id>.scope,
	// cri-containerd-<id>.scope (systemd); libpod-<id>, crio-<id>
	// (cgroupfs).
	runtimeCgroup = regexp.MustCompile(`^(?:(?:docker|libpod|crio|cri-containerd)-([0-9a-f]{64})\.scope|(?:libpod|crio)-([0-9a-f]{64}))$`)
	bareID        = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// containerID finds the container id in /proc/<pid>/cgroup, or "". Every
// line (one per hierarchy on cgroup v1) that names a container must name the
// same one, or none is returned. Within a path the outermost container
// counts: a container nested in another is still in the realm the host runs.
func containerID(cgroup []byte) string {
	id := ""
	for _, line := range bytes.Split(cgroup, []byte("\n")) {
		// hierarchy-id:controllers:path
		f := strings.SplitN(string(line), ":", 3)
		if len(f) != 3 {
			continue
		}
		found := idInPath(f[2])
		switch {
		case found == "":
		case id == "":
			id = found
		case id != found:
			return ""
		}
	}
	return id
}

func idInPath(path string) string {
	parts := strings.Split(path, "/")
	for i, c := range parts {
		if m := runtimeCgroup.FindStringSubmatch(c); m != nil {
			return m[1] + m[2]
		}
		if i == 0 || !bareID.MatchString(c) {
			continue
		}
		// docker with cgroupfs: /docker/<id>; Kubernetes with cgroupfs:
		// /kubepods/[<qos>/]pod<uid>/<id>.
		parent := parts[i-1]
		if parent == "docker" || strings.HasPrefix(parent, "pod") && strings.HasPrefix(path, "/kubepods/") {
			return c
		}
	}
	return ""
}
