package cli

import (
	"bytes"
	"os"
	"strconv"
	"strings"

	"github.com/bpinto/foca/internal/identity"
)

// parents is the client's own view of its ancestors, nearest first, read
// from /proc where there is one. It is reported identity: the service shows
// it as a claim and never trusts it.
func parents(pid int) []identity.Proc {
	var out []identity.Proc
	for pid > 1 && len(out) < identity.MaxClientParents {
		stat, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
		if err != nil {
			break
		}
		open, close := bytes.IndexByte(stat, '('), bytes.LastIndexByte(stat, ')')
		if open < 0 || close < open {
			break
		}
		fields := strings.Fields(string(stat[close+1:]))
		if len(fields) < 2 {
			break
		}
		p := identity.Proc{PID: pid, Name: string(stat[open+1 : close])}
		if exe, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe"); err == nil {
			p.Exe = exe
		}
		out = append(out, p)
		pid, _ = strconv.Atoi(fields[1])
	}
	return out
}
