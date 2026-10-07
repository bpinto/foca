package command

import "golang.org/x/sys/unix"

// waitExited blocks until process pid has exited, and leaves it unreaped:
// until it is reaped, its pid, and so its process group's id, can't be
// reused.
func waitExited(pid int) error {
	for {
		var info unix.Siginfo
		err := unix.Waitid(unix.P_PID, pid, &info, unix.WEXITED|unix.WNOWAIT, nil)
		if err != unix.EINTR {
			return err
		}
	}
}
