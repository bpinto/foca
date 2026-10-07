package command

import "golang.org/x/sys/unix"

// waitExited blocks until process pid has exited, and leaves it unreaped:
// until it is reaped, its pid, and so its process group's id, can't be
// reused. macOS has no waitid with WNOWAIT in x/sys, so it waits on a
// kqueue for NOTE_EXIT, which fires before the parent reaps.
func waitExited(pid int) error {
	kq, err := unix.Kqueue()
	if err != nil {
		return err
	}
	defer unix.Close(kq)
	change := []unix.Kevent_t{{Ident: uint64(pid), Filter: unix.EVFILT_PROC, Flags: unix.EV_ADD | unix.EV_ONESHOT, Fflags: unix.NOTE_EXIT}}
	ev := make([]unix.Kevent_t, 1)
	for {
		n, err := unix.Kevent(kq, change, ev, nil)
		switch {
		case err == unix.EINTR:
			continue
		case err == unix.ESRCH:
			// Already exited. Only this process reaps it, so it is
			// still there, unreaped.
			return nil
		case err != nil:
			return err
		case n == 1 && ev[0].Flags&unix.EV_ERROR != 0:
			if e := unix.Errno(ev[0].Data); e != unix.ESRCH {
				return e
			}
			return nil
		case n == 1:
			return nil
		}
	}
}
