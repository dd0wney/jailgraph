//go:build linux

package seccomp

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// Kernel ABI structs for the seccomp user-notification interface. golang.org/x/sys
// exposes the ioctl/flag constants but not these types, so we mirror the kernel
// layout exactly. The compile-time size assertions below catch any drift: the
// ioctl request codes encode the struct size (e.g. NOTIF_RECV = 0xc0502100 →
// 0x50 = 80 bytes), so a wrong layout would corrupt every notification.

// seccompData is what the BPF program and the supervisor see for each syscall.
type seccompData struct {
	nr                 int32
	arch               uint32
	instructionPointer uint64
	args               [6]uint64
}

// seccompNotif is delivered by SECCOMP_IOCTL_NOTIF_RECV.
type seccompNotif struct {
	id    uint64
	pid   uint32
	flags uint32
	data  seccompData
}

// seccompNotifResp is sent by SECCOMP_IOCTL_NOTIF_SEND.
type seccompNotifResp struct {
	id    uint64
	val   int64
	error int32
	flags uint32
}

// Compile-time exact-size assertions. These are constant expressions, so a
// layout mistake fails the build rather than surfacing as garbage at runtime.
const (
	_ = uint(unsafe.Sizeof(seccompData{}) - 64)
	_ = uint(64 - unsafe.Sizeof(seccompData{}))
	_ = uint(unsafe.Sizeof(seccompNotif{}) - 80)
	_ = uint(80 - unsafe.Sizeof(seccompNotif{}))
	_ = uint(unsafe.Sizeof(seccompNotifResp{}) - 24)
	_ = uint(24 - unsafe.Sizeof(seccompNotifResp{}))
)

// ioctl issues a raw ioctl with a pointer argument.
func ioctl(fd int, req uint, arg unsafe.Pointer) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(arg))
	if errno != 0 {
		return errno
	}
	return nil
}

// notifRecv blocks until the kernel delivers the next trapped syscall.
func notifRecv(fd int) (seccompNotif, error) {
	var req seccompNotif
	err := ioctl(fd, uint(unix.SECCOMP_IOCTL_NOTIF_RECV), unsafe.Pointer(&req))
	return req, err
}

// notifSend returns a response, releasing the suspended target thread.
func notifSend(fd int, resp seccompNotifResp) error {
	return ioctl(fd, uint(unix.SECCOMP_IOCTL_NOTIF_SEND), unsafe.Pointer(&resp))
}

// notifIDValid reports whether a notification id still refers to a live request.
// It must be re-checked AFTER reading the target's memory: if it returns an
// error the target died or the syscall was interrupted, the pid may have been
// reused, and any data already read is untrustworthy and must be discarded.
func notifIDValid(fd int, id uint64) bool {
	return ioctl(fd, uint(unix.SECCOMP_IOCTL_NOTIF_ID_VALID), unsafe.Pointer(&id)) == nil
}
