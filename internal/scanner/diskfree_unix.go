//go:build unix

package scanner

import "syscall"

// FreeBytes returns the space available under dir; ok is false when it cannot be told.
func FreeBytes(dir string) (free int64, ok bool) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, false
	}
	return int64(st.Bavail) * int64(st.Bsize), true
}
