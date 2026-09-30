//go:build !unix

package scanner

// FreeBytes cannot be told on this platform.
func FreeBytes(string) (int64, bool) { return 0, false }
