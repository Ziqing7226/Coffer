//go:build linux

package main

import "syscall"

// filesystemName reports the filesystem holding path, best effort.
func filesystemName(path string) (string, bool) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return "", false
	}
	return linuxFsName(uint64(st.Type)), true
}

func linuxFsName(magic uint64) string {
	switch magic {
	case 0x4d44:
		return "vfat"
	case 0x2011b6bb:
		return "exfat"
	case 0xef53:
		return "ext4"
	case 0x9123683e:
		return "btrfs"
	case 0x01021994:
		return "tmpfs"
	case 0x58465342:
		return "xfs"
	}
	return "unknown"
}
