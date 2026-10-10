package vault

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	lockName       = "vault.lock"
	lockStaleAfter = 15 * time.Minute
)

// lockInfo identifies the lock holder for diagnostics and crash recovery.
type lockInfo struct {
	Host    string
	PID     int
	Started time.Time
}

func (i lockInfo) String() string {
	return fmt.Sprintf("host=%s\npid=%d\nstarted=%s\n", i.Host, i.PID, i.Started.Format(time.RFC3339Nano))
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return h
}

func parseLock(data []byte) (lockInfo, bool) {
	var info lockInfo
	for _, line := range strings.Split(string(data), "\n") {
		v, ok := strings.CutPrefix(line, "host=")
		if ok {
			info.Host = v
			continue
		}
		if v, ok := strings.CutPrefix(line, "pid="); ok {
			info.PID, _ = strconv.Atoi(v)
			continue
		}
		if v, ok := strings.CutPrefix(line, "started="); ok {
			if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
				info.Started = t
			}
		}
	}
	return info, info.Host != "" && info.PID > 0 && !info.Started.IsZero()
}

// stale decides whether a held lock may be stolen: its holder is provably
// gone (dead pid on this host), or it outlived lockStaleAfter (covers
// cross-machine holders and platforms without a liveness probe).
// Timestamps further in the future than futureSkew are treated as
// untrustworthy: a planted lock dated years ahead falls back to the file's
// mtime — blocking writes at most lockStaleAfter, never until the stated
// date. Unparseable content uses the same mtime fallback.
const futureSkew = time.Hour

func stale(info lockInfo, mtime time.Time) bool {
	now := time.Now()
	startedOK := !info.Started.IsZero() && !info.Started.After(now.Add(futureSkew))
	if info.Host != "" && startedOK {
		if now.Sub(info.Started) > lockStaleAfter {
			return true
		}
		return info.Host == hostname() && !pidAlive(info.PID)
	}
	// No trustworthy content timestamp: mtime decides; an mtime itself
	// dated beyond skew is nonsense content — steal rather than block.
	if mtime.After(now.Add(futureSkew)) {
		return true
	}
	return now.Sub(mtime) > lockStaleAfter
}

// acquireLock takes the vault writer lock (spec §6, writer lock): an
// exclusively created vault.lock held for the duration of one write
// operation, so concurrent writers cannot lose each other's updates.
// Readers never lock — object files are immutable and manifest
// generations authenticate independently.
func acquireLock(dir string) (release func(), guard string, err error) {
	path := filepath.Join(dir, lockName)
	info := lockInfo{Host: hostname(), PID: os.Getpid(), Started: time.Now().UTC()}
	for attempt := 0; attempt < 2; attempt++ {
		err := writeLockFile(path, info)
		if err == nil {
			return func() {
				// Remove only the lock we wrote: if it was stolen from us,
				// it now belongs to the thief.
				if cur, rerr := os.ReadFile(path); rerr == nil && string(cur) == guard {
					os.Remove(path)
				}
			}, info.String(), nil
		}
		if !os.IsExist(err) {
			return nil, "", err
		}
		// vault.lock may be a planted file: read without following
		// symlinks, refuse non-regular files, and bound the size — a
		// symlink to /dev/zero would otherwise read forever.
		data, rerr := readLimited(path, 8192)
		if rerr != nil {
			return nil, "", rerr
		}
		held, _ := parseLock(data)
		mtime := time.Now()
		if fi, serr := os.Stat(path); serr == nil {
			mtime = fi.ModTime()
		}
		if stale(held, mtime) {
			os.Remove(path)
			continue
		}
		holder := fmt.Sprintf("pid %d on %s", held.PID, held.Host)
		if held.PID == 0 {
			holder = "unknown holder"
		}
		return nil, "", fmt.Errorf(
			"another coffer operation is writing to this vault (%s, started %s); retry when it finishes, or delete %s if you are sure none is running",
			holder, held.Started.Local().Format("15:04:05"), path)
	}
	return nil, "", errors.New("could not acquire the vault writer lock")
}

func writeLockFile(path string, info lockInfo) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.WriteString(info.String())
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		os.Remove(path)
		return werr
	}
	return nil
}
