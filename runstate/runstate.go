package runstate

import (
	"runtime"
	"strconv"
	"strings"
	"sync"
)

var (
	mu             sync.Mutex
	checkByGID     = make(map[int64]string)
	memoDepsByRule = make(map[string]map[string]bool)
)

func SetCurrentCheck(checkID string) {
	gid := goid()
	if gid == 0 || strings.TrimSpace(checkID) == "" {
		return
	}
	mu.Lock()
	checkByGID[gid] = checkID
	mu.Unlock()
}

func ClearCurrentCheck() {
	gid := goid()
	if gid == 0 {
		return
	}
	mu.Lock()
	delete(checkByGID, gid)
	mu.Unlock()
}

func RecordMemoAccess(memoName string) {
	name := strings.TrimSpace(memoName)
	if name == "" {
		return
	}
	gid := goid()
	if gid == 0 {
		return
	}
	mu.Lock()
	checkID := checkByGID[gid]
	if checkID == "" {
		mu.Unlock()
		return
	}
	if memoDepsByRule[checkID] == nil {
		memoDepsByRule[checkID] = make(map[string]bool)
	}
	memoDepsByRule[checkID][name] = true
	mu.Unlock()
}

func MemoNamesForChecks(checkIDs map[string]bool) map[string]bool {
	if len(checkIDs) == 0 {
		return nil
	}
	out := make(map[string]bool)
	mu.Lock()
	for checkID := range checkIDs {
		deps := memoDepsByRule[checkID]
		for memoName := range deps {
			out[memoName] = true
		}
	}
	mu.Unlock()
	return out
}

func goid() int64 {
	var buf [64]byte
	n := runtime.Stack(buf[:], false)
	line := strings.TrimPrefix(string(buf[:n]), "goroutine ")
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return 0
	}
	id, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil {
		return 0
	}
	return id
}
