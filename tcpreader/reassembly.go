package tcpreader

import (
	"container/list"
	"math"

	"github.com/google/gopacket/layers"
)

type sequence uint32

const ipPackageMax = uint32(math.MaxUint16) * 10

func (s sequence) Less(t sequence) bool {
	return s.Sub(t) < 0
}

func (s sequence) Add(len int) sequence {
	return s + sequence(len)
}

func (s sequence) Sub(t sequence) int {
	if uint32(s) > (math.MaxUint32-ipPackageMax) &&
		uint32(t) < ipPackageMax {
		return -int(math.MaxUint32 - s + t + 1)
	} else if uint32(s) < ipPackageMax &&
		uint32(t) > (math.MaxUint32-ipPackageMax) {
		return int(math.MaxUint32 - t + s + 1)
	}
	return int(s) - int(t)
}

type assemblerPkg struct {
	*layers.TCP
	priv *assemblerPkg
	next *assemblerPkg
}

type assemblerCache struct {
	*list.List
	maxSize int
}

func newAssemblerCache(size int) assemblerCache {
	return assemblerCache{
		List:    list.New(),
		maxSize: size,
	}
}

func (a *assemblerCache) InsertOrderd(t *layers.TCP) bool {
	if a.Len() >= a.maxSize {
		return false
	}

	for e := a.List.Front(); e != nil; e = e.Next() {
		val := e.Value.(*layers.TCP)
		if t.Seq == val.Seq { // same seq
			if len(t.LayerPayload()) > len(val.LayerPayload()) {
				// if inpute package size greater than current, replace
				e.Value = t
			}
			return true
		}

		// seq less than current, insert before it
		if sequence(t.Seq).Less(sequence(val.Seq)) {
			a.List.InsertBefore(t, e)
			return true
		}
	}

	// seq is max than all elements, push back
	a.List.PushBack(t)
	return true
}

// SkipRanges return cached tcpCachePkg when skip
func (a *assemblerCache) TrimDiscontinuous() bool {
	e := a.List.Back()
	if e == nil {
		return false
	}

	nextSeq := sequence(e.Value.(*layers.TCP).Seq)

	for e = e.Prev(); e != nil; e = e.Prev() {
		val := e.Value.(*layers.TCP)
		curSeq := sequence(val.Seq)
		curEnd := curSeq.Add(len(val.LayerPayload()))

		if curEnd.Add(1).Less(nextSeq) {
			break
		}

		nextSeq = curSeq
	}

	// clear discontinuous package
	for e != nil {
		s := e.Prev()
		a.List.Remove(e)
		e = s
	}

	return true
}
