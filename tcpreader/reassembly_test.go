package tcpreader

import (
	"math"
	"reflect"
	"testing"

	"github.com/google/gopacket/layers"
)

func TestSquence(t *testing.T) {
	specs := []struct {
		Start uint32
		Add   int
		Want  uint32
	}{
		{1, 5, 6},
		{math.MaxUint32 - 1010, 5, math.MaxUint32 - 1005},
		{math.MaxUint32 - 1000, 2000, 999},
	}

	for idx, spec := range specs {
		s := sequence(spec.Start)
		r := sequence(spec.Want)

		// test add
		result := s.Add(spec.Add)
		if result != r {
			t.Fatalf("test-%d-add %d+%d want %d got %d",
				idx, s, spec.Add, r, result)
		}

		// test sub
		ri := r.Sub(s)
		if ri != spec.Add {
			t.Fatalf("test-%d-sub1 %d-%d want %d got %d",
				idx, r, s, spec.Add, ri)
		}
		ri = s.Sub(r)
		if ri != -spec.Add {
			t.Fatalf("test-%d-sub2 %d-%d want %d got %d",
				idx, s, r, -spec.Add, ri)
		}

		// test less
		if !s.Less(r) {
			t.Fatalf("test-%d-less %d<%d false",
				idx, s, r)
		}
	}
}

func (a *assemblerCache) seqArr() []uint32 {
	ret := make([]uint32, a.List.Len())

	for pos, e := 0, a.List.Front(); e != nil; e = e.Next() {
		ret[pos] = e.Value.(*layers.TCP).Seq
		pos++
	}

	return ret
}

func TestAssemblerCache(t *testing.T) {
	specs := []struct {
		Seq     uint32
		Len     int
		Rsize   int
		RInsert bool
	}{
		{1, 5, 1, true},                     // 6
		{1, 4, 1, true},                     // 6
		{1, 6, 1, true},                     // 6
		{math.MaxUint32 - 1010, 5, 2, true}, // math.MaxUint32 - 1005
		{8, 6, 3, true},                     // 6
		{9, 6, 3, false},                    // 6
	}
	wantSeq := []uint32{math.MaxUint32 - 1010, 1, 8}
	wantTrimSeq := []uint32{1, 8}

	ass := newAssemblerCache(3)
	if ass.TrimDiscontinuous() {
		t.Fatalf("test-trim-empty not false")
	}

	for idx, spec := range specs {
		tcp := &layers.TCP{
			Seq: spec.Seq,
			BaseLayer: layers.BaseLayer{
				Payload: make([]byte, spec.Len),
			},
		}

		ret := ass.InsertOrderd(tcp)
		// test less
		if ret != spec.RInsert {
			t.Fatalf("test-%d-insert %d-%d expect %v got %v",
				idx, spec.Seq, spec.Len, spec.RInsert, ret)
		}
		if ass.Len() != spec.Rsize {
			t.Fatalf("test-%d-size expect %d got %d",
				idx, spec.Rsize, ass.Len())
		}
	}

	fact := ass.seqArr()
	if !reflect.DeepEqual(fact, wantSeq) {
		t.Fatalf("test-seqArr expect %v got %v",
			fact, wantSeq)
	}

	ass.TrimDiscontinuous()
	fact = ass.seqArr()
	if !reflect.DeepEqual(fact, wantTrimSeq) {
		t.Fatalf("test-seqArr expect %v got %v",
			fact, wantTrimSeq)
	}
}
