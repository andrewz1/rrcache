package rrcache

import (
	"github.com/miekg/dns"
)

type rrMap map[rrKey]*rrVal

// create key:value map for RRs
func newRRMap(size int) rrMap {
	return make(rrMap, size)
}

// reset map
func (m *rrMap) reset() {
	if m == nil {
		return
	}
	for k := range *m {
		delete(*m, k)
	}
}

// put entry to map
func (m *rrMap) put(k rrKey, v *rrVal) {
	if m == nil {
		return
	}
	(*m)[k] = v
}

// put RR to map
func (m *rrMap) putRR(k rrKey, rr dns.RR) {
	if rr == nil {
		return
	}
	m.put(k, newRRVal(rr))
}

// get entry from map
func (m *rrMap) get(k rrKey) *rrVal {
	if m == nil {
		return nil
	}
	return (*m)[k]
}

// get RR slice from
func (m *rrMap) getRRs(k rrKey) []dns.RR {
	return m.get(k).getRR()
}

// copy data from one map to other
func (m *rrMap) copyFrom(src rrMap) {
	if m == nil || len(src) == 0 {
		return
	}
	for k, v := range src {
		m.put(k, v)
	}
}

// walk all values in map, if f returns true - entry deleted
func (m *rrMap) forEachDel(f func(v *rrVal) bool) {
	if m == nil {
		return
	}
	for k, v := range *m {
		if f(v) {
			delete(*m, k)
		}
	}
}

// walk all values in map with given func
func (m *rrMap) forEachVal(f func(v *rrVal)) {
	if m == nil {
		return
	}
	for _, v := range *m {
		f(v)
	}
}
