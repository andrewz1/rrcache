package rrcache

import (
	"github.com/miekg/dns"
)

type rrMap map[rrKey]*rrVal

func newRRMap(size int) rrMap {
	return make(rrMap, size)
}

func (m *rrMap) reset() {
	if m == nil {
		return
	}
	for k := range *m {
		delete(*m, k)
	}
}

func (m *rrMap) put(k rrKey, v *rrVal) {
	if m == nil {
		return
	}
	(*m)[k] = v
}

func (m *rrMap) get(k rrKey) *rrVal {
	if m == nil {
		return nil
	}
	return (*m)[k]
}

func (m *rrMap) getRR(k rrKey) []dns.RR {
	if m == nil {
		return nil
	}
	return m.get(k).getRR()
}

func (m *rrMap) copyFrom(src rrMap) {
	if m == nil {
		return
	}
	for k, v := range src {
		m.put(k, v)
	}
}

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

func (m *rrMap) forEachVal(f func(v *rrVal)) {
	if m == nil {
		return
	}
	for _, v := range *m {
		f(v)
	}
}
