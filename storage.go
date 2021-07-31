package rrcache

import (
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	minEvictInt = 10 * time.Second
)

type rrStorage struct {
	sync.RWMutex
	m rrMap
	t *time.Ticker
}

func newStorage(evictInt time.Duration) *rrStorage {
	if evictInt < minEvictInt {
		evictInt = minEvictInt
	}
	s := &rrStorage{
		m: newRRMap(0),
		t: time.NewTicker(evictInt),
	}
	go s.evict()
	return s
}

func (s *rrStorage) reset() {
	if s == nil {
		return
	}
	s.Lock()
	s.m.reset()
	s.Unlock()
}

func (s *rrStorage) copyFrom(src rrMap) {
	if s == nil {
		return
	}
	s.Lock()
	s.m.copyFrom(src)
	s.Unlock()
}

func (s *rrStorage) cleanup(now int64) {
	if s == nil {
		return
	}
	s.Lock()
	s.m.forEachDel(func(v *rrVal) bool {
		return v.exp <= now
	})
	s.Unlock()
}

func (s *rrStorage) evict() {
	if s == nil {
		return
	}
	for t := range s.t.C {
		s.cleanup(t.Unix())
	}
}

func (s *rrStorage) Put(rrs []dns.RR) {
	if s == nil || len(rrs) == 0 {
		return
	}
	m := newRRMap(len(rrs))
	for _, rr := range rrs {
		k := keyFromRR(rr)
		if v := m.get(k); v == nil || oneRR(rr) {
			m.put(k, newRRVal(rr))
		} else {
			v.add(rr)
		}
	}
	s.copyFrom(m)
}

func (s *rrStorage) PutNeg(q *dns.Question, rrs []dns.RR) {
	if s == nil || q == nil {
		return
	}
	rr := lastRR(rrs)
	if rr == nil {
		return
	}
	k := keyFromQ(q)
	k2 := k.soaKey()
	s.Lock()
	s.m.put(k, newRRVal(rr))
	if k2 != nil {
		s.m.put(*k2, newRRVal(rr))
	}
	s.Unlock()
}

func (s *rrStorage) getOne(q *dns.Question) ([]dns.RR, *dns.Question) {
	k := keyFromQ(q) // question I need to find
	s.RLock()
	rrs := s.m.getRR(k)
	s.RUnlock()
	if len(rrs) == 1 && oneRR(rrs[0]) {
		return rrs, nil
	}
	qr := *q // new reply
	return nil, &qr
}

func (s *rrStorage) Get(q *dns.Question) ([]dns.RR, *dns.Question) {
	if s == nil || q == nil {
		return nil, nil // this is not my case...
	}
	if oneRRType(q.Qtype) {
		return s.getOne(q)
	}
	k := keyFromQ(q)             // question I need to find
	rrs := make([]dns.RR, 0, 16) // make pool for this?
	neg := false                 // negative response
	s.RLock()
	// no CNAME or SOA in key type here
	for {
		// try original name
		rrs = append(rrs, s.m.getRR(k)...)
		if k.match(rrs) {
			break
		}
		if rr := lastRR(rrs); isSOA(rr) {
			neg = true
			rrs = append(rrs[:0], rr)
			break
		}
		// try CNAME
		r := s.m.getRR(k.cnkey())
		if len(r) != 1 { // CNAME key not found or invalid
			break
		}
		if isSOA(r[0]) { // check if record is SOA
			neg = true
			rrs = append(rrs[:0], r[0])
			break
		} else if k.update(r[0]) { // check if record is CNAME and update key
			rrs = append(rrs, r[0])
		} else {
			break
		}
	}
	s.RUnlock()
	if neg {
		return rrs, nil
	}
	if len(rrs) == 0 {
		qr := *q        // new reply
		return nil, &qr // nothing found in cache
	}
	if k.match(rrs) {
		return rrs, nil // found full response
	}
	lRR := rrs[len(rrs)-1]
	if !isCNAME(lRR) {
		qr := *q        // new reply
		return nil, &qr // something went wrong...
	}
	cn := lRR.(*dns.CNAME)
	qr := *q                     // new reply
	qr.Name = fixName(cn.Target) // update name to last CNAME
	return rrs, &qr
}

func (s *rrStorage) Len() int {
	if s == nil {
		return 0
	}
	l := 0
	s.RLock()
	s.m.forEachVal(func(v *rrVal) {
		l += len(v.rrs)
	})
	s.RUnlock()
	return l
}

// NewRRCache create new cache instance with given evict interval
func NewRRCache(evictInt time.Duration) *rrStorage {
	return newStorage(evictInt)
}

// IsNeg detects is response negative (need to put in NS section)
func IsNeg(rrs []dns.RR) bool {
	if len(rrs) != 1 {
		return false
	}
	return isSOA(rrs[0])
}
