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

// make new storage
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

// reset storage
func (s *rrStorage) reset() {
	if s == nil {
		return
	}
	s.Lock()
	s.m.reset()
	s.Unlock()
}

// copy data from map to storage
func (s *rrStorage) copyFrom(src rrMap) {
	if s == nil {
		return
	}
	s.Lock()
	s.m.copyFrom(src)
	s.Unlock()
}

// one cleanup iteration for storage
func (s *rrStorage) cleanup(now int64) {
	s.Lock()
	s.m.forEachDel(func(v *rrVal) bool {
		return v.exp <= now
	})
	s.Unlock()
}

// evict loop for storage
func (s *rrStorage) evict() {
	for t := range s.t.C {
		s.cleanup(t.Unix())
	}
}

// Put RR slice in storage
func (s *rrStorage) Put(rrs []dns.RR) {
	if s == nil || len(rrs) == 0 {
		return
	}
	m := newRRMap(len(rrs))
	for _, rr := range rrs {
		k := keyFromRR(rr)
		if v := m.get(k); v == nil || oneRR(rr) {
			m.putRR(k, rr)
		} else {
			v.addRR(rr)
		}
	}
	s.copyFrom(m)
}

// PutNeg - put negative RR (SOA) for given question
func (s *rrStorage) PutNeg(q *dns.Question, rrs []dns.RR) {
	if s == nil || q == nil {
		return
	}
	rr := lastRR(rrs)
	if !isSOA(rr) {
		return
	}
	k := keyFromQ(q)
	k2, ok := k.soaKey()
	s.Lock()
	s.m.putRR(k, rr)
	if ok {
		s.m.putRR(k2, rr)
	}
	s.Unlock()
}

// get slice of one rr of valid type
func (s *rrStorage) getOne(q *dns.Question) ([]dns.RR, *dns.Question) {
	k := keyFromQ(q) // question I need to find
	s.RLock()
	rrs := s.m.getRRs(k)
	s.RUnlock()
	if len(rrs) == 1 && oneRR(rrs[0]) {
		return rrs, nil
	}
	qr := *q // new reply
	return nil, &qr
}

// Get data from storage
func (s *rrStorage) Get(q *dns.Question) ([]dns.RR, *dns.Question) {
	if s == nil || q == nil {
		return nil, nil // this is not my case...
	}
	if oneRRType(q.Qtype) {
		return s.getOne(q)
	}
	k := keyFromQ(q)             // question I need to find
	rrs := make([]dns.RR, 0, 16) // make pool for this?
	neg := false                 // negative response flag
	s.RLock()
	// no CNAME or SOA type in k key here
	for {
		// try original name
		rrs = append(rrs, s.m.getRRs(k)...)
		if k.match(rrs) { // last RR match key in question
			break
		}
		// check if last RR is SOA - this is negative answer for domain
		if rr := lastRR(rrs); isSOA(rr) {
			neg = true
			rrs = append(rrs[:0], rr)
			break
		}
		// try CNAME for domain
		crr := s.m.getRRs(k.cnameKey()) // CNAME RR
		if len(crr) != 1 {              // CNAME not found or invalid
			break
		}
		if isSOA(crr[0]) { // check is returned RR is SOA and return negative answer
			neg = true
			rrs = append(rrs[:0], crr[0])
			break
		} else if k.update(crr[0]) { // check if record is CNAME and update original key with target
			rrs = append(rrs, crr[0]) // add CNAME to return slice
		} else { // unknown RR type...
			break
		}
	}
	s.RUnlock()
	if neg { // negative answer
		return rrs, nil
	}
	if len(rrs) == 0 { // no data found in cache
		qr := *q        // new reply
		return nil, &qr // nothing found in cache
	}
	if k.match(rrs) { // found full answer
		return rrs, nil // found full response
	}
	qr := *q // new reply
	if target, isCN := lastCNAME(rrs); isCN {
		qr.Name = fixName(target) // update name to last CNAME
		return rrs, &qr
	}
	return nil, &qr // something went wrong...
}

// Len() returns count of RRs in storage
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
