package rrcache

import (
	"time"

	"github.com/miekg/dns"
)

type rrVal struct {
	rrs []dns.RR
	exp int64
}

func newRRVal(src dns.RR) *rrVal {
	rr := dns.Copy(src)
	h := rr.Header()
	exp := time.Now().Unix() + int64(h.Ttl)
	h.Ttl = 0
	return &rrVal{
		rrs: []dns.RR{rr},
		exp: exp,
	}
}

func (v *rrVal) add(src dns.RR) {
	if v == nil {
		return
	}
	rr := dns.Copy(src)
	rr.Header().Ttl = 0
	v.rrs = append(v.rrs, rr)
}

func (v *rrVal) getTTL() uint32 {
	if v == nil {
		return 0
	}
	if ttl := v.exp - time.Now().Unix(); ttl > 0 {
		return uint32(ttl)
	}
	return 0
}

func (v *rrVal) getRR() []dns.RR {
	if v == nil || len(v.rrs) == 0 {
		return nil
	}
	ttl := v.getTTL()
	if ttl == 0 {
		return nil
	}
	rrs := make([]dns.RR, 0, len(v.rrs))
	for _, rr := range v.rrs {
		rr1 := dns.Copy(rr)
		rr1.Header().Ttl = ttl
		rrs = append(rrs, rr1)
	}
	return rrs
}
