package rrcache

import (
	"github.com/miekg/dns"
)

type rrKey struct {
	qname  string
	qtype  uint16
	qclass uint16
}

// make key from Question
func keyFromQ(q *dns.Question) rrKey {
	return rrKey{
		qname:  fixName(q.Name),
		qtype:  q.Qtype,
		qclass: q.Qclass,
	}
}

// make key from RR
func keyFromRR(rr dns.RR) rrKey {
	h := rr.Header()
	return rrKey{
		qname:  fixName(h.Name),
		qtype:  h.Rrtype,
		qclass: h.Class,
	}
}

// is key match with last RR from slice
func (k *rrKey) match(rrs []dns.RR) bool {
	if rr := lastRR(rrs); rr != nil {
		return rr.Header().Rrtype == k.qtype && rr.Header().Class == k.qclass
	}
	return false
}

// make CNAME key from key
func (k *rrKey) cnameKey() rrKey { // make cname key from key
	return rrKey{
		qname:  k.qname,
		qtype:  dns.TypeCNAME,
		qclass: k.qclass,
	}
}

// update key name from given CNAME RR
func (k *rrKey) update(rr dns.RR) bool {
	if k == nil || !isCNAME(rr) {
		return false
	}
	cn := rr.(*dns.CNAME)
	k.qname = fixName(cn.Target)
	return true
}

// generate SOA key (for negative cache)
func (k *rrKey) soaKey() (rrKey, bool) {
	if k == nil || k.qtype == dns.TypeSOA {
		return rrKey{}, false
	}
	return rrKey{
		qname:  k.qname,
		qtype:  dns.TypeSOA,
		qclass: k.qclass,
	}, true
}
