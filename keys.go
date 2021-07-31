package rrcache

import (
	"github.com/miekg/dns"
)

type rrKey struct {
	qname  string
	qtype  uint16
	qclass uint16
}

func keyFromQ(q *dns.Question) rrKey {
	return rrKey{
		qname:  fixName(q.Name),
		qtype:  q.Qtype,
		qclass: q.Qclass,
	}
}

func keyFromRR(rr dns.RR) rrKey {
	h := rr.Header()
	return rrKey{
		qname:  fixName(h.Name),
		qtype:  h.Rrtype,
		qclass: h.Class,
	}
}

func (k rrKey) match(rrs []dns.RR) bool {
	l := len(rrs)
	if l == 0 {
		return false
	}
	h := rrs[l-1].Header() // last RR header
	return h.Rrtype == k.qtype && h.Class == k.qclass
}

func (k rrKey) cnkey() rrKey { // make cname key from key
	return rrKey{
		qname:  k.qname,
		qtype:  dns.TypeCNAME,
		qclass: k.qclass,
	}
}

func (k *rrKey) update(rr dns.RR) bool {
	if k == nil || !isCNAME(rr) {
		return false
	}
	cn := rr.(*dns.CNAME)
	k.qname = fixName(cn.Target)
	return true
}

func (k *rrKey) soaKey() *rrKey {
	if k == nil || k.qtype == dns.TypeSOA {
		return nil
	}
	return &rrKey{
		qname:  k.qname,
		qtype:  dns.TypeSOA,
		qclass: k.qclass,
	}
}
