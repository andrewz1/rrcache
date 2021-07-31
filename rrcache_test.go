package rrcache

import (
	"testing"

	"github.com/miekg/dns"
)

func makeRR(s string) dns.RR {
	rr, err := dns.NewRR(s)
	if err != nil {
		panic(err)
	}
	return rr
}

func TestRRCache(t *testing.T) {
	c := NewRRCache(0)
	rrs := make([]dns.RR, 0, 10)
	rrs = append(rrs, makeRR("www.ru. CNAME www1.ru."))
	rrs = append(rrs, makeRR("www1.ru. CNAME www2.ru."))
	rrs = append(rrs, makeRR("www2.ru. CNAME www3.ru."))
	rrs = append(rrs, makeRR("www3.ru. CNAME www4.ru."))
	rrs = append(rrs, makeRR("www4.ru. A 1.1.1.1"))
	rrs = append(rrs, makeRR("www4.ru. A 1.1.1.2"))
	c.Put(rrs)
	t.Log("len:", c.Len())
	qq := dns.Question{
		Name:   "www.ru.",
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	}
	var qr *dns.Question
	rrs, qr = c.Get(&qq)
	t.Log(rrs, qr)
}
