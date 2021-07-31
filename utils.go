package rrcache

import (
	"strings"

	"github.com/miekg/dns"
)

func fixName(name string) string {
	l := len(name)
	if l == 0 {
		return "."
	}
	n := strings.ToLower(name)
	if n[l-1] == '.' {
		return n
	}
	return n + "."
}

func oneRRType(t uint16) bool {
	switch t {
	case dns.TypeCNAME, dns.TypeSOA: // this RR types must be replaced
		return true
	default:
		return false
	}
}

func oneRR(rr dns.RR) bool {
	if rr == nil {
		return false
	}
	return oneRRType(rr.Header().Rrtype)
}

func isType(rr dns.RR, t uint16) bool {
	if rr == nil {
		return false
	}
	return rr.Header().Rrtype == t
}

func isCNAME(rr dns.RR) bool {
	return isType(rr, dns.TypeCNAME)
}

func isSOA(rr dns.RR) bool {
	return isType(rr, dns.TypeSOA)
}

func lastRR(rrs []dns.RR) dns.RR {
	l := len(rrs)
	if l == 0 {
		return nil
	}
	return rrs[l-1]
}

func lastIsSOA(rrs []dns.RR) bool {
	return isSOA(lastRR(rrs))
}
