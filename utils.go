package rrcache

import (
	"strings"

	"github.com/miekg/dns"
)

// normalize domain name
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

// check if type must be replaced in cache
func oneRRType(t uint16) bool {
	switch t {
	case dns.TypeCNAME, dns.TypeSOA: // this RR types must be replaced
		return true
	default:
		return false
	}
}

// as above but check RR
func oneRR(rr dns.RR) bool {
	if rr == nil {
		return false
	}
	return oneRRType(rr.Header().Rrtype)
}

// check if RR have specified type
func isType(rr dns.RR, t uint16) bool {
	if rr == nil {
		return false
	}
	return rr.Header().Rrtype == t
}

// is RR have CNAME type
func isCNAME(rr dns.RR) bool {
	return isType(rr, dns.TypeCNAME)
}

// is RR have SOA type
func isSOA(rr dns.RR) bool {
	return isType(rr, dns.TypeSOA)
}

// get last RR from slice
func lastRR(rrs []dns.RR) dns.RR {
	l := len(rrs)
	if l == 0 {
		return nil
	}
	return rrs[l-1]
}

// get cname target
func lastCNAME(rrs []dns.RR) (string, bool) {
	rr := lastRR(rrs)
	if rr == nil || !isCNAME(rr) {
		return "", false
	}
	cn := rr.(*dns.CNAME)
	return cn.Target, true
}

// check if last RR is SOA (for negative detect)
func lastIsSOA(rrs []dns.RR) bool {
	return isSOA(lastRR(rrs))
}
