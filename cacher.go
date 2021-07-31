package rrcache

import (
	"github.com/miekg/dns"
)

type Cacher interface {
	Get(*dns.Question) ([]dns.RR, *dns.Question)
	Put([]dns.RR)
	PutNeg(*dns.Question, []dns.RR)
	Len() int
}
