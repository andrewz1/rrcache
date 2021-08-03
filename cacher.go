package rrcache

import (
	"github.com/miekg/dns"
)

// Cacher is a cache interface
type Cacher interface {
	Get(*dns.Question) ([]dns.RR, *dns.Question)
	Put([]dns.RR)
	PutNeg(*dns.Question, []dns.RR)
	Len() int
}
