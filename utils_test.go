package rrcache

import (
	"testing"
)

func TestLastRR(t *testing.T) {
	t.Log(lastIsSOA(nil))
}
