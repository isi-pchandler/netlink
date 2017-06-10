// +build linux

package netlink

import (
	"testing"
)

func TestGetBridgeLinkInfo(t *testing.T) {
	links, err := GetBridgeLinkInfo()
	if err != nil {
		t.Fatalf("%v", err)
	}
	for _, l := range links {
		t.Logf("%#v", l)
	}
}
