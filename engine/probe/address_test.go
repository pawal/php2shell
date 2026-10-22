package probe

import (
	"net/netip"
	"testing"
)

func TestNotGlobalReason(t *testing.T) {
	public := []string{
		"93.184.215.14", "1.1.1.1", "8.8.8.8",
		"2606:4700:4700::1111", "2a00:1450:4001:82a::200e", "2620:4f:8000::1",
	}
	for _, text := range public {
		if reason := NotGlobalReason(netip.MustParseAddr(text)); reason != "" {
			t.Errorf("%s declined as %q", text, reason)
		}
	}
	declined := []string{
		"0.0.0.0", "10.1.2.3", "100.64.0.1", "127.0.0.1", "169.254.169.254",
		"172.16.0.1", "192.0.2.1", "192.168.1.1", "198.18.0.1", "198.51.100.1",
		"203.0.113.1", "224.0.0.1", "240.0.0.1", "255.255.255.255",
		"::", "::1", "fc00::1", "fd00::1", "fe80::1", "fec0::1", "ff02::1",
		"2001:db8::1", "3fff::1", "100::1",
		// IPv4 carried in IPv6, whatever the embedded address.
		"::ffff:127.0.0.1", "::ffff:8.8.8.8", "::127.0.0.1", "::8.8.8.8",
		"::ffff:0:8.8.8.8", "64:ff9b::808:808", "64:ff9b::7f00:1",
		"64:ff9b:1::808:808", "2002:7f00:1::1", "2002:808:808::1",
		"2001:0:4136:e378:8000:63bf:3fff:fdd2",
		"2a00:1450:4001:82a:0:5efe:7f00:1", "2a00:1450:4001:82a:200:5efe:808:808",
	}
	for _, text := range declined {
		if NotGlobalReason(netip.MustParseAddr(text)) == "" {
			t.Errorf("%s admitted", text)
		}
	}
	if NotGlobalReason(netip.MustParseAddr("fe80::1%en0")) == "" {
		t.Error("a scoped address admitted")
	}
	if NotGlobalReason(netip.Addr{}) == "" {
		t.Error("the zero address admitted")
	}
}
