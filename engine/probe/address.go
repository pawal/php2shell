package probe

import "net/netip"

// block is a range the policy declines, named for the refusal.
type block struct {
	prefix netip.Prefix
	name   string
}

func mustBlocks(pairs ...string) []block {
	out := make([]block, 0, len(pairs)/2)
	for i := 0; i < len(pairs); i += 2 {
		out = append(out, block{netip.MustParsePrefix(pairs[i]), pairs[i+1]})
	}
	return out
}

// ipv4Declined is every IANA special-purpose IPv4 block not globally reachable.
var ipv4Declined = mustBlocks(
	"0.0.0.0/8", "this network",
	"10.0.0.0/8", "private use",
	"100.64.0.0/10", "shared address space",
	"127.0.0.0/8", "loopback",
	"169.254.0.0/16", "link local",
	"172.16.0.0/12", "private use",
	"192.0.0.0/24", "IETF protocol assignments",
	"192.0.2.0/24", "documentation",
	"192.88.99.0/24", "6to4 relay anycast",
	"192.168.0.0/16", "private use",
	"198.18.0.0/15", "benchmarking",
	"198.51.100.0/24", "documentation",
	"203.0.113.0/24", "documentation",
	"224.0.0.0/4", "multicast",
	"240.0.0.0/4", "reserved",
)

// ipv6Global is the only IPv6 range admitted; everything outside it is declined.
var ipv6Global = netip.MustParsePrefix("2000::/3")

// ipv6Declined are the blocks inside 2000::/3 that are not ordinary hosts,
// among them every form that carries an IPv4 address.
var ipv6Declined = mustBlocks(
	"2001::/23", "IETF protocol assignments",
	"2001::/32", "Teredo, which embeds IPv4",
	"2001:db8::/32", "documentation",
	"2002::/16", "6to4, which embeds IPv4",
	"3fff::/20", "documentation",
)

// NotGlobalReason names why an address is not a public unicast host, or
// returns "" for one that is. An IPv4 address carried in IPv6 is refused in
// every form rather than unwrapped.
func NotGlobalReason(addr netip.Addr) string {
	switch {
	case !addr.IsValid():
		return "invalid address"
	case addr.Zone() != "":
		return "scoped address"
	case addr.Is4In6():
		return "IPv4-mapped IPv6, which embeds IPv4"
	case addr.Is4():
		for _, b := range ipv4Declined {
			if b.prefix.Contains(addr) {
				return b.name
			}
		}
		if addr == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
			return "broadcast"
		}
		return ""
	}
	if !ipv6Global.Contains(addr) {
		return ipv6Outside(addr)
	}
	for _, b := range ipv6Declined {
		if b.prefix.Contains(addr) {
			return b.name
		}
	}
	if isatap(addr) {
		return "ISATAP, which embeds IPv4"
	}
	return ""
}

// ipv6Outside names the common ranges outside 2000::/3 for a clearer refusal.
func ipv6Outside(addr netip.Addr) string {
	for _, b := range ipv6Named {
		if b.prefix.Contains(addr) {
			return b.name
		}
	}
	return "not global unicast IPv6"
}

var ipv6Named = mustBlocks(
	"::/128", "unspecified",
	"::1/128", "loopback",
	"::/96", "IPv4-compatible IPv6, which embeds IPv4",
	"::ffff:0:0:0/96", "IPv4-translated IPv6, which embeds IPv4",
	"64:ff9b::/96", "NAT64, which embeds IPv4",
	"64:ff9b:1::/48", "NAT64, which embeds IPv4",
	"100::/64", "discard only",
	"fc00::/7", "unique local",
	"fe80::/10", "link local",
	"fec0::/10", "site local",
	"ff00::/8", "multicast",
)

// isatap reports an interface identifier of the ISATAP form, 0000:5efe or
// 0200:5efe followed by an IPv4 address (RFC 5214).
func isatap(addr netip.Addr) bool {
	b := addr.As16()
	return (b[8] == 0x00 || b[8] == 0x02) && b[9] == 0x00 && b[10] == 0x5e && b[11] == 0xfe
}
