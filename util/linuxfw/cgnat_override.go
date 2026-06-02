// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package linuxfw

import (
	"net/netip"
	"strings"

	"tailscale.com/envknob"
)

// cgnatReturnRanges returns the set of CGNAT sub-ranges for which inbound
// off-Tailscale traffic should fall out of the Tailscale chain (RETURN) instead
// of being dropped by the CGNAT drop rule.
//
// The ranges are configured via the TS_CGNAT_OVERRIDE_RANGE environment
// variable as a comma-separated list of CIDRs (e.g. "100.96.0.0/11,100.120.0.0/14").
// Invalid entries are ignored. This is a CoreWeave-specific extension to the
// upstream CGNAT drop behavior; see [iptablesRunner.AddExternalCGNATRules] and
// [nftablesRunner.AddExternalCGNATRules].
func cgnatReturnRanges() []netip.Prefix {
	v := envknob.String("TS_CGNAT_OVERRIDE_RANGE")
	if v == "" {
		return nil
	}
	var out []netip.Prefix
	for _, s := range strings.Split(v, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		p, err := netip.ParsePrefix(s)
		if err != nil || !p.IsValid() {
			continue
		}
		out = append(out, p)
	}
	return out
}
