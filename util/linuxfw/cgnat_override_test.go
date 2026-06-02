// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package linuxfw

import (
	"net/netip"
	"reflect"
	"slices"
	"testing"

	"tailscale.com/net/tsaddr"
)

func TestCGNATReturnRanges(t *testing.T) {
	tests := []struct {
		name string
		env  string
		want []netip.Prefix
	}{
		{"empty", "", nil},
		{"single", "100.96.0.0/11", []netip.Prefix{netip.MustParsePrefix("100.96.0.0/11")}},
		{"multiple_with_spaces", " 100.96.0.0/11 , 100.120.0.0/14 ", []netip.Prefix{
			netip.MustParsePrefix("100.96.0.0/11"),
			netip.MustParsePrefix("100.120.0.0/14"),
		}},
		{"skips_invalid", "garbage,100.96.0.0/11", []netip.Prefix{netip.MustParsePrefix("100.96.0.0/11")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("TS_CGNAT_OVERRIDE_RANGE", tt.env)
			if got := cgnatReturnRanges(); !slices.Equal(got, tt.want) {
				t.Errorf("cgnatReturnRanges() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestBuildExternalCGNATRulesOverride verifies that the TS_CGNAT_OVERRIDE_RANGE
// ranges are emitted as RETURN rules in CGNATModeDrop, after the ChromeOS
// RETURN rule and before the CGNAT DROP rule, and that CGNATModeReturn is
// unaffected.
func TestBuildExternalCGNATRulesOverride(t *testing.T) {
	t.Setenv("TS_CGNAT_OVERRIDE_RANGE", "100.96.0.0/11")
	tunname := "tun0"

	gotDrop, err := buildExternalCGNATRules(CGNATModeDrop, tunname)
	if err != nil {
		t.Fatal(err)
	}
	wantDrop := [][]string{
		{"!", "-i", tunname, "-s", tsaddr.ChromeOSVMRange().String(), "-j", "RETURN"},
		{"!", "-i", tunname, "-s", "100.96.0.0/11", "-j", "RETURN"},
		{"!", "-i", tunname, "-s", tsaddr.CGNATRange().String(), "-j", "DROP"},
	}
	if !reflect.DeepEqual(gotDrop, wantDrop) {
		t.Errorf("CGNATModeDrop rules =\n %v\nwant\n %v", gotDrop, wantDrop)
	}

	// Override ranges only apply to the drop mode; return mode is unchanged.
	gotReturn, err := buildExternalCGNATRules(CGNATModeReturn, tunname)
	if err != nil {
		t.Fatal(err)
	}
	wantReturn := [][]string{
		{"!", "-i", tunname, "-s", tsaddr.CGNATRange().String(), "-j", "RETURN"},
	}
	if !reflect.DeepEqual(gotReturn, wantReturn) {
		t.Errorf("CGNATModeReturn rules =\n %v\nwant\n %v", gotReturn, wantReturn)
	}
}
