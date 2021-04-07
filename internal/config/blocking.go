package config

import (
	"fmt"
	"net"

	"github.com/qdm12/dns/pkg/blacklist"
	"github.com/qdm12/golibs/params"
)

func getBlacklistSettings(reader *reader) (settings blacklist.BuilderSettings, err error) {
	settings.BlockMalicious, err = reader.env.OnOff("BLOCK_MALICIOUS", params.Default("on"))
	if err != nil {
		return settings, err
	}
	settings.BlockSurveillance, err = reader.env.OnOff("BLOCK_SURVEILLANCE", params.Default("off"))
	if err != nil {
		return settings, err
	}
	settings.BlockAds, err = reader.env.OnOff("BLOCK_ADS", params.Default("off"))
	if err != nil {
		return settings, err
	}
	settings.AllowedHosts, err = getAllowedHostnames(reader)
	if err != nil {
		return settings, err
	}
	settings.AddBlockedHosts, err = getBlockedHostnames(reader)
	if err != nil {
		return settings, err
	}
	settings.AddBlockedIPs, err = getBlockedIPs(reader)
	if err != nil {
		return settings, err
	}
	settings.AddBlockedIPNets, err = getBlockedIPNets(reader)
	if err != nil {
		return settings, err
	}
	rebindingProtection, err := reader.env.OnOff("REBINDING_PROTECTION", params.Default("on"))
	if err != nil {
		return settings, err
	}
	if rebindingProtection {
		privateIPNets, err := getPrivateIPNets()
		if err != nil {
			return settings, err
		}
		settings.AddBlockedIPNets = append(settings.AddBlockedIPNets, privateIPNets...)
	}

	return settings, nil
}

// getAllowedHostnames obtains a list of hostnames to unblock from block lists
// from the comma separated list for the environment variable UNBLOCK.
func getAllowedHostnames(reader *reader) (hostnames []string, err error) {
	hostnames, err = reader.env.CSV("ALLOWED_HOSTNAMES")
	if err != nil {
		return nil, err
	}
	for _, hostname := range hostnames {
		if !reader.verifier.MatchHostname(hostname) {
			return nil, fmt.Errorf("unblocked hostname %q does not seem valid", hostname)
		}
	}
	return hostnames, nil
}

// getBlockedHostnames obtains a list of hostnames to block from the comma
// separated list for the environment variable BLOCK_HOSTNAMES.
func getBlockedHostnames(reader *reader) (hostnames []string, err error) {
	hostnames, err = reader.env.CSV("BLOCK_HOSTNAMES")
	if err != nil {
		return nil, err
	}
	for _, hostname := range hostnames {
		if !reader.verifier.MatchHostname(hostname) {
			return nil, fmt.Errorf("blocked hostname %q does not seem valid", hostname)
		}
	}
	return hostnames, nil
}

// getBlockedIPs obtains a list of IP addresses to block from
// the comma separated list for the environment variable BLOCK_IPS.
func getBlockedIPs(reader *reader) (ips []net.IP, err error) {
	values, err := reader.env.CSV("BLOCK_IPS")
	if err != nil {
		return nil, err
	}

	ips = make([]net.IP, len(values))
	for _, value := range values {
		ip := net.ParseIP(value)
		if ip == nil {
			return nil, fmt.Errorf("invalid blocked IP: %s", err)
		}
		ips = append(ips, ip)
	}

	return ips, nil
}

// getBlockedIPNets obtains a list of IP networks (CIDR notation) to block from
// the comma separated list for the environment variable BLOCK_IPNETS.
func getBlockedIPNets(reader *reader) (ipNets []*net.IPNet, err error) {
	values, err := reader.env.CSV("BLOCK_IPNETS")
	if err != nil {
		return nil, err
	}

	ipNets = make([]*net.IPNet, len(values))
	for _, value := range values {
		_, ipNet, err := net.ParseCIDR(value)
		if err != nil {
			return nil, fmt.Errorf("invalid blocked IP network CIDR: %s", err)
		}
		ipNets = append(ipNets, ipNet)
	}

	return ipNets, nil
}

func getPrivateIPNets() (privateIPNets []*net.IPNet, err error) {
	privateCIDRs := []string{
		"127.0.0.1/8",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16",
		"::1/128",
		"fc00::/7",
		// "fe80::/10", - TODO intepreted as 0.0.0.0/0
		"::ffff:0:0/96",
	}
	privateIPNets = make([]*net.IPNet, len(privateCIDRs))
	for i := range privateCIDRs {
		_, ipNet, err := net.ParseCIDR(privateCIDRs[i])
		if err != nil {
			return nil, err
		}
		privateIPNets[i] = ipNet
	}

	return privateIPNets, nil
}
