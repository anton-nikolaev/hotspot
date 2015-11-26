#!/usr/bin/perl

# This script generates dhcp config for isc-dhcpd
# Usage: ./this_script.pl > /usr/local/etc/hs-dhcp.conf

# There should be in the /usr/local/etc/dhcpd.conf file:  
# include "/usr/local/etc/hs-dhcp.conf";

use strict;
use Config::IniFiles;
use Net::CIDR;
use DBM::Deep;
use Data::Dumper;
use HTML::Template;
use IO::Socket;
use constant CONFIG_PATH => '/usr/local/etc/hotspot.ini';

my $ini = Config::IniFiles->new(-file => CONFIG_PATH)
	or die "Cant read ini file ".CONFIG_PATH;
my $debug = $ini->val('GLOBAL', 'debug');
my $include_tmpl = $ini->val('GLOBAL', 'dhcp_config_file_tmpl');

sub warn_debug
{
	my $msg = shift;
	return 0 unless $debug eq 'yes';
	return warn "DEBUG $msg";
}

my @config;
foreach my $iface ($ini->Sections)
{
	next if $iface eq 'GLOBAL';

	my $my_ip = $ini->val($iface, 'my_ip_address');
	$my_ip = Net::CIDR::cidrvalidate($my_ip);
	unless ($my_ip)
	{
		warn "Invalid my_ip_address parameter in config section $iface";
		next;
	};


	my $hs_net = $ini->val($iface, 'hs_net');
	$hs_net = Net::CIDR::cidrvalidate($hs_net);
	unless ($hs_net)
	{
		warn "Invalid hs_net parameter in config section $iface";
		next;
	};

	if (not Net::CIDR::cidrlookup($my_ip, $hs_net))
	{
		warn "Param my_ip_address $my_ip does not belong to hs_net $hs_net";
		next;
	};
	
	unless ($hs_net =~ /\/(\d+)$/)
	{
		warn "Cant get prefix from hs_net parameter in config section $iface";
		next;
	};
	my $net_prefix = $1;
	$my_ip =~ s/\/\d{1,2}$/\/$net_prefix/;

	my $range = $ini->val($iface, 'dhcp_range');
	unless ($range =~ /^\s*(\S+)\s+(\S+)\s*$/)
	{
		warn "Cant find first and last ip in the dhcp_range in config section ".
			"$iface: $range";
		next;
	};
	my $range_first_ip = $1;
	my $range_last_ip = $2;
	my $range_first_n = unpack("N", IO::Socket::inet_aton($range_first_ip));
	my $range_last_n = unpack("N", IO::Socket::inet_aton($range_last_ip));

	if (not $range_first_n or
		not $range_last_n or
		$range_last_n <= $range_first_n)
	{
		warn "Cant convert ip addresses in the dhcp_range in config section ".
			"$iface: $range";
		next;
	};

	if (not Net::CIDR::cidrlookup($range_first_ip, $hs_net) or
		not Net::CIDR::cidrlookup($range_last_ip, $hs_net))
	{
		warn "First or last ip in the dhcp_range in config section $iface ".
				"does not belong to hs_net ($hs_net): $range";
		next;
	};
	
	my $tmpl = HTML::Template->new(filename => $include_tmpl);
	$tmpl->param(hs_net => $hs_net =~ /^(.*)\/\d{1,2}$/);

	# convert prefix to a netmask format 255.255.255.255
	$tmpl->param
	(hs_net_mask =>
		join
		('.', 
			map 
			{
				unpack("N", pack("B32", substr("0" x 32 . $_, -32)))
			}
			(
				(1 x $net_prefix) .
				(0 x (32 - $net_prefix))
			) =~ /(.{8})/g
		)
	);

	$tmpl->param(range_ip_first => $range_first_ip);
	$tmpl->param(range_ip_last => $range_last_ip);
	$tmpl->param(lease_time_in_seconds => $ini->val($iface, 'dhcp_lease_time'));
	$tmpl->param(my_ip_address => $my_ip =~ /^(.*)\/\d{1,2}$/);
	$tmpl->param(hs_name => $iface);
	push(@config, $tmpl->output);

};

print STDOUT join("\n", @config);
