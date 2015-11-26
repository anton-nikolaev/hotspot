#!/usr/bin/perl

use strict;
use constant CONFIG_PATH => '/usr/local/etc/hotspot.ini';
use Data::Dumper;
use Config::IniFiles;

my $ini = Config::IniFiles->new(-file => CONFIG_PATH)
	or die "Cant read ini file ".CONFIG_PATH;
my $debug = $ini->val('GLOBAL', 'debug');

sub warn_debug
{
	my $msg = shift;
	return 0 unless $debug eq 'yes';
	return warn "$msg";
}

sub sys_run
{
	my $cmd = shift;
	warn_debug($cmd);
	my $exit_code = system($cmd);
	warn "sys_run($cmd) returned non-zero status: $exit_code" if $exit_code;
	return $exit_code;
}

my $rc_conf_local = "/etc/rc.conf.local";
warn_debug("Rewriting $rc_conf_local with network interfaces config");
sys_run("/root/write_rc_conf_local.pl > $rc_conf_local");

warn_debug("Collecting hardware interfaces for all hotspots...");
my %hw_ifaces;
foreach ($ini->Sections)
{
	next unless /^(\w+\d+)(\.\d+)?$/;
	$hw_ifaces{$1} = 1;
}

warn_debug("Restarting interfaces: ".join(', ', keys %hw_ifaces));
foreach (keys %hw_ifaces)
{
	next unless $_;
	sys_run("/etc/rc.d/netif restart $_");
};

warn_debug("Restarting named");
sys_run("/etc/rc.d/named restart");

warn_debug("Restarting netgraph nodes");
sys_run("/usr/local/etc/rc.d/010.hotspot stop");
sys_run("/usr/local/etc/rc.d/010.hotspot start");

my $dhcp_conf = "/usr/local/etc/hs-dhcp.conf";
warn_debug("Rewriting $dhcp_conf with dhcpd config");
sys_run("/root/write_dhcpd_conf.pl > $dhcp_conf");

warn_debug("Restarting dhcp server");
sys_run("/usr/local/etc/rc.d/isc-dhcpd restart");

warn_debug("Restarting web server");
sys_run("/usr/local/etc/rc.d/starman restart");

warn_debug("Reloading firewall rules");
sys_run("/etc/rc.d/ipfw restart");
