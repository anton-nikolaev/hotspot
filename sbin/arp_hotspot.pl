#!/usr/bin/perl

use strict;
use Data::Dumper;
use Getopt::Long;
use POSIX qw(strftime);
#use Net::ARP;
use constant ARP_BIN => '/usr/sbin/arp';

my ($ip_addr, $mac_addr, $delete);
my $opt = Getopt::Long::Parser->new();
$opt->getoptions
(
	'ip_addr=s' => \$ip_addr,
	'mac_addr=s' => \$mac_addr,
	'delete' => \$delete
);

die "Mandatory parameter ip_addr missing" unless $ip_addr;
die "Parameter ip_addr is invalid: $ip_addr"
	unless $ip_addr =~ /^(\d{1,3}(\.\d{1,3}){3})(\/32)?$/;
$ip_addr = $1;

if ($delete)
{
#	warn "Removing $ip_addr from arp table";
	if(open(ARP_DEL, ARP_BIN." -nd $ip_addr"))
	{
		my @output;
		while (<>)
		{
			chomp;
			push (@output, $_);
		};
		my $output = join(' ', @output);
		die "Cant delete arp record for ip $ip_addr: $output"
			unless $output =~ /^\s*[\d\.]+\s+\([\d\.]+\)\s+deleted\s*$/;
		close(ARP_DEL);
	};
}
elsif ($mac_addr and $ip_addr)
{
	# arp static fix requested
#	warn "Adding a static fix for $ip_addr with mac $mac_addr";
	$mac_addr = lc($mac_addr);
	die "Parameter mac_addr is invalid: $mac_addr"
		 unless $mac_addr =~ /^[\da-f]{2}(\:[\da-f]{2}){5}$/;
	system(ARP_BIN." -ns $ip_addr $mac_addr");
}
else
{
	# get arp address by ip requested

	#	print STDOUT Net::ARP::arp_lookup("", $ip_addr);
	open(ARP_CMD, ARP_BIN." -an|")
		or die "Cant run arp: $!";
#my %arp_table;
	while(<ARP_CMD>)
	{
		chomp;
		next unless /\s+\(([\d\.]+)\)\s+/;
		my $ip = $1;
		next unless $ip eq $ip_addr;
		next unless /\s+([\da-f]{2}(\:[\da-f]{2}){5})\s+/;
		my $mac = $1;
		print STDOUT $mac if $mac;
		last;
#	$arp_table{$ip} = $mac;
	};
	close(ARP_CMD);
};
#warn Dumper \%arp_table;
#print STDOUT $arp_table{$ip_addr};
