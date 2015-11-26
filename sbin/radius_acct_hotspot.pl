#!/usr/bin/perl

use strict;
use DBM::Deep;
use Config::IniFiles;
use Data::Dumper;
use Authen::Radius;
use Getopt::Long;
use POSIX qw(strftime);
use constant CONFIG_PATH => '/usr/local/etc/hotspot.ini';

#my $uid = $>;
#die "Do not run me as root!" if $uid == 0;

my $ini = Config::IniFiles->new(-file => CONFIG_PATH)
	or die "Cant read ini file ".CONFIG_PATH;
my $debug = $ini->val('GLOBAL', 'debug');
my $db_dir = $ini->val('GLOBAL', 'local_mdb_dir_path');
my $arp_script = $ini->val('GLOBAL', 'arp_script');
my $radius_dict_path = $ini->val('GLOBAL', 'radius_dict_path');
my $radius_secret = $ini->val('GLOBAL', 'radius_secret');
my $radius_timeout = $ini->val('GLOBAL', 'radius_timeout');
my $radius_nas_id = $ini->val('GLOBAL', 'radius_nas_id');
my $radius_nas_ip_address = $ini->val('GLOBAL', 'radius_nas_ip_address');
my $radius_nas_port_type = $ini->val('GLOBAL', 'radius_nas_port_type');
my $default_term_cause = $ini->val('GLOBAL', 'radius_default_term_cause');
my $sudo = $ini->val('GLOBAL', 'sudo_bin_path');
my @radius_acct_servers =
	split(' ', $ini->val('GLOBAL', 'radius_acct_servers'));

Authen::Radius->load_dictionary($radius_dict_path);

sub warn_debug
{
	my $msg = shift;
	return 0 unless $debug eq 'yes';
	return warn strftime('%F %T', localtime)." DEBUG $msg";
}

my ($action, $term_cause, $req_ip);
my $opt = Getopt::Long::Parser->new();
$opt->getoptions
(
	'action=s' => \$action,
	'term_cause=s' => \$term_cause,
	'session_ip=s' => \$req_ip
);

my %default_attrs =
(
	'NAS-Port-Type' => $radius_nas_port_type,
	'NAS-Identifier' => $radius_nas_id,
	'NAS-IP-Address' => $radius_nas_ip_address
);

die "Mandatory parameter action missing" unless $action;
die "Mandatory parameter session_ip missing" unless $req_ip;

my $ss_db = DBM::Deep->new("$db_dir/sessions.dbm");
die "There is no session with ip address $req_ip"
	unless $ss_db->exists($req_ip);

my $ss = $ss_db->get($req_ip);
my $iface = $ss->get('iface');
my $ss_ctime = $ss->get('create_time');
my $client_mac = `$sudo $arp_script --ip_addr=$req_ip`;
$client_mac = $ss->get('mac_address')
	unless $client_mac =~ /^[\da-f]{2}(\:[\da-f]{2}){5}$/;
my $login = $ss->get('login');
my $nas_port = $ss->get('nas_port');
my $ss_id = $ss->get('ss_id');
my $hs_name = $ini->val($iface, 'radius_called_station_id');
my $ss_input_octets = $ss->get('input_octets');
my $ss_output_octets = $ss->get('output_octets');
my $ss_input_packets = $ss->get('input_packets');
my $ss_output_packets = $ss->get('output_packets');

warn_debug
("Processing session for ip $req_ip: ".
	join
	(
		', ',
		(
			"iface=$iface",
			"ctime=".strftime('%F_%T', localtime($ss_ctime)),
			"mac=$client_mac",
			"login=$login",
			"hs=$hs_name",
			"nas_port=$nas_port",
			"ss_id=$ss_id"
		)
	)
);

warn_debug("Session traffic so far (in/out): ".
	"$ss_input_octets/$ss_output_octets bytes, ".
	"$ss_input_packets/$ss_output_packets packets");

my %attrs = 
(
	%default_attrs,
	'Calling-Station-Id' => $client_mac,
	'Called-Station-Id' => $hs_name,
	'NAS-Port-Id' => $iface, 
	'User-Name' => $login,
	'Framed-IP-Address' => $req_ip,
	'NAS-Port' => $nas_port,
	'Acct-Session-Id' => $ss_id,
	'Event-Timestamp' => time
);

if ($action eq 'stop')
{
	$term_cause = $default_term_cause unless $term_cause;
	my %valid_term_cause = 
		map { $_ => 1 }
			(qw(User-Request NAS-Reboot Idle-Timeout NAS-Request));
	die "Parameter term_cause is invalid ($term_cause). Valid are: ".
		join(', ', keys %valid_term_cause)."."
			unless exists $valid_term_cause{$term_cause};

	$attrs{'Acct-Status-Type'} = 'Stop';
	$attrs{'Acct-Terminate-Cause'} = $term_cause;
	$attrs{'Acct-Session-Time'} = time - $ss_ctime;
}
elsif ($action eq 'start')
{
	$attrs{'Acct-Status-Type'} = 'Start';
}
elsif ($action eq 'alive')
{
	$attrs{'Acct-Status-Type'} = 'Alive';
	$attrs{'Acct-Session-Time'} = time - $ss_ctime;
}
else
{
	die "Unknown action parameter value: $action";
};

if (($action eq 'stop') or ($action eq 'alive'))
{
	$attrs{'Acct-Input-Octets'} = $ss_input_octets;
	$attrs{'Acct-Output-Octets'} = $ss_output_octets;
	$attrs{'Acct-Input-Packets'} = $ss_input_packets;
	$attrs{'Acct-Output-Packets'} = $ss_output_packets;
};

my $rad = Authen::Radius->new
(
	Host => $radius_acct_servers[0],
	Secret => $radius_secret,
	NodeList => \@radius_acct_servers,
	TimeOut => $radius_timeout
);

map
{
	$rad->add_attributes({ Name => $_, Value => $attrs{$_} })
} keys %attrs;

warn_debug("Radius acct request prepared with attrs: ".Dumper \%attrs);

unless ($rad->send_packet(ACCOUNTING_REQUEST, 3))
{
	warn "Cant send_packet to ".$rad->get_active_node.
		" via Authen::Radius: ".$rad->get_error." ".$rad->strerror;
}
else
{
	my $rep_code = $rad->recv_packet("DETECT_BAD_ID");
	unless ($rep_code == ACCOUNTING_RESPONSE)
	{
		warn("Radius server ".$rad->get_active_node.
			"returned reply code $rep_code");
	}
	else
	{
		warn_debug("Radius server ".$rad->get_active_node.
			" accept accounting");
	};
	warn_debug("Accounting reply attributes: ".	
			Dumper { map { $_->{'Name'} => $_->{'Value'} }
					$rad->get_attributes });
};
