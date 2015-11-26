#!/usr/bin/perl

use strict;
use Plack::Builder;
use Plack::Request;
use Plack::Response;
use Config::IniFiles;
use Data::Dumper;
use Net::CIDR;
use POSIX qw(strftime);

use constant CONFIG_PATH => '/usr/local/etc/hotspot.ini';
my $ini = Config::IniFiles->new(-file => CONFIG_PATH)
	or die "Cant read ini file ".CONFIG_PATH;

my $debug = $ini->val('GLOBAL', 'debug');
my $db_dir = $ini->val('GLOBAL', 'local_mdb_dir_path');
my $arp_script = $ini->val('GLOBAL', 'arp_script');
my $ipfw_script = $ini->val('GLOBAL', 'ipfw_script');
my $sudo = $ini->val('GLOBAL', 'sudo_bin_path');
my $radius_acct_script = $ini->val('GLOBAL', 'radius_acct_script');
my $ipacct_script = $ini->val('GLOBAL', 'ipacct_script');
my @valid_ip_addrs =
	split(' ', $ini->val('GLOBAL', 'remove_ss_allow_web_access'));

push (@valid_ip_addrs, '127.0.0.1/8') unless @valid_ip_addrs;

foreach (@valid_ip_addrs)
{
	s/^([\d\.]+)$/$1\/32/;
	die "Invalid ip address ($_) in ipacct_allow_web_access parameter"
		unless Net::CIDR::cidrvalidate($_);
};

sub warn_msg
{
	my $msg = shift;
	return warn strftime('%F %T', localtime)." $msg";
}

sub warn_debug
{
	my $msg = shift;
	return 0 unless $debug eq 'yes';
	return warn_msg("DEBUG ".$msg);
}

sub sys_run
{
	my $cmd = shift;
	warn_debug($cmd);
	my $exit_code = system($cmd);
	warn_msg("sys_run($cmd) returned non-zero status: $exit_code") if $exit_code;
	return $exit_code;
}

my $app = sub
{
	my $env = shift;
#	warn Dumper $env;
	my $req = Plack::Request->new($env);

	my $resp = Plack::Response->new(503);
	$resp->content_type('text/plain');
	$resp->body("Gate misconfigured");


	# get client ip, try to detect nginx first
	my $client_ip = $req->header('X-Real-IP');
	$client_ip = $req->address unless $client_ip;
	unless (Net::CIDR::cidrvalidate($client_ip))
	{
		warn_msg("Cant get a proper client ip address!");
		return $resp->finalize;
	};
	warn_debug("Client ip address is $client_ip");
	
	unless (Net::CIDR::cidrlookup($client_ip, @valid_ip_addrs))
	{
		warn_msg("Remove session forbidden for $client_ip, ".
			"allowed only for ".join(' ', @valid_ip_addrs));
		$resp->status(403);
		$resp->body("This function may not be used from ".
			"your ip ($client_ip)");
		return $resp->finalize;
	};

	my $req_ip = $req->param('ss_ip');
	unless ($req_ip)
	{
		warn_msg("Parameter ss_ip missing.");
		$resp->status(400);
		$resp->body('Parameter ss_ip missing.');
		return $resp->finalize;
	};

	my $cookies_db;
	eval { $cookies_db = DBM::Deep->new($db_dir."/cookies.dbm"); }
		or do
		{
			warn_msg("Cant open cookies table: $@ ");
			return $resp->finalize;
		};

	my $ss_db;
	eval { $ss_db = DBM::Deep->new($db_dir."/sessions.dbm"); }
		or do
		{
			warn_msg("Cant open sessions table: $@");
			return $resp->finalize;
		};
	warn_debug("Local cookies and sessions tables opened from $db_dir");

	unless ($ss_db->exists($req_ip))
	{
		warn_msg("Could not find session with ip $req_ip.");
		$resp->status(404);
		$resp->body('Session not founded.');
		return $resp->finalize;
	};

	my $login = $ss_db->get($req_ip)->get('login');
	sys_run($ipacct_script);
	sys_run("$radius_acct_script --action stop ".
		"--session_ip=$req_ip --term_cause=NAS-Request");
	sys_run("$sudo $ipfw_script --revoke_access --session_ip=$req_ip");
	sys_run("$sudo $arp_script --ip_addr=$req_ip --delete");
	$ss_db->delete($req_ip);
	$cookies_db->delete($req_ip) if $cookies_db->exists($req_ip);

	$resp->status(200);
	$resp->body("Session with ip $req_ip and login $login removed.");
	warn_msg("Session $req_ip ($login) removed by web request");
	return $resp->finalize;
}; # my $app = sub { ...

my $builder = Plack::Builder->new();
$app = $builder->mount('/' => $app);
$app = $builder->to_app($app);
