#!/usr/bin/perl

# This script helps the system to maintain hotspot service.
# During shutdown it removes all sessions, send a reboot signal to radius.
# Periodic daemon runs this script to keep all cookies and sessions up to date.

use strict;
use Getopt::Long;
use DBM::Deep;
use Config::IniFiles;
use POSIX qw(strftime);
use constant CONFIG_PATH => '/usr/local/etc/hotspot.ini';

my $ini = Config::IniFiles->new(-file => CONFIG_PATH)
	or die "Cant read ini file ".CONFIG_PATH;
my $debug = $ini->val('GLOBAL', 'debug');
my $db_dir = $ini->val('GLOBAL', 'local_mdb_dir_path');
my $arp_script = $ini->val('GLOBAL', 'arp_script');
my $radius_acct_script = $ini->val('GLOBAL', 'radius_acct_script');
my $ipfw_script = $ini->val('GLOBAL', 'ipfw_script');
my $ipacct_script = $ini->val('GLOBAL', 'ipacct_script');
my $sudo = $ini->val('GLOBAL', 'sudo_bin_path');

my $opt = Getopt::Long::Parser->new();
my $action;
my $req_ip;
$opt->getoptions
(
	'action=s' => \$action,
	'debug=s' => \$debug
);
die "Mandatory parameter action is missing" unless $action;

sub warn_debug
{
	my $msg = shift;
	return 0 unless $debug eq 'yes';
	return warn strftime('%F %T', localtime)." DEBUG $msg";
}

sub sys_run
{
	my $cmd = shift;
	warn_debug($cmd);
	my $exit_code = system($cmd);
	warn "sys_run($cmd) returned non-zero status: $exit_code" if $exit_code;
	return $exit_code;
}

if ($action eq 'shutdown')
{
	# finish all sessions, but keep cookies - so after reboot all goes smoothly
	# remove arp, revoke ipfw access, send acct stop requests
	sys_run($ipacct_script);
	my $ss_db = DBM::Deep->new("$db_dir/sessions.dbm");
	my $ss_ip = $ss_db->first_key();
	while ($ss_ip)
	{
		my $ss = $ss_db->get($ss_ip);
		sys_run("$radius_acct_script --action stop ".
			"--session_ip=$ss_ip --term_cause=NAS-Reboot");
		sys_run("$sudo $ipfw_script --revoke_access --session_ip=$ss_ip");
		sys_run("$sudo $arp_script --ip_addr=$ss_ip --delete");
		$ss_db->delete($ss_ip);
		$ss_ip = $ss_db->next_key($ss_ip);
	};
}
elsif ($action eq 'update')
{
	# manage sessions:
	# - clean up the cookies,
	my $cookies_db = DBM::Deep->new("$db_dir/cookies.dbm");
	my $cookie_ip = $cookies_db->first_key();
	while ($cookie_ip)
	{
		my $this_cookie = $cookies_db->get($cookie_ip);
		my $value = $this_cookie->get('cookie');
		my $ctime = $this_cookie->get('create_time');
		my $iface = $this_cookie->get('iface');
		my $login = $this_cookie->get('login');
	
		warn_debug
		("Processing cookie for ip $cookie_ip: ".
			join
			(
				', ',
				(
					"value=$value",
						"iface=$iface",
					"ctime=".strftime('%F_%T', localtime($ctime)),
					"login=$login",
				)
			)
		);

		my $cookie_timeout = $ini->val($iface, 'cookie_timeout');
		my $cookie_time = time - $ctime;
	
		warn_debug("This cookie lasts for $cookie_time seconds");
		if ($cookie_time > $cookie_timeout)
		{
			warn_debug("It lasts too long ".
				"(timeout for $iface is $cookie_timeout sec), removing");
			$cookies_db->delete($cookie_ip);
		};
		
		$cookie_ip = $cookies_db->next_key($cookie_ip);
	}; # while ($cookie_ip) ...

	sys_run($ipacct_script);

	# - purge old sessions, update active sessions
	my $ss_db = DBM::Deep->new("$db_dir/sessions.dbm");
	my $ss_ip = $ss_db->first_key();
	while ($ss_ip)
	{
		my $ss = $ss_db->get($ss_ip);
		my $iface = $ss->get('iface');
		my $session_timeout = $ini->val($iface, 'session_timeout');
		my $ss_update_time = $ss->get('last_update_time');
		my $idle_time = time - $ss_update_time;
		warn_debug("Session timeout set for iface $iface ".
			"is $session_timeout sec, last update time is ".
				strftime('%F %T', localtime($ss_update_time)));

		if ($idle_time > $session_timeout)
		{
			warn_debug("Session timed out, idle time is $idle_time sec");
			sys_run("$radius_acct_script --action stop ".
				"--session_ip=$ss_ip --term_cause=Idle-Timeout");
			sys_run("$sudo $ipfw_script --revoke_access --session_ip=$ss_ip");
			$ss_db->delete($ss_ip);
			sys_run("$sudo $arp_script --ip_addr=$ss_ip --delete");
		}
		else
		{
			warn_debug("Session is not timed out");
			sys_run("$radius_acct_script --action alive --session_ip=$ss_ip");
		};
		$ss_ip = $ss_db->next_key($ss_ip);
	};
}
else
{
	die "Unknown action parameter: $action";
};
