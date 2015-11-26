#!/usr/bin/perl

use strict;
use Getopt::Long;
use DBM::Deep;
use Config::IniFiles;
use Data::Dumper;
use POSIX qw(strftime);
use constant CONFIG_PATH => '/usr/local/etc/hotspot.ini';

my $ini = Config::IniFiles->new(-file => CONFIG_PATH)
	or die "Cant read ini file ".CONFIG_PATH;
my $debug = $ini->val('GLOBAL', 'debug');
my $db_dir = $ini->val('GLOBAL', 'local_mdb_dir_path');
my $sudo = $ini->val('GLOBAL', 'sudo_bin_path');
my $pre_run_cmd = $ini->val('GLOBAL', 'ipacct_pre_run_cmd');
my $post_run_cmd = $ini->val('GLOBAL', 'ipacct_post_run_cmd');
my $show_cmd = $ini->val('GLOBAL', 'ipacct_run_cmd');
my $pid_file = $ini->val('GLOBAL', 'ipacct_script_pid_file');
my $pid_wait_timeout = $ini->val('GLOBAL', 'ipacct_script_pid_wait_timeout');
my $out_dir = $ini->val('GLOBAL', 'ipacct_output_dir');

die "Invalid directory ($out_dir) in parameter ipacct_output_dir"
	unless -d $out_dir;

if (not $pid_wait_timeout =~ /^\d+$/)
{
	warn "Invalid value for param ipacct_script_pid_wait_timeout (using 15): ".
			$pid_wait_timeout if $pid_wait_timeout;
	$pid_wait_timeout = 15;
};

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

die "Mandatory config parameter missing ipacct_script_pid_file"
	unless $pid_file;

if (-r $pid_file)
{
	my $pid = `/bin/cat $pid_file`;
	$pid =~ s/\D//g;
	my $start_time = time;
	while (kill (0, $pid))
	{
		# process exists
		die "Process PID=$pid still running after ".
			"$pid_wait_timeout sec of waiting. Exiting!"
				if (time - $start_time) > $pid_wait_timeout;
		warn_debug("Waiting for PID $pid to exit...");
		sleep 1;
	};
	# pid file exist, but no process
	unlink($pid_file)
		or die "Cant remove my pid file $pid_file: $!";
};

open (WRITE_PID, ">$pid_file")
	or die "Cant write $pid_file: $!";
print WRITE_PID "$$";
close(WRITE_PID);

my $ss_db = DBM::Deep->new("$db_dir/sessions.dbm");
my %ss_login_by_ip;
my $ss_ip = $ss_db->first_key();
while ($ss_ip)
{
	my $ss = $ss_db->get($ss_ip);
	$ss_login_by_ip{$ss_ip} = $ss->get('login');
	$ss_ip = $ss_db->next_key($ss_ip);
};

warn_debug
("Current sessions: ".
	(
		scalar keys %ss_login_by_ip ?
		join(', ', map { $ss_login_by_ip{$_}." ($_)" } keys %ss_login_by_ip) :
		'none'
	)
);

my $cur_time = time;
my $out_file = "traffic.$cur_time.raw";
my $out_file_tmp = $out_dir."/.tmp.".$out_file;
$out_file = $out_dir."/$out_file";

open(OUT_FILE, ">>$out_file_tmp")
	or die "Cant write $out_file_tmp: $!";

if ($pre_run_cmd)
{
	sys_run("$sudo $pre_run_cmd") and die "pre_run_cmd failed, exiting";
};

my %update_ss_ip;
warn_debug("Gathering ip accounting running $show_cmd with sudo");
open(SHOW_CMD, "$sudo $show_cmd|")
	or die "Cant run $show_cmd: $!";
while(<SHOW_CMD>)
{
	my ($src_ip, $dst_ip, $packs, $bytes, $extra) = split(/\s+/, $_, 5);
	warn ("Extra output: $extra") if $extra;
	my ($outbound, $inbound, $ss_ip);
	my $src_login = "*";
	my $dst_login = "*";
	if (exists $ss_login_by_ip{$src_ip})
	{
		$src_login = $ss_login_by_ip{$src_ip};
		$outbound = "yes";
	}
	elsif (exists $ss_login_by_ip{$dst_ip})
	{
		$dst_login = $ss_login_by_ip{$dst_ip};
		$inbound = "yes";
	};

	if ($inbound)
	{
		# here is inbound traffic for client with session ip as dst_ip
		my $ss = $ss_db->get($dst_ip);
		$ss->put(input_octets => $bytes + $ss->get('input_octets'));
		$ss->put(input_packets => $packs + $ss->get('input_packets'));
		$update_ss_ip{$dst_ip} = $cur_time
			unless exists $update_ss_ip{$dst_ip};
	};
	
	if ($outbound)
	{
		# here is outbound traffic for client with session ip as src_ip
		my $ss = $ss_db->get($src_ip);
		$ss->put(output_octets => $bytes + $ss->get('output_octets'));
		$ss->put(output_packets => $packs + $ss->get('output_packets'));
		$update_ss_ip{$src_ip} = $cur_time
			unless exists $update_ss_ip{$src_ip};
	};

	print OUT_FILE
		"$src_ip $dst_ip $packs $bytes $src_login $dst_login\n";
};
close(SHOW_CMD);
close(OUT_FILE);
sys_run("$sudo $post_run_cmd") if $post_run_cmd;

foreach (keys %update_ss_ip)
{
	my $ss = $ss_db->get($_);
	$ss->put('last_update_time', $cur_time);
};

rename ($out_file_tmp, $out_file)
	or warn "Cant rename $out_file_tmp to $out_file: $!";

unlink($pid_file)
	or die "Cant remove my pid file $pid_file: $!";

__END__

