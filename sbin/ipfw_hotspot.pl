#!/usr/bin/perl

use strict;
use Config::IniFiles;
use Net::CIDR;
use DBM::Deep;
use Data::Dumper;
use HTML::Template;
use Getopt::Long;
use POSIX qw(strftime);
use constant CONFIG_PATH => '/usr/local/etc/hotspot.ini';

my $ini = Config::IniFiles->new(-file => CONFIG_PATH)
	or die "Cant read ini file ".CONFIG_PATH;
my $debug = $ini->val('GLOBAL', 'debug');
my $db_dir = $ini->val('GLOBAL', 'local_mdb_dir_path');
my $tmpl_dir = $ini->val('GLOBAL', 'ipfw_tmpl_dir');
my $min_rule_num = $ini->val('GLOBAL', 'ipfw_min_rule_num');
my $max_rule_num = $ini->val('GLOBAL', 'ipfw_max_rule_num');

my $req_ip;
my $rate_limit;
my $grant_access;
my $revoke_access;
my $rc_load;
my $opt = Getopt::Long::Parser->new();
$opt->getoptions
(
	'rate_limit=i' => \$rate_limit,
	'revoke_access' => \$revoke_access,
	'grant_access' => \$grant_access,
	'rc_load' => \$rc_load,
	'session_ip=s' => \$req_ip
);

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

my $ss_db;
$ss_db = DBM::Deep->new("$db_dir/sessions.dbm");

die "Options revoke_access and grant_access should not be used together."
	if $revoke_access and $grant_access;

my @ipfw_commands;

if ($revoke_access or $grant_access)
{
	die "Mandatory parameter session_ip missing." unless $req_ip;
	die "Session for ip $req_ip does not exists."
		unless $ss_db->exists($req_ip);
	my $ss = $ss_db->get($req_ip);

	# get ipfw tab num for this ip
	my $iface = $ss->get('iface')
		or die "Cant get iface from session with ip $req_ip";

	my $ipfw_tab_num = $ini->val($iface, 'ipfw_table_num')
		or die "Cant get ipfw_table_num for hotspot section $iface";

	warn_debug("Working with ip $req_ip, iface $iface");

	if ($grant_access)
	{
		warn_debug("Grant access requested");

		if ($rate_limit)
		{
			warn_debug("Rate limit requested: $rate_limit");

			die "Invalid rate_limit (should be positive integer): $rate_limit"
				unless $rate_limit =~ /^\d+$/;

			warn_debug("Searching for free rule_nums in range ".
				"$min_rule_num - $max_rule_num");
			my $in_rate_rule_num;
			my $out_rate_rule_num;
			unless (open(IPFW_LIST, '/sbin/ipfw list|'))
			{
				warn "Cant get ipfw list output, ".
					"rate limit is not applied for $req_ip";
				}
			else
			{
				my %rule_nums;
				while (<IPFW_LIST>)
				{
					chomp;
					next unless /^(\d+)\s+/;				
					# multiply by one needed to trim out all leading zeroes
					$rule_nums{$1 * 1} = 1; 
				};
				close(IPFW_LIST);
				warn_debug("Used rule numbers: ".join(', ', keys %rule_nums));
	
				for (my $i = $min_rule_num; $i < $max_rule_num; ++$i)
				{
					next if exists $rule_nums{$i};
					unless ($in_rate_rule_num)
					{
						$in_rate_rule_num = $i;
						warn_debug("Got rule_num for inbound pipe: ".
							$in_rate_rule_num);
						next;
					}
					else
					{
						$out_rate_rule_num = $i;
						warn_debug("Got rule_num for outbound pipe: ".
							$out_rate_rule_num);
						last;
					};
				};
			};

			$ss->put('out_rate_rule_num' => $out_rate_rule_num);
			$ss->put('in_rate_rule_num' => $in_rate_rule_num);

			my $tmpl = HTML::Template->new
				(filename => $tmpl_dir."/grant_rate_limit.tmpl");
			$tmpl->param(in_rule_num => $in_rate_rule_num);
			$tmpl->param(out_rule_num => $out_rate_rule_num);
			$tmpl->param(rate_limit => $rate_limit);
			$tmpl->param(iface => $iface);
			$tmpl->param(client_ip => $req_ip);
			push (@ipfw_commands, $tmpl->output);
		}; # if ($rate_limit) ...

		push (@ipfw_commands, "/sbin/ipfw table $ipfw_tab_num add $req_ip");

	} # if ($grant_access) ...
	elsif ($revoke_access)
	{
		warn_debug("Revoke access requested");

		die "Parameter rate_limit is usable with grant_access only."
			if $rate_limit;

		my $ipfw_tab_list_cmd = "/sbin/ipfw table $ipfw_tab_num list";
		warn_debug("Running $ipfw_tab_list_cmd");
		unless (open(IPFW_TAB_LIST, $ipfw_tab_list_cmd."|"))
		{
			warn "Cant run $ipfw_tab_list_cmd: $!";
		}
		else
		{
			while (<IPFW_TAB_LIST>)
			{
				chomp;
				/^(\S+)/;
				warn_debug("Table $ipfw_tab_num element $1");
				next if ($1 ne $req_ip) and ($1 ne $req_ip."/32");
				my $rm_cmd = "/sbin/ipfw table $ipfw_tab_num ".
					"delete $req_ip";
				push (@ipfw_commands, $rm_cmd);
			};
			close (IPFW_TAB_LIST);
		};

		# remove rate limit ipfw rules, if there are any
		if ($ss->get('rate_limit'))
		{
			warn_debug("This ip address $req_ip has rate_limit set, removing");
			my $tmpl = HTML::Template->new
				(filename => $tmpl_dir."/revoke_rate_limit.tmpl");
			$tmpl->param(out_rule_num => $ss->get('out_rate_rule_num'));
			$tmpl->param(in_rule_num => $ss->get('in_rate_rule_num'));
			push (@ipfw_commands, $tmpl->output);
		};

	}; # elsif ($revoke_access) ....

} # if ($revoke_access or $grant_access) ...
elsif ($rc_load)
{
	warn_debug("rc_load requested");
	die "Parameter req_ip is only usable with revoke_access or grant_access."
		if $req_ip;

	my %table_nums;
	my $cur_pipe_num = $min_rule_num;
	foreach my $iface ($ini->Sections)
	{
		next if $iface eq 'GLOBAL';
		warn_debug("Working with iface $iface");

		my $tmpl = HTML::Template->new(filename => $tmpl_dir."/rc_load.tmpl");

		my $table_num = $ini->val($iface, 'ipfw_table_num');
		die "Duplicate ipfw_table_num parameter for $iface"
			if exists $table_nums{$table_num};
		$table_nums{$table_num} = 1;

		my $my_ip = $ini->val($iface, 'my_ip_address');
		$my_ip = Net::CIDR::cidrvalidate($my_ip);
		die "Invalid my_ip_address parameter in config section $iface"
			unless $my_ip;

		my $hs_net = $ini->val($iface, 'hs_net');
		$hs_net = Net::CIDR::cidrvalidate($hs_net);
		die "Invalid hs_net parameter in config section $iface"
			unless $hs_net;
		
		warn_debug("my ip address = $my_ip, ".
			"hs network = $hs_net, ".
			"ipfw table number = $table_num");

		my $bw_limit = $ini->val($iface, 'bwidth_limit');
		if ($bw_limit)
		{
			warn_debug("Rate limit for this hotspot set to $bw_limit");

			die "Invalid bwidth_limit value for $iface: $bw_limit"
					unless $bw_limit =~ /^(\d+)(M|K|k)?$/;
			$bw_limit = uc($bw_limit);
	
			warn_debug("Searching for free rule numbers");
			$cur_pipe_num = sprintf('%05d', $cur_pipe_num);
			while (`/sbin/ipfw list |grep ^$cur_pipe_num`)
			{
				warn_debug("Checking rule number $cur_pipe_num");
				++$cur_pipe_num;
				last if $cur_pipe_num >= $max_rule_num;
				$cur_pipe_num = sprintf('%05d', $cur_pipe_num);
			};
			die "Max ipfw rule number reached: $max_rule_num"
				if $cur_pipe_num >= $max_rule_num;
			warn_debug("Using rule number $cur_pipe_num and the next one");
			$tmpl->param(in_pipe_num => ($cur_pipe_num * 1));
			$tmpl->param(out_pipe_num => ++$cur_pipe_num);
			$tmpl->param(bw_limit => $bw_limit);
			++$cur_pipe_num;
		};
	
		$tmpl->param(hotspot_disabled => 1)
			if lc($ini->val($iface, 'hotspot_disabled')) eq 'yes';
		$tmpl->param(radius_auth => 1)
			if lc($ini->val($iface, 'radius_auth')) eq 'yes';
	
		$tmpl->param(table_num => $table_num);
#		$tmpl->param(allowed_tcp_ports => "80,443");
		$tmpl->param(allowed_tcp_ports => "");
		$tmpl->param(iface => $iface);
		$tmpl->param(hs_net => $hs_net);

		my $ss_ip = $ss_db->first_key();
		my @sessions_add;
		while ($ss_ip)
		{
			if ($ss_db->get($ss_ip)->get('iface') eq $iface)
			{
				my $rate_limit = $ss_db->get($ss_ip)->get('rate_limit');
				if ($rate_limit)
				{
					my $rl_tmpl = HTML::Template->new
						(filename => $tmpl_dir."/grant_rate_limit.tmpl");
					$rl_tmpl->param(in_rule_num => $cur_pipe_num);
					$rl_tmpl->param(out_rule_num => ++$cur_pipe_num);
					$rl_tmpl->param(rate_limit => $rate_limit);
					$rl_tmpl->param(iface => $iface);
					$rl_tmpl->param(client_ip => $ss_ip);
					push (@ipfw_commands, $rl_tmpl->output());
					++$cur_pipe_num;
				};

				push (@sessions_add,
					{ ip => $ss_ip, table_num => $table_num });
			};
			$ss_ip = $ss_db->next_key($ss_ip);
		};
		$tmpl->param(sessions_add => \@sessions_add);

		push (@ipfw_commands, $tmpl->output);

	}; # foreach my $iface ($ini->Sections)

} # elsif ($rc_load) ...
else
{
	die "Usage: $0 --revoke_access | --grant_access | --rc_load ".
		"[ --session_ip ip.add.re.ss ] [ --rate_limit bit_s_num ]\n";
};

foreach my $cmd_text (@ipfw_commands)
{
	# use empty lines as separators
	foreach (split(/\n\s*\n/, $cmd_text))
	{
		# take out all newlines
		s/\n/ /g;

		# skip comments
		next if /^\s*\#/;

		# take out any leading spaces
		s/^\s+//;

		# shrink all multiply spaces and tabs
		s/\s+/ /g;

		sys_run($_);
	};
};
