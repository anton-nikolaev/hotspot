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
my $out_dir = $ini->val('GLOBAL', 'ipacct_output_dir');
my @valid_ip_addrs =
	split(' ', $ini->val('GLOBAL', 'ipacct_allow_web_access'));

push (@valid_ip_addrs, '127.0.0.1/8') unless @valid_ip_addrs;

foreach (@valid_ip_addrs)
{
	s/^([\d\.]+)$/$1\/32/;
	die "Invalid ip address ($_) in ipacct_allow_web_access parameter"
		unless Net::CIDR::cidrvalidate($_);
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

my $app = sub
{
	my $env = shift;
#	warn Dumper $env;
	my $req = Plack::Request->new($env);
	my $resp = Plack::Response->new(503);
	$resp->content_type('text/plain');
	$resp->body("Cant read local accounting files");

	# get client ip, try to detect nginx first
	my $client_ip = $req->header('X-Real-IP');
	$client_ip = $req->address unless $client_ip;
	unless (Net::CIDR::cidrvalidate($client_ip))
	{
		warn "Cant get a proper client ip address!";
		$resp->body("Gate misconfigured");
		return $resp->finalize;
	};
	warn_debug("Client ip address is $client_ip");
	
	unless (Net::CIDR::cidrlookup($client_ip, @valid_ip_addrs))
	{
		warn "Accounting access forbidden for $client_ip, ".
			"allowed only for ".join(' ', @valid_ip_addrs);
		$resp->status(403);
		$resp->body("Accounting can not be retreived from ".
			"your ip ($client_ip)");
		return $resp->finalize;
	};

	my @acct_files;
	opendir(ACCT_DIR, $out_dir)	or do
	{
		warn "Cant opendir $out_dir: $!";
		return $resp->finalize;
	};
	while(readdir ACCT_DIR)
	{
		push (@acct_files, $_);
	};
	closedir(ACCT_DIR);

	my @out_lines;
	my @processed_files;
	foreach (@acct_files)
	{
		next unless /^traffic\.\d+\.raw$/;
		my $file_wpath = $out_dir."/$_";
		open (ACCT_FILE, $file_wpath) or do
		{
			warn "Cant read file $file_wpath: $!";
			return $resp->finalize;
		};
		while(<ACCT_FILE>)
		{
			push (@out_lines, $_);
		};
		close(ACCT_FILE);
		push (@processed_files, $file_wpath);
	};
	
	foreach (@processed_files)
	{
		unlink($_) or warn "Cant remove file $_: $!";
	};
	
	$resp->status(200);
	$resp->body(join('', @out_lines));
	return $resp->finalize;
}; # my $app = sub { ...

my $builder = Plack::Builder->new();
$app = $builder->mount('/' => $app);
$app = $builder->to_app($app);
