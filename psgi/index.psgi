#!/usr/bin/perl

use strict;
use Plack::Builder;
use Plack::Request;
use Plack::Response;
use Plack::App::File;
use Config::IniFiles;
use Data::Dumper;
use Net::CIDR;
use POSIX qw(strftime);
use URI::Encode;
use HTML::Template;
use Authen::Radius;
use DBM::Deep;
use String::Random;

use constant CONFIG_PATH => '/usr/local/etc/hotspot.ini';
my $ini = Config::IniFiles->new(-file => CONFIG_PATH)
	or die "Cant read ini file ".CONFIG_PATH;

my $debug = $ini->val('GLOBAL', 'debug');
my $tmpl_dir = $ini->val('GLOBAL', 'default_tmpl_dir_path');
my $radius_dict_path = $ini->val('GLOBAL', 'radius_dict_path');
my $radius_secret = $ini->val('GLOBAL', 'radius_secret');
my $radius_timeout = $ini->val('GLOBAL', 'radius_timeout');
my $radius_nas_id = $ini->val('GLOBAL', 'radius_nas_id');
my $radius_nas_ip_address = $ini->val('GLOBAL', 'radius_nas_ip_address');
my $radius_nas_port_type = $ini->val('GLOBAL', 'radius_nas_port_type');
my $arp_script = $ini->val('GLOBAL', 'arp_script');
my $ipfw_script = $ini->val('GLOBAL', 'ipfw_script');
my $default_hostname = $ini->val('GLOBAL', 'default_hostname');
my $db_dir = $ini->val('GLOBAL', 'local_mdb_dir_path');
my $default_redirect_url = $ini->val('GLOBAL', 'default_redirect_url');
my $sudo = $ini->val('GLOBAL', 'sudo_bin_path');
my $radius_acct_script = $ini->val('GLOBAL', 'radius_acct_script');
my $ipacct_script = $ini->val('GLOBAL', 'ipacct_script');
my $dhcp_leases_file = $ini->val('GLOBAL', 'dhcp_leases_file');
my @radius_auth_servers =
	split(' ', $ini->val('GLOBAL', 'radius_auth_servers'));

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
	warn "sys_run($cmd) returned non-zero status: $exit_code" if $exit_code;
	return $exit_code;
}

Authen::Radius->load_dictionary($radius_dict_path);

# read and parse all interface vlans on starting daemon
my %hs_vlan_by_ip;
foreach my $vlan_int ($ini->Sections)
{
	next if $vlan_int eq 'GLOBAL';
	my $gate_ip_wprefix = $ini->val($vlan_int, 'hs_net');
	$gate_ip_wprefix = Net::CIDR::cidrvalidate($gate_ip_wprefix);
	die "Invalid hs_net parameter in config section $vlan_int"
		unless $gate_ip_wprefix;
	$hs_vlan_by_ip{$gate_ip_wprefix} = $vlan_int;
};

sub send_radius_auth_req
{
	my %HKeys = @_;

	my $rad = Authen::Radius->new
	(
		Host => $radius_auth_servers[0],
		Secret => $radius_secret,
		NodeList => \@radius_auth_servers,
		TimeOut => $radius_timeout
	);

	my %attrs =
	(
		'NAS-Port-Type' => $radius_nas_port_type,
		'Calling-Station-Id' => $HKeys{'calling_station_id'},
		'Called-Station-Id' => $HKeys{'called_station_id'},
		'NAS-Port-Id' => $HKeys{'nas_port_id'},
		'User-Name' => $HKeys{'user'},
		'Framed-IP-Address' => $HKeys{'client_ip'},
		'User-Password' => $HKeys{'password'},
		'Service-Type' => "Login-User",
		'NAS-Port' => $HKeys{'nas_port'},
		'Acct-Session-Id' => $HKeys{'ss_id'},
		'NAS-Identifier' => $radius_nas_id,
		'NAS-IP-Address' => $radius_nas_ip_address
	);

	map
	{
		$rad->add_attributes({ Name => $_, Value => $attrs{$_} })
	} keys %attrs;

	$attrs{'User-Password'} = '<hidden>' if $attrs{'User-Password'};
	warn_debug("Radius auth request prepared with attrs: ".Dumper \%attrs);

	$rad->send_packet(ACCESS_REQUEST)
		or die "Cant send_packet to ".$rad->get_active_node.
			" via Authen::Radius: ".$rad->get_error." ".$rad->strerror;
	my $rep_code = $rad->recv_packet("DETECT_BAD_ID");

	if ($rep_code)
	{

		my %reply_attrs =
			map { $_->{'Name'} => $_->{'Value'} } $rad->get_attributes;

		warn_debug("Radius server ".$rad->get_active_node.
			" replied with code=$rep_code and attrs: ".Dumper \%reply_attrs);

		return 0 if $rep_code == ACCESS_REJECT;

		die "Radius returned unexpected reply with code = $rep_code"
			unless $rep_code == ACCESS_ACCEPT;

		my $rate_limit = $reply_attrs{'Mikrotik-Rate-Limit'};
		if ($rate_limit =~ /^(\d+)(k|K|M)?$/)
		{
			if (lc($2) eq 'k')
			{
				$rate_limit = $1 * 1024;
			}
			elsif ($2 eq 'M')
			{
				$rate_limit = $1 * (1024 * 1024);
			};
		}
		elsif ($rate_limit)
		{
			warn_msg("Rate limit for ".$HKeys{'client_ip'}.
				" is not valid (ignored): $rate_limit");
			$rate_limit = '';
		};

		return
		{
			login => $HKeys{'user'},
			rate_limit => $rate_limit
		};
	};
	die "Radius server ".$rad->get_active_node.
		" error: ".$rad->get_error." ".$rad->strerror;
}

my $app = sub
{
	my $env = shift;
#	warn Dumper $env;
	my $req = Plack::Request->new($env);
	my $resp = Plack::Response->new(503);
	$resp->content_type('text/html; charset=UTF-8');
	$resp->body("Gate misconfigured.");
	$resp->header('Expires' => strftime('%a, %d %b %Y %T %z', localtime));
	$resp->header('Cache-Control' => 'no-store, no-cache, must-revalidate');

	my $encoder = URI::Encode->new( { encode_reserved => 1 } );
	unless ($req->header('host') eq $default_hostname)
	{
		my $redirect_to =
			"http://$default_hostname/?src_ref=".
			$encoder->encode($req->header('host').$req->path_info);
#		my $redirect_to = "http://$default_hostname";
		warn_debug("Redirecting to $redirect_to");
		$resp->redirect($redirect_to);
		return $resp->finalize;
	};

	# get client ip, try to detect nginx first
	my $client_ip = $req->header('X-Real-IP');
	$client_ip = $req->address unless $client_ip;
	unless (Net::CIDR::cidrvalidate($client_ip))
	{
		warn_msg("Cant get a proper client ip address!");
		return $resp->finalize;
	};
	warn_debug("Client ip address is $client_ip");


	# find interface which this client belongs to
	my $this_client_iface;
	foreach (keys %hs_vlan_by_ip)
	{
		next unless Net::CIDR::cidrlookup($client_ip, $_);
		$this_client_iface = $hs_vlan_by_ip{$_};
		last;
	};

	# no section for such address, probably comes outside or so
	unless ($this_client_iface)
	{
		$resp->code(403);
		$resp->body("There is no hotspot service for ip $client_ip defined.");
		warn_msg("No interface found for ip $client_ip");
		return $resp->finalize;
	};
	warn_debug("Interface for $client_ip is $this_client_iface");

	if (my $web_tmpl_dir = $ini->val($this_client_iface, 'web_tmpl_dir'))
	{
		warn_debug("Using alternative web templates from $web_tmpl_dir");
		$tmpl_dir = $web_tmpl_dir;
	};

	# serve static files and directories
	my $path_info = $req->path_info;
	if ($path_info and (not $path_info =~ /^\s*\/\s*$/))
	{
		return Plack::App::File->new(root => $tmpl_dir)->to_app->($env);
	};

	if ($ini->val($this_client_iface, 'hotspot_disabled') eq 'yes')
	{
		$resp->code(403);
		my $tmpl = HTML::Template->new
			(filename => "$tmpl_dir/hotspot_disabled.html");
#		$resp->body("Service for this hotspot is not provided at the moment.");
		$resp->body($tmpl->output);
		warn_debug("hotspot_disabled set for $this_client_iface");
		return $resp->finalize;
	};

	# Clients without radius auth on interface should access internet via
	# NAT directly. This is impossible him to get there, unless some
	# misconfiguration taken place.
	my $try_radius_auth = $ini->val($this_client_iface, 'radius_auth');
	unless ($try_radius_auth)
	{
		warn_msg("Client with ip $client_ip comes to auth at web-server ".
			"from interface $this_client_iface with radius_auth = no");
		return $resp->finalize;
	};

	# we need mac address of the client
	my $client_mac = `$sudo $arp_script --ip_addr=$client_ip`;
	unless ($client_mac =~ /^[\da-f]{2}(\:[\da-f]{2}){5}$/)
	{
		warn_msg("Invalid arp address for $client_ip: $client_mac");
		return $resp->finalize;
	};
	warn_debug("ARP address for $client_ip is $client_mac");

	# check if this ip given by *our* dhcp server
	open(DHCP_LEASES, $dhcp_leases_file)
		or do
		{
			warn_msg("Cant read dhcp_leases_file $dhcp_leases_file: $!");
			return $resp->finalize;
		};
	my $dhcp_lease_ip_mac;
	while (<DHCP_LEASES>)
	{
		chomp;
		if (/^\s*lease\s+([\d\.]+)\s*\{\s*$/)
		{
			$dhcp_lease_ip_mac = 'ip_founded' if $1 eq $client_ip;
			next;
		};
		$dhcp_lease_ip_mac = $1
			if $dhcp_lease_ip_mac and
			/^\s*hardware ethernet ([\da-fA-F\:]{17})\s*\;\s*$/;
		if (/^\s*binding state (.*)$/ and $dhcp_lease_ip_mac)
		{
			my $bind_state = $1;
			$dhcp_lease_ip_mac = ''
				unless $bind_state =~ /^active\;\s*$/;
		};
		last if $dhcp_lease_ip_mac and /^\s*\}\s*$/;
	};
	close(DHCP_LEASES);
	unless (lc($dhcp_lease_ip_mac) eq lc($client_mac))
	{
		warn_msg("Client mac address from the dhcp lease ($dhcp_lease_ip_mac) ".
			"does not match the one from arp table ($client_mac)");
		my $tmpl = HTML::Template->new
			(filename => "$tmpl_dir/dhcp_lease_mismatch.html");
		$resp->status(403);
		$resp->body($tmpl->output);
		return $resp->finalize;
	};

	# Trying to auth via radius...
	my $called_station_id =
		$ini->val($this_client_iface, 'radius_called_station_id');

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

	# Check his session first...
	my $session_ref = $ss_db->get($client_ip);

	my $str_rand = String::Random->new(max => 8);
	my $new_ss_id = $str_rand->randregex('[a-f0-9]{8}');
	my $new_nas_port = $str_rand->randregex('[0-9]{10}');

	my $client_authenticated;
	if (($req->method eq 'GET') and not $session_ref)
	{
		# he comes from proxy redirect, he wants the login page or 
		# log in automatically with mac or cookie...
			
		# there is no session, so we could create it...
		if ($ini->val($this_client_iface, 'radius_keep_cookie') and
			$req->cookies->{'hs_auth'})
		{
			my $req_cookie = $req->cookies->{'hs_auth'};
			warn_debug("There is our cookie in request: $req_cookie");
			if ($cookies_db->exists($client_ip))
			{
				my $this_cookie = $cookies_db->get($client_ip);
				my $value = $this_cookie->get('cookie');
				my $login = $this_cookie->get('login');
				my $iface = $this_cookie->get('iface');
				my $ctime = $this_cookie->get('create_time');
				my $rate_limit = $this_cookie->get('rate_limit');
				warn_debug("There is a cookie for $client_ip in the table: ".
					"value=$value, login=$login, iface=$iface, ".
					"ctime=".strftime('%F_%T', localtime($ctime)));
				if (($value eq $req_cookie) and ($iface eq $this_client_iface))
				{
					warn_msg("Restoring the session for $client_ip ($login, $rate_limit) ".
							"from cookies table");
					$client_authenticated =
					{
						login => $login,
						rate_limit => $rate_limit
					};
				};
			}
		};

		if ($ini->val($this_client_iface, 'radius_try_mac') and 
			not $client_authenticated)
		{
			warn_debug("Trying to auth $client_ip via mac");
			my $auth_status;
			eval
			{
				$client_authenticated = send_radius_auth_req
				(
					calling_station_id => $client_mac,
					called_station_id => $called_station_id,
					user => uc($client_mac),
					password => 'xxxx',
					nas_port_id => $this_client_iface,
					client_ip => $client_ip,
					ss_id => $new_ss_id,
					nas_port => $new_nas_port
				)
			};
			if ($@)
			{
				$resp->body("Gate is down.");
				warn_msg("Radius auth error: $@");
				return $resp->finalize;
			};
		
			unless ($client_authenticated)
			{
				warn_debug("Auth with mac failed for $client_ip");
			}
			else
			{
				warn_msg("Authorized $client_ip with radius via mac address $client_mac");
			};
		};

		unless ($client_authenticated)
		{
			warn_debug("Sending a login page to $client_ip");
			my $tmpl = HTML::Template->new(filename => "$tmpl_dir/login.html");
			$tmpl->param(src_ref => $encoder->encode($req->param('src_ref')));
			$resp->status(200);
			$resp->body($tmpl->output);
			return $resp->finalize;
		};

		warn_debug("Client $client_ip authenticated with method GET");
	
	} # if (($req->method eq 'GET') and not $session_ref) ...
	elsif (($req->method eq 'GET') and $session_ref)
	{
		# there is a session, so he is already logged in
		# so he wants to view his stats or to log out
		warn_debug("Client $client_ip requested his session stats");
		my $tmpl = HTML::Template->new(filename => "$tmpl_dir/session.html");
		$tmpl->param(path_info => $req->path_info);
		$tmpl->param(login => $session_ref->get('login'));
		$tmpl->param(create_time =>
			strftime('%F %T', localtime($session_ref->get('create_time'))));
		$tmpl->param(traf_in_packs => $session_ref->get('input_packets'));
		$tmpl->param(traf_out_packs => $session_ref->get('output_packets'));
		$tmpl->param(traf_in_bytes => $session_ref->get('input_octets'));
		$tmpl->param(traf_out_bytes => $session_ref->get('output_octets'));
		$tmpl->param
		(
			rate_limit => 
				$session_ref->get('rate_limit') ? 
				($session_ref->get('rate_limit') / 1024) :
				""
		);

		$resp->status(200);
		$resp->body($tmpl->output);
		return $resp->finalize;
	}
	elsif ($req->method eq 'DELETE')
	{
		warn_debug("Client $client_ip requested logout");
		unless ($session_ref)
		{
#			warn_msg("Session for $client_ip does not exists! ".
#				"We cant do the logout.");
			my $redirect_to = "http://$default_hostname";
			warn_debug("Session does not exists, redirecting to $redirect_to");
			$resp->redirect($redirect_to);
			return $resp->finalize;
		};

		if (sys_run($ipacct_script) or
			sys_run("$radius_acct_script --action=stop ".
				"--session_ip=$client_ip --term_cause=User-Request") or
			sys_run("$sudo $ipfw_script --revoke_access ".
				"--session_ip=$client_ip") or
			sys_run("$sudo $arp_script --ip_addr=$client_ip --delete"))
		{
			$resp->body('Gate is down.');
		};

		$cookies_db->delete($client_ip) if $cookies_db->exists($client_ip);
		$ss_db->delete($client_ip);

		warn_msg("Logged out $client_ip");
		$resp->status(200);
		$resp->body('Session logged out.');
		return $resp->finalize;
	}
	elsif ($req->method eq 'POST')
	{
		# comes from login page with login and password, wants to log in..
		if ($session_ref)
		{
			# how does he get there? with a proper session he could not 
			# be redirected here.
			warn_msg("Session for $client_ip already exists");
			return $resp->finalize;
		};

		$resp->status(400);

		my $req_login = $req->param('login');
		unless ($req_login =~ /^[\d\w\.\-\_]{1,50}$/)
		{
			warn_msg("Invalid login ($req_login) received from $client_ip");
			my $tmpl = HTML::Template->new
				(filename => "$tmpl_dir/invalid_login.html");
			$tmpl->param(login => $req_login);
			$resp->body($tmpl->output);
			return $resp->finalize;
		};
		my $req_pass = $req->param('pass');

		warn_debug("Received POST request from $client_ip, trying to ".
			"auth via login and password");
		eval
		{
			$client_authenticated = send_radius_auth_req
			(
				calling_station_id => $client_mac,
				called_station_id => $called_station_id,
				user => $req_login,
				password => $req_pass,
				nas_port_id => $this_client_iface,
				client_ip => $client_ip,
				ss_id => $new_ss_id,
				nas_port => $new_nas_port
			)
		};
		if ($@)
		{
			$resp->status(503);
			$resp->body("Gate is down.");
			warn_msg("Radius auth error: $@");
			return $resp->finalize;
		};

		unless ($client_authenticated)
		{
			$resp->status(403);
			my $tmpl = HTML::Template->new
				(filename => "$tmpl_dir/login_auth_fail.html");
			$tmpl->param(login => $req_login);
#			$resp->body("Access for $req_login rejected.");
			$resp->body($tmpl->output);
			warn_msg("Access for user $req_login on $called_station_id ".
					"rejected by radius.");
			return $resp->finalize;
		};

		warn_msg("Authorized $client_ip with radius via login $req_login and password");

		if ($ini->val($this_client_iface, 'radius_keep_cookie'))
		{
			warn_debug("Generating a new cookie for $req_login");
			my $str_rand = String::Random->new(max => 8);
			my $new_cookie = $str_rand->randregex('[a-zA-Z0-9]{20}');
			my $cookie_create_time = time;
			my %new_cookie_db_av =
			(
				cookie => $new_cookie,
				login => $req_login,
				create_time => $cookie_create_time,
				iface => $this_client_iface,
				rate_limit => $client_authenticated->{'rate_limit'}
			);
			$cookies_db->put($client_ip, \%new_cookie_db_av);
			warn_debug("Cookie saved in the table for ip $client_ip: ".
				Dumper \%new_cookie_db_av);

			my $cookie_expires =
				time + $ini->val($this_client_iface, 'cookie_timeout');

			warn_debug("New cookie ($new_cookie) saved in the table, ".
				"creation time is ".
					strftime('%F %T', localtime($cookie_create_time)).". ".
				"Adding it to the http reply for $client_ip ".
				"with expire date ".
					strftime('%F %T', localtime($cookie_expires)));

			$resp->cookies->{'hs_auth'} =
			{
				value => $new_cookie,
				path  => "/",
				domain => $default_hostname,
				expires => $cookie_expires
			};
		}; # if ($ini->val($this_client_iface, 'radius_keep_cookie'))
		
		warn_debug("Client $client_ip authenticated with method POST");

	} # if ($req->method eq 'GET') ... else if 'POST' ...
	else
	{
		warn_msg("Http method ".$req->method." is not expected");
		$resp->status(405);
		$resp->body("Unsupported method.");
		$resp->header('Allow' => 'GET, POST, DELETE');
	};

	my $ss_rate_limit = $client_authenticated->{'rate_limit'};
	# create session
	my %new_ss_db_av = 
	(
		login => $client_authenticated->{'login'},
		iface => $this_client_iface,
		ss_id => $new_ss_id,
		nas_port => $new_nas_port,
		create_time => time,
		last_update_time => time,
		mac_address => $client_mac,
		input_octets => 0,
		output_octets => 0,
		input_packets => 0,
		output_packets => 0,
		rate_limit => $ss_rate_limit,
		in_rate_rule_num => '',
		out_rate_rule_num => '' 
	);

	$ss_db->put($client_ip, \%new_ss_db_av);
	warn_debug("Session for $client_ip saved in the table.");

	if ($ss_rate_limit and ($ss_rate_limit !~ /^\d+$/))
	{
		warn_msg("Session rate_limit for ip $client_ip is not valid ".
			"(session start skipped): $ss_rate_limit");		
		$ss_rate_limit = '';
	};

	sys_run("$sudo $arp_script --ip_addr=$client_ip --mac_addr=$client_mac");

	sys_run("$radius_acct_script --action=start ".
				"--session_ip=$client_ip");
	sys_run
	(
		"$sudo $ipfw_script --grant_access ".
		"--session_ip $client_ip".
		($ss_rate_limit ? " --rate_limit $ss_rate_limit" : "")
	);

	# we cant do http redirect with headers here, because we need to
	# give him a cookie. so - html method only
	my $src_ref = $req->param('src_ref');
	my $redirect_to = $src_ref ?
		"http://".$encoder->decode($src_ref) : $default_redirect_url;
	warn_debug("Redirecting to $redirect_to");
	$resp->status(200);
	$resp->body
	(	
		'<html><head>'.
			'<meta http-equiv="refresh" content="0;url='.
			$redirect_to.'"'.
		'</head></html>'
	);
	return $resp->finalize;

}; # my $app = sub { ...

my $builder = Plack::Builder->new();
$app = $builder->mount('/' => $app);
$app = $builder->to_app($app);
