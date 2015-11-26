#!/usr/bin/perl 

use strict;
use Authen::Radius;
use Data::Dumper;

Authen::Radius->load_dictionary('/usr/local/etc/radius.dictionary');

	my $rad = Authen::Radius->new
	(
		Host => '4.4.4.4:1645',
		Secret => 'qwe123',
		TimeOut => 5
	);

	my %attrs =
	(
          'NAS-Port-Type' => 'Wireless-IEEE-802-11',
          'Acct-Session-Id' => 'd0c6c2d6',
          'Service-Type' => 'Login-User',
          'Called-Station-Id' => 'hs-someloc',
          'Calling-Station-Id' => '00:ff:ff:ff:aa:aa',
          'User-Name' => 'some-user',
          'NAS-Identifier' => 'Burnet HotSpot',
          'User-Password' => 'secret',
          'Framed-IP-Address' => '192.168.5.5',
          'NAS-IP-Address' => '192.168.6.6',
          'NAS-Port' => '0307385829',
          'NAS-Port-Id' => 'rl0.698'
	);

	map
	{
		$rad->add_attributes({ Name => $_, Value => $attrs{$_} })
	} keys %attrs;

#	$rad->add_attributes({ Name => 8,
#		Value => '512k', Vendor => 14988});

	$rad->send_packet(ACCESS_REQUEST)
		or die "Cant send_packet to ".$rad->get_active_node.
			" via Authen::Radius: ".$rad->get_error." ".$rad->strerror;

	my $rep_code = $rad->recv_packet("DETECT_BAD_ID");

	my %reply_attrs =
		map { $_->{'Name'} => $_->{'Value'} } $rad->get_attributes;
#		map { warn Dumper $_ } $rad->get_attributes;

#	warn $rep_code;
	warn Dumper \%reply_attrs;

