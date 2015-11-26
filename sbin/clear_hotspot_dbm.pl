#!/usr/bin/perl

use strict;
use Config::IniFiles;
use DBM::Deep;
use Data::Dumper;
use constant CONFIG_PATH => '/usr/local/etc/hotspot.ini';

my $ini = Config::IniFiles->new(-file => CONFIG_PATH)
	or die "Cant read ini file ".CONFIG_PATH;
my $db_dir = $ini->val('GLOBAL', 'local_mdb_dir_path');


foreach (qw(sessions cookies))
{
	warn "$db_dir/$_";
	my $db = DBM::Deep->new("$db_dir/$_.dbm");
	warn Dumper $db->export;
#	$db->clear;
}
