#!/usr/bin/perl

use strict;
use Plack::Builder;
use Plack::Util;

my $builder = Plack::Builder->new();
my $app = $builder->mount
	('/' => Plack::Util::load_psgi '/usr/local/www/psgi/index.psgi');
$app = $builder->mount
	('/accounting' =>
		Plack::Util::load_psgi '/usr/local/www/psgi/web_acct.psgi');
$app = $builder->mount
	('/remove_ss' =>
		Plack::Util::load_psgi '/usr/local/www/psgi/remove_ss.psgi');
$builder->to_app($app);
