#!/usr/bin/env perl6

use lib <lib>;
use PKI::X509::Utils;

my $pfil = "t/certbot-acme-testdata/cert-100sans.pem";
if !@*ARGS {
    print qq:to/HERE/;
    Usage: $*PROGRAM-NAME N
    where N is number of repetitions in 1000s.
    HERE
    exit;
}
 
my $arg = shift @*ARGS;
my $n = $arg.UInt * 1000;
say "Running $n repetitions...";

my $debug = 0;
my $inc = 100;
for 1..$n -> $i {
    say "Rep $i" if $debug && !($i mod $inc);
    read-pem: $pfil;
}

sub read-pem($fname) {
    for $fname.IO.lines -> $line {
    }
}

sub pem2asc($line) {
}

sub pem2asc($line) {
}

