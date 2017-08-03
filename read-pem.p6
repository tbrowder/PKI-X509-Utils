#!/usr/bin/env perl6

use Base64;

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
    read-pem($pfil);
}

my %ctyps = [
    # legal certificate types
    # see RFC7468 for details
    # values are handler functions
    'PUBLIC KEY' => 0,
    'ATTRIBUTE CERTIFICATE' => 0,
    'ENCRYPTED PRIVATE KEY' => 0,
    'PRIVATE KEY' => 0,
    'CMS' => 0,
    'CERTIFICATE REQUEST' => 0,
    'CRL' => 0,
    'CERTIFICATE' => 0,
];

my %wtyps = set [
    # old or illegal certificate types
    # see RFC7468 for details
    'PKCS7',
    'NEW CERTIFICATE REQUEST',
];

my $label = rx/<[\-]>+/;
sub read-pem($fname) {
    my $pem-typ = '';
    my $in-pem = 0;
    for $fname.IO.lines -> $line {
        if $in-pem {
            my $asc = pem2asc($line);
        }
        elsif $line ~~ /^ \s* '-----BEGIN ' (<$label>) '-----' \s* $/ {
            # test for pem type
            $in-pem = 1;
        }
        elsif $line ~~ /^ \s* '-----END ' (<$label>) '-----' \s* $/ {
            $in-pem = 0;
        }
    }
}

sub pem2asc($line) {
    constant @base64 = <
        A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
        a b c d e f g h i j k l m n o p q r s t u v w x y z
        0 1 2 3 4 5 6 7 8 9 + /
    >;

    my $nchars = $line.chars;
    # should have 64 chars per line (not counting the eol)
    if $nchars != 64 {
        say "WARNING: line '$line' has $nchars, should be 64.";
    }
    my $nbits = $nchars * 8;
    if !($nbits mod 6) {
        # okay
    }
}


