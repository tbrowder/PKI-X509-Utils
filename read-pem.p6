#!/usr/bin/env perl6

use Base64;

use lib <lib>;
use PKI::X509::Utils;

my @pfils;
if !@*ARGS {
    print qq:to/HERE/;
    Usage: $*PROGRAM-NAME go

    Extracts base64 dedoded text from a test set of pem files.
    HERE
    exit;
}
 
my $debug = 0;
my $inc = 100;
for @pfils -> $pfil {
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

BEGIN {
@pfils = <
t/certbot-acme-testdata/cert-100sans.pem
t/certbot-acme-testdata/cert-idnsans.pem
t/certbot-acme-testdata/cert-san.pem
t/certbot-acme-testdata/cert.pem
t/certbot-acme-testdata/critical-san.pem
t/certbot-acme-testdata/csr-100sans.pem
t/certbot-acme-testdata/csr-6sans.pem
t/certbot-acme-testdata/csr-idnsans.pem
t/certbot-acme-testdata/csr-nosans.pem
t/certbot-acme-testdata/csr-san.pem
t/certbot-acme-testdata/csr.pem
t/certbot-acme-testdata/dsa512_key.pem
t/certbot-acme-testdata/rsa1024_key.pem
t/certbot-acme-testdata/rsa2048_cert.pem
t/certbot-acme-testdata/rsa2048_key.pem
t/certbot-acme-testdata/rsa256_key.pem
t/certbot-acme-testdata/rsa512_key.pem
>;
} # end BEGIN block
