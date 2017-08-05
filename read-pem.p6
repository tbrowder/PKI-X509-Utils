#!/usr/bin/env perl6

use NativeCall;

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
    say "Reading cert file '$pfil'...";
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
    # status: ???
    'DSA PARAMETERS' => 0,
    'DSA PRIVATE KEY' => 0,
];

my %wtyps = set [
    # old or illegal certificate types
    # see RFC7468 for details
    'PKCS7',
    'NEW CERTIFICATE REQUEST',
];

my token label-rx {<-[\-]>+}

sub read-pem($fname) {
    my $pem-typ = '';
    my $in-pem = 0;
    # note there may be multiple certs per file
    # it is an error to have a known last line followed
    # by another in-pem line
    my $last-line = 0;
    for $fname.IO.lines -> $line {
        if $line ~~ /^ \s* '-----BEGIN ' (<label-rx>) '-----' \s* $/ {
            $last-line = 0;
            # test for pem type
            my $label = ~$0;
            say "Found beginning cert label '$label'";
            $in-pem = 1;
            $pem-typ = $label;
        }
        elsif $line ~~ /^ \s* '-----END ' (<label-rx>) '-----' \s* $/ {
            $last-line = 0;
            my $label = ~$0;
            say "Found ending cert label '$label'";
            $in-pem = 0;
            if $label ne $pem-typ {
                say "WARNING: beginning cert label '$pem-typ' doesn't";
                say "         match ending cert label '$label'";
            }
        }
        elsif $in-pem {
            my $asc = pem2asc($line, $last-line);
            say $asc;
        }
    }
}

sub pem2asc($line, $last-line is rw --> Str) {
    constant @base64 = <
        A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
        a b c d e f g h i j k l m n o p q r s t u v w x y z
        0 1 2 3 4 5 6 7 8 9 + /
    >;
    state %base64 = @base64.kv.hash.antipairs;

    my $nchars = $line.chars;
    # should have 64 chars per line (not counting the eol)
    # the last line may be padded to 64 or
    # have less than 64 with or without padding
    # no way, without a peek at the next line, to know
    # for sure it is the last pem line
    
    my $pchars = 0;
    my $pidx = index $line, '=';
    if $pidx {
        $pchars = $nchars - $pidx;
        die "FATAL: num pad chars = $pchars which is > 2" if $pchars > 2;
    }
 
    if $pchars || $nchars != 64 {
        if !$last-line {
            $last-line = 1;
        }
        else {
            say "WARNING: line '$line' is a known last line with an existing last line.";
            say "         num chars = $nchars which is > 64" if $nchars < 64;
            say "         num pad chars = $pchars" if $pchars;
        }
    }

    if !($nchars mod 4) {
        # okay
    }
    else {
        say "WARNING: Illegal line '$line'";
        say "         nchars $nchars is not a multiple of 4!";
        return '';
    }

    my @chars = $line.comb;
    my $asc = '';

    my $count = 0;
    loop (my $i = 0; $i < $nchars; $i += 4) {
        # convert the 4 characters into a 24-bit binary string
        # we should have 4 chars
        my $nchars-remain = $nchars - $i; 
        die "FATAL: have $nchars-remain chars but should have 4" if $nchars-remain < 4;
        # get the 24-bit string first
        my @bits;
        my $has-pad = 0;
        loop (my $j = 0; $j < 4; ++$j) {
            my $e = @chars[$i+$j]; # encoded char
            $has-pad = 1 if $e eq '=';
            my $d = $e eq '=' ?? 0 !! %base64{$e}; 
            my $b = sprintf "%06b", $d;
            @bits.append($b.comb);
        }
        die "FATAL: nbits != 24" if @bits.elems != 24;
        # convert each significant byte back to ascii
        $asc ~= @bits[0..7].join.parse-base(2).chr; 
        $asc ~= @bits[8..15].join.parse-base(2).chr if !$has-pad || $pchars < 2; 
        $asc ~= @bits[16..23].join.parse-base(2).chr if !$has-pad || $pchars < 1; 
    }

    return $asc;
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
