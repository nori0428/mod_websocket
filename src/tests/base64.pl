#!/usr/bin/perl
# https://github.com/ncb000gt/node-base64/tree/master/tests

use MIME::Base64 qw(encode_base64);

my $fname = shift || die "usage: `$0 fname`";

open my $file, '<', $fname or die "$!";
while (read($file, $buf, 60 * 57)) {
    print encode_base64($buf, '');
}

# EOF
