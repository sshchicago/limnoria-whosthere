#!/usr/bin/env python

# 
# dhcpd_leases_parser.py
#
# Copyright 2008, Paul McGuire
#
# Sample parser to parse a dhcpd.leases file to extract leases 
# and lease attributes
#
# format ref: http://www.linuxmanpages.com/man5/dhcpd.leases.5.php
#

sample = r"""\
# All times in this file are in UTC (GMT), not your local timezone.   This is
# not a bug, so please don't ask about it.   There is no portable way to
# store leases in the local timezone, so please don't request this as a
# feature.   If this is inconvenient or confusing to you, we sincerely
# apologize.   Seriously, though - don't ask.
# The format of this file is documented in the dhcpd.leases(5) manual page.
# This lease file was written by isc-dhcp-V3.0.4

lease 192.168.0.250 {
  starts 3 2008/01/23 17:16:41;
  ends 6 2008/02/02 17:16:41;
  tstp 6 2008/02/02 17:16:41;
  binding state free;
  hardware ethernet 00:17:f2:9b:d8:19;
  uid "\001\000\027\362\233\330\031";
}
lease 192.168.0.198 {
  starts 1 2008/02/04 13:46:55;
  ends never;
  tstp 1 2008/02/04 17:04:14;
  binding state free;
  hardware ethernet 00:13:72:d3:3b:98;
  uid "\001\000\023r\323;\230";
}
lease 192.168.0.239 {
  starts 3 2008/02/06 12:12:03;
  ends 4 2008/02/07 12:12:03;
  tstp 4 2008/02/07 12:12:03;
  binding state free;
  hardware ethernet 00:1d:09:65:93:26;
}
"""

f = open('/Users/chris/dhcpd.leases')
sample = f.read()

from pyparsing import *
import datetime,time

LBRACE,RBRACE,SEMI,QUOTE = map(Suppress,'{};"')
ipAddress = Combine(Word(nums) + ('.' + Word(nums))*3)
hexint = Word(hexnums,exact=2)
macAddress = Combine(hexint + (':'+hexint)*5)
hdwType = Word(alphanums)

yyyymmdd = Combine((Word(nums,exact=4)|Word(nums,exact=2))+
                    ('/'+Word(nums,exact=2))*2)
hhmmss = Combine(Word(nums,exact=2)+(':'+Word(nums,exact=2))*2)
dateRef = oneOf(list("0123456"))("weekday") + yyyymmdd("date") + \
                                                        hhmmss("time")

startsStmt = "starts" + dateRef + SEMI
endsStmt = "ends" + (dateRef | "never") + SEMI
clttStmt = "cltt" + dateRef + SEMI
tstpStmt = "tstp" + dateRef + SEMI
tsfpStmt = "tsfp" + dateRef + SEMI
hdwStmt = "hardware" + hdwType("type") + macAddress("mac") + SEMI
uidStmt = "uid" + QuotedString('"')("uid") + SEMI
bindingStmt = "binding" + Word(alphanums) + Word(alphanums) + SEMI
rewindBindingStmt = "rewind binding" + Word(alphanums) + Word(alphanums) + SEMI
nextBindingStmt = "next binding" + Word(alphanums) + Word(alphanums) + SEMI
clientHostnameStmt = "client-hostname" + QuotedString('"') + SEMI


leaseStatement = startsStmt | endsStmt | clttStmt | tstpStmt | tsfpStmt | hdwStmt | \
                    uidStmt | bindingStmt | nextBindingStmt | rewindBindingStmt | clientHostnameStmt

leaseDef = "lease" + ipAddress("ipaddress") + LBRACE + \
                            Dict(ZeroOrMore(Group(leaseStatement))) + RBRACE


leases = []
starttime = time.time()
for lease in leaseDef.searchString(sample):
    thisLease = {}
    thisLease['mac'] = lease.hardware.mac
    thisLease['ip'] = lease.ipaddress
    thisLease['host'] = lease.get('client-hostname')
    thisLease['lease_start'] = lease.starts
    thisLease['lease_end'] = lease.ends
    thisLease['last_interaction'] = lease.cltt

    try:
        client_hostname = lease.client-hostname
    except NameError:
        client_hostname = None
    leases.append(thisLease)

parsetime = time.time() - starttime
print "Took %s seconds to run." % parsetime
#from pprint import pprint
#pprint(leases)
