limnoria-whosthere
===================

A Limnoria plugin that lists who has active DHCP leases
-------------------------------------------------------

### Background

One day in the #sshc IRC channel, a good-natured ribbing of who was spending lots of time in the space occurred. While someone was denying that they had spent over 24 hours straight in the space, an idea came to mind - what if we just look at the DHCP lease table in the dynamic IP address range to see who's there? 

From that, this plugin was born. 

### How it works

Since the DHCP server is considered a "trusted" host, and the IRC bot is on a non-trusted network, there's some gapping put in place.

For our design, we use a host called "`monkey`" that sits on the trusted network.

These tasks are run on a schedule:

1. `monkey` logs into the DHCP server, and pulls the lease pool database
2. `monkey` reads the lease pool database, focuses on the dynamic DHCP range, does DNS lookups as a last-ditch effort to add in missing hostnames, and stores the data structure of the information to a pickle file
3. `monkey` SCPs the resulting picklefile to the server running the IRC bot

The IRC bot then:

1. When prompted, loads the picklefile that was SCP'd from `monkey`
2. Dumps out active leases.

Since only `monkey` has private keys to the DHCP server and the IRC bot server, compromising the IRC bot or the server it runs on will not compromise access to the DHCP server.

### Features

Well, none of this is written yet, but here's the initial roadmap:

* Lists IPs, hostnames, and MAC addresses (with the last three fields masked for privacy) 
* Will look up MAC aaddresses in the IEEE OUI database, if stored locally (http://standards.ieee.org/develop/regauth/oui/oui.txt)

### TODO

These are not going to get implemented off the bat, but will be:

* Ability to store a mapping of hostnames to real people
* Flag to turn on/off MAC address masking

### Requirements

* A Limnoria IRC bot. (I'm not using any of the Limnoria-specific features,
 so Supybot should work as well.)

#### Python libraries required:

* pyparsing
* ipaddr
