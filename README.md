# MASSCAN: Mass IPv4 port scanner

This is a port scanner with the following features:
* very large ranges (like the entire Internet or 10.x.x.x)
* very fast (millions of packets/second)
* randomization of port/IP combo
* stateless
* kill list (easily avoid certain ranges)

This port scanner has the following limitations:
* only tests if port is open/closed, no banner checking
* only 'raw' packet support


# Building

First, install libpcap.

	$ apt-get install libpcap-dev

Then type make, there is no configuration step.

	$ make

On Windows, use the VisualStudio 2010 project.


# Regression testing

The project contains a built-in self-test:

	$ masscan --selftest
	selftest: success!

If the self-test succeeds, you'll get a simple success message, and the
program returns the value of 0 if you want to script it. Otherwise, it'll
print an error message indicating which module failed, and return a 1
as the code.

The regression test is completely offline: it doesn't send any packets.
It's just testing the invidual units within the program. I plan to create
an online test, where a second program listens on the network to verify
that what's transmitted is the same thing that was specified to be sent.


# Usage

An example usage is the following:

	$ masscan -i eth0 -p80,8000-8100 10.0.0.0/8 -c settings.conf

This will:
* scan the 10.x.x.x subnet, all 16 million addresses
* scans port 80 and the range 8000 to 8100, or 102 addresses total

## Setting router MAC address (IMPORTANT!!)

You need to set the destination router's MAC address.
I haven't added the code to figure this out yet. This is done by
putting it in the configuration file:

	router-mac = 00:11:22:33:44:55

or on the command line

	$ masscan --router-mac=00:11:22:33:44:55

## Transmit rate (IMPORTANT!!)

This program spews out packets very fast. Even in virtual-machine
through a virtualized network layer, it can transmit 200,000 packets
per second. This will overload a lot of network.

By default, the program attempts to throttle transmission, but this
code is broken at the moment.


# How it works

Here are some notes on the design.

## Spews out packets asynchronously

This is an **asynchronous** program. That means it has a single thread
that spews out packets indiscriminately without waiting for responses.
Another thread collects the responses.

This has lots of subtle consequences. For example, you can't use this
program to scan the local subnet, because it can't ARP targets and 
wait for responses -- that's synchronous thinking.

## Randomization

Packets are sent in a random order, randomizing simultaneously the IPv4
address and the port.

In other words, if you are scanning the entire Internet at a very fast
rate, somebody owning a Class C network will see a very slow rate of
packets.

The way we do this randomization is that we assign every IP/port combo
a sequence number, then use a function that looks like:

	seqno = translate(seqno);

The `translate()` function uses some quirky math, based on the LCG PRNG
(the basic random number generator we are all familiar with) to do this
translation.

The key property here is that we can completely randomize the order
withou keeping any state in memory. In other words, scanning the 
entire Internet for all ports is a 48-bit problem (32-bit address and
16-bit port), but we accomplish this with only a few kilobytes of
memory.

