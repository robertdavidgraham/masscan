# MASSCAN: Mass IPv4 port scanner

This is a port scanner. It spews out packets at a high rate, then catches any
responses asynchronously. Because it's asynchronous, it's a lot faster than 
''nmap'' -- and a lot less feature rich.

The intent is to be a 48-bit scanner -- scanning all ports (16-bits) on all
IPv4 addresses (32-bits). It's also useful on smaller problems, such as the
10.x.x.x address space within a company.

It randomizes the IPv4+port combination, whereas nmap only randomizes the
IPv4 address. This is so that we can send out 10-million packet per second
when scanning the entire Internet, but the owner of a Class C network will
only see 1 packet per second comming in.


# Building

First, install libpcap.

	$ apt-get install libpcap-dev

Then type make, there is no configuration step.

	$ make

On Windows, use the VisualStudio 2010 project.


# Regression testing

The project contains a built-in self-test:

	$ make regress
	masscan --selftest
	selftest: success!

If the self-test fails, the program returns an exit code of '1' and an
error message particular to which module and subtest failed.

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

