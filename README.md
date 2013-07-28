# MASSCAN: Mass IPv4 port scanner

This port scanner with the following features:
* very large ranges (like the entire Internet or 10.x.x.x)
* very fast (millions of packets/second)
* randomization of port/IP combo
* stateless
* kill list (easily avoid certain ranges)

This port scanner has the following limitations:
* only tests if port is open/closed, no banner checking
* only 'raw' packet support

# Status

Only compiles on Windows at the moment, but it's generic ANSI C and
libpcap, so only minor changes are needed to make it work on Linux.

# Building

First, install libpcap.

	$ apt-get install libpcap-dev

Then type make, there is no configuration step.

	$ make

On Windows, use the VisualStudio 2010 project.

# Regression testing

The project contains a built-in self-test using the '-T' option. Run
it like the following:

	$ masscan -T
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

	$ masscan -p80,8000-8100 10.0.0.0/8 --rate=1000 --ignore=killist.txt

This will:
* scan the 10.x.x.x subnet, all 16 million addresses
* transmits at a rate of 1000 packets/second
* scans port 80 and the range 8000 to 8100, or 102 addresses total
* ignores any address ranges in the file killist.txt

# How it works

Using a custom network driver (PF_RING, DPDK), a low-end computer can 
transmit packets at a rate of 15-million packets/second. This means we can 
scan the entire Internet of port 80 in under five minutes.

This assumes trivial overhead for generating packets. That's the purpose of
this program: to do the least amount of processing per packet possible. We
start with a 15-mpps packet generator, and then work backwards to figure out
the minimal logic to create those packets.

This also assumes that packets don't get dropped on reception. If we attempt
to send 15-mpps at a target subnet, most will get dropped. In addition, this
will annoy the target. While we can send packets at that rate, we need to
make sure nobody receives them at that rate.

We solve this problem by randomizing the order in which we send packets. 
Assuming we are scanning ALL ports and ALL IPv4 addresses, this means that
packet we send will have a completely random IPv4 address and port number.

One way to randomize is to keep track of "state", consisting of a table of
things we have yet to transmit. This is messy. It would consume a huge amount
of memory, and be slow as each packet caused one or more cache misses.

A better way is to first assign each packet a sequence number, then use an
algorithm that creates a 1-to-1 translation to a new sequence. In other 
words:
	seqno = translate(seqno);
We need to look for a mathematical algorithm that has this 1-to-1 property.

The LCG algorithm fits this property. Given an input sequence of numbers,
such as 1 through 10, it'll spit them out in random order, without keeping
state. (LCG stands for "linear-congruential-generator").

One problem with the LCG is that it needs the right constants. To do that
requires hunting for primes. So one of the major complications is the code
that calculates them on the fly. For a very large range, such as scanning
the entire Internet, it'll take a while to do the calculation.








