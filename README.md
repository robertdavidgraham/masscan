# MASSCAN: Mass IPv4 port scanner

This is a port scanner. It spews out packets at a high rate, then catches any
responses asynchronously. Because it's asynchronous, it's a lot faster than 
`nmap` -- and a lot less feature rich.

This is a 48-bit scanner: scanning all ports (16-bits) on all
IPv4 addresses (32-bits). It's also useful on smaller problems, such as the
10.x.x.x address space within a company.

It randomizes the IPv4+port combination, whereas `nmap only randomizes the
IPv4 address. This is so that we can send out 10-million packet per second
when scanning the entire Internet, but the owner of a Class C network will
only see 1 packet per second comming in.


# Building

On Debian/Ubuntu, it goes something like this:

	$ git clone https://github.com/robertdavidgraham/masscan
	$ cd masscan
	$ sudo apt-get install build-essential
	$ sudo apt-get install libpcap-dev
	$ make
	$ make regresss

This puts the program in the `masscan\bin` subdirectory.

* Windows: use the Visual Studio 2010 project in the `vs10` subdirectory
* Windows: MingGW should work
* Windows: cygwin shouldn't work
* Mac OS X: once you install the development tools, just `make`
* FreeBSD: doesn't work, probably, but I'm hoping to get around to it
* other: won't work, don't care

The code works with PF_RING. There are no special build instructions. After
(or before) building this project, follow the PF_RING directions to install.
Run Masscan with the `--pfring` option, and it will go try to use PF_RING 
instead of libpcap. If it can't find the driver (`pf_ring`) or the shared
library (`/usr/lib/libpfring.so`), it'll warn you. For me, even `make install`
didn't install things, so I had to manually install the kernel drivers and
shared library. With the PF_RING-customized driver `ixgbe` on an Intel 10gbps
network card, this program runs at 12-million packets/second.


# Regression testing

The project contains a built-in self-test:

	$ make regress
	bin/masscan --regress
	selftest: success!

If the self-test fails, the program returns an exit code of '1' and an
error message particular to which module and subtest failed.

NOTE: The regression test is completely offline: it doesn't send any packets.
It's just testing the invidual units within the program. I plan to create
an online test, where a second program listens on the network to verify
that what's transmitted is the same thing that was specified to be sent.


# Usage

Usage is similar to `nmap`, such as the following scan:

	# masscan -p80,8000-8100 10.0.0.0/8

This will:
* scan the 10.x.x.x subnet, all 16 million addresses
* scans port 80 and the range 8000 to 8100, or 102 addresses total
* print output to <stdout> that can be redirected to a file

To see the complete list of options, use the `--echo` feature. This
dumps the current configuration and exits. This ouput can be used as input back
into the program:

	# masscan masscan -p80,8000-8100 10.0.0.0/8 --echo > xxx.conf
	# masscan -c xxx.conf --rate 1000


# Comparison with Nmap

Where reasonable, every effort has been taken to make the program familiar
to `nmap` users, even though it's fundamentally different. Two important
differences are:

* no default ports to scan, you must specify `-p <ports>`
* target hosts are IP addresses or simple ranges, not DNS names, nor 
  the funky subnet ranges `nmap` can use.

You can think of `masscan` as having the following settings permanently
enabled:
* `-sS`: this does SYN scan only (currently, will change in future)
* `-Pn`: doesn't ping hosts first, which is fundamental to the async operation
* `-n`: no DNS resolution happens
* `--randomize-hosts`: scan completely randomized
* `--send-eth`: sends using raw `libpcap`

If you want a list of additional `nmap` compatible settings, use the following
command:

	# masscan --nmap

# Tips on reading the code

The file `main.c` contains the `main()` function, as you'd expect. Also,
this file contains the main scanning thread that spews packets, as well
as the catching thread that catches responses. This is the core functionality
of the program, everything else is secondary.


# Transmit rate (IMPORTANT!!)

This program spews out packets very fast. On Windows, or from VMs,
it can do 300,000 packets/second. On a Linux (no virtualization) it'll
do 1.6 million packets-per-second. That's fast enough to melt most networks.

Note that it'll only melt your own network. It randomizes the target
IP addresses so that it shouldn't overwhelm any one network.

By default, the rate is set to 100 packets/second. To increase the rate to
a million use something like "--rate 1000000".


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
without keeping any state in memory. In other words, scanning the 
entire Internet for all ports is a 48-bit problem (32-bit address and
16-bit port), but we accomplish this with only a few kilobytes of
memory.

# Authors

This tool created by Robert Graham:
email: robert_david_graham@yahoo.com
twitter: @ErrataRob

