# MASSCAN: Mass IPv4 port scanner

This is a port scanner. It spews out packets at a high rate, up to 10 million
packets-per-second, fast enough to scan the entire Internet for one port
in 6 minutes. I can do this because it's *asynchronous*: one thread transmits
packets, another thread receives them, without much communication between
the treads, or remembering *state* about each packet that was sent.

This program looks a lot like the most famous port scanner, `nmap`, but
because it's *asynchronous*, it's less feature rich (albeit 10,000 times
faster).

This is a 48-bit scanner: scanning all ports (16-bits) on all
IPv4 addresses (32-bits). It's also useful on smaller problems, such as the
10.x.x.x address space within a company.

This randomizes the IPv4+port combination, whereas `nmap` only randomizes the
IPv4 address. That means we don't produce complete output *per host*, but
output *per host+port* combination. By randomizing the port alongside the IP
address, target networks won't get overwhelmed.


# Building

On Debian/Ubuntu, it goes something like this:

	$ git clone https://github.com/robertdavidgraham/masscan
	$ cd masscan
	$ sudo apt-get install libpcap-dev
	$ make
	$ make regresss

This puts the program in the `masscan/bin` subdirectory. You'll have to
manually copy it to something like `/usr/local/bin` if you want to
install it elsewhere on the system.

While Linux is the primary target platform, the code runs well on many other
systems. Here's some additional info:
* Windows:Visual Studio: use the VS10 project in the `vs10` subdirectory
* Windows:MingGW: just type `make`
* Windows:cygwin: won't work, I hate cygwin
* Mac OS X: once you install the development tools, just type `make`
* FreeBSD: type `gmake`, probably will have some problems
* other: won't work, don't care

Linux and Windows (both 64-bit) are what I use every day, so that's what's
likely to work best. If you are having some problem on another platform,
try going back a version or two.


## PF_RING

Because of Linux kernel overhead, the transmit rate is limited to about
2 million packets/second. To go faster, a "zero-overhead" driver is needed
that bypasses the Linux kernel. One such driver is known as PF_RING DNA. Using
this driver, the code can run at 10 million packets/second. And really, it's
only that slow because since I don't have an Internet connection that fast,
I haven't had a time to optimize it further. I'm pretty sure I coiuld get 
20 million packets/second with a minor amount of tuning.

The PF_RING drivers must be installed separately. You need to install the
`pf_ring.ko` driver, as well as replace the `ixgbe.ko` driver for Intel
cards. You need the shared library `/usr/lib/libpfring.so` in the
proper directory. You probably need to reconfigure things so that the 
drivers install automatically on bootup.

As for `masscan`, no special build instructions are needed. Indeed, you
can use a binary built before the installation of any PF_RING files. The
program will automatically detect if PF_RING is available and use it. You
can force the issue with the `--pfring` command-line option, which will 
force `masscan` to fail if it can't use PF_RING, and print diagnostic 
information why.


## Regression testing

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

To test performance, run something like the following:

	$ bin/masscan 0.0.0.0/4 -p80 --rate 100000000 --router-mac 66-55-44-33-22-11

By setting a bogus MAC address for the local router, the packets won't
go anywhere. This will benchmark how fast the program will run on the 
local system, and will also stress test the local switch.


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

	# masscan -p80,8000-8100 10.0.0.0/8 --echo > xxx.conf
	# masscan -c xxx.conf --rate 1000


## How to scan the entire Internet

The program is designed to scan everything. Therefore, you can do something
like the following:

	# masscan 0.0.0.0/0 -p0-65535

This actually won't work, warning you that you don't have any `--exclude`
ranges defined. That's because indiscriminate scanning of the entire Internet
quickly gets your IP address on ban lists, causing your IP address to get
filtered before you complete the scan. Thus, but excluding the ranges of
people who don't want to be scanned, you can avoid such bans. I hate it when
I do this accidentally, so I've put this warning mechanism in to prevent
accidental mistakes when scanning any range larger than a billion addresses.

Therefore, what your command will really look like is the following:

	# masscan 0.0.0.0/0 -p0-65535 --excludefile exclude.txt

But this just prints the results to the command-line. You probably want them
saved to a file instead. Therefore, you want something like:

	# masscan 0.0.0.0/0 -p0-65535 --excludefile exclude.txt -oX scan.xml

This saves the results in an XML file, allowing you to easily dump the
results in a database or something.

But, this only goes at the default rate of 100 packets/second, which will
take forever to scan the Internet. You need to speed it up as so:

	# masscan 0.0.0.0/0 -p0-65535 --excludefile exclude.txt -oX scan.xml --max-rate 100000

This increases the rate to 100,000 packets/second, which will scan the
entire Internet (minus excludes) in about 10 hours per port (or 655,360 hours
if scanning all ports).

The thing to notice about this command-line is that these are all `nmap`
compatible options. In addition, "invisible" options compatible with `nmap`
are also set for you: `-sS -Pn -n --randomize-hosts --send-eth`. Likewise,
the format of the XML file is inspired by `nmap`. There are, of course, a
lot of minor differences, because the *asynchronous* nature of the program
leads to a fundamentally different approach to the problem.

The above command-line is a bit cumbersome. Instead of putting everything
on the command-line, it can be stored in a file instead. The above settings
would look like this:

	# My Scan
	rate =  100000.00
	output-format = xml
	output-status = all
	output-filename = scan.xml
	ports = 0-65535
	range = 0.0.0.0-255.255.255.255
	excludefile = exclude.txt

To use this configuration file, use the `-c`:

	# masscan -c myscan.conf

This also makes things easier when you repeat a scan.


## Comparison with Nmap

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

## Transmit rate (IMPORTANT!!)

This program spews out packets very fast. On Windows, or from VMs,
it can do 300,000 packets/second. On a Linux (no virtualization) it'll
do 1.6 million packets-per-second. That's fast enough to melt most networks.

Note that it'll only melt your own network. It randomizes the target
IP addresses so that it shouldn't overwhelm any distant network.

By default, the rate is set to 100 packets/second. To increase the rate to
a million use something like `--rate 1000000`.

It's floating point. So if you want one packet ever 10 seconds, use the value
`--rate 0.1`.


# Design

This is an *asynchronous* design. In other words, it is to `nmap` what
the `nginx` web-server is to `Apache`. It doesn't keep track of which
packets were sent. Instead, it puts a *syncookie* in the packets it
transmits, so that when it receives a response, it can figure out what
was originally transmitted. This allows the *transmit-thread* to
work completely independently from the *receive-thread*.

All asynchronous port scanners share this basic design. Others that use
it are `scanrand`, `unicornscan`, and `ZMap`.

The major benefit of `masscan` is speed. It can use a *zero-overhead* driver
in order to bypass the kernel. This allows it go at 10 million packets/second,
which is fast enough to scan the entire Internet for one port in about
six minutes. This assumes, of course, that you have an Internet connection
that supports such speeds. Actually, this limitation is purely arbitrary
because we are using only a single transmit-thread. We could create 
multiple transmit/recieve queues, and multiple threads, and run much
faster. This is a purely academic problem, since already the 10 million
rate is faster than networks support.

Also, the code is more portable. It runs on Windows and Macintosh as well
as Linux. This is mostly because Windows and Mac are friendlier development
environments to work from, they are both significantly slower than Linux
in terms of scan speed (though both can reach the 100,000 packets/second
speed, which you don't want to exceed if you want to avoid causing
problems in your network).

## Code Layout

The file `main.c` contains the `main()` function, as you'd expect. It also
contains the `transmit_thread()` and `receive_thread()` functions. These
functions are fairly large, trying to expose all the details you need to
worry about in order to see how the program works.

## Randomization (LCG)

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

