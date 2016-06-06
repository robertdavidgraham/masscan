Using afl fuzzer against masscan
================================

AFL (American-Fuzzy-Lop) is an automated *fuzzer*. It takes existing
input to a program, then morphs that input in order to test new 
code paths through the code. It's extremely successful at finding 
bugs as well as *vulnerabilities*.

There are two inputs to *masscan*. One is the files it reads, which
come in various formats. The second is input from the network, in 
response to network probes, which consist of various network protocols.

For AFL, there is also the issue of how *masscan* crashes. It tries to
print a backtrace. This causes AFL to falsely mark this as a "hang"
rather than a "crash". To fix this, run *masscan* with the *--nobacktrace*
option.

## Fuzzing file formats ##

The *masscan* program reads the following files. You can set the fuzzer
at each one of these to fuzz how it parses the contents.

*-c <filename.conf>*

*Masscan* can read its configuration either from the command-line or from a file.
To create a file, run *masscan* as normal, then hit <ctrl-c>. This will save all
it's settings, even default values, into a file. It's a good starting point for
fuzzing.

*--readscan <filename.mass>*

One of the possible outputs of *masscan* is in a proprietary binary format. You
can then run *masscan* to convert to any other output format.

In other words, you can run masscan to output XML like:

    masscan <blah blah blah> -oX scan.xml
    
Or, in a two step process:

    masscan <blah blah blah> -ob scan.mass
    
    masscan --readscan scan.mass -oX scan.xml
    

*--exclude-file <filename.ranges>*

*Masscan* can scan large ragnes, like *0.0.0.0/0* (the entire Internet). You may
want to exclude specific addresses or ranges. These are configured in the
"exclude file".

You can also read ranges using *--include-file <filename.ranges>* or 
*-iL <filename.ranges>*, but as far as fuzzing, I'm pretty sure it'll 
be the same results.

*--hello-file[<port>] <filename>*

This file is read, then dumped blindly across a TCP connection, in order
to say "hello" to a service. Since there's no parsing here, I'm not sure
you'll find anything fuzzing this.

*--nmap-payloads <filename>*

This file specifies the default payloads for UDP. It's in the same file
format as for *nmap*. There's some juicy parsing here that may lead
to bugs.

*--pcap-payloads <filename.pcap>*

This is the same as *--nmap-payloads*, but reads the UDP payloads from
a *libpcap* file.

## Fuzzing network protocols ##

*Masscan* parses several network protocols. It also must reassemble
fragmented responses over TCP for any application protocol. Remember:
*masscan* has it's own stack, so must parse everything that comes
over the network.

AFL has no ability to read from the network at this time. Moreover,
even then it wouldn't work easily, since *masscan* has a network stack
rather than just an application layer to deal with.

The trick is to first use *masscan* on a target that responds back
on a protocol, then save just the response side of the TCP connection
to a file. Then, when running *masscan* under AFL, read in that file
using the option *--adapter file:<filename.pcap>*. Then, and this is 
critical, you must hard code all the TCP stack values to match those
of the original connection.

I generated the file *masscan/data/afl-http.pcap* as an example file
to read for fuzzing the parsing of HTTP. The command-line parameters
to use are:

    bin/masscan --nobacktrace --adapter file:data/afl-http.pcap --source-ip 10.20.30.200 --source-port 6000 --source-mac 00-11-22-33-44-55 --router-mac c0-c1-c0-a0-9b-9d --seed 0 --banners -p80 74.125.196.147 --nostatus

The explanation are:

    *--nobacktrace*: so that AFL correctly marks crashes as crashes
    and not as hangs.
    
    *--adapter file:*: This option normally specifies the adapter,
    like *eth0* or *en1*. By putting the *file:* prefix on an adapter name,
    it'll use a file (in *libpcap* format) to use instead. In this case,
    transmits are dropped, and any packets are read from a file.
    
    *--source-ip*, *--source-port*, *--source-mac*, *--router-mac*:
    These are the hard-coded TCP/IP stack settings that must match the packets
    in the file.
    
    *--seed*: This must match the randomization seed in the packet file. Since
    everything else is hardcoded, I think the only thing this will control
    will be the sequence number of the TCP connection.
    
    *--banners*: this tell the scanner to not simply find open ports, but also
    establish a TCP connection and interact with the protocol, and report on
    the results.
    
    *-p<port>*: The destination IP address to connect to.
    
    *<ip-address>*: The IP address to connect to

This should produce an output like the following. If you get the
banner back, then you know you've successfully done everything
correctly. Conversely, if you set *--seed 1*, then it won't work,
because it'll reject responses that match the wrong seed.

    Starting masscan 1.0.3 (http://bit.ly/14GZzcT) at 2016-06-06 05:19:03 GMT
    -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
    Initiating SYN Stealth Scan
    Scanning 1 hosts [1 port/host]
    Discovered open port 80/tcp on 74.125.196.147
    Banner on port 80/tcp on 74.125.196.147: [title] Google
    Banner on port 80/tcp on 74.125.196.147: [http] HTTP/1.0 200 OK\x0d\x0a...
    ...
    
(Additional output is truncated -- you get the idea).

The problem with this is that *masscan* will take about 10 seconds before it 
produces the results. When it establishes a connection, it waits a few seconds
for the other side to transmit, then sends it's "hello", then waits many
seconds for all output to be received. I don't know if this messes AFL up,
whether I need to add additional options to truncate any waiting.








