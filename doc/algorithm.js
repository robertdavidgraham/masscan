/*

    This is an implementation of the core Masscan scanning algorithm
    in JavaScript/NodeJS. The core scanning algorithm is what makes
    Masscan unique from other scanners, so it's worth highlighting
    separately in a sample program.

    REVIEW OF SCANNERS

    The most famous port-scanner is "nmap". However, it is a
    "host-at-a-time" scanner, and struggles at scanning large networks.

    Masscan is an asynchronous, probe-at-a-time scanner. It spews out
    probes to different ports, without caring if two probes happen to
    be send to the same host. If the user wants a list of all ports
    open on a single host, they have to post-process the masscan output
    themselves, because masscan doesn't do it.

    There are other asynchronous port-scanners, like scanrand, unicornscan,
    and zmap. However, they have limitations in the way they do randomization
    of their scans. They have limitations on the ranges of addresses and
    ports that they'll accept, try to store an individual memory record
    for everything scanned, or only partly randomize their scans.

    THE WAY MASSCAN WORKS

    Masscan first stores the targets as a "list of ranges". IP address
    ranges are stored in one structure, and port ranges are stored
    in another structure.

    Then, a single index variable is used to enumerate the set of all 
    IP:port combinations. The scan works by simply incrementing the 
    index variable from 0 to the total number of probes (the 'range').

    Then, before the enumeration step, the index is permuted into another
    random index within the same range, in a 1-to-1 mapping. In other
    words, the algorithm is theoretically reversable: given the output
    of the permutation function, we can obtain the original index.

EXAMPLE

    This program can be run like the following:

    node patent.js 10.0.0.0-10.0.0.5 192.168.0.0/31 80,U:161
    10.0.0.0-10.0.0.5
    192.168.0.0-192.168.0.1
    0.0.0.80-0.0.0.80
    0.1.0.161-0.1.0.161
    --> 10.0.0.4 udp:161
    --> 10.0.0.0 udp:161
    --> 10.0.0.1 udp:161
    --> 10.0.0.4 tcp:80
    --> 192.168.0.1 tcp:80
    --> 10.0.0.0 tcp:80
    --> 10.0.0.2 udp:161
    --> 10.0.0.5 udp:161
    --> 192.168.0.0 tcp:80
    --> 192.168.0.0 udp:161
    --> 10.0.0.1 tcp:80
    --> 10.0.0.3 udp:161
    --> 10.0.0.2 tcp:80
    --> 10.0.0.5 tcp:80
    --> 192.168.0.1 udp:161
    --> 10.0.0.3 tcp:80

    What you see first is the target ranges being echoed back that it scans,
    first the IP address ranges, followed by the port ranges. The port ranges
    are in weird decimal-dot notation because they share the same code
    as for IPv4 addresses.

    Then we see the randomized output, where individual probes are sent to a
    random IP address and port.

TransmitThread

    All the majic happens in the "TransmitThread()" function near the bottom
    of this file.

    We first see how the index variable 'i' is incremented from 0 to the
    total number of packets that will be sent. We then see how first this
    index is permuted to 'xXx', then this variable is separated into
    one index for the IP address and another index for the port. Then,
    those indexes are used to enumerate one of the IP addresses and
    one of the ports.

Blackrock

    This is the permutation function. It implements an encryption algorithm
    based on DES (Data Encryption Standard). However, the use of real DES
    would impose a restricting on the range that it be an even power of 2.
    In the above example, with 14 total probes, this doesn't apply.
    Therefore, we have to change binary operators like XOR with their
    non-binary equivelents.

    The upshot is that we first initialize Blackrock with the range (and
    a seed/key), and then shuffle the index. The process is stateless,
    meaning that any time we shuffle the number '5' we always get the 
    same result, regardless of what has happened before.

Targets, RangeList, Range

    A Range is just a begin/end of an integer. We use this both for
    IPv4 addresses (which are just 32-bit integers) and ports
    (which are 16 bit integers).

    A RangeList is just an array of Ranges. In Masscan, this object
    sorts and combines ranges, making sure there are no duplicates,
    but that isn't used in this example.

    The RangeList object shows how an index can enumerate the 
    individual addresses/ports. This is down by walking the list
    and subtracting from the index the size of each range, until
    we reach a range that is larger than the index.

    The Targets object just holds both the IP and port lists.

*/

function Range(begin, end) {
    if (typeof begin == 'undefined' && typeof end == 'undefined') {
        this.begin = 0xFFFFFFFF;
        this.end = 0;
    } else if (typeof end == 'undefined') {
        this.begin = begin;
        this.end = begin;
    } else {
        this.begin = begin;
        this.end = end;
    }

    this.toString = function () {
        return ((this.begin >> 24) & 0xFF)
            + "." + ((this.begin >> 16) & 0xFF)
            + "." + ((this.begin >> 8) & 0xFF)
            + "." + ((this.begin >> 0) & 0xFF)
            + "-" + ((this.end >> 24) & 0xFF)
            + "." + ((this.end >> 16) & 0xFF)
            + "." + ((this.end >> 8) & 0xFF)
            + "." + ((this.end >> 0) & 0xFF);
    }

    this.count = function () {
        return this.end - this.begin + 1;
    }
    this.pick = function (index) {
        return this.begin + index;
    }
    return this;
}

function RangeList() {
    this.list = [];
    this.total_count = 0;

    this.push = function (range) {
        this.list.push(range);
        this.total_count += range.count();
    }

    this.count = function () {
        return this.total_count;
    }

    this.pick = function (index) {
        for (var i in this.list) {
            var item = this.list[i];
            if (index < item.count())
                return item.pick(index);
            else
                index -= item.count();
        }
        return null;
    }
}


function Targets() {
    this.ports = new RangeList();
    this.ips = new RangeList();

    this.parse_ip = function (text) {
        var x = text.split(".");
        var result = 0;
        result |= parseInt(x[0]) << 24;
        result |= parseInt(x[1]) << 16;
        result |= parseInt(x[2]) << 8;
        result |= parseInt(x[3]) << 0;
        return result;
    }

    this.parse_ports = function (arg) {
        var offset = 0;

        if (arg.indexOf(":") !== -1) {
            var x = arg.split(":");
            if (x[0] == "U")
                offset = 65536;
            else if (x[0] == "S")
                offset = 65536 * 2;
            arg = x[1];
        }

        var target;
        if (arg.indexOf("-") !== -1) {
            var x = arg.split("-");
            target = new Range(parseInt(x[0]), parseInt(x[1]));
        } else
            target = new Range(parseInt(arg));

        target.begin += offset;
        target.end += offset;
        this.ports.push(target);
    }
    this.parse_args = function (argv) {
        for (var i in argv) {
            var arg = argv[i];

            if (arg.indexOf(",") !== -1) {
                var x = arg.split(",");
                for (var j in x)
                    this.parse_ports(x[j]);
            } else if (arg.indexOf("/") !== -1) {
                var x = arg.split("/");
                var address = this.parse_ip(x[0]);
                var prefix = parseInt(x[1]);
                var mask = 0xFFFFFFFF << (32 - prefix);
                address = address & mask;
                var target = new Range(address, address | ~mask);
                this.ips.push(target);
            } else if (arg.indexOf("-") !== -1) {
                var x = arg.split("-");
                var begin = this.parse_ip(x[0]);
                var end = this.parse_ip(x[1]);
                var target = new Range(begin, end);
                this.ips.push(target);
            } else if (arg.indexOf(".") !== -1) {
                var target = new Range(this.parse_ip(arg));
                this.ips.push(target);
            } else {
                this.parse_ports(arg);
            }
        }
    }
    this.print = function () {
        var i;
        for (i in this.ips.list) {
            console.log(this.ips.list[i].toString());
        }
        for (i in this.ports.list) {
            console.log(this.ports.list[i].toString());
        }
    }
    return this;
}



function Blackrock(range, seed) {
    var split = Math.floor(Math.sqrt(range * 1.0));

    this.rounds = 3;
    this.seed = seed;
    this.range = range;
    this.a = split - 1;
    this.b = split + 1;

    while (this.a * this.b <= range)
        this.b++;

    /** Inner permutation function */
    this.F = function (j, R, seed) {
        var primes = [961752031, 982324657, 15485843, 961752031];
        R = ((R << (R & 0x4)) + R + seed);
        return Math.abs((((primes[j] * R + 25) ^ R) + j));
    }

    /** Outer feistal construction */
    this.fe = function (r, a, b, m, seed) {
        var L, R;
        var j;
        var tmp;

        L = m % a;
        R = Math.floor(m / a);

        for (j = 1; j <= r; j++) {
            if (j & 1) {
                tmp = (L + this.F(j, R, seed)) % a;
            } else {
                tmp = (L + this.F(j, R, seed)) % b;
            }
            L = R;
            R = tmp;
        }
        if (r & 1) {
            return a * L + R;
        } else {
            return a * R + L;
        }
    }

    /** Outer reverse feistal construction */
    this.unfe = function (r, a, b, m, seed) {
        var L, R;
        var j;
        var tmp;

        if (r & 1) {
            R = m % a;
            L = Math.floor(m / a);
        } else {
            L = m % a;
            R = Math.floor(m / a);
        }

        for (j = r; j >= 1; j--) {
            if (j & 1) {
                tmp = this.F(j, L, seed);
                if (tmp > R) {
                    tmp = (tmp - R);
                    tmp = a - (tmp % a);
                    if (tmp == a)
                        tmp = 0;
                } else {
                    tmp = (R - tmp);
                    tmp %= a;
                }
            } else {
                tmp = this.F(j, L, seed);
                if (tmp > R) {
                    tmp = (tmp - R);
                    tmp = b - (tmp % b);
                    if (tmp == b)
                        tmp = 0;
                } else {
                    tmp = (R - tmp);
                    tmp %= b;
                }
            }
            R = L;
            L = tmp;
        }
        return a * R + L;
    }

    this.shuffle = function (m) {
        var c;

        c = this.fe(this.rounds, this.a, this.b, m, this.seed);
        while (c >= this.range)
            c = this.fe(this.rounds, this.a, this.b, c, this.seed);

        return c;
    }

    this.unshuffle = function (m) {
        var c;

        c = unfe(this.rounds, this.a, this.b, m, this.seed);
        while (c >= this.range)
            c = unfe(this.rounds, this.a, this.b, c, this.seed);

        return c;
    }
    return this;
}

function TransmitThread(targets, transmit, seed) {
    var range = targets.ips.count() * targets.ports.count();
    var b = Blackrock(range, seed);

    for (var i = 0; i < range; i++) {
        var xXx = b.shuffle(i);

        var ip_index = Math.floor(xXx / targets.ports.count());
        var port_index = Math.floor(xXx % targets.ports.count());

        var ip = targets.ips.pick(ip_index);
        var port = targets.ports.pick(port_index);

        transmit(ip, port);
    }
}

function Transmit2Thread(targets, transmit, seed, start, stop, increment) {
    var range = targets.ips.count() * targets.ports.count();
    var b = Blackrock(range, seed);

    for (var i = start; i < range && i < stop; i += increment) {
        var xXx = b.shuffle(i);

        var ip_index = Math.floor(xXx / targets.ports.count());
        var port_index = Math.floor(xXx % targets.ports.count());

        var ip = targets.ips.pick(ip_index);
        var port = targets.ports.pick(port_index);

        transmit(ip, port);
    }
}


function transmit(ip, port) {
    var proto = "tcp";
    if (port > 65536 * 2) {
        proto = "sctp";
        port -= 65536 * 2;
    } else if (port > 65536) {
        proto = "udp";
        port -= 65536;
    }

    var ipstring = ((ip >> 24) & 0xFF)
            + "." + ((ip >> 16) & 0xFF)
            + "." + ((ip >> 8) & 0xFF)
            + "." + ((ip >> 0) & 0xFF)

    console.log("--> " + ipstring + " " + proto + ":" + port);
}

var targets = new Targets();
targets.parse_args(process.argv.splice(2));
targets.print();

TransmitThread(targets, transmit, 42);

