# Vulnerability Information and Policy

This document contains information about robustness of this project against
hacker attacks. It describes known vulnerabilities that have been found
in previous versions, and describes policies how vulnerabilities are handled.

## Security contact

robert_david_graham@yahoo.com
@ErrataRob on twitter


## Known vulnerabilities and advisories

none

## Bounty

I'm offering $100, payable in cash or Bitcoin, for security vulnerabilities.
This is primarily for remote vulnerabilities, such as the ability of a target
to buffer-overflow the scanner, or even cause it to crash.

But I'd consider other vulnerabilities as well. Does Kali ship this with suid
and there's a preload bug? That's not really a vuln in this code, but if it's 
something I could fix, I'd consider paying a bounty for it.


## Disclosure policy

If you've got a vuln, just announce it. Please send info to the contact above
as well, please.

I'll probably get around to fixing it within a month or so. This really isn't
heavily used software, so I'm lax on this.

## Threats

The primary threat is from hostile targets on the Internet sending back
responses in order to:
* exploit a buffer-overflow vulnerability
* spoof packets trying to give fraudulent scan results (mitigated with our
  SYN cookies)
* flood packets trying to overload bandwidth/storage
* bad data, such as corrupting banners or DNS names trying to exploit
  downstream consumers with bad html or script tags.

The secondary threat is from use of the program. For example, when a bad
parameter is entered on the command-line, the program spits it back out
in a helpful error message. This is fine for a command-line program that
should run as `root` anyway, but if somebody tries to make it into a 
scriptable service, this becomes a potential vulnerability.

## Safe code policy

Unsafe functions like `strcpy()` are banned.

The code contains an automated regression test by running with the 
`--regress` option. However, currently the regression only tests
a small percentage of the code.










