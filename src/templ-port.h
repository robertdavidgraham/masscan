#ifndef TEMPL_PORT_H
#define TEMPL_PORT_H

enum {
	Templ_TCP = 0,
	Templ_UDP = 65536,
	Templ_SCTP = 65536*2,
	Templ_ICMP_echo = 65536*3+0,
	Templ_ICMP_timestamp = 65536*3+1,
	Templ_ARP = 65536*3+2,
};

#endif
