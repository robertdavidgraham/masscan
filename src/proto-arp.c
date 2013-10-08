#include "proto-arp.h"
#include "proto-preprocess.h"
#include "logger.h"
#include "output.h"
#include "masscan.h"
#include "unusedparm.h"



void
handle_arp(struct Output *out, const unsigned char *px, 
           unsigned length, struct PreprocessedInfo *parsed)
{
    unsigned ip_them;

	UNUSEDPARM(length);
	UNUSEDPARM(px);

    ip_them = parsed->ip_src[0]<<24 | parsed->ip_src[1]<<16
            | parsed->ip_src[2]<< 8 | parsed->ip_src[3]<<0;

    output_report_status(
                    out,
                    Port_ArpOpen,
                    ip_them,
                    0,
                    0,
                    0);

}
