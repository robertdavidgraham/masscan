#include <string.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "smack.h"
#include "string_s.h"
#include "output.h"
#include "proto-preprocess.h"
#include "proto-banner1.h"

static struct SMACK *global_mib;


struct SNMP
{
	uint64_t version;
	uint64_t pdu_tag;
	const unsigned char *community;
	uint64_t community_length;
	uint64_t request_id;
	uint64_t error_index;
	uint64_t error_status;
};

/****************************************************************************
 ****************************************************************************/
struct SnmpOid {
    const char *oid;
    const char *name;
} mib[] = {
    {"43.1006.51.341332", "selftest"}, /* for regression test */
    {"43", "iso.org"},
    {"43.6", "dod"},
    {"43.6.1", "inet"},
    {"43.6.1.2", "mgmt"},
    {"43.6.1.2.1", "mib2"},
    {"43.6.1.2.1.", "sys"},
    {"43.6.1.2.1.1.1", "sysDescr"},
    {"43.6.1.2.1.1.2", "sysObjectID"},
    {"43.6.1.2.1.1.3", "sysUpTime"},
    {"43.6.1.2.1.1.4", "sysContact"},
    {"43.6.1.2.1.1.5", "sysName"},
    {"43.6.1.2.1.1.6", "sysLocation"},
    {"43.6.1.2.1.1.7", "sysServices"},
    {"43.6.1.4", "priv"},
    {"43.6.1.4.1", "enterprise"},
    {"43.6.1.4.1.2001", "okidata"},
    {0,0},
};

/****************************************************************************
 ****************************************************************************/
static uint64_t
asn1_length(const unsigned char *px, uint64_t length, uint64_t *r_offset)
{
	uint64_t result;

	if ( (*r_offset >= length) 
		|| ((px[*r_offset] & 0x80) 
		&& ((*r_offset) + (px[*r_offset]&0x7F) >= length))) {
		*r_offset = length;
		return 0xFFFFffff;
	}
	result = px[(*r_offset)++];
	if (result & 0x80) {
		unsigned length_of_length = result & 0x7F;
		if (length_of_length == 0) {
			*r_offset = length;
			return 0xFFFFffff;
		}
		result = 0;
		while (length_of_length) {
			result = result * 256 + px[(*r_offset)++];
			if (result > 0x10000) {
				*r_offset = length;
				return 0xFFFFffff;
			}
            length_of_length--;
		}
	}
	return result;
}


/****************************************************************************
 ****************************************************************************/
static uint64_t
asn1_integer(const unsigned char *px, uint64_t length, uint64_t *r_offset)
{
	uint64_t int_length;
	uint64_t result;

	if (px[(*r_offset)++] != 0x02) {
		*r_offset = length;
		return 0xFFFFffff;
	}

	int_length = asn1_length(px, length, r_offset);
	if (int_length == 0xFFFFffff) {
		*r_offset = length;
		return 0xFFFFffff;
	}
	if (*r_offset + int_length > length) {
		*r_offset = length;
		return 0xFFFFffff;
	}

	result = 0;
	while (int_length--)
		result = result * 256 + px[(*r_offset)++];

	return result;
}

/****************************************************************************
 ****************************************************************************/
static unsigned 
asn1_tag(const unsigned char *px, uint64_t length, uint64_t *r_offset)
{
	if (*r_offset >= length)
		return 0;
	return px[(*r_offset)++];
}

/****************************************************************************
 ****************************************************************************/
static uint64_t
next_id(const unsigned char *oid, unsigned *offset, uint64_t oid_length)
{
    uint64_t result = 0;
    while (*offset < oid_length && (oid[*offset] & 0x80)) {
        result <<= 7;
        result |= oid[(*offset)++]&0x7F;
    }
    if (*offset < oid_length) {
        result <<= 7;
        result |= oid[(*offset)++]&0x7F;
    }
    return result;
}

/****************************************************************************
 ****************************************************************************/
void
snmp_banner_oid(const unsigned char *oid, size_t oid_length,
            unsigned char *banner, unsigned *banner_offset, unsigned banner_max)
{
    unsigned i;
    size_t id;
    unsigned offset;
    unsigned state;
    size_t found_id = SMACK_NOT_FOUND;
    size_t found_offset = 0;

    /*
     * Find the var name
     */
    state = 0;
    for (offset=0; offset<oid_length; ) {

        id = smack_search_next( global_mib,
                                &state,
                                oid,
                                &offset,
                                (unsigned)oid_length);
        if (id != SMACK_NOT_FOUND) {
            found_id = id;
            found_offset = offset;
        }
    }

    /* Do the string */
    if (found_id != SMACK_NOT_FOUND) {
        const char *str = mib[found_id].name;
        for (i=0; str[i]; i++) {
            if (*banner_offset < banner_max)
                banner[(*banner_offset)++] = str[i];
        }
    }

    /* Do remaining OIDs */
    for (i=(unsigned)found_offset; i<oid_length; ) {
        char foo[32] = {0};
        uint64_t x = next_id(oid, &i, oid_length);

        if (x == 0 && i >= oid_length)
            break;

        sprintf_s(foo, sizeof(foo), ".%llu", x);
        if (*banner_offset + strlen(foo) < banner_max) {
            memcpy(banner + *banner_offset, foo, strlen(foo));
            *banner_offset += (unsigned)strlen(foo);
        }
    }
}

/****************************************************************************
 ****************************************************************************/
void
snmp_banner(const unsigned char *oid, size_t oid_length,
            uint64_t var_tag,
            const unsigned char *var, size_t var_length,
            unsigned char *banner, unsigned *banner_offset, unsigned banner_max)
{
    size_t i;

    if (*banner_offset != 0 && *banner_offset < banner_max)
        banner[(*banner_offset)++] = '\n';

    /* print the OID */
    snmp_banner_oid(oid, oid_length,
                    banner, banner_offset, banner_max);

    if (*banner_offset < banner_max)
        banner[(*banner_offset)++] = ':';

    switch (var_tag) {
    case 2:
        {
            char foo[32];
            uint64_t result = 0;
            for (i=0; i<var_length; i++)
                result = result<<8 | var[i];
            sprintf_s(foo, sizeof(foo), "%llu", foo);
            if (*banner_offset + strlen(foo) < banner_max) {
                memcpy(banner + *banner_offset, foo, strlen(foo));
                *banner_offset += (unsigned)strlen(foo);
            }
        }
        break;
    case 6:
        snmp_banner_oid(var, var_length,
                        banner, banner_offset, banner_max);
        break;
    case 4:
    default:
        {
            /* TODO: this needs to be normalized */
            for (i=0; i<var_length; i++) {
                if (*banner_offset < banner_max)
                    banner[(*banner_offset)++] = var[i];
            }
        }
        break;
    }
}


/****************************************************************************
 * This is a parser for SNMP packets.
 *
 * TODO: only SNMPv0 is supported, the parser will have to be extended for
 * newer SNMP.
 ****************************************************************************/
void
snmp_parse(const unsigned char *px, uint64_t length,
    unsigned char *banner, unsigned *banner_offset, unsigned banner_max)
{
	uint64_t offset=0;
	uint64_t outer_length;
	struct SNMP snmp[1];

	memset(&snmp, 0, sizeof(*snmp));

	/* tag */
	if (asn1_tag(px, length, &offset) != 0x30)
		return;

	/* length */
	outer_length = asn1_length(px, length, &offset);
	if (length > outer_length + offset)
		length = outer_length + offset;

	/* Version */
	snmp->version = asn1_integer(px, length, &offset);
	if (snmp->version != 0)
		return;

	/* Community */
	if (asn1_tag(px, length, &offset) != 0x04)
		return;
	snmp->community_length = asn1_length(px, length, &offset);
	snmp->community = px+offset;
	offset += snmp->community_length;

	/* PDU */
	snmp->pdu_tag = asn1_tag(px, length, &offset);
	if (snmp->pdu_tag < 0xA0 || 0xA5 < snmp->pdu_tag)
		return;
	outer_length = asn1_length(px, length, &offset);
	if (length > outer_length + offset)
		length = outer_length + offset;

	/* Request ID */
	snmp->request_id = asn1_integer(px, length, &offset);
	snmp->error_status = asn1_integer(px, length, &offset);
	snmp->error_index = asn1_integer(px, length, &offset);

	/* Varbind List */
	if (asn1_tag(px, length, &offset) != 0x30)
		return;
	outer_length = asn1_length(px, length, &offset);
	if (length > outer_length + offset)
		length = outer_length + offset;


	/* Var-bind list */
	while (offset < length) {
		uint64_t varbind_length;
		uint64_t varbind_end;
		if (px[offset++] != 0x30) {
			break;
		}
		varbind_length = asn1_length(px, length, &offset);
		if (varbind_length == 0xFFFFffff)
			break;
		varbind_end = offset + varbind_length;
		if (varbind_end > length) {
			return;
		}
		
		/* OID */
		if (asn1_tag(px,length,&offset) != 6)
			return;
		else {
			uint64_t oid_length = asn1_length(px, length, &offset);
			const unsigned char *oid = px+offset;
            uint64_t var_tag;
            uint64_t var_length;
            const unsigned char *var;

			offset += oid_length;
			if (offset > length)
				return;

            var_tag = asn1_tag(px,length,&offset);
            var_length = asn1_length(px, length, &offset);
            var = px+offset;

            offset += var_length;
            if (offset > length)
                return;

            if (var_tag == 5)
                continue; /* null */

            snmp_banner(oid, oid_length, var_tag, var, var_length, banner, banner_offset, banner_max);
		}
	}
}

#define TWO_BYTE       ((~0)<<7)
#define THREE_BYTE     ((~0)<<14)
#define FOUR_BYTE      ((~0)<<21)
#define FIVE_BYTE      ((~0)<<28)


/****************************************************************************
 ****************************************************************************/
unsigned
id_prefix_count(unsigned id)
{
    if (id & FIVE_BYTE)
        return 4;
    if (id & FOUR_BYTE)
        return 3;
    if (id & THREE_BYTE)
        return 2;
    if (id & TWO_BYTE)
        return 1;
    return 0;
}

/****************************************************************************
 * Convert text OID to binary
 ****************************************************************************/
unsigned
convert_oid(unsigned char *dst, size_t sizeof_dst, const char *src)
{
    size_t offset = 0;

    while (*src) {
        const char *next_src;
        unsigned long id;
        unsigned count;
        unsigned i;

        while (*src == '.')
            src++;

        id = strtoul(src, (char**)&next_src, 0);
        if (src == next_src)
            break;
        else
            src = next_src;

        count = id_prefix_count(id);
        for (i=count; i>0; i--) {
            if (offset < sizeof_dst)
                dst[offset++] = ((id>>(7*i)) & 0x7F) | 0x80;
        }
        if (offset < sizeof_dst)
            dst[offset++] = (id & 0x7F);


    }

    return (unsigned)offset;
}

/****************************************************************************
 ****************************************************************************/
void handle_snmp(struct Output *out, const unsigned char *px, unsigned length, struct PreprocessedInfo *parsed)
{
    unsigned char banner[1024];
    unsigned banner_offset = 0;
    unsigned banner_length = sizeof(banner);
    unsigned ip_them;
    
    UNUSEDPARM(length);

    snmp_parse(px + parsed->app_offset, parsed->app_length,
        banner, &banner_offset, banner_length);
    if (!banner_offset)
        return;

    ip_them = parsed->ip_src[0]<<24 | parsed->ip_src[1]<<16
            | parsed->ip_src[2]<< 8 | parsed->ip_src[3]<<0;

    output_report_banner(
            out,
            ip_them, parsed->port_src, 
            PROTO_SNMP,
            banner, banner_offset);


}


/****************************************************************************
 * We need to initialize the OID/MIB parser
 * This should be called on program startup.
 * This is so that we can show short names, like "sysName", rather than
 * the entire OID.
 ****************************************************************************/
void
snmp_init()
{
    unsigned i;

    /* We use an Aho-Corasick pattern matcher for this. Not necessarily
     * the most efficient, but also not bad */
    global_mib = smack_create("snmp-mib", 0);

    /* We just go through the table of OIDs and add them all one by
     * one */
    for (i=0; mib[i].name; i++) {
        unsigned char pattern[256];
        unsigned len;

        len = convert_oid(pattern, sizeof(pattern), mib[i].oid);

        smack_add_pattern(  global_mib,
                            pattern,
                            len,
                            i,
                            0 //SMACK_ANCHOR_BEGIN
                            );
    }

    /* Now that we've added all the OIDs, we need to compile this into
     * an efficient data structure. Later, when we get packets, we'll
     * use this for searching */
    smack_compile(global_mib);

}

/****************************************************************************
 ****************************************************************************/
static int
snmp_selftest_banner()
{
    static const unsigned char snmp_response[] = {
        0x30, 0x38, 
         0x02, 0x01, 0x00, 
         0x04, 0x06, 0x70, 0x75, 0x62, 0x6C, 0x69, 0x63, 
         0xA2, 0x2B, 
           0x02, 0x01, 0x26, 
           0x02, 0x01, 0x00, 
           0x02, 0x01, 0x00, 
           0x30, 0x20, 
            0x30, 0x1E, 
              0x06, 0x08, 
                0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x02, 0x00, 
              0x06, 0x12, 
                0x2B, 0x06, 0x01, 0x04, 0x01, 0x8F, 0x51, 0x01, 0x01, 0x01, 0x82, 0x29, 0x5D, 0x01, 0x1B, 0x02, 0x02, 0x01, 
    };
    unsigned char banner[256];
    unsigned banner_offset = 0;
    unsigned banner_max = sizeof(banner);

    snmp_parse(snmp_response, sizeof(snmp_response),
                banner, &banner_offset, banner_max);


    return memcmp(banner, "sysObjectID:okidata.1.1.1.297.93", 30) != 0;
}

/****************************************************************************
 ****************************************************************************/
int
snmp_selftest()
{
    static const unsigned char xx[] = {
        43, 0x80|7, 110, 51, 0x80|20, 0x80|106, 84,
    };
    size_t i;
    unsigned state;
    unsigned offset;
    size_t found_id = SMACK_NOT_FOUND;


    if (snmp_selftest_banner())
        return 1;

    /*
     * test of searching OIDs
     */
    state = 0;
    offset = 0;
    while (offset < sizeof(xx)) {
        i = smack_search_next(  global_mib,
                                &state, 
                                xx,
                                &offset,
                                (unsigned)sizeof(xx)
                                );
        if (i != SMACK_NOT_FOUND)
            found_id = i;
    }
    if (found_id == SMACK_NOT_FOUND) {
        fprintf(stderr, "snmp: oid parser failed\n");
        return 1;
    }
    if (strcmp(mib[found_id].name, "selftest") != 0) {
        fprintf(stderr, "snmp: oid parser failed\n");
        return 1;
    }



    return 0;
}





