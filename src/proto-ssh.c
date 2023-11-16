#include "proto-ssh.h"
#include "proto-banner1.h"
#include "unusedparm.h"
#include "masscan-app.h"
#include "stack-tcp-api.h"
#include <ctype.h>

#define PAYLOAD_BANNER  "SSH-2.0-OPENSSH_7.9\r\n"
#define SIZE_BANNER 21
#define PAYLOAD_KEY_EXHANGE_INIT    "\x00\x00\x04\x4c" /* packet length: 1100 */ \
                                    "\x04" /* padding_length (this value is include in the packet length) */ \
                                    "\x14" /* message_code = 20 */ \
                                    "\xf3\xca\xd2\x90\xec\xf4\x7c\x47\x55\x4c\x88\xcf\x3a\x72\x2b\xb2" /*cookie */ \
                                    "\x00\x00\x00\xd8" /* kex_algorithms_length */ \
                                    "diffie-hellman-group14-sha1,diffie-hellman-group1-sha1,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha1,diffie-hellman-group-exchange-sha256" /* kex_algorithms_string */ \
                                    "\x00\x00\x00\x21" /* server_host_key_algorithms_length */ \
                                    "ssh-rsa,rsa-sha2-512,rsa-sha2-256" /* server_host_key_algorithms_string */ \
                                    "\x00\x00\x00\xaf" /* encryption_algorithms_client_to_server_length */ \
                                    "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com,aes128-cbc,aes192-cbc,aes256-cbc,blowfish-cbc,cast128-cbc,3des-cbc" /* encryption_algorithms_client_to_server_string */ \
                                    "\x00\x00\x00\xaf" /* encryption_algorithms_server_to_client_length */ \
                                    "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com,aes128-cbc,aes192-cbc,aes256-cbc,blowfish-cbc,cast128-cbc,3des-cbc" /* encryption_algorithms_server_to_client_string */ \
                                    "\x00\x00\x00\xd5" /* mac_algorithms_client_to_server_length */ \
                                    "umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1" /* mac_algorithms_client_to_server_string */ \
                                    "\x00\x00\x00\xd5" /* mac_algorithms_server_to_client_length */ \
                                    "umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1" /* mac_algorithms_server_to_client_string */ \
                                    "\x00\x00\x00\x04" /* compression_algorithms_client_to_server_length */ \
                                    "none" /* compression_algorithms_client_to_server_string */ \
                                    "\x00\x00\x00\x04" /* compression_algorithms_server_to_client_length */ \
                                    "none" /* compression_algorithms_server_to_client_string */ \
                                    "\x00\x00\x00\x00" /* languages_client_to_server_length */ \
                                    "\x00\x00\x00\x00" /* languages_server_to_client_length */ \
                                    "\x00" /* first_KEX_Packet_Follows */ \
                                    "\x00\x00\x00\x00" /* reserved */ \
                                    "\x00\x00\x00\x00" /* Padding_String */ \
                                    "\x00\x00\x00\x8c" /* DH_packet_length */ \
                                    "\x05" /* DH_padding_length */ \
                                    "\x1e" /* DH_message_code */ \
                                    "\x00\x00\x00\x81" /* DH_multiprecision_integer_length */ \
                                    "\x00\xd4\x6e\xe0\x12\xa6\x56\x95\x37\xa0\x14\x2e\x4e\x4d\x57\x48\x1d\x4b\x80\x90\x1e\x61\x6f\x5c\xc4\xd7\xbc\x17\x25\xb7\x41\x8c\x6c\x8b\xed\x74\x2d\xc0\x54\xeb\x08\x3a\x79\x5e\x0c\xad\x04\xe8\xb7\xfb\xa1\x68\x62\x66\xd3\x9a\x26\x39\xaa\x6c\x89\x2f\x5c\x99\xab\xd2\x43\xda\xa7\xef\x1c\x19\xdc\xa6\x03\xc9\x8a\x56\x19\x74\xd1\xb8\x08\xdc\x76\x14\xe7\x86\x50\x74\x01\xed\xd4\xfb\x1a\x1a\x25\x5d\x1a\xc7\x5f\x0c\xb3\xcc\x58\x5a\x40\xd5\x04\xa5\xc1\x30\x14\x86\xf0\xb8\x33\x17\xb4\x23\x9d\x43\x6d\x38\x87\xec\xa9\xbc\x3b" /* DH_padding_string */ \
                                    "\x00\x00\x00\x00\x00" /* DH_padding_string */
#define SIZE_KEY_EXCHANGE_INIT (1100+4+140+4)    //length_of_the_first_packet(packet_length + length of the packet_length_field(4)) + DH_packet_length (including the DH_padding_length) + the length of the DH_length_field (4).
#define PAYLOAD_NEWKEYS "\x00\x00\x00\x0c" /* packet length */ \
                        "\x0a" /* padding length */ \
                        "\x15" /* message code */ \
                        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" /* padding string */
#define SIZE_NEWKEYS (12+4)

#define DEADSTORE(x) x=x

/***************************************************************************
 ***************************************************************************/
static void
ssh_parse(  const struct Banner1 *banner1,
        void *banner1_private,
        struct StreamState *pstate,
        const unsigned char *px, size_t length,
        struct BannerOutput *banout,
        struct stack_handle_t *socket)
{
    unsigned state = pstate->state;
    size_t packet_length = pstate -> sub.ssh.packet_length;
    unsigned i;
    enum{
        BANNER = 0,
        MSG_KEY_EXCHANGE_INIT = 1,
        MSG_NEW_KEYS = 2,
        MSG_UNKNOWN = 9,
        PADDING_LENGTH = 10,
        MESSAGE_CODE = 11,
        CHECK_LENGTH = 20,
        LENGTH_1 = 21,
        LENGTH_2 = 22,
        LENGTH_3 = 23,
        LENGTH_4 = 24,
        BEFORE_END = 29,
        END = 30,
        ERROR = 31,
    };

    UNUSEDPARM(banner1_private);
    UNUSEDPARM(banner1);

    for (i=0; i<length; i++) {
        banout_append_char(banout, PROTO_SSH2, px[i]);
        switch (state) {
        case BANNER:
            if (px[i] == '\n') {
                tcpapi_send(socket, PAYLOAD_BANNER, SIZE_BANNER, 0);
                packet_length = 0;
                state = LENGTH_1;
            }
            if (px[i] == '\0' || !(isspace(px[i]) || isprint(px[i]))) {
                state = ERROR;
                tcpapi_close(socket);
                continue;
            }
            break;

        case LENGTH_1:
            /*
             * Compute the length of the message (padding_length_field,
             * message_code, payload, padding).
             * The length doesn't include the packet_length_field (+4).
             */
            packet_length = px[i] << 24;
            state++;
            break;
        case LENGTH_2:
            packet_length += px[i] << 16;
            state++;
            break;
        case LENGTH_3:
            packet_length += px[i] << 8;
            state++;
            break;
        case LENGTH_4:
            packet_length += px[i];
            state = PADDING_LENGTH;
            break;

        case PADDING_LENGTH:
            packet_length--;
            state = MESSAGE_CODE;
            break;

        case MESSAGE_CODE:
            /*
             * The state will depend on the message code
             */
            packet_length--;
            switch(px[i]) {
            case '\x14':
                state = MSG_KEY_EXCHANGE_INIT;
                DEADSTORE(state); /*remove warning*/
            case '\x15':
                state = MSG_NEW_KEYS;
                DEADSTORE(state); /*remove warning*/
                break;
            default:
                state = CHECK_LENGTH; /* read & discard this message */
                DEADSTORE(state); /*remove warning*/
                break;
            }

        case MSG_KEY_EXCHANGE_INIT:
            packet_length--;
            tcpapi_send(socket, PAYLOAD_KEY_EXHANGE_INIT, SIZE_KEY_EXCHANGE_INIT, 0);
            state = CHECK_LENGTH;
            break;

        case MSG_NEW_KEYS:
            packet_length--;
            tcpapi_send(socket, PAYLOAD_NEWKEYS, SIZE_NEWKEYS,0);
            state = BEFORE_END;
            break;

        case CHECK_LENGTH:
            if (! --packet_length)
                state = LENGTH_1;
            break;

        case BEFORE_END:
            if (! --packet_length)
                state = END;
            break;

        case END:
            tcpapi_close(socket);
            state = 0xffffffff;
            break;

        default:
            i = (unsigned)length;
        }
    }
    pstate->state = state;
    pstate->sub.ssh.packet_length = packet_length;
}

/***************************************************************************
 ***************************************************************************/
static void *
ssh_init(struct Banner1 *banner1)
{
    UNUSEDPARM(banner1);
    return 0;
}


/***************************************************************************
 ***************************************************************************/
static int
ssh_selftest(void)
{
    return 0;
}

/***************************************************************************
 ***************************************************************************/
const struct ProtocolParserStream banner_ssh = {
    "ssh", 22, 0, 0, 0,
    ssh_selftest,
    ssh_init,
    ssh_parse,
};
