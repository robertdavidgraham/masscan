#ifndef RAWSOCK_PFRING_H
#define RAWSOCK_PFRING_H
#include <stdint.h>
#include <time.h>

/*
 * Various PF_RING defines
 */
struct __pfring;
typedef struct __pfring pfring;

typedef enum {
  rx_and_tx_direction = 0,
  rx_only_direction,
  tx_only_direction
} packet_direction;
struct pfring_pkthdr {
  struct xtimeval {
        long    tv_sec;
        long    tv_usec;
  } ts;
  unsigned caplen;
  unsigned len;
  /* only filled in if PF_RING_LONG_HEADER set */
  unsigned char extended_hdr[512];
};
#define PF_RING_ERROR_GENERIC              -1
#define PF_RING_ERROR_INVALID_ARGUMENT     -2
#define PF_RING_ERROR_NO_PKT_AVAILABLE     -3
#define PF_RING_ERROR_NO_TX_SLOT_AVAILABLE -4
#define PF_RING_ERROR_WRONG_CONFIGURATION  -5
#define PF_RING_ERROR_END_OF_DEMO_MODE     -6
#define PF_RING_ERROR_NOT_SUPPORTED        -7
#define PF_RING_ERROR_INVALID_LIB_VERSION  -8
#define PF_RING_ERROR_UNKNOWN_ADAPTER      -9
#define PF_RING_ERROR_NOT_ENOUGH_MEMORY   -10
#define PF_RING_ERROR_INVALID_STATUS      -11
#define PF_RING_DNA_SYMMETRIC_RSS    1 << 0
#define PF_RING_REENTRANT            1 << 1
#define PF_RING_LONG_HEADER          1 << 2
#define PF_RING_PROMISC              1 << 3
#define PF_RING_TIMESTAMP            1 << 4
#define PF_RING_HW_TIMESTAMP         1 << 5
#define PF_RING_RX_PACKET_BOUNCE     1 << 6
#define PF_RING_DNA_FIXED_RSS_Q_0    1 << 7
#define PF_RING_STRIP_HW_TIMESTAMP   1 << 8
#define PF_RING_DO_NOT_PARSE         1 << 9  /* parsing already disabled in zero-copy */
#define PF_RING_DO_NOT_TIMESTAMP     1 << 10 /* sw timestamp already disabled in zero-copy */

/*
 * function prototypes
 */
typedef pfring*(*PFRING_OPEN)(
                    const char *device_name,
                    unsigned caplen,
                    unsigned flags);
typedef void (*PFRING_CLOSE)(pfring *ring);
typedef int (*PFRING_ENABLE_RING)(pfring *ring);
typedef int (*PFRING_SEND)( pfring *ring,
                    const unsigned char *buffer,
                    unsigned buffer_length,
                    unsigned char flush_packet);
typedef int (*PFRING_RECV)(    pfring *ring,
                    unsigned char** buffer,
                    unsigned buffer_length,
                    struct pfring_pkthdr *hdr,
                    unsigned char wait_for_incoming_packet);
typedef int (*PFRING_POLL)(pfring *ring, unsigned wait_duration);
typedef int (*PFRING_VERSION)(pfring *ring, unsigned *version);
typedef int (*PFRING_SET_DIRECTION)(pfring *ring, int direction);
typedef int (*PFRING_SET_APPLICATION_NAME)(pfring *ring, char *name);
typedef int (*PFRING_GET_BOUND_DEVICE)(pfring *ring, unsigned char mac_address[6]);

/*
 * scoped object
 */
extern struct PFRING {
    PFRING_OPEN                     open;
    PFRING_CLOSE                    close;
    PFRING_ENABLE_RING              enable_ring;
    PFRING_SEND                     send;
    PFRING_RECV                     recv;
    PFRING_POLL                     poll;
    PFRING_VERSION                  version;
    PFRING_SET_DIRECTION            set_direction;
    PFRING_SET_APPLICATION_NAME     set_application_name;
    PFRING_GET_BOUND_DEVICE         get_bound_device;
} PFRING;

/*
 * call this to load the library
 */
int PFRING_init(void);

#endif
