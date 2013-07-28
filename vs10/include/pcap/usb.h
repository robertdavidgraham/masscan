/*
 * Copyright (c) 2006 Paolo Abeni (Italy)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote 
 * products derived from this software without specific prior written 
 * permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Basic USB data struct
 * By Paolo Abeni <paolo.abeni@email.it>
 *
 * @(#) $Header: /tcpdump/master/libpcap/pcap/usb.h,v 1.6 2007/09/22 02:06:08 guy Exp $
 */
 
#ifndef _PCAP_USB_STRUCTS_H__
#define _PCAP_USB_STRUCTS_H__

/* 
 * possible transfer mode
 */
#define URB_TRANSFER_IN   0x80
#define URB_ISOCHRONOUS   0x0
#define URB_INTERRUPT     0x1
#define URB_CONTROL       0x2
#define URB_BULK          0x3

/*
 * possible event type
 */
#define URB_SUBMIT        'S'
#define URB_COMPLETE      'C'
#define URB_ERROR         'E'

/*
 * USB setup header as defined in USB specification.
 * Appears at the front of each packet in DLT_USB captures.
 */
typedef struct _usb_setup {
	u_int8_t bmRequestType;
	u_int8_t bRequest;
	u_int16_t wValue;
	u_int16_t wIndex;
	u_int16_t wLength;
} pcap_usb_setup;


/*
 * Header prepended by linux kernel to each event.
 * Appears at the front of each packet in DLT_USB_LINUX captures.
 */
typedef struct _usb_header {
	u_int64_t id;
	u_int8_t event_type;
	u_int8_t transfer_type;
	u_int8_t endpoint_number;
	u_int8_t device_address;
	u_int16_t bus_id;
	char setup_flag;/*if !=0 the urb setup header is not present*/
	char data_flag; /*if !=0 no urb data is present*/
	int64_t ts_sec;
	int32_t ts_usec;
	int32_t status;
	u_int32_t urb_len;
	u_int32_t data_len; /* amount of urb data really present in this event*/
	pcap_usb_setup setup;
} pcap_usb_header;


#endif
