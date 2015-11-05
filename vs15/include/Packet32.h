/*
 * Copyright (c) 1999 - 2005 NetGroup, Politecnico di Torino (Italy)
 * Copyright (c) 2005 - 2007 CACE Technologies, Davis (California)
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
 * 3. Neither the name of the Politecnico di Torino, CACE Technologies 
 * nor the names of its contributors may be used to endorse or promote 
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
 */

/** @ingroup packetapi
 *  @{ 
 */

/** @defgroup packet32h Packet.dll definitions and data structures
 *  Packet32.h contains the data structures and the definitions used by packet.dll.
 *  The file is used both by the Win9x and the WinNTx versions of packet.dll, and can be included
 *  by the applications that use the functions of this library
 *  @{
 */

#ifndef __PACKET32
#define __PACKET32

#include <winsock2.h>

#ifdef HAVE_AIRPCAP_API
#include <airpcap.h>
#else
#if !defined(AIRPCAP_HANDLE__EAE405F5_0171_9592_B3C2_C19EC426AD34__DEFINED_)
#define AIRPCAP_HANDLE__EAE405F5_0171_9592_B3C2_C19EC426AD34__DEFINED_
typedef struct _AirpcapHandle *PAirpcapHandle;
#endif /* AIRPCAP_HANDLE__EAE405F5_0171_9592_B3C2_C19EC426AD34__DEFINED_ */
#endif /* HAVE_AIRPCAP_API */

#ifdef HAVE_DAG_API
#include <dagc.h>
#endif /* HAVE_DAG_API */

// Working modes
#define PACKET_MODE_CAPT 0x0 ///< Capture mode
#define PACKET_MODE_STAT 0x1 ///< Statistical mode
#define PACKET_MODE_MON 0x2 ///< Monitoring mode
#define PACKET_MODE_DUMP 0x10 ///< Dump mode
#define PACKET_MODE_STAT_DUMP MODE_DUMP | MODE_STAT ///< Statistical dump Mode


/// Alignment macro. Defines the alignment size.
#define Packet_ALIGNMENT sizeof(int)
/// Alignment macro. Rounds up to the next even multiple of Packet_ALIGNMENT. 
#define Packet_WORDALIGN(x) (((x)+(Packet_ALIGNMENT-1))&~(Packet_ALIGNMENT-1))

#define NdisMediumNull	-1		///< Custom linktype: NDIS doesn't provide an equivalent
#define NdisMediumCHDLC	-2		///< Custom linktype: NDIS doesn't provide an equivalent
#define NdisMediumPPPSerial	-3	///< Custom linktype: NDIS doesn't provide an equivalent
#define NdisMediumBare80211	-4	///< Custom linktype: NDIS doesn't provide an equivalent
#define NdisMediumRadio80211	-5	///< Custom linktype: NDIS doesn't provide an equivalent
#define NdisMediumPpi		-6	///< Custom linktype: NDIS doesn't provide an equivalent

// Loopback behaviour definitions
#define NPF_DISABLE_LOOPBACK	1	///< Drop the packets sent by the NPF driver
#define NPF_ENABLE_LOOPBACK		2	///< Capture the packets sent by the NPF driver

/*!
  \brief Network type structure.

  This structure is used by the PacketGetNetType() function to return information on the current adapter's type and speed.
*/
typedef struct NetType
{
	UINT LinkType;	///< The MAC of the current network adapter (see function PacketGetNetType() for more information)
	ULONGLONG LinkSpeed;	///< The speed of the network in bits per second
}NetType;


//some definitions stolen from libpcap

#ifndef BPF_MAJOR_VERSION

/*!
  \brief A BPF pseudo-assembly program.

  The program will be injected in the kernel by the PacketSetBPF() function and applied to every incoming packet. 
*/
struct bpf_program 
{
	UINT bf_len;				///< Indicates the number of instructions of the program, i.e. the number of struct bpf_insn that will follow.
	struct bpf_insn *bf_insns;	///< A pointer to the first instruction of the program.
};

/*!
  \brief A single BPF pseudo-instruction.

  bpf_insn contains a single instruction for the BPF register-machine. It is used to send a filter program to the driver.
*/
struct bpf_insn 
{
	USHORT	code;		///< Instruction type and addressing mode.
	UCHAR 	jt;			///< Jump if true
	UCHAR 	jf;			///< Jump if false
	int k;				///< Generic field used for various purposes.
};

/*!
  \brief Structure that contains a couple of statistics values on the current capture.

  It is used by packet.dll to return statistics about a capture session.
*/
struct bpf_stat 
{
	UINT bs_recv;		///< Number of packets that the driver received from the network adapter 
						///< from the beginning of the current capture. This value includes the packets 
						///< lost by the driver.
	UINT bs_drop;		///< number of packets that the driver lost from the beginning of a capture. 
						///< Basically, a packet is lost when the the buffer of the driver is full. 
						///< In this situation the packet cannot be stored and the driver rejects it.
	UINT ps_ifdrop;		///< drops by interface. XXX not yet supported
	UINT bs_capt;		///< number of packets that pass the filter, find place in the kernel buffer and
						///< thus reach the application.
};

/*!
  \brief Packet header.

  This structure defines the header associated with every packet delivered to the application.
*/
struct bpf_hdr 
{
	struct timeval	bh_tstamp;	///< The timestamp associated with the captured packet. 
								///< It is stored in a TimeVal structure.
	UINT	bh_caplen;			///< Length of captured portion. The captured portion <b>can be different</b>
								///< from the original packet, because it is possible (with a proper filter)
								///< to instruct the driver to capture only a portion of the packets.
	UINT	bh_datalen;			///< Original length of packet
	USHORT		bh_hdrlen;		///< Length of bpf header (this struct plus alignment padding). In some cases,
								///< a padding could be added between the end of this structure and the packet
								///< data for performance reasons. This filed can be used to retrieve the actual data 
								///< of the packet.
};

/*!
  \brief Dump packet header.

  This structure defines the header associated with the packets in a buffer to be used with PacketSendPackets().
  It is simpler than the bpf_hdr, because it corresponds to the header associated by WinPcap and libpcap to a
  packet in a dump file. This makes straightforward sending WinPcap dump files to the network.
*/
struct dump_bpf_hdr{
    struct timeval	ts;			///< Time stamp of the packet
    UINT			caplen;		///< Length of captured portion. The captured portion can smaller than the 
								///< the original packet, because it is possible (with a proper filter) to 
								///< instruct the driver to capture only a portion of the packets. 
    UINT			len;		///< Length of the original packet (off wire).
};


#endif

struct bpf_stat;

#define        DOSNAMEPREFIX   TEXT("Packet_")	///< Prefix added to the adapters device names to create the WinPcap devices
#define        MAX_LINK_NAME_LENGTH	64			//< Maximum length of the devices symbolic links
#define        NMAX_PACKET 65535

/*!
  \brief Addresses of a network adapter.

  This structure is used by the PacketGetNetInfoEx() function to return the IP addresses associated with 
  an adapter.
*/
typedef struct npf_if_addr {
	struct sockaddr_storage IPAddress;	///< IP address.
	struct sockaddr_storage SubnetMask;	///< Netmask for that address.
	struct sockaddr_storage Broadcast;	///< Broadcast address.
}npf_if_addr;


#define ADAPTER_NAME_LENGTH 256 + 12	///<  Maximum length for the name of an adapter. The value is the same used by the IP Helper API.
#define ADAPTER_DESC_LENGTH 128			///<  Maximum length for the description of an adapter. The value is the same used by the IP Helper API.
#define MAX_MAC_ADDR_LENGTH 8			///<  Maximum length for the link layer address of an adapter. The value is the same used by the IP Helper API.
#define MAX_NETWORK_ADDRESSES 16		///<  Maximum length for the link layer address of an adapter. The value is the same used by the IP Helper API.


typedef struct WAN_ADAPTER_INT WAN_ADAPTER; ///< Describes an opened wan (dialup, VPN...) network adapter using the NetMon API
typedef WAN_ADAPTER *PWAN_ADAPTER; ///< Describes an opened wan (dialup, VPN...) network adapter using the NetMon API

#define INFO_FLAG_NDIS_ADAPTER		0	///< Flag for ADAPTER_INFO: this is a traditional ndis adapter
#define INFO_FLAG_NDISWAN_ADAPTER	1	///< Flag for ADAPTER_INFO: this is a NdisWan adapter, and it's managed by WANPACKET
#define INFO_FLAG_DAG_CARD			2	///< Flag for ADAPTER_INFO: this is a DAG card
#define INFO_FLAG_DAG_FILE			6	///< Flag for ADAPTER_INFO: this is a DAG file
#define INFO_FLAG_DONT_EXPORT		8	///< Flag for ADAPTER_INFO: when this flag is set, the adapter will not be listed or openend by winpcap. This allows to prevent exporting broken network adapters, like for example FireWire ones.
#define INFO_FLAG_AIRPCAP_CARD		16	///< Flag for ADAPTER_INFO: this is an airpcap card
#define INFO_FLAG_NPFIM_DEVICE		32

/*!
  \brief Describes an opened network adapter.

  This structure is the most important for the functioning of packet.dll, but the great part of its fields
  should be ignored by the user, since the library offers functions that avoid to cope with low-level parameters
*/
typedef struct _ADAPTER  { 
	HANDLE hFile;				///< \internal Handle to an open instance of the NPF driver.
	CHAR  SymbolicLink[MAX_LINK_NAME_LENGTH]; ///< \internal A string containing the name of the network adapter currently opened.
	int NumWrites;				///< \internal Number of times a packets written on this adapter will be repeated 
								///< on the wire.
	HANDLE ReadEvent;			///< A notification event associated with the read calls on the adapter.
								///< It can be passed to standard Win32 functions (like WaitForSingleObject
								///< or WaitForMultipleObjects) to wait until the driver's buffer contains some 
								///< data. It is particularly useful in GUI applications that need to wait 
								///< concurrently on several events. In Windows NT/2000 the PacketSetMinToCopy()
								///< function can be used to define the minimum amount of data in the kernel buffer
								///< that will cause the event to be signalled. 
	
	UINT ReadTimeOut;			///< \internal The amount of time after which a read on the driver will be released and 
								///< ReadEvent will be signaled, also if no packets were captured
	CHAR Name[ADAPTER_NAME_LENGTH];
	PWAN_ADAPTER pWanAdapter;
	UINT Flags;					///< Adapter's flags. Tell if this adapter must be treated in a different way, using the Netmon API or the dagc API.

#ifdef HAVE_AIRPCAP_API
	PAirpcapHandle	AirpcapAd;
#endif // HAVE_AIRPCAP_API

#ifdef HAVE_NPFIM_API
	void* NpfImHandle;
#endif // HAVE_NPFIM_API

#ifdef HAVE_DAG_API
	dagc_t *pDagCard;			///< Pointer to the dagc API adapter descriptor for this adapter
	PCHAR DagBuffer;			///< Pointer to the buffer with the packets that is received from the DAG card
	struct timeval DagReadTimeout;	///< Read timeout. The dagc API requires a timeval structure
	unsigned DagFcsLen;			///< Length of the frame check sequence attached to any packet by the card. Obtained from the registry
	DWORD DagFastProcess;		///< True if the user requests fast capture processing on this card. Higher level applications can use this value to provide a faster but possibly unprecise capture (for example, libpcap doesn't convert the timestamps).
#endif // HAVE_DAG_API
}  ADAPTER, *LPADAPTER;

/*!
  \brief Structure that contains a group of packets coming from the driver.

  This structure defines the header associated with every packet delivered to the application.
*/
typedef struct _PACKET {  
	HANDLE       hEvent;		///< \deprecated Still present for compatibility with old applications.
	OVERLAPPED   OverLapped;	///< \deprecated Still present for compatibility with old applications.
	PVOID        Buffer;		///< Buffer with containing the packets. See the PacketReceivePacket() for
								///< details about the organization of the data in this buffer
	UINT         Length;		///< Length of the buffer
	DWORD        ulBytesReceived;	///< Number of valid bytes present in the buffer, i.e. amount of data
									///< received by the last call to PacketReceivePacket()
	BOOLEAN      bIoComplete;	///< \deprecated Still present for compatibility with old applications.
}  PACKET, *LPPACKET;

/*!
  \brief Structure containing an OID request.

  It is used by the PacketRequest() function to send an OID to the interface card driver. 
  It can be used, for example, to retrieve the status of the error counters on the adapter, its MAC address, 
  the list of the multicast groups defined on it, and so on.
*/
struct _PACKET_OID_DATA {
    ULONG Oid;					///< OID code. See the Microsoft DDK documentation or the file ntddndis.h
								///< for a complete list of valid codes.
    ULONG Length;				///< Length of the data field
    UCHAR Data[1];				///< variable-lenght field that contains the information passed to or received 
								///< from the adapter.
}; 
typedef struct _PACKET_OID_DATA PACKET_OID_DATA, *PPACKET_OID_DATA;

#ifdef __cplusplus
extern "C" {
#endif

/**
 *  @}
 */

/*
BOOLEAN QueryWinPcapRegistryStringA(CHAR *SubKeyName,
								 CHAR *Value,
								 UINT *pValueLen,
								 CHAR *DefaultVal);

BOOLEAN QueryWinPcapRegistryStringW(WCHAR *SubKeyName,
								 WCHAR *Value,
								 UINT *pValueLen,
								 WCHAR *DefaultVal);
*/
								 
//---------------------------------------------------------------------------
// EXPORTED FUNCTIONS
//---------------------------------------------------------------------------

PCHAR PacketGetVersion();
PCHAR PacketGetDriverVersion();
BOOLEAN PacketSetMinToCopy(LPADAPTER AdapterObject,int nbytes);
BOOLEAN PacketSetNumWrites(LPADAPTER AdapterObject,int nwrites);
BOOLEAN PacketSetMode(LPADAPTER AdapterObject,int mode);
BOOLEAN PacketSetReadTimeout(LPADAPTER AdapterObject,int timeout);
BOOLEAN PacketSetBpf(LPADAPTER AdapterObject,struct bpf_program *fp);
BOOLEAN PacketSetLoopbackBehavior(LPADAPTER  AdapterObject, UINT LoopbackBehavior);
INT PacketSetSnapLen(LPADAPTER AdapterObject,int snaplen);
BOOLEAN PacketGetStats(LPADAPTER AdapterObject,struct bpf_stat *s);
BOOLEAN PacketGetStatsEx(LPADAPTER AdapterObject,struct bpf_stat *s);
BOOLEAN PacketSetBuff(LPADAPTER AdapterObject,int dim);
BOOLEAN PacketGetNetType (LPADAPTER AdapterObject,NetType *type);
LPADAPTER PacketOpenAdapter(PCHAR AdapterName);
BOOLEAN PacketSendPacket(LPADAPTER AdapterObject,LPPACKET pPacket,BOOLEAN Sync);
INT PacketSendPackets(LPADAPTER AdapterObject,PVOID PacketBuff,ULONG Size, BOOLEAN Sync);
LPPACKET PacketAllocatePacket(void);
VOID PacketInitPacket(LPPACKET lpPacket,PVOID  Buffer,UINT  Length);
VOID PacketFreePacket(LPPACKET lpPacket);
BOOLEAN PacketReceivePacket(LPADAPTER AdapterObject,LPPACKET lpPacket,BOOLEAN Sync);
BOOLEAN PacketSetHwFilter(LPADAPTER AdapterObject,ULONG Filter);
BOOLEAN PacketGetAdapterNames(PTSTR pStr,PULONG  BufferSize);
BOOLEAN PacketGetNetInfoEx(PCHAR AdapterName, npf_if_addr* buffer, PLONG NEntries);
BOOLEAN PacketRequest(LPADAPTER  AdapterObject,BOOLEAN Set,PPACKET_OID_DATA  OidData);
HANDLE PacketGetReadEvent(LPADAPTER AdapterObject);
BOOLEAN PacketSetDumpName(LPADAPTER AdapterObject, void *name, int len);
BOOLEAN PacketSetDumpLimits(LPADAPTER AdapterObject, UINT maxfilesize, UINT maxnpacks);
BOOLEAN PacketIsDumpEnded(LPADAPTER AdapterObject, BOOLEAN sync);
BOOL PacketStopDriver();
VOID PacketCloseAdapter(LPADAPTER lpAdapter);
BOOLEAN PacketStartOem(PCHAR errorString, UINT errorStringLength);
BOOLEAN PacketStartOemEx(PCHAR errorString, UINT errorStringLength, ULONG flags);
PAirpcapHandle PacketGetAirPcapHandle(LPADAPTER AdapterObject);

//
// Used by PacketStartOemEx
//
#define PACKET_START_OEM_NO_NETMON	0x00000001

#ifdef __cplusplus
}
#endif 

#endif //__PACKET32
