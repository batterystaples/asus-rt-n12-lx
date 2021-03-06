#ifndef	__FASTPATH_CORE_H__
#define	__FASTPATH_CORE_H__

#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <net/dst.h>
//#include <net/netfilter/nf_conntrack.h>
//#include <net/route.h>


/*
	Virtual Rome Driver API & System (Light Rome Driver Simulator)
*/

#if defined (__IRAM_GEN)
#undef	__IRAM_GEN
#define	__IRAM_GEN
#endif

//#define	ipaddr_t		__u32
//#define	uint8		__u8
//#define	uint16		__u16
//#define	uint32		__u32
//typedef unsigned long long	__uint64;

#if 0
#define DEBUGP_API printk
#else
#define DEBUGP_API(format, args...)
#endif

#if 0
#define DEBUGP_PKT printk
#else
#define DEBUGP_PKT(format, args...)
#endif

#if 0
#define DEBUGP_SYS printk
#else
#define DEBUGP_SYS(format, args...)
#endif

//#define	DEBUG_PROCFILE	/* Create ProcFile for debug */

//define this macro to improve qos
#define IMPROVE_QOS

#define CONFIG_UDP_FRAG_CACHE 1   //enable fragmentation cache ,mark_add

#if 1
/***********************************cary:refine filter.c**********************************/
#define FASTPATH_FILTER	1
/***********************************************************************************/
#define CUSTOM_RSP_PACKET 
#define DOS_FILTER 
#define URL_FILTER

//#define URL_CONTENT_AUTHENTICATION

#define ACTION_ALLOW 1
#define ACTION_DENY 0
#define WEEK_ALL_DAY 1<<7
#define TIME_ALL_TIME 1<<0
#define FAST_PPTP
#define FAST_L2TP
#endif
//#define DEL_NAPT_TBL
#define DEL_ROUTE_TBL	//sync from rtl865x --2010.02.09
#define NO_ARP_USED	// 2008.01.09, Forrest Lin. Use kernel route cache already.
#define INVALID_PATH_BY_FIN


#if defined(FAST_L2TP)
#if 0
	#define DEBUGP	printk
#else
	#define DEBUGP(fmt, args...) {}
#endif

#ifdef URL_CONTENT_AUTHENTICATION
#define RTL_UNAUTH_BUFFER_SIZE 8
#define RTL_URL_CONTENT_READED 0x1

typedef struct _unAuth_skb_s
{
	struct list_head list;	
	int id; /*skb->iphdr.id*/
	uint32 saddr;
	uint32 daddr;
	uint32 flag; /*whether the url content is readed by application....*/
	struct sk_buff *skb;
} unAuth_skb_t;

int rtl_urlContent_auth(struct sk_buff *skb);
#endif


#define control_message 0x8000
#define connect_control 0xc
#define stop_control 0x4
#define call_reply 0xb

struct l2tp_info
{
	struct net_device *wan_dev;
	struct net_device *ppp0_dev;
	unsigned long last_xmit;
	__u32 daddr;
	__u32 saddr;
	__u16 tid;                   /* Tunnel ID */
	__u16 cid;                   /* Caller ID */
        unsigned char mac_header[ETH_HLEN];
	__u16 valid;
	

};

struct l2tp_ext_hdr
{
	__u16 source;
	__u16 dest;
	__u16 len;
	__u16 checksum;
	__u16 type;
	__u16 tid;
	__u16 cid;
	__u16 addr_control;
	__u16 protocol;
};

struct avp_info
{
	__u16 length;
        __u16 vendorid;
	__u16 attr;
	__u16 mss_type;
};

struct l2tp_header
{
	__u16 ver;                   /* Version and friends */
	__u16 length;                /* Optional Length */
	__u16 tid;                   /* Tunnel ID */
	__u16 cid;                   /* Caller ID */
	__u16 Ns;                    /* Optional next sent */
	__u16 Nr;                    /* Optional next received */
};
extern void (*l2tp_tx_id_hook)(struct sk_buff *skb);

#endif


#if defined(FAST_PPTP)

#if 0
	#define FAST_PPTP_PRINT	printk
#else
	#define FAST_PPTP_PRINT(fmt, args...) {}
#endif

/*
struct pptp_info {
	struct net_device *wan_dev;
	unsigned int tx_seqno;
	unsigned int rx_seqno;
	__u32 saddr;
	__u32 daddr;
	__u16 callID;
	__u16 peer_callID;
	__u16 tx_ipID;
	__u16 ipID;
	struct net_device *ppp0_dev;
	struct net_device *lan_dev;
	unsigned char mac_header[ETH_HLEN];
	unsigned int tx_seqno_daemon;
	unsigned int rx_seqno_daemon;
	int ppp_hdr_len;
	unsigned char ppp_hdr[4];
};
*/

extern int fast_pptp_fw;


/* following define are imported from kerenl */
#define SC_COMP_RUN     0x00001000      /* compressor has been inited */
enum NPmode {
     NPMODE_PASS,                /* pass the packet through */
     NPMODE_DROP,                /* silently drop the packet */
     NPMODE_ERROR,               /* return an error */
     NPMODE_QUEUE                /* save it up for later. */
};

#define NUM_NP	6		/* Number of NPs. */
struct ppp_file {
	enum {
		INTERFACE=1, CHANNEL
	}		kind;
	struct sk_buff_head xq;		/* pppd transmit queue */
	struct sk_buff_head rq;		/* receive queue for pppd */
	wait_queue_head_t rwait;	/* for poll on reading /dev/ppp */
	atomic_t	refcnt;		/* # refs (incl /dev/ppp attached) */
	int		hdrlen;		/* space to leave for headers */
	int		index;		/* interface unit / channel number */
	int		dead;		/* unit/channel has been shut down */
};

//To sync with drivers/net/ppp_generic.c
struct ppp {
	struct ppp_file	file;		/* stuff for read/write/poll 0 */
	struct file	*owner;		/* file that owns this unit 48 */
	struct list_head channels;	/* list of attached channels 4c */
	int		n_channels;	/* how many channels are attached 54 */
	spinlock_t	rlock;		/* lock for receive side 58 */
	spinlock_t	wlock;		/* lock for transmit side 5c */
	int		mru;		/* max receive unit 60 */
#if defined(CONFIG_PPP_MPPE_MPPC)
	int		mru_alloc;	/* MAX(1500,MRU) for dev_alloc_skb() */
#endif
	unsigned int	flags;		/* control bits 64 */
	unsigned int	xstate;		/* transmit state bits 68 */
	unsigned int	rstate;		/* receive state bits 6c */
	int		debug;		/* debug flags 70 */
	struct slcompress *vj;		/* state for VJ header compression */
	enum NPmode	npmode[NUM_NP];	/* what to do with each net proto 78 */
	struct sk_buff	*xmit_pending;	/* a packet ready to go out 88 */
	struct compressor *xcomp;	/* transmit packet compressor 8c */
	void		*xc_state;	/* its internal state 90 */
	struct compressor *rcomp;	/* receive decompressor 94 */
	void		*rc_state;	/* its internal state 98 */
	unsigned long	last_xmit;	/* jiffies when last pkt sent 9c */
	unsigned long	last_recv;	/* jiffies when last pkt rcvd a0 */
	struct net_device *dev;		/* network interface device a4 */
	int		closing;	/* is device closing down? a8 */
#ifdef CONFIG_PPP_MULTILINK
	int		nxchan;		/* next channel to send something on */
	u32		nxseq;		/* next sequence number to send */
	int		mrru;		/* MP: max reconst. receive unit */
	u32		nextseq;	/* MP: seq no of next packet */
	u32		minseq;		/* MP: min of most recent seqnos */
	struct sk_buff_head mrq;	/* MP: receive reconstruction queue */
#endif /* CONFIG_PPP_MULTILINK */
	struct net_device_stats stats;	/* statistics */
#ifdef CONFIG_PPP_FILTER
	struct sock_filter *pass_filter;	/* filter for packets to pass */
	struct sock_filter *active_filter;/* filter for pkts to reset idle */
	unsigned pass_len, active_len;
#endif /* CONFIG_PPP_FILTER */
	struct net	*ppp_net;	/* the net we belong to */
};

extern void (*sync_tx_pptp_gre_seqno_hook)(struct sk_buff *skb);
#endif
#if defined(CUSTOM_RSP_PACKET)
void register_customRspHook(int *_cusRsp401_func,int *_cusRspTCPFinAck_func,int *_cusRspTCPEndAck_func);
void unregister_customRspHook();
void register_customRspStr(char *_str);
void unregister_customRspStr();
 int  GenerateHTTP401(struct sk_buff *skb);
#endif
#ifdef DOS_FILTER
	extern int filter_enter(struct sk_buff *skb);
	extern int __init filter_init(void);
	extern void __exit filter_exit(void);
	extern void filter_addconnect(ipaddr_t ipaddr);
	extern void filter_delconnect(ipaddr_t ipaddr);
#endif

#ifdef FAST_PPTP
	extern void fast_pptp_filter(struct sk_buff *skb);
	extern void fast_pptp_sync_rx_seq(struct sk_buff *skb);
	extern int __init fast_pptp_init(void);
	extern void __exit fast_pptp_exit(void);
	extern int fast_pptp_to_lan(struct sk_buff **pskb);
	extern int Check_GRE_rx_net_device(struct sk_buff *skb);
	extern int pptp_tcp_finished;
#endif

#ifdef FAST_L2TP
	extern int __init fast_l2tp_init(void);
	extern void __exit fast_l2tp_exit(void);
	extern int fast_l2tp_to_wan(struct sk_buff *skb);
	extern void fast_l2tp_rx(struct sk_buff *skb);
	extern void l2tp_tx_id(struct sk_buff *skb);	
	extern int fast_l2tp_fw;
#endif



/* ---------------------------------------------------------------------------------------------------- */

#define	IFNAME_LEN_MAX		16
#define	MAC_ADDR_LEN_MAX		18
#define	ARP_TABLE_LIST_MAX		32
#define	ARP_TABLE_ENTRY_MAX	128
#define	ROUTE_TABLE_LIST_MAX	16
#define	ROUTE_TABLE_ENTRY_MAX	64
#if !defined(CONFIG_RTL8186_KB_N)
#define	NAPT_TABLE_LIST_MAX	1024
#define	NAPT_TABLE_ENTRY_MAX	1024
#define	PATH_TABLE_LIST_MAX	1024
#endif

#define	PATH_TABLE_ENTRY_MAX	(NAPT_TABLE_ENTRY_MAX<<1)
#define	INTERFACE_ENTRY_MAX	8

#if 0
#define	ETHER_ADDR_LEN		6
typedef struct ether_addr_s {
        uint8 octet[ETHER_ADDR_LEN];
} ether_addr_t;
#endif

/* ########### API #################################################################################### */
enum LR_RESULT
{
	/* Common error code */
	LR_SUCCESS = 0,						/* Function Success */
	LR_FAILED = -1,						/* General Failure, not recommended to use */
	LR_ERROR_PARAMETER = -2,				/* The given parameter error */
	LR_EXIST = -3,							/* The entry you want to add has been existed, add failed */
	LR_NONEXIST = -4,						/* The specified entry is not found */
	
	LR_NOBUFFER = -1000,					/* Out of Entry Space */
	LR_INVAPARAM = -1001,					/* Invalid parameters */
	LR_NOTFOUND = -1002,					/* Entry not found */
	LR_DUPENTRY = -1003,					/* Duplicate entry found */
};

#if 0
enum IF_FLAGS
{
	IF_NONE,
	IF_INTERNAL = (0<<1),					/* This is an internal interface. */
	IF_EXTERNAL = (1<<1),					/* This is an external interface. */
};

enum FDB_FLAGS
{
	FDB_NONE = 0,
};
#endif

enum ARP_FLAGS
{
	ARP_NONE = 0,
};

enum RT_FLAGS
{
	RT_NONE = 0,
};

enum SE_TYPE
{
	SE_PPPOE = 1,
	SE_PPTP = 2,
	SE_L2TP = 3,
};
enum SE_FLAGS
{
	SE_NONE = 0,
};

enum NP_PROTOCOL
{
	NP_UDP = 1,
	NP_TCP = 2,
};
enum NP_FLAGS
{
	NP_NONE = 0,
};

/* ---------------------------------------------------------------------------------------------------- */
#if 0
enum LR_RESULT rtk_addInterface( uint8* ifname, ipaddr_t ipAddr, ether_addr_t* gmac, uint32 mtu, enum IF_FLAGS flags );
enum LR_RESULT rtk_configInterface( uint8* ifname, uint32 vlanId, uint32 fid, uint32 mbr, uint32 untag, enum IF_FLAGS flags );
enum LR_RESULT rtk_delInterface( uint8* ifname );
enum LR_RESULT rtk_addFdbEntry( uint32 vid, uint32 fid, ether_addr_t* mac, uint32 portmask, enum FDB_FLAGS flags );
enum LR_RESULT rtk_delFdbEntry( uint32 vid, uint32 fid, ether_addr_t* mac );
#endif
enum LR_RESULT rtk_addArp( ipaddr_t ip, ether_addr_t* mac, enum ARP_FLAGS flags );
enum LR_RESULT rtk_modifyArp( ipaddr_t ip, ether_addr_t* mac, enum ARP_FLAGS flags );
enum LR_RESULT rtk_delArp( ipaddr_t ip );
enum LR_RESULT rtk_addRoute( ipaddr_t ip, ipaddr_t mask, ipaddr_t gateway, uint8* ifname, enum RT_FLAGS flags );
enum LR_RESULT rtk_modifyRoute( ipaddr_t ip, ipaddr_t mask, ipaddr_t gateway, uint8* ifname, enum RT_FLAGS flags );
enum LR_RESULT rtk_delRoute( ipaddr_t ip, ipaddr_t mask );
enum LR_RESULT rtk_addSession( uint8* ifname, enum SE_TYPE seType, uint32 sessionId, enum SE_FLAGS flags );
enum LR_RESULT rtk_delSession( uint8* ifname );
enum LR_RESULT rtk_addNaptConnection( enum NP_PROTOCOL protocol, ipaddr_t intIp, uint32 intPort,
									ipaddr_t extIp, uint32 extPort,
									ipaddr_t remIp, uint32 remPort,
#if defined(IMPROVE_QOS)
									struct sk_buff *pskb, struct nf_conn *ct, 
#endif								
									enum NP_FLAGS flags);
enum LR_RESULT rtk_delNaptConnection( enum NP_PROTOCOL protocol, ipaddr_t intIp, uint32 intPort,
                                                               ipaddr_t extIp, uint32 extPort,
                                                               ipaddr_t remIp, uint32 remPort );
enum LR_RESULT
rtk_idleNaptConnection(enum NP_PROTOCOL protocol,ipaddr_t intIp, uint32 intPort,ipaddr_t extIp, uint32 extPort,
		ipaddr_t remIp, uint32 remPort,
		uint32 interval);

/* [MARCO FUNCTION] ========================================================================= */
#define	MAC2STR(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3], \
	((unsigned char *)&addr)[4], \
	((unsigned char *)&addr)[5]

#define	FASTPATH_MAC2STR(mac, hbuffer) \
	do { \
		int j,k; \
		const char hexbuf[] =  "0123456789ABCDEF"; \
		for (k=0,j=0;k<MAC_ADDR_LEN_MAX && j<6;j++) { \
			hbuffer[k++]=hexbuf[(mac->octet[j]>>4)&15 ]; \
			hbuffer[k++]=hexbuf[mac->octet[j]&15     ]; \
			hbuffer[k++]=':'; \
		} \
		hbuffer[--k]=0; \
	} while(0)	/* Mac Address to String */
#if 0
#define FASTPATH_ADJUST_CHKSUM_NAT(ip_mod, ip_org, chksum) \
	do { \
		s32 accumulate = 0; \
		if (((ip_mod) != 0) && ((ip_org) != 0)){ \
			accumulate = ((ip_org) & 0xffff); \
			accumulate += (( (ip_org) >> 16 ) & 0xffff); \
			accumulate -= ((ip_mod) & 0xffff); \
			accumulate -= (( (ip_mod) >> 16 ) & 0xffff); \
		} \
		accumulate += ntohs(chksum); \
		if (accumulate < 0) { \
			accumulate = -accumulate; \
			accumulate = (accumulate >> 16) + (accumulate & 0xffff); \
			accumulate += accumulate >> 16; \
			chksum = htons((uint16) ~accumulate); \
		} else { \
			accumulate = (accumulate >> 16) + (accumulate & 0xffff); \
			accumulate += accumulate >> 16; \
			chksum = htons((uint16) accumulate); \
		} \
	}while(0)	/* Checksum adjustment */

#define FASTPATH_ADJUST_CHKSUM_NPT(port_mod, port_org, chksum) \
	do { \
		s32 accumulate = 0; \
		if (((port_mod) != 0) && ((port_org) != 0)){ \
			accumulate += (port_org); \
			accumulate -= (port_mod); \
		} \
		accumulate += ntohs(chksum); \
		if (accumulate < 0) { \
			accumulate = -accumulate; \
			accumulate = (accumulate >> 16) + (accumulate & 0xffff); \
			accumulate += accumulate >> 16; \
			chksum = htons((uint16) ~accumulate); \
		} else { \
			accumulate = (accumulate >> 16) + (accumulate & 0xffff); \
			accumulate += accumulate >> 16; \
			chksum = htons((uint16) accumulate); \
		} \
	}while(0)	/* Checksum adjustment */


#define FASTPATH_ADJUST_CHKSUM_NAPT(ip_mod, ip_org, port_mod, port_org, chksum) \
	do { \
		s32 accumulate = 0; \
		if (((ip_mod) != 0) && ((ip_org) != 0)){ \
			accumulate = ((ip_org) & 0xffff); \
			accumulate += (( (ip_org) >> 16 ) & 0xffff); \
			accumulate -= ((ip_mod) & 0xffff); \
			accumulate -= (( (ip_mod) >> 16 ) & 0xffff); \
		} \
		if (((port_mod) != 0) && ((port_org) != 0)){ \
			accumulate += (port_org); \
			accumulate -= (port_mod); \
		} \
		accumulate += ntohs(chksum); \
		if (accumulate < 0) { \
			accumulate = -accumulate; \
			accumulate = (accumulate >> 16) + (accumulate & 0xffff); \
			accumulate += accumulate >> 16; \
			chksum = htons((uint16) ~accumulate); \
		} else { \
			accumulate = (accumulate >> 16) + (accumulate & 0xffff); \
			accumulate += accumulate >> 16; \
			chksum = htons((uint16) accumulate); \
		} \
	}while(0)	/* Checksum adjustment */
#else

#define FASTPATH_ADJUST_CHKSUM_NAT(ip_mod, ip_org, chksum) \
	do { \
		s32 accumulate = 0; \
		accumulate = ((ip_org) & 0xffff); \
		accumulate += (( (ip_org) >> 16 ) & 0xffff); \
		accumulate -= ((ip_mod) & 0xffff); \
		accumulate -= (( (ip_mod) >> 16 ) & 0xffff); \
		accumulate += ntohs(chksum); \
		if (accumulate < 0) { \
			accumulate = -accumulate; \
			accumulate = (accumulate >> 16) + (accumulate & 0xffff); \
			accumulate += accumulate >> 16; \
			chksum = htons((uint16) ~accumulate); \
		} else { \
			accumulate = (accumulate >> 16) + (accumulate & 0xffff); \
			accumulate += accumulate >> 16; \
			chksum = htons((uint16) accumulate); \
		} \
	}while(0)	/* Checksum adjustment */

#define FASTPATH_ADJUST_CHKSUM_NPT(port_mod, port_org, chksum) \
	do { \
		s32 accumulate = 0; \
		accumulate += (port_org); \
		accumulate -= (port_mod); \
		accumulate += ntohs(chksum); \
		if (accumulate < 0) { \
			accumulate = -accumulate; \
			accumulate = (accumulate >> 16) + (accumulate & 0xffff); \
			accumulate += accumulate >> 16; \
			chksum = htons((uint16) ~accumulate); \
		} else { \
			accumulate = (accumulate >> 16) + (accumulate & 0xffff); \
			accumulate += accumulate >> 16; \
			chksum = htons((uint16) accumulate); \
		} \
	}while(0)	/* Checksum adjustment */
	
	
#define FASTPATH_ADJUST_CHKSUM_NAPT(ip_mod, ip_org, port_mod, port_org, chksum) \
	do { \
		s32 accumulate = 0; \
		accumulate = ((ip_org) & 0xffff); \
		accumulate += (( (ip_org) >> 16 ) & 0xffff); \
		accumulate -= ((ip_mod) & 0xffff); \
		accumulate -= (( (ip_mod) >> 16 ) & 0xffff); \
		accumulate += (port_org); \
		accumulate -= (port_mod); \
		accumulate += ntohs(chksum); \
		if (accumulate < 0) { \
			accumulate = -accumulate; \
			accumulate = (accumulate >> 16) + (accumulate & 0xffff); \
			accumulate += accumulate >> 16; \
			chksum = htons((uint16) ~accumulate); \
		} else { \
			accumulate = (accumulate >> 16) + (accumulate & 0xffff); \
			accumulate += accumulate >> 16; \
			chksum = htons((uint16) accumulate); \
		} \
	}while(0)	/* Checksum adjustment */

#endif
/* ---------------------------------------------------------------------------------------------------- */
uint8 *FastPath_Route(ipaddr_t dIp);
int FastPath_Enter(struct sk_buff **skb);
extern int Get_fast_pptp_fw(void);
#ifdef CONFIG_FAST_PATH_MODULE
extern int (*fast_path_hook)(struct sk_buff **pskb) ;
extern enum LR_RESULT (*FastPath_hook1)( ipaddr_t ip, ipaddr_t mask );
extern enum LR_RESULT (*FastPath_hook2)( ipaddr_t ip, ipaddr_t mask, ipaddr_t gateway, uint8* ifname, enum RT_FLAGS flags );                     
extern int (*fast_path_hook)(struct sk_buff **pskb) ;
extern enum LR_RESULT (*FastPath_hook3)( ipaddr_t ip, ipaddr_t mask, ipaddr_t gateway, uint8* ifname, enum RT_FLAGS flags );
extern  enum LR_RESULT (*FastPath_hook4)( enum NP_PROTOCOL protocol, ipaddr_t intIp, uint32 intPort,
                                                               ipaddr_t extIp, uint32 extPort,
                                                               ipaddr_t remIp, uint32 remPort );
extern enum LR_RESULT (*FastPath_hook5)( ipaddr_t ip, ether_addr_t* mac, enum ARP_FLAGS flags );
extern enum LR_RESULT (*FastPath_hook6)( enum NP_PROTOCOL protocol, ipaddr_t intIp, uint32 intPort,
                                                               ipaddr_t extIp, uint32 extPort,
                                                               ipaddr_t remIp, uint32 remPort,
                                                               enum NP_FLAGS flags);
extern enum LR_RESULT (*FastPath_hook7)( ipaddr_t ip );
extern enum LR_RESULT (*FastPath_hook8)( ipaddr_t ip, ether_addr_t* mac, enum ARP_FLAGS flags );
extern int (*FastPath_hook9)( void );
extern int (*FastPath_hook10)(struct sk_buff *skb);
extern enum LR_RESULT (*FastPath_hook11)(enum NP_PROTOCOL protocol,
                ipaddr_t intIp, uint32 intPort,
                ipaddr_t extIp, uint32 extPort,
                ipaddr_t remIp, uint32 remPort,
                uint32 interval);

extern  int fast_pptp_to_wan(struct sk_buff *skb);
#endif


#if 0
int FastPath_Track(struct sk_buff *skb);
#endif
/* ---------------------------------------------------------------------------------------------------- */
#if defined(FASTPATH_FILTER)
#define RTL_FILTER_CONTENT_MAXNUM 40	
#define RTL_TABLE_FILTER_ENTRY_COUNT 10
#define IP_RANGE_TABLE 	1
#define MAC_TABLE		2
#define URL_KEY_TABLE	3
#define SCHEDULT_TABLE	4
#define CONTENT_FILTER	5

typedef struct _rlt_filter_table_head
{
	struct list_head filter_table;
	struct list_head filter_items;
	uint32 flag;
}rlt_filter_table_head;

//ip range table
#define RTL_IP_RANGE_FILTER_ENTRY_COUNT 20
typedef struct _filter_ipRange_fastpath
{
	struct list_head list;
	uint32 addr_start; /*ipaddr start*/	
	uint32 addr_end; /*address end*/
	uint32 flag; /*0 bit: default action[0:block,1:forward];1 bit: src ip or dest ip[0:src, 1:dest];2 bit: refer both direction*/
			    /*bit 9: valid 1; invalid 0*/
}rtl_ipRange_fastpath;

//url and keyword
#define RTL_URL_FILTER_CONTENT_MAXNUM_FASTPATH 40
typedef struct _url_table_head_entry_fastpath
{
	struct list_head list;	
	uint32 flag;
	int (*func)(struct sk_buff *skb);
}url_table_head_entry_fastpath;

typedef struct _url_table_unit_entry_fastpath
{
	struct list_head list;
	char url_content[RTL_URL_FILTER_CONTENT_MAXNUM_FASTPATH];
}url_table_unit_entry_fastpath;

typedef struct _url_entry_fastpath
{
	struct list_head list;
	char url_content[RTL_URL_FILTER_CONTENT_MAXNUM_FASTPATH];
	uint32 flag;
}rtl_url_entry_fastpath;

typedef struct _rtl_mac_entry_fastpath
{
	struct list_head list;
	char mac[ETHER_ADDR_LEN];
	uint8 flag; 
}rtl_mac_entry_fastpath;

typedef struct _rtl_sch_entry_fastpath
{
	struct list_head list;
	uint32 	weekMask; /*bit0: sunday, bit 1: monday, .... bit 6 saturday, bit7: (1: all days, monday~sunday)*/
	uint32 	startTime; /*minutes, ex. 5:21 = 5*60+21 minutes*/
	uint32 	endTime; /*minutes*/
	uint8 	allTimeFlag;/*if alltime(00:00~23:59:59), please set this flag...*/
	uint8 	flag; /* bit0( 0: deny, 1: allow), bit1( 1:block all http packet), bit2(0:default deny; 1: default allow)*/
}rtl_sch_entry_fastpath;

typedef struct _filter_table_info
{
	uint32 type;	//type
	int (*func)(struct sk_buff *skb, void *data);
}filter_table_info;

typedef struct _filter_table_list
{
	struct list_head table_list;
	struct list_head item_list;	
	uint32 type;	//type
	uint32 flag;
	uint32 num;
	int (*func)(struct sk_buff *skb, void *data);
}filter_table_list;

typedef struct _filter_item_entry
{
	struct list_head item_list;	
	struct list_head rule_list;	
	uint32 relation_flag;	//bit0: is the first condition? 1;0
						//bit1: have next condition? 1:0 [next table condition]
						//bit2: have "and" logic condition?1:0
						//bit3: default action: 1 block;0 forward
						//bit4~7: the index of "and" logic rule
						//bit8: all match flag 1: all, 0: not all
						//bit9: NULL flag, 1:NULL, 0: not NULL
	uint32 index;
	uint32 flag;		
	char data[RTL_FILTER_CONTENT_MAXNUM];
}filter_item_entry;

typedef struct _rtl_mac_info
{
	char mac[ETHER_ADDR_LEN];
}rtl_mac_info;

extern filter_table_list table_list_head;

#define	RTL_FP_FLT_TBL_INIT_VALUE	1
#define	RTL_FP_FLT_TBL_EMPTY	(table_list_head.num==RTL_FP_FLT_TBL_INIT_VALUE)
#define	RTL_FP_FLT_TBL_NOT_INIT	(table_list_head.num<RTL_FP_FLT_TBL_INIT_VALUE)
#endif

#endif	/* __FASTPATH_CORE_H__ */

