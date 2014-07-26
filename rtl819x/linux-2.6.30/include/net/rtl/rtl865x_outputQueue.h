#ifndef	RTL865X_OUTPUTQUEUE_H
#define	RTL865X_OUTPUTQUEUE_H
#include <linux/if.h>

#if	!defined(CONFIG_RTL_LAYERED_ASIC_DRIVER)
#define	RTL865XC_MNQUEUE_OUTPUTQUEUE		1
#define	RTL865XC_QOS_OUTPUTQUEUE				1

typedef struct rtl865xC_outputQueuePara_s {

	uint32	ifg;							/* default: Bandwidth Control Include/exclude Preamble & IFG */
	uint32	gap;							/* default: Per Queue Physical Length Gap = 20 */
	uint32	drop;						/* default: Descriptor Run Out Threshold = 500 */

	uint32	systemSBFCOFF;				/*System shared buffer flow control turn off threshold*/
	uint32	systemSBFCON;				/*System shared buffer flow control turn on threshold*/

	uint32	systemFCOFF;				/* system flow control turn off threshold */
	uint32	systemFCON;					/* system flow control turn on threshold */

	uint32	portFCOFF;					/* port base flow control turn off threshold */
	uint32	portFCON;					/* port base flow control turn on threshold */	

	uint32	queueDescFCOFF;				/* Queue-Descriptor=Based Flow Control turn off Threshold  */
	uint32	queueDescFCON;				/* Queue-Descriptor=Based Flow Control turn on Threshold  */

	uint32	queuePktFCOFF;				/* Queue-Packet=Based Flow Control turn off Threshold  */
	uint32	queuePktFCON;				/* Queue-Packet=Based Flow Control turn on Threshold  */
}	rtl865xC_outputQueuePara_t;
#endif

#define	MAX_QOS_RULE_NUM		10
#define	IPPROTO_ANY		256
#define	IPPROTO_BOTH		257

#define	QOS_DEF_QUEUE		0x4
#define	QOS_VALID_MASK	0x2
#define	QOS_TYPE_MASK		0x1
#define	QOS_TYPE_STR		0x0	/*0x0|QOS_VALID_MASK*/
#define	QOS_TYPE_WFQ		0x1	/*0x1|QOS_VALID_MASK*/

#define	EGRESS_BANDWIDTH_GRANULARITY			0x10000	/* 	64*1024	 */
#define	EGRESS_BANDWIDTH_GRANULARITY_BITMASK	0xffff
#define	EGRESS_BANDWIDTH_GRANULARITY_BITLEN	16

#define	INGRESS_BANDWIDTH_GRANULARITY_BITLEN	14

#define	EGRESS_WFQ_MAX_RATIO			0x80

#if 0
#define QOS_DEBUGP		printk
#else
#define QOS_DEBUGP(format, args...)
#endif

#if 0
#define QOS_RULE_DEBUGP		printk
#else
#define QOS_RULE_DEBUGP(format, args...)
#endif

/* priority decision array index */
enum PriDecIdx
{
	PORT_BASE	= 0,
	D1P_BASE, 
	DSCP_BASE, 
	ACL_BASE, 
	NAT_BASE,
	PRI_TYPE_NUM,
};

typedef	unsigned int	bwu;

typedef struct {
	/*	classify	*/
	unsigned int protocol;
	ipaddr_t	local_ip_start;
	ipaddr_t 	local_ip_end;
	ipaddr_t 	remote_ip_start;
	ipaddr_t 	remote_ip_end;
	unsigned short lo_port_start;
	unsigned short lo_port_end;
	unsigned short re_port_start;
	unsigned short re_port_end;

	/*	tc	*/
	uint32		mark;
	unsigned char	prio;
	unsigned char	rate;
} rtl865x_qos_entry_t, *rtl865x_qos_entry_p;

typedef struct {
	uint8		dscpRemark;
	uint8		vlanPriRemark;
	uint16		flags;

	char			ifname[IFNAMSIZ];
	uint32		queueId;			/*	identify outputQueue	*/
	uint32		handle;

	bwu			ceil;
	bwu			burst;
	bwu			bandwidth;		/* average bandwidth, unit kbps	*/
} rtl865x_qos_t, *rtl865x_qos_p;

typedef	rtl865x_qos_entry_t		QOS_T;
typedef	rtl865x_qos_entry_p		QOS_Tp;

typedef struct _rtl865x_qos_rule_t{
	char			inIfname[IFNAMSIZ];
	char			outIfname[IFNAMSIZ];
	rtl865x_AclRule_t *rule;
	uint32			mark;
	uint32			handle;
	struct _rtl865x_qos_rule_t	*next;
} rtl865x_qos_rule_t, *rtl865x_qos_rule_p;

int32 rtl865x_qosSetBandwidth(uint8 *netIfName, uint32 bps);
int32 rtl865x_qosFlushBandwidth(uint8 *netIfName);
int32 rtl865x_qosGetPriorityByHandle(uint8 *priority, uint32 handle);
int32 rtl865x_qosProcessQueue(uint8 *netIfName, rtl865x_qos_t *qosInfo);
int32 rtl865x_setRule2HandleMapping(uint32 ifIdx, uint32 idx, uint32 handle);
int32 rtl865x_qosAddMarkRule(rtl865x_qos_rule_t *rule);
int32 rtl865x_qosFlushMarkRule(void);
int32 rtl865x_qosCheckNaptPriority(rtl865x_AclRule_t *qosRule);
int32 rtl865x_closeQos(uint8 *netIfName);
int32 rtl865x_registerQosCompFunc(int8 (*p_cmpFunc)(rtl865x_qos_t	*entry1, rtl865x_qos_t	*entry2));	
int __init rtl865x_initOutputQueue(uint8 **netIfName);
void __exit rtl865x_exitOutputQueue(void);
int32 rtl865x_qosArrangeRuleByNetif(void);
#if defined(CONFIG_RTL_PROC_DEBUG)
int32 rtl865x_show_allQosAcl(void);
#endif
extern int32 rtl865x_qosArrangeRuleByNetif(void);

extern u8 netIfNameArray[NETIF_NUMBER][IFNAMSIZ];
extern rtl865x_qos_rule_t		*rtl865x_qosRuleHead;

#endif
