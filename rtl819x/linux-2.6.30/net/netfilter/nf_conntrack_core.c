/* Connection state tracking for netfilter.  This is separated from,
   but required by, the NAT layer; it can also be used by an iptables
   extension. */

/* (C) 1999-2001 Paul `Rusty' Russell
 * (C) 2002-2006 Netfilter Core Team <coreteam@netfilter.org>
 * (C) 2003,2004 USAGI/WIDE Project <http://www.linux-ipv6.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/types.h>
#include <linux/netfilter.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/vmalloc.h>
#include <linux/stddef.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/jhash.h>
#include <linux/err.h>
#include <linux/percpu.h>
#include <linux/moduleparam.h>
#include <linux/notifier.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/socket.h>
#include <linux/mm.h>
#include <linux/rculist_nulls.h>
#include <linux/ip.h>

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_l3proto.h>
#include <net/netfilter/nf_conntrack_l4proto.h>
#include <net/netfilter/nf_conntrack_expect.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_extend.h>
#include <net/netfilter/nf_conntrack_acct.h>
#include <net/netfilter/nf_nat.h>
#include <net/netfilter/nf_nat_core.h>

#include <net/rtl/rtl_types.h>
#if defined(CONFIG_RTL_IPTABLES_FAST_PATH) || defined(CONFIG_RTL_HARDWARE_NAT)
#include <linux/netfilter/nf_conntrack_tcp.h>
#endif
#if defined(CONFIG_RTL_IPTABLES_FAST_PATH)
//#include <net/rtl/rtl_types.h>
#include <net/rtl/fastpath/fastpath_core.h>
#if defined(CONFIG_FAST_PATH_MODULE)
enum LR_RESULT (*FastPath_hook4)( enum NP_PROTOCOL protocol, ipaddr_t intIp, uint32 intPort,
                                                               ipaddr_t extIp, uint32 extPort,
                                                               ipaddr_t remIp, uint32 remPort )=NULL;
enum LR_RESULT (*FastPath_hook6)( enum NP_PROTOCOL protocol, ipaddr_t intIp, uint32 intPort,
                                                               ipaddr_t extIp, uint32 extPort,
                                                               ipaddr_t remIp, uint32 remPort,
                                                               enum NP_FLAGS flags)=NULL;
enum LR_RESULT (*FastPath_hook11)(enum NP_PROTOCOL protocol,
		ipaddr_t intIp, uint32 intPort,
		ipaddr_t extIp, uint32 extPort,
		ipaddr_t remIp, uint32 remPort,
		uint32 interval)=NULL;
EXPORT_SYMBOL(FastPath_hook4);
EXPORT_SYMBOL(FastPath_hook6);
EXPORT_SYMBOL(FastPath_hook11);
#endif
#endif

#define NF_CONNTRACK_VERSION	"0.5.0"

int (*nfnetlink_parse_nat_setup_hook)(struct nf_conn *ct,
				      enum nf_nat_manip_type manip,
				      struct nlattr *attr) __read_mostly;
EXPORT_SYMBOL_GPL(nfnetlink_parse_nat_setup_hook);

DEFINE_SPINLOCK(nf_conntrack_lock);
EXPORT_SYMBOL_GPL(nf_conntrack_lock);

unsigned int nf_conntrack_htable_size __read_mostly;
EXPORT_SYMBOL_GPL(nf_conntrack_htable_size);

unsigned int nf_conntrack_max __read_mostly;
EXPORT_SYMBOL_GPL(nf_conntrack_max);

struct nf_conn nf_conntrack_untracked __read_mostly;
EXPORT_SYMBOL_GPL(nf_conntrack_untracked);

static struct kmem_cache *nf_conntrack_cachep __read_mostly;

static int nf_conntrack_hash_rnd_initted;
static unsigned int nf_conntrack_hash_rnd;

#if defined(CONFIG_RTL_IPTABLES_FAST_PATH)
static struct timer_list tcp_patten_ck;
#if defined(IMPROVE_QOS)
int smart_count=0;
#else
static int smart_count=0;
#endif
#endif

#if defined(CONFIG_RTL_NF_CONNTRACK_GARBAGE_NEW)

unsigned int conntrack_min = 0;
unsigned int conntrack_max= 100;

LIST_HEAD(close_list);
LIST_HEAD(last_ack_list);
LIST_HEAD(close_wait_list);
LIST_HEAD(fin_wait_list);
LIST_HEAD(time_wait_list);
LIST_HEAD(syn_recv_list);
LIST_HEAD(syn_sent_list);
LIST_HEAD(established_list);
LIST_HEAD(listen_list);
LIST_HEAD(udp_unreply_list);
LIST_HEAD(udp_assured_list);


struct tcp_state_hash_head Tcp_State_Hash_Head[]={
	{TCP_CONNTRACK_NONE,NULL},
	{TCP_CONNTRACK_ESTABLISHED,&established_list},
	{TCP_CONNTRACK_SYN_SENT,&syn_sent_list},
	{TCP_CONNTRACK_SYN_RECV,&syn_recv_list},
	{TCP_CONNTRACK_FIN_WAIT,&fin_wait_list},
	{TCP_CONNTRACK_TIME_WAIT,&time_wait_list},
	{TCP_CONNTRACK_CLOSE,&close_list},
	{TCP_CONNTRACK_CLOSE_WAIT,&close_wait_list},
	{TCP_CONNTRACK_LAST_ACK,&last_ack_list},
	{TCP_CONNTRACK_LISTEN,&listen_list},
	{TCP_CONNTRACK_MAX,NULL}
	};

struct udp_state_hash_head Udp_State_Hash_Head[]={
	{UDP_UNREPLY,&udp_unreply_list},
	{UDP_ASSURED,&udp_assured_list}
};

 struct DROP_PRORITY drop_priority[]={
 	{TCP_CONNTRACK_CLOSE,10},
	{TCP_CONNTRACK_LAST_ACK,30},
	{TCP_CONNTRACK_CLOSE_WAIT,60},
	{TCP_CONNTRACK_TIME_WAIT,120},
	{TCP_CONNTRACK_FIN_WAIT,120},
	{UDP_UNREPLY,30},
	{UDP_ASSURED,180},
	{TCP_CONNTRACK_SYN_SENT,120},
	{TCP_CONNTRACK_SYN_RECV,60},
	{TCP_CONNTRACK_ESTABLISHED,8*60}
};


static void init_tcp_state_hash(void)
{
	int i;
	for (i = 0; i < sizeof(Tcp_State_Hash_Head)/sizeof(struct tcp_state_hash_head); i++)
	{
		struct tcp_state_hash_head *p;
		p = &Tcp_State_Hash_Head[i];
		if (p->state_hash)
			INIT_LIST_HEAD(p->state_hash);
	}
	for (i = 0; i < sizeof(Udp_State_Hash_Head)/sizeof(struct udp_state_hash_head); i++)
	{
		struct udp_state_hash_head *p;
		p = &Udp_State_Hash_Head[i];
		if (p->state_hash)
			INIT_LIST_HEAD(p->state_hash);
	}

}



/* statistic counters, prot_limit is the threshold for selecting the protocol conntrack to drop.
    eg. if TCP is 95(95%), then when TCP connections occupy more than 95%, gc will choose 
    TCP to drop regardless its priority. Andrew 
*/

unsigned int prot_limit[PROT_MAX];
atomic_t prot_counters[PROT_MAX];
atomic_t _prot_limit[PROT_MAX];

int drop_one_conntrack(void);
static inline void recalculate(void) {
	int i;
	for (i = 0; i < PROT_MAX; i++) {
		atomic_set(&_prot_limit[i], nf_conntrack_max * prot_limit[i] /100);
	}

	//printk("icmp=%u  tcp=%u  udp=%u\n", _prot_limit[PROT_ICMP], _prot_limit[PROT_TCP], _prot_limit[PROT_UDP]);
}

int conntrack_dointvec(ctl_table *table, int write, struct file *filp,
		     void *buffer, size_t *lenp, loff_t *ppos) {

	int err;

	err = proc_dointvec(table, write, filp, buffer, lenp, ppos);
	if (err != 0)
		return err;
	if (write)
		recalculate();
	return 0;
}

int conntrack_dointvec_minmax(ctl_table *table, int write, struct file *filp,
		     void *buffer, size_t *lenp, loff_t *ppos) {

	int err;

	err = proc_dointvec_minmax(table, write, filp, buffer, lenp, ppos);
	if (err != 0)
		return err;
	if (write)
		recalculate();
	return 0;
}
#if 0
static unsigned int
print_tuple_1(char *buffer, const struct ip_conntrack_tuple *tuple,
	    struct ip_conntrack_protocol *proto)
{
	int len;

	len = sprintf(buffer, "src=%u.%u.%u.%u dst=%u.%u.%u.%u ",
		      NIPQUAD(tuple->src.ip), NIPQUAD(tuple->dst.ip));

	len += proto->print_tuple(buffer + len, tuple);

	return len;
}

static unsigned int
print_conntrack_1(char *buffer, const struct ip_conntrack *conntrack)
{
       	unsigned int len;
	struct ip_conntrack_protocol *proto
		= __ip_ct_find_proto(conntrack->tuplehash[IP_CT_DIR_ORIGINAL]
			       .tuple.dst.protonum);

	len = sprintf(buffer, "%-8s %u %lu ",
		      proto->name,
		      conntrack->tuplehash[IP_CT_DIR_ORIGINAL]
		      .tuple.dst.protonum,
		      timer_pending(&conntrack->timeout)
		      ? (conntrack->timeout.expires - jiffies)/HZ : 0);

	len += proto->print_conntrack(buffer + len, conntrack);
	len += print_tuple_1(buffer + len,
			   &conntrack->tuplehash[IP_CT_DIR_ORIGINAL].tuple,
			   proto);
	if (!(conntrack->status & IPS_SEEN_REPLY))
		len += sprintf(buffer + len, "[UNREPLIED] ");
	len += print_tuple_1(buffer + len,
			   &conntrack->tuplehash[IP_CT_DIR_REPLY].tuple,
			   proto);
	if (conntrack->status & IPS_ASSURED)
		len += sprintf(buffer + len, "[ASSURED] ");
	len += sprintf(buffer + len, "use=%u ",
		       atomic_read(&conntrack->ct_general.use));
	len += sprintf(buffer + len, "\n");

	return len;
}
#endif
#endif  //CONFIG_RTL_NF_CONNTRACK_GARBAGE_NEW



static u_int32_t __hash_conntrack(const struct nf_conntrack_tuple *tuple,
				  unsigned int size, unsigned int rnd)
{
	unsigned int n;
	u_int32_t h;

	/* The direction must be ignored, so we hash everything up to the
	 * destination ports (which is a multiple of 4) and treat the last
	 * three bytes manually.
	 */
	n = (sizeof(tuple->src) + sizeof(tuple->dst.u3)) / sizeof(u32);
	h = jhash2((u32 *)tuple, n,
		   rnd ^ (((__force __u16)tuple->dst.u.all << 16) |
			  tuple->dst.protonum));

	return ((u64)h * size) >> 32;
}

static inline u_int32_t hash_conntrack(const struct nf_conntrack_tuple *tuple)
{
	return __hash_conntrack(tuple, nf_conntrack_htable_size,
				nf_conntrack_hash_rnd);
}

bool
nf_ct_get_tuple(const struct sk_buff *skb,
		unsigned int nhoff,
		unsigned int dataoff,
		u_int16_t l3num,
		u_int8_t protonum,
		struct nf_conntrack_tuple *tuple,
		const struct nf_conntrack_l3proto *l3proto,
		const struct nf_conntrack_l4proto *l4proto)
{
	memset(tuple, 0, sizeof(*tuple));

	tuple->src.l3num = l3num;
	if (l3proto->pkt_to_tuple(skb, nhoff, tuple) == 0)
		return false;

	tuple->dst.protonum = protonum;
	tuple->dst.dir = IP_CT_DIR_ORIGINAL;

	return l4proto->pkt_to_tuple(skb, dataoff, tuple);
}
EXPORT_SYMBOL_GPL(nf_ct_get_tuple);

bool nf_ct_get_tuplepr(const struct sk_buff *skb, unsigned int nhoff,
		       u_int16_t l3num, struct nf_conntrack_tuple *tuple)
{
	struct nf_conntrack_l3proto *l3proto;
	struct nf_conntrack_l4proto *l4proto;
	unsigned int protoff;
	u_int8_t protonum;
	int ret;

	rcu_read_lock();

	l3proto = __nf_ct_l3proto_find(l3num);
	ret = l3proto->get_l4proto(skb, nhoff, &protoff, &protonum);
	if (ret != NF_ACCEPT) {
		rcu_read_unlock();
		return false;
	}

	l4proto = __nf_ct_l4proto_find(l3num, protonum);

	ret = nf_ct_get_tuple(skb, nhoff, protoff, l3num, protonum, tuple,
			      l3proto, l4proto);

	rcu_read_unlock();
	return ret;
}
EXPORT_SYMBOL_GPL(nf_ct_get_tuplepr);

bool
nf_ct_invert_tuple(struct nf_conntrack_tuple *inverse,
		   const struct nf_conntrack_tuple *orig,
		   const struct nf_conntrack_l3proto *l3proto,
		   const struct nf_conntrack_l4proto *l4proto)
{
	memset(inverse, 0, sizeof(*inverse));

	inverse->src.l3num = orig->src.l3num;
	if (l3proto->invert_tuple(inverse, orig) == 0)
		return false;

	inverse->dst.dir = !orig->dst.dir;

	inverse->dst.protonum = orig->dst.protonum;
	return l4proto->invert_tuple(inverse, orig);
}
EXPORT_SYMBOL_GPL(nf_ct_invert_tuple);

static void
clean_from_lists(struct nf_conn *ct)
{
	pr_debug("clean_from_lists(%p)\n", ct);
	hlist_nulls_del_rcu(&ct->tuplehash[IP_CT_DIR_ORIGINAL].hnnode);
	hlist_nulls_del_rcu(&ct->tuplehash[IP_CT_DIR_REPLY].hnnode);

	#if defined(CONFIG_RTL_NF_CONNTRACK_GARBAGE_NEW)
       switch (ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.protonum) 
	{
	      	case IPPROTO_TCP:
	       		atomic_dec(&prot_counters[PROT_TCP] );
	        	break;
	        case IPPROTO_UDP:
	        	atomic_dec(&prot_counters[PROT_UDP] );
	        	break;
	        case IPPROTO_ICMP:
	        	atomic_dec(&prot_counters[PROT_ICMP] );
	        	break;
	}

	if((ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.protonum == IPPROTO_TCP)||
		(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.protonum == IPPROTO_UDP))
	{
		list_del(&ct->state_tuple);
	       ct->state_tuple.next=NULL;
		ct->state_tuple.prev=NULL;				
                 	
	}
	#endif //CONFIG_RTL_NF_CONNTRACK_GARBAGE_NEW

	/* Destroy all pending expectations */
	nf_ct_remove_expectations(ct);
}

static void
destroy_conntrack(struct nf_conntrack *nfct)
{
	struct nf_conn *ct = (struct nf_conn *)nfct;
	struct net *net = nf_ct_net(ct);
	struct nf_conntrack_l4proto *l4proto;
#ifdef CONFIG_RTL_HARDWARE_NAT 
	struct nf_conn_nat *nat;
#endif

	pr_debug("destroy_conntrack(%p)\n", ct);
	NF_CT_ASSERT(atomic_read(&nfct->use) == 0);
	NF_CT_ASSERT(!timer_pending(&ct->timeout));

	if (!test_bit(IPS_DYING_BIT, &ct->status))
		nf_conntrack_event(IPCT_DESTROY, ct);
	set_bit(IPS_DYING_BIT, &ct->status);

	/* To make sure we don't get any weird locking issues here:
	 * destroy_conntrack() MUST NOT be called with a write lock
	 * to nf_conntrack_lock!!! -HW */
	rcu_read_lock();
	l4proto = __nf_ct_l4proto_find(nf_ct_l3num(ct), nf_ct_protonum(ct));
	if (l4proto && l4proto->destroy)
		l4proto->destroy(ct);

	rcu_read_unlock();

	
#if defined(CONFIG_RTL_IPTABLES_FAST_PATH)
	//if ( test_bit(IPS_SEEN_REPLY_BIT, &ct->status)) 
	{
		if (ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.protonum == IPPROTO_TCP) {
			/* TCP Connection Tracking */
			
			if(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip 
			   == ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip)
			{
				/*case  WAN->LAN(BC->AB) use C|A-B*/
				#ifdef CONFIG_FAST_PATH_MODULE
				if(FastPath_hook4!=NULL)
				{
					FastPath_hook4(NP_TCP,
					ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip,
					ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.tcp.port),	
					ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip,
					ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.tcp.port),				
					ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip,
					ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.tcp.port)				
					) ;	
				}
				#else
				rtk_delNaptConnection(NP_TCP,
				ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip,
				ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.tcp.port),	
				ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip,
				ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.tcp.port),				
				ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip,
				ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.tcp.port)				
				) ;		
				#endif
			}else{
				/*case  LAN->WAN(AB->BC) use A|C-B*/
				#ifdef CONFIG_FAST_PATH_MODULE
				if(FastPath_hook4!=NULL)
				{
					FastPath_hook4(NP_TCP, 
					ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip,
					ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.tcp.port),
					ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip,
					ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.tcp.port),
					ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip,
					ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.tcp.port)
					);
				}
				#else
				rtk_delNaptConnection(NP_TCP, 
				ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip,
				ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.tcp.port),
				ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip,
				ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.tcp.port),
				ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip,
				ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.tcp.port)
				);
				#endif
			}	
		} else if (ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.protonum == IPPROTO_UDP) {

			/* UDP Connection Tracking */
			/* check "LAN to WAN (AB->BC)" first */
			if(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip 
			   == ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip)	
			{			
				/*case  LAN->WAN(BC->AB) use A|C-B*/
				#ifdef CONFIG_FAST_PATH_MODULE
				if(FastPath_hook4!=NULL)
				{
					FastPath_hook4(NP_UDP, 
					ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip,
					ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.udp.port),
					ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip,
					ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.udp.port),
					ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip,
					ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.udp.port)
					);
				}
				#else
				rtk_delNaptConnection(NP_UDP, 
				ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip,
				ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.udp.port),
				ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip,
				ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.udp.port),
				ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip,
				ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.udp.port)
				);
				#endif
			}
			else if(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip 
			   == ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip)
			{
				/*case  WAN->LAN(BC->AB) use C|A-B*/
				#ifdef CONFIG_FAST_PATH_MODULE
				if(FastPath_hook4!=NULL)
				{
					FastPath_hook4(NP_UDP,
					ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip,
					ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.udp.port),				
					ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip,
					ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.udp.port),				
					ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip,
					ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.udp.port)
					) ;
				}
				#else
				rtk_delNaptConnection(NP_UDP,
				ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip,
				ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.udp.port),				
				ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip,
				ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.udp.port),				
				ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip,
				ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.udp.port)
				) ;			
				#endif
			}
		}
	}	/* IPS_SEEN_REPLY_BIT == 1 */
#endif


#ifdef CONFIG_RTL_HARDWARE_NAT 
	nat = nfct_nat(ct);
	if (nat->hw_acc == 1) 
	{
		if (ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.protonum == IPPROTO_TCP ||
			ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.protonum == IPPROTO_UDP)
		{
			rtl865x_handle_nat(ct, 0);
		}
	}	
#endif


	spin_lock_bh(&nf_conntrack_lock);
	/* Expectations will have been removed in clean_from_lists,
	 * except TFTP can create an expectation on the first packet,
	 * before connection is in the list, so we need to clean here,
	 * too. */
	nf_ct_remove_expectations(ct);

	/* We overload first tuple to link into unconfirmed list. */
	if (!nf_ct_is_confirmed(ct)) {
		BUG_ON(hlist_nulls_unhashed(&ct->tuplehash[IP_CT_DIR_ORIGINAL].hnnode));
		hlist_nulls_del_rcu(&ct->tuplehash[IP_CT_DIR_ORIGINAL].hnnode);
	}

	NF_CT_STAT_INC(net, delete);
	spin_unlock_bh(&nf_conntrack_lock);

	if (ct->master)
		nf_ct_put(ct->master);

	pr_debug("destroy_conntrack: returning ct=%p to slab\n", ct);
	nf_conntrack_free(ct);
}

static void death_by_timeout(unsigned long ul_conntrack)
{
	struct nf_conn *ct = (void *)ul_conntrack;
	struct net *net = nf_ct_net(ct);
	struct nf_conn_help *help = nfct_help(ct);
	struct nf_conntrack_helper *helper;
#ifdef CONFIG_RTL_HARDWARE_NAT
	struct nf_conn_nat *nat;
#endif

#if defined(CONFIG_RTL_IPTABLES_FAST_PATH) || defined(CONFIG_RTL_HARDWARE_NAT)
/*2007-12-19*/
	unsigned long expires = ct->timeout.expires;
	unsigned long now = jiffies;
#endif

#if defined(CONFIG_RTL_IPTABLES_FAST_PATH)
	{
		if (time_after_eq(now, expires)) {
			/* really idle timeout, not force to destroy */
//			if (test_bit(IPS_SEEN_REPLY_BIT, &ct->status)) 
			{
				if (ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.protonum == IPPROTO_TCP &&
					ct->proto.tcp.state < TCP_CONNTRACK_LAST_ACK) {
					/* TCP Connection Tracking */
					
					if (ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip 
						== ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip)
					{
						/* case BC->AB */	
						#ifdef CONFIG_FAST_PATH_MODULE
						if(FastPath_hook11!=NULL)
						{
							if (FastPath_hook11(NP_TCP,
									ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip,
									ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.tcp.port),	
									ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip,
									ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.tcp.port),				
									ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip,
									ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.tcp.port),
									tcp_get_timeouts_by_state(ct->proto.tcp.state)) != LR_SUCCESS) {
#if !defined(IMPROVE_QOS)
								write_lock_bh(&nf_conntrack_lock);
								ct->timeout.expires = now + tcp_get_timeouts_by_state(ct->proto.tcp.state);
								add_timer(&ct->timeout);
								write_unlock_bh(&nf_conntrack_lock);
#endif
								return;
							}
						}
						#else
						if (rtk_idleNaptConnection(NP_TCP,
								ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip,
								ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.tcp.port),	
								ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip,
								ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.tcp.port),				
								ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip,
								ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.tcp.port),
								tcp_get_timeouts_by_state(ct->proto.tcp.state)) != LR_SUCCESS) {
#if !defined(IMPROVE_QOS)
							write_lock_bh(&nf_conntrack_lock);
							ct->timeout.expires = now + tcp_get_timeouts_by_state(ct->proto.tcp.state);
							add_timer(&ct->timeout);
							write_unlock_bh(&nf_conntrack_lock);
#endif
							return;
						}
						#endif			
					}
					else if (ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip 
							 == ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip)
					{
						/* case AB->BC */
						#ifdef CONFIG_FAST_PATH_MODULE
						if(FastPath_hook11!=NULL)
						{
							if (FastPath_hook11(NP_TCP, 
									ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip,
									ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.tcp.port),
									ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip,
									ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.tcp.port),
									ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip,
									ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.tcp.port),
									tcp_get_timeouts_by_state(ct->proto.tcp.state)) != LR_SUCCESS) {
#if !defined(IMPROVE_QOS)
								write_lock_bh(&nf_conntrack_lock);
								ct->timeout.expires = now + tcp_get_timeouts_by_state(ct->proto.tcp.state);
								add_timer(&ct->timeout);
								write_unlock_bh(&nf_conntrack_lock);
#endif
								return;
							}
						}
						#else
						if (rtk_idleNaptConnection(NP_TCP, 
								ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip,
								ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.tcp.port),
								ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip,
								ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.tcp.port),
								ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip,
								ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.tcp.port),
								tcp_get_timeouts_by_state(ct->proto.tcp.state)) != LR_SUCCESS) {
#if !defined(IMPROVE_QOS)
							write_lock_bh(&nf_conntrack_lock);
							ct->timeout.expires = now + tcp_get_timeouts_by_state(ct->proto.tcp.state);
							add_timer(&ct->timeout);
							write_unlock_bh(&nf_conntrack_lock);
#endif
							return;
						}
						#endif
					}
				} 
				else if (ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.protonum == IPPROTO_UDP) {
					/* UDP Connection Tracking */
					
					if (ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip 
						== ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip)
					{
						/* case BC->AB */
						#ifdef CONFIG_FAST_PATH_MODULE
						if(FastPath_hook11!=NULL)
						{
							if (FastPath_hook11(NP_UDP,
									ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip,
									ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.udp.port),	
									ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip,
									ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.udp.port),				
									ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip,
									ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.udp.port),
									nf_ct_udp_timeout_stream) != LR_SUCCESS) {
#if !defined(IMPROVE_QOS)
								write_lock_bh(&nf_conntrack_lock);
								ct->timeout.expires = now + nf_ct_udp_timeout_stream;
								add_timer(&ct->timeout);
								write_unlock_bh(&nf_conntrack_lock);
#endif
								return;
							}	
						}
						#else
						if (rtk_idleNaptConnection(NP_UDP,
								ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip,
								ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.udp.port),	
								ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip,
								ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.udp.port),				
								ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip,
								ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.udp.port),
								nf_ct_udp_timeout_stream) != LR_SUCCESS) {
#if !defined(IMPROVE_QOS)
							write_lock_bh(&nf_conntrack_lock);
							ct->timeout.expires = now + nf_ct_udp_timeout_stream;
							add_timer(&ct->timeout);
							write_unlock_bh(&nf_conntrack_lock);
#endif
							return;
						}	
						#endif
					}
					else if (ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip 
							 == ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip)				
					{
						/* case AB->BC */
						#ifdef CONFIG_FAST_PATH_MODULE
						if(FastPath_hook11!=NULL)
						{
							if (FastPath_hook11(NP_UDP, 
									ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip,
									ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.udp.port),
									ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip,
									ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.udp.port),
									ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip,
									ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.udp.port),
									nf_ct_udp_timeout_stream) != LR_SUCCESS) {
#if !defined(IMPROVE_QOS)
								write_lock_bh(&nf_conntrack_lock);
								ct->timeout.expires = now + nf_ct_udp_timeout_stream;
								add_timer(&ct->timeout);
								write_unlock_bh(&nf_conntrack_lock);
#endif
								return;
							}
						}
						#else
						if (rtk_idleNaptConnection(NP_UDP, 
								ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip,
								ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.udp.port),
								ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip,
								ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.udp.port),
								ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip,
								ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.udp.port),
								nf_ct_udp_timeout_stream) != LR_SUCCESS) {
#if !defined(IMPROVE_QOS)
							write_lock_bh(&nf_conntrack_lock);
							ct->timeout.expires = now + nf_ct_udp_timeout_stream;
							add_timer(&ct->timeout);
							write_unlock_bh(&nf_conntrack_lock);
#endif
							return;
						}
						#endif
					}
				}
			}	/* IPS_SEEN_REPLY_BIT == 1 */
		}
	}
#endif


#ifdef CONFIG_RTL_HARDWARE_NAT  
	{
		if (time_after_eq(now, expires)) {
			/* really idle timeout, not force to destroy */
//			if (test_bit(IPS_SEEN_REPLY_BIT, &ct->status)) 
			{
				nat = nfct_nat(ct);
				if (nat->hw_acc == 1) {
					if (ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.protonum == IPPROTO_TCP &&
						ct->proto.tcp.state < TCP_CONNTRACK_LAST_ACK) {
						if (!rtl865x_handle_nat(ct, 2)) {
							write_lock_bh(&nf_conntrack_lock);
							ct->timeout.expires = now + tcp_get_timeouts_by_state(ct->proto.tcp.state);
							add_timer(&ct->timeout);
							write_unlock_bh(&nf_conntrack_lock);
							return;
						}
					}
					else if (ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.protonum == IPPROTO_UDP) {
						if (!rtl865x_handle_nat(ct, 2)) {
							write_lock_bh(&nf_conntrack_lock);
							ct->timeout.expires = now + nf_ct_udp_timeout_stream;
							add_timer(&ct->timeout);
							write_unlock_bh(&nf_conntrack_lock);
							return;
						}
					}
				}
			}
		}
	}
#endif


	if (help) {
		rcu_read_lock();
		helper = rcu_dereference(help->helper);
		if (helper && helper->destroy)
			helper->destroy(ct);
		rcu_read_unlock();
	}

	spin_lock_bh(&nf_conntrack_lock);
	/* Inside lock so preempt is disabled on module removal path.
	 * Otherwise we can get spurious warnings. */
	NF_CT_STAT_INC(net, delete_list);
	clean_from_lists(ct);
	spin_unlock_bh(&nf_conntrack_lock);
	nf_ct_put(ct);
}

/*
 * Warning :
 * - Caller must take a reference on returned object
 *   and recheck nf_ct_tuple_equal(tuple, &h->tuple)
 * OR
 * - Caller must lock nf_conntrack_lock before calling this function
 */
struct nf_conntrack_tuple_hash *
__nf_conntrack_find(struct net *net, const struct nf_conntrack_tuple *tuple)
{
	struct nf_conntrack_tuple_hash *h;
	struct hlist_nulls_node *n;
	unsigned int hash = hash_conntrack(tuple);

	/* Disable BHs the entire time since we normally need to disable them
	 * at least once for the stats anyway.
	 */
	local_bh_disable();
begin:
	hlist_nulls_for_each_entry_rcu(h, n, &net->ct.hash[hash], hnnode) {
		if (nf_ct_tuple_equal(tuple, &h->tuple)) {
			NF_CT_STAT_INC(net, found);
			local_bh_enable();
			return h;
		}
		NF_CT_STAT_INC(net, searched);
	}
	/*
	 * if the nulls value we got at the end of this lookup is
	 * not the expected one, we must restart lookup.
	 * We probably met an item that was moved to another chain.
	 */
	if (get_nulls_value(n) != hash)
		goto begin;
	local_bh_enable();

	return NULL;
}
EXPORT_SYMBOL_GPL(__nf_conntrack_find);

/* Find a connection corresponding to a tuple. */
struct nf_conntrack_tuple_hash *
nf_conntrack_find_get(struct net *net, const struct nf_conntrack_tuple *tuple)
{
	struct nf_conntrack_tuple_hash *h;
	struct nf_conn *ct;

	rcu_read_lock();
begin:
	h = __nf_conntrack_find(net, tuple);
	if (h) {
		ct = nf_ct_tuplehash_to_ctrack(h);
		if (unlikely(nf_ct_is_dying(ct) ||
			     !atomic_inc_not_zero(&ct->ct_general.use)))
			h = NULL;
		else {
			if (unlikely(!nf_ct_tuple_equal(tuple, &h->tuple))) {
				nf_ct_put(ct);
				goto begin;
			}
		}
	}
	rcu_read_unlock();

	return h;
}
EXPORT_SYMBOL_GPL(nf_conntrack_find_get);

static void __nf_conntrack_hash_insert(struct nf_conn *ct,
				       unsigned int hash,
				       unsigned int repl_hash)
{
	struct net *net = nf_ct_net(ct);

	hlist_nulls_add_head_rcu(&ct->tuplehash[IP_CT_DIR_ORIGINAL].hnnode,
			   &net->ct.hash[hash]);
	hlist_nulls_add_head_rcu(&ct->tuplehash[IP_CT_DIR_REPLY].hnnode,
			   &net->ct.hash[repl_hash]);
}

void nf_conntrack_hash_insert(struct nf_conn *ct)
{
	unsigned int hash, repl_hash;

	hash = hash_conntrack(&ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple);
	repl_hash = hash_conntrack(&ct->tuplehash[IP_CT_DIR_REPLY].tuple);

	__nf_conntrack_hash_insert(ct, hash, repl_hash);
}
EXPORT_SYMBOL_GPL(nf_conntrack_hash_insert);

/* Confirm a connection given skb; places it in hash table */
int
__nf_conntrack_confirm(struct sk_buff *skb)
{
	unsigned int hash, repl_hash;
	struct nf_conntrack_tuple_hash *h;
	struct nf_conn *ct;
	struct nf_conn_help *help;
	struct hlist_nulls_node *n;
	enum ip_conntrack_info ctinfo;
	struct net *net;

	ct = nf_ct_get(skb, &ctinfo);
	net = nf_ct_net(ct);

	/* ipt_REJECT uses nf_conntrack_attach to attach related
	   ICMP/TCP RST packets in other direction.  Actual packet
	   which created connection will be IP_CT_NEW or for an
	   expected connection, IP_CT_RELATED. */
	if (CTINFO2DIR(ctinfo) != IP_CT_DIR_ORIGINAL)
		return NF_ACCEPT;

	hash = hash_conntrack(&ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple);
	repl_hash = hash_conntrack(&ct->tuplehash[IP_CT_DIR_REPLY].tuple);

	/* We're not in hash table, and we refuse to set up related
	   connections for unconfirmed conns.  But packet copies and
	   REJECT will give spurious warnings here. */
	/* NF_CT_ASSERT(atomic_read(&ct->ct_general.use) == 1); */

	/* No external references means noone else could have
	   confirmed us. */
	NF_CT_ASSERT(!nf_ct_is_confirmed(ct));
	pr_debug("Confirming conntrack %p\n", ct);

	spin_lock_bh(&nf_conntrack_lock);

	/* See if there's one in the list already, including reverse:
	   NAT could have grabbed it without realizing, since we're
	   not in the hash.  If there is, we lost race. */
	hlist_nulls_for_each_entry(h, n, &net->ct.hash[hash], hnnode)
		if (nf_ct_tuple_equal(&ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple,
				      &h->tuple))
			goto out;
	hlist_nulls_for_each_entry(h, n, &net->ct.hash[repl_hash], hnnode)
		if (nf_ct_tuple_equal(&ct->tuplehash[IP_CT_DIR_REPLY].tuple,
				      &h->tuple))
			goto out;

	/* Remove from unconfirmed list */
	hlist_nulls_del_rcu(&ct->tuplehash[IP_CT_DIR_ORIGINAL].hnnode);

#if defined(CONFIG_RTL_NF_CONNTRACK_GARBAGE_NEW)
	switch (ip_hdr(skb)->protocol) 
	{
		case IPPROTO_TCP:
			if(Tcp_State_Hash_Head[ct->proto.tcp.state].state_hash!=NULL)
			{
				list_add_tail(&ct->state_tuple,Tcp_State_Hash_Head[ct->proto.tcp.state].state_hash);		
			}
			atomic_inc(&prot_counters[PROT_TCP] );
			break;
		case IPPROTO_UDP:
			if(ct->status & IPS_SEEN_REPLY)				
				list_add_tail(&ct->state_tuple,Udp_State_Hash_Head[1].state_hash);		  
			else				
				list_add_tail(&ct->state_tuple,Udp_State_Hash_Head[0].state_hash);
			atomic_inc(&prot_counters[PROT_UDP] );
			break;
		case IPPROTO_ICMP:
			atomic_inc(&prot_counters[PROT_ICMP] );
			break;
	}	        			 
#endif

	/* Timer relative to confirmation time, not original
	   setting time, otherwise we'd get timer wrap in
	   weird delay cases. */
	ct->timeout.expires += jiffies;
	add_timer(&ct->timeout);
	atomic_inc(&ct->ct_general.use);
	set_bit(IPS_CONFIRMED_BIT, &ct->status);

	/* Since the lookup is lockless, hash insertion must be done after
	 * starting the timer and setting the CONFIRMED bit. The RCU barriers
	 * guarantee that no other CPU can find the conntrack before the above
	 * stores are visible.
	 */
	__nf_conntrack_hash_insert(ct, hash, repl_hash);
	NF_CT_STAT_INC(net, insert);
	spin_unlock_bh(&nf_conntrack_lock);

	help = nfct_help(ct);
	if (help && help->helper)
		nf_conntrack_event_cache(IPCT_HELPER, ct);
#ifdef CONFIG_NF_NAT_NEEDED
	if (test_bit(IPS_SRC_NAT_DONE_BIT, &ct->status) ||
	    test_bit(IPS_DST_NAT_DONE_BIT, &ct->status))
		nf_conntrack_event_cache(IPCT_NATINFO, ct);
#endif
	nf_conntrack_event_cache(master_ct(ct) ?
				 IPCT_RELATED : IPCT_NEW, ct);
	return NF_ACCEPT;

out:
	NF_CT_STAT_INC(net, insert_failed);
	spin_unlock_bh(&nf_conntrack_lock);
	return NF_DROP;
}
EXPORT_SYMBOL_GPL(__nf_conntrack_confirm);

/* Returns true if a connection correspondings to the tuple (required
   for NAT). */
int
nf_conntrack_tuple_taken(const struct nf_conntrack_tuple *tuple,
			 const struct nf_conn *ignored_conntrack)
{
	struct net *net = nf_ct_net(ignored_conntrack);
	struct nf_conntrack_tuple_hash *h;
	struct hlist_nulls_node *n;
	unsigned int hash = hash_conntrack(tuple);

	/* Disable BHs the entire time since we need to disable them at
	 * least once for the stats anyway.
	 */
	rcu_read_lock_bh();
	hlist_nulls_for_each_entry_rcu(h, n, &net->ct.hash[hash], hnnode) {
		if (nf_ct_tuplehash_to_ctrack(h) != ignored_conntrack &&
		    nf_ct_tuple_equal(tuple, &h->tuple)) {
			NF_CT_STAT_INC(net, found);
			rcu_read_unlock_bh();
			return 1;
		}
		NF_CT_STAT_INC(net, searched);
	}
	rcu_read_unlock_bh();

	return 0;
}
EXPORT_SYMBOL_GPL(nf_conntrack_tuple_taken);

#define NF_CT_EVICTION_RANGE	8

/* There's a small race here where we may free a just-assured
   connection.  Too bad: we're in trouble anyway. */
static noinline int early_drop(struct net *net, unsigned int hash)
{
	/* Use oldest entry, which is roughly LRU */
	struct nf_conntrack_tuple_hash *h;
	struct nf_conn *ct = NULL, *tmp;
	struct hlist_nulls_node *n;
	unsigned int i, cnt = 0;
	int dropped = 0;

	rcu_read_lock();
	for (i = 0; i < nf_conntrack_htable_size; i++) {
		hlist_nulls_for_each_entry_rcu(h, n, &net->ct.hash[hash],
					 hnnode) {
			tmp = nf_ct_tuplehash_to_ctrack(h);
			if (!test_bit(IPS_ASSURED_BIT, &tmp->status))
				ct = tmp;
			cnt++;
		}

		if (ct && unlikely(nf_ct_is_dying(ct) ||
				   !atomic_inc_not_zero(&ct->ct_general.use)))
			ct = NULL;
		if (ct || cnt >= NF_CT_EVICTION_RANGE)
			break;
		hash = (hash + 1) % nf_conntrack_htable_size;
	}
	rcu_read_unlock();

	if (!ct)
		return dropped;

	if (del_timer(&ct->timeout)) {
		death_by_timeout((unsigned long)ct);
		dropped = 1;
		NF_CT_STAT_INC_ATOMIC(net, early_drop);
	}
	nf_ct_put(ct);
	return dropped;
}

struct nf_conn *nf_conntrack_alloc(struct net *net,
				   const struct nf_conntrack_tuple *orig,
				   const struct nf_conntrack_tuple *repl,
				   gfp_t gfp)
{
	struct nf_conn *ct;

#if defined(CONFIG_RTL_NF_CONNTRACK_GARBAGE_NEW)
	int nf_conntrack_threshold = (nf_conntrack_max * 80)/100;
	if((nf_conntrack_max- nf_conntrack_threshold) > 160)
		nf_conntrack_threshold = nf_conntrack_max-160;
#endif	

	if (unlikely(!nf_conntrack_hash_rnd_initted)) {
		get_random_bytes(&nf_conntrack_hash_rnd,
				sizeof(nf_conntrack_hash_rnd));
		nf_conntrack_hash_rnd_initted = 1;
	}

	/* We don't want any race condition at early drop stage */
	atomic_inc(&net->ct.count);

#if defined(CONFIG_RTL_NF_CONNTRACK_GARBAGE_NEW)
	if (nf_conntrack_max && unlikely(atomic_read(&net->ct.count) > nf_conntrack_threshold))
#else	
	if (nf_conntrack_max && unlikely(atomic_read(&net->ct.count) > nf_conntrack_max))
#endif
	{
#if defined(CONFIG_RTL_NF_CONNTRACK_GARBAGE_NEW)
#else
		unsigned int hash = hash_conntrack(orig);
#endif
		/* Try dropping from this hash chain. */
		
#if defined(CONFIG_RTL_NF_CONNTRACK_GARBAGE_NEW)
		if(!drop_one_conntrack()){
#else	
		#if 0
		if (!early_drop(&ip_conntrack_hash[hash])) {
			atomic_dec(&ip_conntrack_count);
		#endif
		if (!early_drop(net, hash)) {
			atomic_dec(&net->ct.count);
#endif		
			if (net_ratelimit())
				printk(KERN_WARNING
				       "nf_conntrack: table full, dropping"
				       " packet.\n");
			return ERR_PTR(-ENOMEM);
		}
	}

	/*
	 * Do not use kmem_cache_zalloc(), as this cache uses
	 * SLAB_DESTROY_BY_RCU.
	 */
	ct = kmem_cache_alloc(nf_conntrack_cachep, gfp);
	if (ct == NULL) {
		pr_debug("nf_conntrack_alloc: Can't alloc conntrack.\n");
		atomic_dec(&net->ct.count);
		return ERR_PTR(-ENOMEM);
	}
	/*
	 * Let ct->tuplehash[IP_CT_DIR_ORIGINAL].hnnode.next
	 * and ct->tuplehash[IP_CT_DIR_REPLY].hnnode.next unchanged.
	 */
	memset(&ct->tuplehash[IP_CT_DIR_MAX], 0,
	       sizeof(*ct) - offsetof(struct nf_conn, tuplehash[IP_CT_DIR_MAX]));
	ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple = *orig;
	ct->tuplehash[IP_CT_DIR_ORIGINAL].hnnode.pprev = NULL;
	ct->tuplehash[IP_CT_DIR_REPLY].tuple = *repl;
	ct->tuplehash[IP_CT_DIR_REPLY].hnnode.pprev = NULL;
	/* Don't set timer yet: wait for confirmation */
	setup_timer(&ct->timeout, death_by_timeout, (unsigned long)ct);
#ifdef CONFIG_NET_NS
	ct->ct_net = net;
#endif

	/*
	 * changes to lookup keys must be done before setting refcnt to 1
	 */
	smp_wmb();
	atomic_set(&ct->ct_general.use, 1);
	return ct;
}
EXPORT_SYMBOL_GPL(nf_conntrack_alloc);

void nf_conntrack_free(struct nf_conn *ct)
{
	struct net *net = nf_ct_net(ct);

	nf_ct_ext_destroy(ct);
	atomic_dec(&net->ct.count);
	nf_ct_ext_free(ct);
	kmem_cache_free(nf_conntrack_cachep, ct);
}
EXPORT_SYMBOL_GPL(nf_conntrack_free);

/* Allocate a new conntrack: we return -ENOMEM if classification
   failed due to stress.  Otherwise it really is unclassifiable. */
static struct nf_conntrack_tuple_hash *
init_conntrack(struct net *net,
	       const struct nf_conntrack_tuple *tuple,
	       struct nf_conntrack_l3proto *l3proto,
	       struct nf_conntrack_l4proto *l4proto,
	       struct sk_buff *skb,
	       unsigned int dataoff)
{
	struct nf_conn *ct;
	struct nf_conn_help *help;
	struct nf_conntrack_tuple repl_tuple;
	struct nf_conntrack_expect *exp;

	if (!nf_ct_invert_tuple(&repl_tuple, tuple, l3proto, l4proto)) {
		pr_debug("Can't invert tuple.\n");
		return NULL;
	}

	ct = nf_conntrack_alloc(net, tuple, &repl_tuple, GFP_ATOMIC);
	if (IS_ERR(ct)) {
		pr_debug("Can't allocate conntrack.\n");
		return (struct nf_conntrack_tuple_hash *)ct;
	}

	if (!l4proto->new(ct, skb, dataoff)) {
		nf_conntrack_free(ct);
		pr_debug("init conntrack: can't track with proto module\n");
		return NULL;
	}

	nf_ct_acct_ext_add(ct, GFP_ATOMIC);

	spin_lock_bh(&nf_conntrack_lock);
	exp = nf_ct_find_expectation(net, tuple);
	if (exp) {
		pr_debug("conntrack: expectation arrives ct=%p exp=%p\n",
			 ct, exp);
		/* Welcome, Mr. Bond.  We've been expecting you... */
		__set_bit(IPS_EXPECTED_BIT, &ct->status);
		ct->master = exp->master;
		if (exp->helper) {
			help = nf_ct_helper_ext_add(ct, GFP_ATOMIC);
			if (help)
				rcu_assign_pointer(help->helper, exp->helper);
		}

#ifdef CONFIG_NF_CONNTRACK_MARK
		ct->mark = exp->master->mark;
#endif
#ifdef CONFIG_NF_CONNTRACK_SECMARK
		ct->secmark = exp->master->secmark;
#endif
		nf_conntrack_get(&ct->master->ct_general);
		NF_CT_STAT_INC(net, expect_new);
	} else {
		__nf_ct_try_assign_helper(ct, GFP_ATOMIC);
		NF_CT_STAT_INC(net, new);
	}

#if defined(CONFIG_RTL_NF_CONNTRACK_GARBAGE_NEW)
	INIT_LIST_HEAD(&ct->state_tuple);
#endif


	/* Overload tuple linked list to put us in unconfirmed list. */
	hlist_nulls_add_head_rcu(&ct->tuplehash[IP_CT_DIR_ORIGINAL].hnnode,
		       &net->ct.unconfirmed);

	spin_unlock_bh(&nf_conntrack_lock);

	if (exp) {
		if (exp->expectfn)
			exp->expectfn(ct, exp);
		nf_ct_expect_put(exp);
	}

	return &ct->tuplehash[IP_CT_DIR_ORIGINAL];
}

/* On success, returns conntrack ptr, sets skb->nfct and ctinfo */
static inline struct nf_conn *
resolve_normal_ct(struct net *net,
		  struct sk_buff *skb,
		  unsigned int dataoff,
		  u_int16_t l3num,
		  u_int8_t protonum,
		  struct nf_conntrack_l3proto *l3proto,
		  struct nf_conntrack_l4proto *l4proto,
		  int *set_reply,
		  enum ip_conntrack_info *ctinfo)
{
	struct nf_conntrack_tuple tuple;
	struct nf_conntrack_tuple_hash *h;
	struct nf_conn *ct;

	if (!nf_ct_get_tuple(skb, skb_network_offset(skb),
			     dataoff, l3num, protonum, &tuple, l3proto,
			     l4proto)) {
		pr_debug("resolve_normal_ct: Can't get tuple\n");
		return NULL;
	}

	/* look for tuple match */
	h = nf_conntrack_find_get(net, &tuple);
	if (!h) {
		h = init_conntrack(net, &tuple, l3proto, l4proto, skb, dataoff);
		if (!h)
			return NULL;
		if (IS_ERR(h))
			return (void *)h;
	}
	ct = nf_ct_tuplehash_to_ctrack(h);

	/* It exists; we have (non-exclusive) reference. */
	if (NF_CT_DIRECTION(h) == IP_CT_DIR_REPLY) {
		*ctinfo = IP_CT_ESTABLISHED + IP_CT_IS_REPLY;
		/* Please set reply bit if this packet OK */
		*set_reply = 1;
	} else {
		/* Once we've had two way comms, always ESTABLISHED. */
		if (test_bit(IPS_SEEN_REPLY_BIT, &ct->status)) {
			pr_debug("nf_conntrack_in: normal packet for %p\n", ct);
			*ctinfo = IP_CT_ESTABLISHED;
		} else if (test_bit(IPS_EXPECTED_BIT, &ct->status)) {
			pr_debug("nf_conntrack_in: related packet for %p\n",
				 ct);
			*ctinfo = IP_CT_RELATED;
		} else {
			pr_debug("nf_conntrack_in: new packet for %p\n", ct);
			*ctinfo = IP_CT_NEW;
		}
		*set_reply = 0;
	}
	skb->nfct = &ct->ct_general;
	skb->nfctinfo = *ctinfo;
	return ct;
}

unsigned int
nf_conntrack_in(struct net *net, u_int8_t pf, unsigned int hooknum,
		struct sk_buff *skb)
{
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;
	struct nf_conntrack_l3proto *l3proto;
	struct nf_conntrack_l4proto *l4proto;
	unsigned int dataoff;
	u_int8_t protonum;
	int set_reply = 0;
	int ret;
	
#if !defined(IMPROVE_QOS)
#if defined(CONFIG_RTL_IPTABLES_FAST_PATH)
	int assured=0;
	int create_udp_link = 0;
	int create_tcp_link = 0;
#endif
#endif


	/* Previously seen (loopback or untracked)?  Ignore. */
	if (skb->nfct) {
		NF_CT_STAT_INC_ATOMIC(net, ignore);
		return NF_ACCEPT;
	}

	/* rcu_read_lock()ed by nf_hook_slow */
	l3proto = __nf_ct_l3proto_find(pf);
	ret = l3proto->get_l4proto(skb, skb_network_offset(skb),
				   &dataoff, &protonum);
	if (ret <= 0) {
		pr_debug("not prepared to track yet or error occured\n");
		NF_CT_STAT_INC_ATOMIC(net, error);
		NF_CT_STAT_INC_ATOMIC(net, invalid);
		return -ret;
	}

	l4proto = __nf_ct_l4proto_find(pf, protonum);

	/* It may be an special packet, error, unclean...
	 * inverse of the return code tells to the netfilter
	 * core what to do with the packet. */
	if (l4proto->error != NULL) {
		ret = l4proto->error(net, skb, dataoff, &ctinfo, pf, hooknum);
		if (ret <= 0) {
			NF_CT_STAT_INC_ATOMIC(net, error);
			NF_CT_STAT_INC_ATOMIC(net, invalid);
			return -ret;
		}
	}

	ct = resolve_normal_ct(net, skb, dataoff, pf, protonum,
			       l3proto, l4proto, &set_reply, &ctinfo);
	if (!ct) {
		/* Not valid part of a connection */
		NF_CT_STAT_INC_ATOMIC(net, invalid);
		return NF_ACCEPT;
	}

	if (IS_ERR(ct)) {
		/* Too stressed to deal. */
		NF_CT_STAT_INC_ATOMIC(net, drop);
		return NF_DROP;
	}

	NF_CT_ASSERT(skb->nfct);

	ret = l4proto->packet(ct, skb, dataoff, ctinfo, pf, hooknum);
	if (ret <= 0) {
		/* Invalid: inverse of the return code tells
		 * the netfilter core what to do */
		pr_debug("nf_conntrack_in: Can't track with proto module\n");
		nf_conntrack_put(skb->nfct);
		skb->nfct = NULL;
		NF_CT_STAT_INC_ATOMIC(net, invalid);
		if (ret == -NF_DROP)
			NF_CT_STAT_INC_ATOMIC(net, drop);
		return -ret;
	}

#if !defined(IMPROVE_QOS)	
#if defined(CONFIG_RTL_IPTABLES_FAST_PATH)
	/*
	 * ### for iperf application test ###
	 * the behavior of iperf UDP test is LAN PC (client) will burst UDP from LAN to WAN (by one way),
	 * WAN PC (server) will only send one UDP packet (statistics) at the end of test.
	 * so the fastpath or hardware NAT will create link at the end of test.
	 *
	 * the purpose for adding the following code is to create fastpath or hardware NAT link 
	 * when we only get one packet from LAN to WAN in UDP case.
	 */
	{
		extern unsigned int _br0_ip;
		extern unsigned int _br0_mask;
		uint32 sip, dip;

		sip = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip;
		dip = ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip;

		if ((ip_hdr(skb)->protocol == IPPROTO_UDP) &&
				((ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip 
					 == ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip)
#if defined(UNNUMBER_IP)
					 && (is_unnumber_ip(dip)==FALSE)
#endif
					 )) 
		{ 
			/* UDP and "LAN to WAN" */
			/* ignore some cases:  
			 *	1. sip = br0's ip -----> (ex. sip 192.168.1.254 ==> dip 239.255.255.250)
			 * 	2. (sip & br0's mask) != (br0's ip & br0's mask) -----> sip is not in br0's subnet
			 *	3. (dip & br0's mask) =  (br0's ip & br0's mask) -----> dip is in br0's subnet
			 *	4. dip != multicast IP address
			 *	5. sip != gip
			 */
			if ((sip != _br0_ip) &&
				((sip & _br0_mask) == (_br0_ip & _br0_mask)) &&
				((dip & _br0_mask) != (_br0_ip & _br0_mask)) &&
				((dip & 0xf0000000) != 0xe0000000) &&
				(sip != (ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip))
				)
			{
				create_udp_link = 1;
				/* copied from last 2 line of this function **/
				set_bit(IPS_SEEN_REPLY_BIT, &ct->status);
				/* next 3 lines are copied from udp_packet() in ip_conntrack_proto_udp.c */
				nf_ct_refresh(ct,skb, nf_ct_udp_timeout_stream);
				/* Also, more likely to be important, and not a probe */
				set_bit(IPS_ASSURED_BIT, &ct->status);
 			}
#if defined(UNNUMBER_IP)	
			else if (((is_unnumber_ip(sip)==TRUE) && (is_unnumber_ip(dip)==FALSE)))
			{
				create_udp_link = 1;
			}
#endif
		}
		else if((ip_hdr(skb)->protocol == IPPROTO_TCP) &&
	 		((ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip==ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip) 
#if defined(UNNUMBER_IP)
	 		&& (is_unnumber_ip(dip)==FALSE)
#endif
	 		)&& !assured)
 		{
 			
			struct iphdr *iph=ip_hdr(skb);
			struct tcphdr *tcph=(void *) iph + iph->ihl*4;
				if (!tcph->fin && !tcph->syn && !tcph->rst && tcph->psh==1 && 
					tcph->ack ==1 &&  (iph->daddr !=_br0_ip) && ((sip & _br0_mask) == (_br0_ip & _br0_mask)) &&
					((dip & _br0_mask) != (_br0_ip & _br0_mask)) && (sip != (ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip))){ 
						
						smart_count++;
						if(smart_count >810){
							//panic_printk("the case hit for mart flow:tcp state=%d, assured=%d\n",ct->proto.tcp.state,test_bit(IPS_ASSURED_BIT, &ct->status));
							create_tcp_link=1;
						}
				}	

			if ((!create_tcp_link) 
#if defined(UNNUMBER_IP)
				&& (is_unnumber_ip(sip)==TRUE) && (is_unnumber_ip(dip)==FALSE) 
#endif
				)
			{
				create_tcp_link = 1;
			}
 		}
	}
#endif

#if defined(CONFIG_RTL_IPTABLES_FAST_PATH)
	assured = test_bit(IPS_ASSURED_BIT, &ct->status);
#endif


#if defined(CONFIG_RTL_IPTABLES_FAST_PATH)
	
	/*1.add "!(ct->helper)" to fix ftp-cmd type packet 
	  2.add identify case LAN->WAN(AB->BC) or WAN->LAN(BC->AB) 
	  3.add !(ct->nat.info.helper) for best ALG avoid
	  */

	if (!(nfct_help(ct)) &&  (assured) && ((create_udp_link) || (create_tcp_link)))
	{


		if (ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.protonum == IPPROTO_TCP) {
			/* TCP Connection Tracking */

			//printk("******%s(%d), ipid(%d)\n",__FUNCTION__,__LINE__,ip_hdr(skb)->id);
			//printk("#####%s(%d), original.sip(0x%x),original.dip(0x%x),reply.sip(0x%x),reply.dip(0x%x)\n",__FUNCTION__,__LINE__,
			//ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip,ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip,
			//ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip,ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip
			//);
			
			if(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip 
			   == ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip)
			{
				/*case BC->AB*/
				#ifdef CONFIG_FAST_PATH_MODULE
				if(FastPath_hook6!=NULL)
				{
					FastPath_hook6(NP_TCP,
					ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip,
					ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.tcp.port),	
					ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip,
					ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.tcp.port),				
					ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip,
					ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.tcp.port),
					NP_NONE);					
				}
				#else
				
				rtk_addNaptConnection(NP_TCP,
				ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip,
				ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.tcp.port),	
				ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip,
				ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.tcp.port),				
				ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip,
				ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.tcp.port),
				NP_NONE);		
				#endif
				
			}else if(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip 
				 == ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip)
			{
					
				/*case AB->BC*/
				#ifdef CONFIG_FAST_PATH_MODULE
				if(FastPath_hook6!=NULL)
				{
					FastPath_hook6(NP_TCP, 
						ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip,
						ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.tcp.port),
						ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip,
						ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.tcp.port),
						ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip,
						ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.tcp.port),
						NP_NONE);
				}
				#else
				rtk_addNaptConnection(NP_TCP, 
					ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip,
					ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.tcp.port),
					ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip,
					ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.tcp.port),
					ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip,
					ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.tcp.port),
					NP_NONE);
				#endif
			}
							
		} else if (ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.protonum == IPPROTO_UDP) {
			/* UDP Connection Tracking */
			/* check "LAN to WAN (AB->BC)" first */
			 if(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip 
				== ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip)				
			{
			/*case AB->BC*/
			#ifdef CONFIG_FAST_PATH_MODULE
				if(FastPath_hook6!=NULL)
				{
					FastPath_hook6(NP_UDP, 
						ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip,
						ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.udp.port),
						ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip,
						ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.udp.port),
						ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip,
						ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.udp.port),
						NP_NONE);
				}
				#else
				rtk_addNaptConnection(NP_UDP, 
					ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip,
					ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.udp.port),
					ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip,
					ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.udp.port),
					ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip,
					ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.udp.port),
					NP_NONE);
				#endif
			}
			else if(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip 
				== ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip)
			{
			/*case BC->AB*/
			#ifdef CONFIG_FAST_PATH_MODULE
				if(FastPath_hook6!=NULL)
				{
					FastPath_hook6(NP_UDP,
						ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip,
						ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.udp.port),	
						ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip,
						ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.udp.port),				
						ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip,
						ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.udp.port),
						NP_NONE);
				}
				#else
				rtk_addNaptConnection(NP_UDP,
					ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip,
					ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.udp.port),	
					ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip,
					ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.udp.port),				
					ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip,
					ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.udp.port),
					NP_NONE);			
				#endif				
			}
			

		}

	}
#endif
#endif  //End of !defined(IMPROVE_QOS)

	if (set_reply && !test_and_set_bit(IPS_SEEN_REPLY_BIT, &ct->status))
		nf_conntrack_event_cache(IPCT_STATUS, ct);

	return ret;
}
EXPORT_SYMBOL_GPL(nf_conntrack_in);

bool nf_ct_invert_tuplepr(struct nf_conntrack_tuple *inverse,
			  const struct nf_conntrack_tuple *orig)
{
	bool ret;

	rcu_read_lock();
	ret = nf_ct_invert_tuple(inverse, orig,
				 __nf_ct_l3proto_find(orig->src.l3num),
				 __nf_ct_l4proto_find(orig->src.l3num,
						      orig->dst.protonum));
	rcu_read_unlock();
	return ret;
}
EXPORT_SYMBOL_GPL(nf_ct_invert_tuplepr);

/* Alter reply tuple (maybe alter helper).  This is for NAT, and is
   implicitly racy: see __nf_conntrack_confirm */
void nf_conntrack_alter_reply(struct nf_conn *ct,
			      const struct nf_conntrack_tuple *newreply)
{
	struct nf_conn_help *help = nfct_help(ct);

	/* Should be unconfirmed, so not in hash table yet */
	NF_CT_ASSERT(!nf_ct_is_confirmed(ct));

	pr_debug("Altering reply tuple of %p to ", ct);
	nf_ct_dump_tuple(newreply);

	ct->tuplehash[IP_CT_DIR_REPLY].tuple = *newreply;
	if (ct->master || (help && !hlist_empty(&help->expectations)))
		return;

	rcu_read_lock();
	__nf_ct_try_assign_helper(ct, GFP_ATOMIC);
	rcu_read_unlock();
}
EXPORT_SYMBOL_GPL(nf_conntrack_alter_reply);

#if defined(CONFIG_RTL_NF_CONNTRACK_GARBAGE_NEW)

static int getinfo_conntrack_proto(char *buffer, char **start, off_t offset, int length)
{
	//unsigned int dst_entries = atomic_read(&ipv4_dst_ops.entries);
	//int i, lcpu;
	int len = 0;

        //for (lcpu = 0; lcpu < smp_num_cpus; lcpu++) {
        //        i = cpu_logical_map(lcpu);

		len += sprintf(buffer+len, "%08x  %08x %08x\n",
			       atomic_read(&prot_counters[PROT_ICMP]),
			       atomic_read(&prot_counters[PROT_TCP]),
			       atomic_read(&prot_counters[PROT_UDP])
			);
	//}
	len -= offset;

	if (len > length)
		len = length;
	if (len < 0)
		len = 0;

	*start = buffer + offset;
  	return len;
}


void nf_ct_refresh_udp(struct nf_conn *ct, unsigned long extra_jiffies,char* status)
{
  	//IP_NF_ASSERT(ct->timeout.data == (unsigned long)ct);
	write_lock_bh(&nf_conntrack_lock);
	/* If not in hash table, timer will not be active yet */
	//if (!is_confirmed(ct))
	if(!test_bit(IPS_CONFIRMED_BIT, &ct->status))	
		ct->timeout.expires = extra_jiffies;
	else {
		/* Need del_timer for race avoidance (may already be dying). */
		if (del_timer(&ct->timeout)) {
			ct->timeout.expires = jiffies + extra_jiffies;
			add_timer(&ct->timeout);

			list_del(&ct->state_tuple);
		 	ct->state_tuple.next=NULL;
			ct->state_tuple.prev=NULL;
			if (ct->status & IPS_SEEN_REPLY) {
				list_add_tail(&ct->state_tuple, &udp_assured_list);
			} else {
				list_add_tail(&ct->state_tuple, &udp_unreply_list);
			}			
	
		}
	}
	write_unlock_bh(&nf_conntrack_lock);
}
void nf_ct_refresh_tcp(struct nf_conn *ct, unsigned long extra_jiffies,enum tcp_conntrack oldstate,enum tcp_conntrack newstate )
{
        //IP_NF_ASSERT(ct->timeout.data == (unsigned long)ct);

	write_lock_bh(&nf_conntrack_lock);
	/* If not in hash table, timer will not be active yet */
	if (!test_bit(IPS_CONFIRMED_BIT, &ct->status))
		ct->timeout.expires = extra_jiffies;
	else {
		/* Need del_timer for race avoidance (may already be dying). */
		if (del_timer(&ct->timeout)) {
			ct->timeout.expires = jiffies + extra_jiffies;
			add_timer(&ct->timeout);		
						
			list_del(&ct->state_tuple);                     
			ct->state_tuple.next=NULL;
			ct->state_tuple.prev=NULL;			
			list_add_tail(&ct->state_tuple, Tcp_State_Hash_Head[newstate].state_hash);
		}
	}
	write_unlock_bh(&nf_conntrack_lock);
}
#endif


/* Refresh conntrack for this many jiffies and do accounting if do_acct is 1 */
void __nf_ct_refresh_acct(struct nf_conn *ct,
			  enum ip_conntrack_info ctinfo,
			  const struct sk_buff *skb,
			  unsigned long extra_jiffies,
			  int do_acct)
{
	int event = 0;

	NF_CT_ASSERT(ct->timeout.data == (unsigned long)ct);
	NF_CT_ASSERT(skb);

	spin_lock_bh(&nf_conntrack_lock);

	/* Only update if this is not a fixed timeout */
	if (test_bit(IPS_FIXED_TIMEOUT_BIT, &ct->status))
		goto acct;

	/* If not in hash table, timer will not be active yet */
	if (!nf_ct_is_confirmed(ct)) {
		ct->timeout.expires = extra_jiffies;
		event = IPCT_REFRESH;
	} else {
		unsigned long newtime = jiffies + extra_jiffies;

		/* Only update the timeout if the new timeout is at least
		   HZ jiffies from the old timeout. Need del_timer for race
		   avoidance (may already be dying). */
		if (newtime - ct->timeout.expires >= HZ
		    && del_timer(&ct->timeout)) {
			ct->timeout.expires = newtime;
			add_timer(&ct->timeout);
			event = IPCT_REFRESH;
		}
	}

acct:
	if (do_acct) {
		struct nf_conn_counter *acct;

		acct = nf_conn_acct_find(ct);
		if (acct) {
			acct[CTINFO2DIR(ctinfo)].packets++;
			acct[CTINFO2DIR(ctinfo)].bytes +=
				skb->len - skb_network_offset(skb);
		}
	}

	spin_unlock_bh(&nf_conntrack_lock);

	/* must be unlocked when calling event cache */
	if (event)
		nf_conntrack_event_cache(event, ct);
}
EXPORT_SYMBOL_GPL(__nf_ct_refresh_acct);

#if defined(CONFIG_RTL_NF_CONNTRACK_GARBAGE_NEW)

void __nf_ct_refresh_acct_proto(struct nf_conn *ct, 
				      enum ip_conntrack_info ctinfo,
				      const struct sk_buff *skb,
				      unsigned long extra_jiffies,
				      int do_acct,
				      unsigned char proto, 
				      void * extra1,
				      void * extra2)
{

	int event = 0;

	//IP_NF_ASSERT(ct->timeout.data == (unsigned long)ct);
	//IP_NF_ASSERT(skb);

	write_lock_bh(&nf_conntrack_lock);

	/* Only update if this is not a fixed timeout */
	if (test_bit(IPS_FIXED_TIMEOUT_BIT, &ct->status)) {
		write_unlock_bh(&nf_conntrack_lock);
		return;
	}

	/* If not in hash table, timer will not be active yet */
	if (!test_bit(IPS_CONFIRMED_BIT, &ct->status)) {
		ct->timeout.expires = extra_jiffies;
		event = IPCT_REFRESH;
	} else {
		/* Need del_timer for race avoidance (may already be dying). */
		if (del_timer(&ct->timeout)) {
			ct->timeout.expires = jiffies + extra_jiffies;
			add_timer(&ct->timeout);
			event = IPCT_REFRESH;

			switch(proto) {
			case 6:
				list_del(&ct->state_tuple);                     
				ct->state_tuple.next=NULL;
				ct->state_tuple.prev=NULL;			
				list_add_tail(&ct->state_tuple, Tcp_State_Hash_Head[(enum tcp_conntrack) extra2].state_hash);
				break;
			case 17:
				list_del(&ct->state_tuple);
			 	ct->state_tuple.next=NULL;
				ct->state_tuple.prev=NULL;
				if (ct->status & IPS_SEEN_REPLY) {
					list_add_tail(&ct->state_tuple, &udp_assured_list);
				} else {
					list_add_tail(&ct->state_tuple, &udp_unreply_list);
				}
				break;				
			}
		}
	}

#ifdef CONFIG_IP_NF_CT_ACCT
	if (do_acct) {
		ct->counters[CTINFO2DIR(ctinfo)].packets++;
		ct->counters[CTINFO2DIR(ctinfo)].bytes += 
						ntohs(skb->nh.iph->tot_len);
		if ((ct->counters[CTINFO2DIR(ctinfo)].packets & 0x80000000)
		    || (ct->counters[CTINFO2DIR(ctinfo)].bytes & 0x80000000))
			event |= IPCT_COUNTER_FILLING;
	}
#endif

	write_unlock_bh(&nf_conntrack_lock);

	/* must be unlocked when calling event cache */
	if (event)
		nf_conntrack_event_cache(event, ct);
}


#endif


bool __nf_ct_kill_acct(struct nf_conn *ct,
		       enum ip_conntrack_info ctinfo,
		       const struct sk_buff *skb,
		       int do_acct)
{
	if (do_acct) {
		struct nf_conn_counter *acct;

		spin_lock_bh(&nf_conntrack_lock);
		acct = nf_conn_acct_find(ct);
		if (acct) {
			acct[CTINFO2DIR(ctinfo)].packets++;
			acct[CTINFO2DIR(ctinfo)].bytes +=
				skb->len - skb_network_offset(skb);
		}
		spin_unlock_bh(&nf_conntrack_lock);
	}

	if (del_timer(&ct->timeout)) {
		ct->timeout.function((unsigned long)ct);
		return true;
	}
	return false;
}
EXPORT_SYMBOL_GPL(__nf_ct_kill_acct);

#if defined(CONFIG_NF_CT_NETLINK) || defined(CONFIG_NF_CT_NETLINK_MODULE)

#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <linux/mutex.h>

/* Generic function for tcp/udp/sctp/dccp and alike. This needs to be
 * in ip_conntrack_core, since we don't want the protocols to autoload
 * or depend on ctnetlink */
int nf_ct_port_tuple_to_nlattr(struct sk_buff *skb,
			       const struct nf_conntrack_tuple *tuple)
{
	NLA_PUT_BE16(skb, CTA_PROTO_SRC_PORT, tuple->src.u.tcp.port);
	NLA_PUT_BE16(skb, CTA_PROTO_DST_PORT, tuple->dst.u.tcp.port);
	return 0;

nla_put_failure:
	return -1;
}
EXPORT_SYMBOL_GPL(nf_ct_port_tuple_to_nlattr);

const struct nla_policy nf_ct_port_nla_policy[CTA_PROTO_MAX+1] = {
	[CTA_PROTO_SRC_PORT]  = { .type = NLA_U16 },
	[CTA_PROTO_DST_PORT]  = { .type = NLA_U16 },
};
EXPORT_SYMBOL_GPL(nf_ct_port_nla_policy);

int nf_ct_port_nlattr_to_tuple(struct nlattr *tb[],
			       struct nf_conntrack_tuple *t)
{
	if (!tb[CTA_PROTO_SRC_PORT] || !tb[CTA_PROTO_DST_PORT])
		return -EINVAL;

	t->src.u.tcp.port = nla_get_be16(tb[CTA_PROTO_SRC_PORT]);
	t->dst.u.tcp.port = nla_get_be16(tb[CTA_PROTO_DST_PORT]);

	return 0;
}
EXPORT_SYMBOL_GPL(nf_ct_port_nlattr_to_tuple);

int nf_ct_port_nlattr_tuple_size(void)
{
	return nla_policy_len(nf_ct_port_nla_policy, CTA_PROTO_MAX + 1);
}
EXPORT_SYMBOL_GPL(nf_ct_port_nlattr_tuple_size);
#endif

/* Used by ipt_REJECT and ip6t_REJECT. */
static void nf_conntrack_attach(struct sk_buff *nskb, struct sk_buff *skb)
{
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;

	/* This ICMP is in reverse direction to the packet which caused it */
	ct = nf_ct_get(skb, &ctinfo);
	if (CTINFO2DIR(ctinfo) == IP_CT_DIR_ORIGINAL)
		ctinfo = IP_CT_RELATED + IP_CT_IS_REPLY;
	else
		ctinfo = IP_CT_RELATED;

	/* Attach to new skbuff, and increment count */
	nskb->nfct = &ct->ct_general;
	nskb->nfctinfo = ctinfo;
	nf_conntrack_get(nskb->nfct);
}

/* Bring out ya dead! */
static struct nf_conn *
get_next_corpse(struct net *net, int (*iter)(struct nf_conn *i, void *data),
		void *data, unsigned int *bucket)
{
	struct nf_conntrack_tuple_hash *h;
	struct nf_conn *ct;
	struct hlist_nulls_node *n;

	spin_lock_bh(&nf_conntrack_lock);
	for (; *bucket < nf_conntrack_htable_size; (*bucket)++) {
		hlist_nulls_for_each_entry(h, n, &net->ct.hash[*bucket], hnnode) {
			ct = nf_ct_tuplehash_to_ctrack(h);
			if (iter(ct, data))
				goto found;
		}
	}
	hlist_nulls_for_each_entry(h, n, &net->ct.unconfirmed, hnnode) {
		ct = nf_ct_tuplehash_to_ctrack(h);
		if (iter(ct, data))
			set_bit(IPS_DYING_BIT, &ct->status);
	}
	spin_unlock_bh(&nf_conntrack_lock);
	return NULL;
found:
	atomic_inc(&ct->ct_general.use);
	spin_unlock_bh(&nf_conntrack_lock);
	return ct;
}

void nf_ct_iterate_cleanup(struct net *net,
			   int (*iter)(struct nf_conn *i, void *data),
			   void *data)
{
	struct nf_conn *ct;
	unsigned int bucket = 0;

	while ((ct = get_next_corpse(net, iter, data, &bucket)) != NULL) {
		/* Time to push up daises... */
		if (del_timer(&ct->timeout))
			death_by_timeout((unsigned long)ct);
		/* ... else the timer will get him soon. */

		nf_ct_put(ct);
	}
}
EXPORT_SYMBOL_GPL(nf_ct_iterate_cleanup);

struct __nf_ct_flush_report {
	u32 pid;
	int report;
};

static int kill_all(struct nf_conn *i, void *data)
{
	struct __nf_ct_flush_report *fr = (struct __nf_ct_flush_report *)data;

	/* get_next_corpse sets the dying bit for us */
	nf_conntrack_event_report(IPCT_DESTROY,
				  i,
				  fr->pid,
				  fr->report);
	return 1;
}

void nf_ct_free_hashtable(void *hash, int vmalloced, unsigned int size)
{
	if (vmalloced)
		vfree(hash);
	else
		free_pages((unsigned long)hash,
			   get_order(sizeof(struct hlist_head) * size));
}
EXPORT_SYMBOL_GPL(nf_ct_free_hashtable);

void nf_conntrack_flush(struct net *net, u32 pid, int report)
{
	struct __nf_ct_flush_report fr = {
		.pid 	= pid,
		.report = report,
	};
	nf_ct_iterate_cleanup(net, kill_all, &fr);
}
EXPORT_SYMBOL_GPL(nf_conntrack_flush);

static void nf_conntrack_cleanup_init_net(void)
{
	nf_conntrack_helper_fini();
	nf_conntrack_proto_fini();
	kmem_cache_destroy(nf_conntrack_cachep);
}

static void nf_conntrack_cleanup_net(struct net *net)
{
	nf_ct_event_cache_flush(net);
	nf_conntrack_ecache_fini(net);
 i_see_dead_people:
	nf_conntrack_flush(net, 0, 0);
	if (atomic_read(&net->ct.count) != 0) {
		schedule();
		goto i_see_dead_people;
	}
	/* wait until all references to nf_conntrack_untracked are dropped */
	while (atomic_read(&nf_conntrack_untracked.ct_general.use) > 1)
		schedule();

	nf_ct_free_hashtable(net->ct.hash, net->ct.hash_vmalloc,
			     nf_conntrack_htable_size);
	nf_conntrack_acct_fini(net);
	nf_conntrack_expect_fini(net);
	free_percpu(net->ct.stat);
}

#if defined(CONFIG_RTL_NF_CONNTRACK_GARBAGE_NEW)


/* It's possible that no conntrack deleted due to large threshold value. 
     Perhaps we can try to dynamically reduce the threshold if nothing can be removed.
*/
static inline int __drop_one_udp(void){
	int i = 0;
	struct list_head *ptr;
	read_lock_bh(&nf_conntrack_lock);       
	for(i =0; i<sizeof(drop_priority)/sizeof(struct DROP_PRORITY); i++)
	{
		
		if(drop_priority[i].state <= TCP_CONNTRACK_MAX )	 //ramen--drop tcp conntrack				
			continue;
	 		
	 	ptr = Udp_State_Hash_Head[drop_priority[i].state-UDP_UNREPLY].state_hash; 		
 		if (!list_empty(ptr))
		{

			struct nf_conn* tmp=list_entry(ptr->next,struct nf_conn, state_tuple);

			del_timer(&tmp->timeout);
			death_by_timeout((unsigned long)tmp);
			read_unlock_bh(&nf_conntrack_lock);
			return 1;
		}
	  	
	}
	read_unlock_bh(&nf_conntrack_lock);
       return 0;
}


static inline int __drop_one_tcp(void){
	int i = 0;
	struct list_head *ptr;
	read_lock_bh(&nf_conntrack_lock);       
	for(i =0; i<sizeof(drop_priority)/sizeof(struct DROP_PRORITY); i++)
	{
		
		if(drop_priority[i].state >= TCP_CONNTRACK_MAX )	 //ramen--drop tcp conntrack				
			continue;
	 		
	 	ptr = Tcp_State_Hash_Head[drop_priority[i].state].state_hash;	
 		if (!list_empty(ptr))
		{
			struct nf_conn* tmp=list_entry(ptr->next,struct nf_conn, state_tuple);

			del_timer(&tmp->timeout);
			death_by_timeout((unsigned long)tmp);
			read_unlock_bh(&nf_conntrack_lock);
			return 1;
 		}

	}
	read_unlock_bh(&nf_conntrack_lock);
       return 0;
}

static inline int __drop_one_conntrack(int factor)
{
       //DEBUGP("enter the drop_one_tcp_conntrack.............\n");
	int i = 0;
	struct list_head *ptr;
	struct list_head* it;
	struct nf_conn* tmp;
	read_lock_bh(&nf_conntrack_lock);       
	for(i =0; i<sizeof(drop_priority)/sizeof(struct DROP_PRORITY); i++)
	{
		if(drop_priority[i].state < TCP_CONNTRACK_MAX )	 //ramen--drop tcp conntrack	
		{
			ptr = Tcp_State_Hash_Head[drop_priority[i].state].state_hash;
			if(!list_empty(ptr))	
			{				
				list_for_each(it, ptr) {
					tmp = list_entry(it, struct nf_conn, state_tuple);
					if (((((tmp->timeout.expires - jiffies)/HZ) >> factor)<=drop_priority[i].threshold )
						&&del_timer(&tmp->timeout)) 
					{
						#if defined(CONFIG_RTL_NF_CONNTRACK_GARBAGE_NEW_DEBUG)
						printk("%s %s(%d) Drop TCP %p\n", __FILE__,__FUNCTION__,__LINE__,tmp);
						#endif
						death_by_timeout((unsigned long)tmp);								
				       	read_unlock_bh(&nf_conntrack_lock);
						return 1;
					} else {
						// give up this list because it's sorted and we've seen the smallest that doesn't fit our criteria.
						break;
					}
				}
			}
			else
				continue;
		}
		else //ramen--drop udp conntrack
 		{
 			ptr = Udp_State_Hash_Head[drop_priority[i].state-UDP_UNREPLY].state_hash;	 	 
	 		if(!list_empty(ptr))
			{
				list_for_each(it, ptr) 
				{
					tmp = list_entry(it, struct nf_conn, state_tuple);
					if (((((tmp->timeout.expires - jiffies)/HZ) >> factor)<=drop_priority[i].threshold )
						&&del_timer(&tmp->timeout)) 
					{
						#if defined(CONFIG_RTL_NF_CONNTRACK_GARBAGE_NEW_DEBUG)
						printk("%s %s(%d) Drop UDP %p\n", __FILE__,__FUNCTION__,__LINE__,tmp);
						#endif
						death_by_timeout((unsigned long)tmp);					
			       		read_unlock_bh(&nf_conntrack_lock);
						return 1;
					} else {
						// give up this list because it's sorted and we've seen the smallest that doesn't fit our criteria.
						break;
					}				
				}	
 			}
			else
				continue;
		}
	} 		
	read_unlock_bh(&nf_conntrack_lock);
       return 0;
}


int drop_one_conntrack(void) {
	if ((atomic_read(&_prot_limit[PROT_TCP]) < atomic_read(&prot_counters[PROT_TCP])) && __drop_one_tcp()) {
		return 1;
	}

	if ((atomic_read(&_prot_limit[PROT_UDP]) < atomic_read(&prot_counters[PROT_UDP])) && __drop_one_udp()) {
		return 1;
	}
	if ( __drop_one_conntrack(0) || 
	     __drop_one_conntrack(1) ||
	     __drop_one_conntrack(31))
		return 1;
	else
		return 0;		
}

#endif


/* Mishearing the voices in his head, our hero wonders how he's
   supposed to kill the mall. */
void nf_conntrack_cleanup(struct net *net)
{
	if (net_eq(net, &init_net))
		rcu_assign_pointer(ip_ct_attach, NULL);

	/* This makes sure all current packets have passed through
	   netfilter framework.  Roll on, two-stage module
	   delete... */
	synchronize_net();

	nf_conntrack_cleanup_net(net);

	if (net_eq(net, &init_net)) {
		rcu_assign_pointer(nf_ct_destroy, NULL);
		nf_conntrack_cleanup_init_net();
	}
}

void *nf_ct_alloc_hashtable(unsigned int *sizep, int *vmalloced, int nulls)
{
	struct hlist_nulls_head *hash;
	unsigned int nr_slots, i;
	size_t sz;

	*vmalloced = 0;

	BUILD_BUG_ON(sizeof(struct hlist_nulls_head) != sizeof(struct hlist_head));
	nr_slots = *sizep = roundup(*sizep, PAGE_SIZE / sizeof(struct hlist_nulls_head));
	sz = nr_slots * sizeof(struct hlist_nulls_head);
	hash = (void *)__get_free_pages(GFP_KERNEL | __GFP_NOWARN | __GFP_ZERO,
					get_order(sz));
	if (!hash) {
		*vmalloced = 1;
		printk(KERN_WARNING "nf_conntrack: falling back to vmalloc.\n");
		hash = __vmalloc(sz, GFP_KERNEL | __GFP_ZERO, PAGE_KERNEL);
	}

	if (hash && nulls)
		for (i = 0; i < nr_slots; i++)
			INIT_HLIST_NULLS_HEAD(&hash[i], i);

	return hash;
}
EXPORT_SYMBOL_GPL(nf_ct_alloc_hashtable);

int nf_conntrack_set_hashsize(const char *val, struct kernel_param *kp)
{
	int i, bucket, vmalloced, old_vmalloced;
	unsigned int hashsize, old_size;
	int rnd;
	struct hlist_nulls_head *hash, *old_hash;
	struct nf_conntrack_tuple_hash *h;

	/* On boot, we can set this without any fancy locking. */
	if (!nf_conntrack_htable_size)
		return param_set_uint(val, kp);

	hashsize = simple_strtoul(val, NULL, 0);
	if (!hashsize)
		return -EINVAL;

	hash = nf_ct_alloc_hashtable(&hashsize, &vmalloced, 1);
	if (!hash)
		return -ENOMEM;

	/* We have to rehahs for the new table anyway, so we also can
	 * use a newrandom seed */
	get_random_bytes(&rnd, sizeof(rnd));

	/* Lookups in the old hash might happen in parallel, which means we
	 * might get false negatives during connection lookup. New connections
	 * created because of a false negative won't make it into the hash
	 * though since that required taking the lock.
	 */
	spin_lock_bh(&nf_conntrack_lock);
	for (i = 0; i < nf_conntrack_htable_size; i++) {
		while (!hlist_nulls_empty(&init_net.ct.hash[i])) {
			h = hlist_nulls_entry(init_net.ct.hash[i].first,
					struct nf_conntrack_tuple_hash, hnnode);
			hlist_nulls_del_rcu(&h->hnnode);
			bucket = __hash_conntrack(&h->tuple, hashsize, rnd);
			hlist_nulls_add_head_rcu(&h->hnnode, &hash[bucket]);
		}
	}
	old_size = nf_conntrack_htable_size;
	old_vmalloced = init_net.ct.hash_vmalloc;
	old_hash = init_net.ct.hash;

	nf_conntrack_htable_size = hashsize;
	init_net.ct.hash_vmalloc = vmalloced;
	init_net.ct.hash = hash;
	nf_conntrack_hash_rnd = rnd;
	spin_unlock_bh(&nf_conntrack_lock);

	nf_ct_free_hashtable(old_hash, old_vmalloced, old_size);
	return 0;
}
EXPORT_SYMBOL_GPL(nf_conntrack_set_hashsize);

module_param_call(hashsize, nf_conntrack_set_hashsize, param_get_uint,
		  &nf_conntrack_htable_size, 0600);

#if defined(CONFIG_RTL_IPTABLES_FAST_PATH)
static void tcp_patten_ck_fn(unsigned long arg)
{	
	smart_count = 0;
      	mod_timer(&tcp_patten_ck, jiffies + 100);
}
#endif


static int nf_conntrack_init_init_net(void)
{
	int max_factor = 8;
	int ret;

	/* Idea from tcp.c: use 1/16384 of memory.  On i386: 32MB
	 * machine has 512 buckets. >= 1GB machines have 16384 buckets. */
	if (!nf_conntrack_htable_size) {
		nf_conntrack_htable_size
			= (((num_physpages << PAGE_SHIFT) / 16384)
			   / sizeof(struct hlist_head));
		if (num_physpages > (1024 * 1024 * 1024 / PAGE_SIZE))
			nf_conntrack_htable_size = 16384;
		if (nf_conntrack_htable_size < 32)
			nf_conntrack_htable_size = 32;

		/* Use a max. factor of four by default to get the same max as
		 * with the old struct list_heads. When a table size is given
		 * we use the old value of 8 to avoid reducing the max.
		 * entries. */
		max_factor = 4;
	}
	nf_conntrack_max = max_factor * nf_conntrack_htable_size;

	printk("nf_conntrack version %s (%u buckets, %d max)\n",
	       NF_CONNTRACK_VERSION, nf_conntrack_htable_size,
	       nf_conntrack_max);

	nf_conntrack_cachep = kmem_cache_create("nf_conntrack",
						sizeof(struct nf_conn),
						0, SLAB_DESTROY_BY_RCU, NULL);
	if (!nf_conntrack_cachep) {
		printk(KERN_ERR "Unable to create nf_conn slab cache\n");
		ret = -ENOMEM;
		goto err_cache;
	}

	ret = nf_conntrack_proto_init();
	if (ret < 0)
		goto err_proto;

	ret = nf_conntrack_helper_init();
	if (ret < 0)
		goto err_helper;

#if defined(CONFIG_RTL_NF_CONNTRACK_GARBAGE_NEW)
	init_tcp_state_hash();
	//proc_net_create ("conntrack_proto", 0, getinfo_conntrack_proto);
	prot_limit[PROT_ICMP] = 1;
	prot_limit[PROT_TCP] = 94;
	prot_limit[PROT_UDP] = 5;
	recalculate();
#endif


#if defined(CONFIG_RTL_IPTABLES_FAST_PATH)
	init_timer(&tcp_patten_ck);
      tcp_patten_ck.expires  = jiffies + 100;
      tcp_patten_ck.data     = 0L;
      tcp_patten_ck.function = tcp_patten_ck_fn;
      mod_timer(&tcp_patten_ck, jiffies + 100);
#endif

	return 0;

err_helper:
	nf_conntrack_proto_fini();
err_proto:
	kmem_cache_destroy(nf_conntrack_cachep);
err_cache:
	return ret;
}

static int nf_conntrack_init_net(struct net *net)
{
	int ret;

	atomic_set(&net->ct.count, 0);
	INIT_HLIST_NULLS_HEAD(&net->ct.unconfirmed, 0);
	net->ct.stat = alloc_percpu(struct ip_conntrack_stat);
	if (!net->ct.stat) {
		ret = -ENOMEM;
		goto err_stat;
	}
	ret = nf_conntrack_ecache_init(net);
	if (ret < 0)
		goto err_ecache;
	net->ct.hash = nf_ct_alloc_hashtable(&nf_conntrack_htable_size,
					     &net->ct.hash_vmalloc, 1);
	if (!net->ct.hash) {
		ret = -ENOMEM;
		printk(KERN_ERR "Unable to create nf_conntrack_hash\n");
		goto err_hash;
	}
	ret = nf_conntrack_expect_init(net);
	if (ret < 0)
		goto err_expect;
	ret = nf_conntrack_acct_init(net);
	if (ret < 0)
		goto err_acct;

	/* Set up fake conntrack:
	    - to never be deleted, not in any hashes */
#ifdef CONFIG_NET_NS
	nf_conntrack_untracked.ct_net = &init_net;
#endif
	atomic_set(&nf_conntrack_untracked.ct_general.use, 1);
	/*  - and look it like as a confirmed connection */
	set_bit(IPS_CONFIRMED_BIT, &nf_conntrack_untracked.status);

	return 0;

err_acct:
	nf_conntrack_expect_fini(net);
err_expect:
	nf_ct_free_hashtable(net->ct.hash, net->ct.hash_vmalloc,
			     nf_conntrack_htable_size);
err_hash:
	nf_conntrack_ecache_fini(net);
err_ecache:
	free_percpu(net->ct.stat);
err_stat:
	return ret;
}

int nf_conntrack_init(struct net *net)
{
	int ret;

	if (net_eq(net, &init_net)) {
		ret = nf_conntrack_init_init_net();
		if (ret < 0)
			goto out_init_net;
	}
	ret = nf_conntrack_init_net(net);
	if (ret < 0)
		goto out_net;

	if (net_eq(net, &init_net)) {
		/* For use by REJECT target */
		rcu_assign_pointer(ip_ct_attach, nf_conntrack_attach);
		rcu_assign_pointer(nf_ct_destroy, destroy_conntrack);
	}
	return 0;

out_net:
	if (net_eq(net, &init_net))
		nf_conntrack_cleanup_init_net();
out_init_net:
	return ret;
}
