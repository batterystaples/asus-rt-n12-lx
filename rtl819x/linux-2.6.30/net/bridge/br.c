/*
 *	Generic parts
 *	Linux ethernet bridge
 *
 *	Authors:
 *	Lennert Buytenhek		<buytenh@gnu.org>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/init.h>
#include <linux/llc.h>
#include <net/llc.h>
#include <net/stp.h>

#include "br_private.h"

#include <linux/proc_fs.h>
#if defined (CONFIG_RTL865X_LANPORT_RESTRICTION)
#include "lan_restrict.h"
#endif
#if defined(CONFIG_DOMAIN_NAME_QUERY_SUPPORT)
extern int __init br_filter_init(void);
extern void __exit br_filter_exit(void);
#endif

#if defined (CONFIG_RTL_IGMP_SNOOPING)
#include <linux/inetdevice.h>
#include <net/rtl/rtl865x_igmpsnooping_glue.h>
#include <net/rtl/rtl865x_igmpsnooping.h>
#include <net/rtl/rtl865x_multicast.h>
#include <net/rtl/rtl865x_netif.h>
#include <net/rtl/rtl_nic.h>
#endif
int IGMPProxyOpened = 0;

int (*br_should_route_hook)(struct sk_buff *skb);

static const struct stp_proto br_stp_proto = {
	.rcv	= br_stp_rcv,
};

static struct pernet_operations br_net_ops = {
	.exit	= br_net_exit,
};

//it's for host-slave hostapd EAP hack 
#ifdef CONFIG_RTL_EAP_RELAY
struct proc_dir_entry *procHostMac=NULL;
unsigned char inband_Hostmac[6]={0x00,0xE0,0x4C,0x81,0x96,0xC1}; 

static int br_hostmac_read_proc(char *page, char **start, off_t off, 
		int count, int *eof, void *data)
{

      int len;

      len = sprintf(page, "%x:%x:%x:%x:%x:%x\n", inband_Hostmac[0],inband_Hostmac[1]
	  										, inband_Hostmac[2],inband_Hostmac[3]
	  										, inband_Hostmac[4],inband_Hostmac[5]);


      if (len <= off+count) *eof = 1;
      *start = page + off;
      len -= off;
      if (len>count) len = count;
      if (len<0) len = 0;
      return len;

}

static int br_hostmac_write_proc(struct file *file, const char *buffer,
		      unsigned long count, void *data)
{
      char br_tmp[48]; 
       int mac[6];		  
	
      if (count < 2) 
	    return -EFAULT;

	
      if (buffer && !copy_from_user(&br_tmp, buffer, 48)) {
	  	int num=0;	
		int i=0;
             num = sscanf(br_tmp, "%d:%d:%d:%d:%d:%d",&mac[0],&mac[1]
	  										, &mac[2],&mac[3]
	  										, &mac[4],&mac[5]);
            
		for(i=0;i<6;i++)
			inband_Hostmac[i] = (unsigned char)(mac[i] & 0x000000ff);	  	 
            
                if (num !=  6) {
                        printk("br_hostmac_write_proc invalid vlan parameter!\n");
                }
	    return count;
      }
      return -EFAULT;
}
#endif

#if defined(CONFIG_RTL_WLAN_BLOCK_RELAY)
int rtl_wlan_block_relay_enable=0;
struct proc_dir_entry *procwlanblockrelay=NULL;
static int br_wlanblockread_proc(char *page, char **start, off_t off, 
		int count, int *eof, void *data)
{
	int len;
	len = sprintf(page, "wlanblock:%c\n\n",rtl_wlan_block_relay_enable+'0');
	if (len <= off+count) *eof = 1;
      *start = page + off;
      len -= off;
      if (len>count) len = count;
      if (len<0) len = 0;
      return len;
}
static int br_wlanblockwrite_proc(struct file *file, const char *buffer,
		      unsigned long count, void *data)
{
      unsigned char block_tmp; 
      if (count < 2) 
	    return -EFAULT;
      
	if (buffer && !copy_from_user(&block_tmp, buffer, 1)) {
		rtl_wlan_block_relay_enable = block_tmp - '0';
		if(rtl_wlan_block_relay_enable)
		{
			rtl_wlan_block_relay_enable=1;
		}
		else
			rtl_wlan_block_relay_enable=0;	
	    	return count;
      }
	return -EFAULT;
}
#endif
#if defined (CONFIG_RTL_IGMP_SNOOPING)

struct proc_dir_entry *procigmp=NULL;
int igmpsnoopenabled=0;	// Should be 0(default), set 1 when igmpproxy up!
extern struct net_bridge *bridge0;

struct proc_dir_entry *procMCastFastFwd=NULL;
int ipMulticastFastFwd=0;
int needCheckMfc=0;
static int br_igmpread_proc(char *page, char **start, off_t off, 
		int count, int *eof, void *data)
{

      int len;
      int i,j,k;
   
    len = sprintf(page, "igmpsnoopenabled:%c\n\n", igmpsnoopenabled + '0');
    len += sprintf(page+len, "bridge multicast fdb:\n");


	for (i = 0; i < BR_HASH_SIZE; i++) {
		struct net_bridge_fdb_entry *f;
		struct hlist_node *h, *n;
		
		j=0;
		hlist_for_each_entry_safe(f, h, n, &bridge0->hash[i], hlist) {
			if(MULTICAST_MAC(f->addr.addr) )
			{
				  len += sprintf(page+len,"[%d][%d]mCastMac:0x%x:%x:%x:%x:%x:%x,use_count is %d,ageing_timer is %lu\n",
					i,j,f->addr.addr[0],f->addr.addr[1],f->addr.addr[2],f->addr.addr[3],f->addr.addr[4],f->addr.addr[5],f->use_count,(jiffies<f->ageing_timer) ?0:(jiffies-f->ageing_timer));
				
				for(k=0;k<FDB_IGMP_EXT_NUM;k++)
				{
					if(f->igmp_fdb_arr[k].valid)
					{
						len += sprintf(page+len,"\t<%d>clientMac:0x%x:%x:%x:%x:%x:%x,ageing_time:%lu\n",
						k,f->igmp_fdb_arr[k].SrcMac[0],f->igmp_fdb_arr[k].SrcMac[1],f->igmp_fdb_arr[k].SrcMac[2],f->igmp_fdb_arr[k].SrcMac[3],f->igmp_fdb_arr[k].SrcMac[4],f->igmp_fdb_arr[k].SrcMac[5],(jiffies<f->igmp_fdb_arr[k].ageing_time) ?0:(jiffies-f->igmp_fdb_arr[k].ageing_time));
					}
				}

				j++;
				len += sprintf(page+len,"--------------------------------------------\n");
			}

		}
		
	}

	
      if (len <= off+count) *eof = 1;
      *start = page + off;
      len -= off;
      if (len>count) len = count;
      if (len<0) len = 0;
      return len;

}

static int br_igmpwrite_proc(struct file *file, const char *buffer,
		      unsigned long count, void *data)
{
      unsigned char br_tmp; 
      if (count < 2) 
	    return -EFAULT;
      
	if (buffer && !copy_from_user(&br_tmp, buffer, 1)) {
		igmpsnoopenabled = br_tmp - '0';
		if(igmpsnoopenabled)
		{
			igmpsnoopenabled=1;
		}
		else
		{
#if defined (CONFIG_RTL_HARDWARE_MULTICAST)		
			rtl865x_reinitMulticast();
#endif
			rtl_flushAllIgmpRecord();
		}
	    return count;
      }
      return -EFAULT;
}

static int br_mCastFastFwdRead_proc(char *page, char **start, off_t off, 
		int count, int *eof, void *data)
{

      int len;

      len = sprintf(page, "%c,%c\n", ipMulticastFastFwd + '0',needCheckMfc + '0');


      if (len <= off+count) *eof = 1;
      *start = page + off;
      len -= off;
      if (len>count) len = count;
      if (len<0) len = 0;
      return len;

}

static int br_mCastFastFwdWrite_proc(struct file *file, const char *buffer,
		      unsigned long count, void *data)
{
	unsigned int tmp=0; 
	char 		tmpbuf[512];
	char		*strptr;
	char		*tokptr;
	

	if (count < 2) 
		return -EFAULT;

	if (buffer && !copy_from_user(tmpbuf, buffer, count)) 
	{
		tmpbuf[count] = '\0';

		strptr=tmpbuf;

		
		tokptr = strsep(&strptr,",");
		if (tokptr==NULL)
		{
			tmp=simple_strtol(strptr, NULL, 0);
			printk("tmp=%d\n",tmp);
			if(tmp==0)
			{
				ipMulticastFastFwd=0;
			}
			return -EFAULT;
		}
		
		ipMulticastFastFwd = simple_strtol(tokptr, NULL, 0);
		//printk("ipMulticastFastFwd=%d\n",ipMulticastFastFwd);
		if(ipMulticastFastFwd)
		{
			ipMulticastFastFwd=1;
		}

		tokptr = strsep(&strptr,",");
		if (tokptr==NULL)
		{
			return -EFAULT;
		}
		
		needCheckMfc = simple_strtol(tokptr, NULL, 0);

		if(needCheckMfc)
		{
			needCheckMfc=1;
		}

		return count;
	}
	return -EFAULT;
}

struct proc_dir_entry *procIgmpQuery=NULL;
int igmpQueryEnabled=0;	
static int br_igmpQueryRead_proc(char *page, char **start, off_t off, 
		int count, int *eof, void *data)
{

      int len;

      len = sprintf(page, "%c\n", igmpQueryEnabled + '0');


      if (len <= off+count) *eof = 1;
      *start = page + off;
      len -= off;
      if (len>count) len = count;
      if (len<0) len = 0;
      return len;

}

static int br_igmpQueryWrite_proc(struct file *file, const char *buffer,
		      unsigned long count, void *data)
{
      unsigned char tmp; 
      if (count < 2) 
	    return -EFAULT;
      
	if (buffer && !copy_from_user(&tmp, buffer, 1)) {
		igmpQueryEnabled = tmp - '0';
		if(igmpQueryEnabled)
		{
			igmpQueryEnabled=1;
		}
		else
		{
			igmpQueryEnabled=0;
		}
	    return count;
      }
      return -EFAULT;
}

#if defined(CONFIG_BR_IGMP_V3_QUERY)
/*igmpv3 general query*/
static unsigned char igmpQueryBuf[64]={	0x01,0x00,0x5e,0x00,0x00,0x01,		/*destination mac*/
									0x00,0x00,0x00,0x00,0x00,0x00,		/*offset:6*/
									0x08,0x00,						/*offset:12*/
									0x46,0x00,0x00,0x24,				/*offset:14*/
									0x00,0x00,0x40,0x00,				/*offset:18*/
									0x01,0x02,0x00,0x00,				/*offset:22*/
									0x00,0x00,0x00,0x00,				/*offset:26,source ip*/
									0xe0,0x00,0x00,0x01,				/*offset:30,destination ip*/
									0x94,0x04,0x00,0x00,				/*offset:34,router alert option*/
									0x11,0x01,0x00,0x00,				/*offset:38*/
									0x00,0x00,0x00,0x00,				/*offset:42,queried multicast ip address*/
									0x0a,0x3c,0x00,0x00,				/*offset:46*/
									0x00,0x00,0x00,0x00,				/*offset:50*/
									0x00,0x00,0x00,0x00,				/*offset:54*/
									0x00,0x00,0x00,0x00,				/*offset:58*/
									0x00,0x00							/*offset:62*/
									
								};			


#else
/*igmpv2 general query*/
static unsigned char igmpQueryBuf[64]={	0x01,0x00,0x5e,0x00,0x00,0x01,		/*destination mac*/
									0x00,0x00,0x00,0x00,0x00,0x00,		/*offset:6*/
									0x08,0x00,						/*offset:12*/
									0x45,0x00,0x00,0x1c,				/*offset:14*/
									0x00,0x00,0x40,0x00,				/*offset:18*/
									0x01,0x02,0x00,0x00,				/*offset:22*/
									0x00,0x00,0x00,0x00,				/*offset:26*/
									0xe0,0x00,0x00,0x01,				/*offset:30*/
									0x11,0x01,0x0c,0xfa,				/*offset:34*/
									0x00,0x00,0x00,0x00,				/*offset:38*/
									0x00,0x00,0x00,0x00,				/*offset:42*/
									0x00,0x00,0x00,0x00,				/*offset:46*/
									0x00,0x00,0x00,0x00,				/*offset:50*/
									0x00,0x00,0x00,0x00,				/*offset:54*/
									0x00,0x00,0x00,0x00,				/*offset:58*/
									0x00,0x00							/*offset:62*/
									
								};			

#endif

static unsigned short  br_ipv4Checksum(unsigned char *pktBuf, unsigned int pktLen)
{
	/*note: the first bytes of  packetBuf should be two bytes aligned*/
	unsigned int  checksum=0;
	unsigned int  count=pktLen;
	unsigned short   *ptr= (unsigned short *)pktBuf;	
	
	 while(count>1)
	 {
		  checksum+= ntohs(*ptr);
		  ptr++;
		  count -= 2;
	 }
	 
	if(count>0)
	{
		checksum+= *(pktBuf+pktLen-1)<<8; /*the last odd byte is treated as bit 15~8 of unsigned short*/
	}

	/* Roll over carry bits */
	checksum = (checksum >> 16) + (checksum & 0xffff);
	checksum += (checksum >> 16);

	/* Return checksum */
	return ((unsigned short) ~ checksum);

}

static unsigned char* br_generateIgmpQuery(struct net_bridge * br)
{
	struct net_device* brDev = NULL;
	unsigned short checkSum=0;
	struct in_device *in_dev;	
	struct net_device *landev;
	struct in_ifaddr *ifap = NULL;
	
      
	if(br==NULL)
	{
		return NULL;
	}
	
	brDev = br->dev;
	
	memcpy(&igmpQueryBuf[6],brDev->dev_addr,6);			/*set source mac address*/
	
	/*set source ip address*/
	if ((landev = __dev_get_by_name(&init_net, RTL_PS_BR0_DEV_NAME)) != NULL){
		in_dev=(struct net_device *)(landev->ip_ptr);
		if (in_dev != NULL) {
			for (ifap=in_dev->ifa_list; ifap != NULL; ifap=ifap->ifa_next) {
				if (strcmp(RTL_PS_BR0_DEV_NAME, ifap->ifa_label) == 0){
					memcpy(&igmpQueryBuf[26],&ifap->ifa_address,4);
				}
			}
			
		}
	}
	else
	{
		return NULL;
	}
	
	igmpQueryBuf[24]=0;
	igmpQueryBuf[25]=0;
	#if defined (CONFIG_BR_IGMP_V3_QUERY)
	checkSum=br_ipv4Checksum(&igmpQueryBuf[14],24);
	#else
	checkSum=br_ipv4Checksum(&igmpQueryBuf[14],20);
	#endif
	igmpQueryBuf[24]=(checkSum&0xff00)>>8;
	igmpQueryBuf[25]=(checkSum&0x00ff);

	#if defined (CONFIG_BR_IGMP_V3_QUERY)
	igmpQueryBuf[40]=0;
	igmpQueryBuf[41]=0;
	checkSum=br_ipv4Checksum(&igmpQueryBuf[38],12);
	igmpQueryBuf[40]=(checkSum&0xff00)>>8;
	igmpQueryBuf[41]=(checkSum&0x00ff);
	#else
	igmpQueryBuf[36]=0;
	igmpQueryBuf[37]=0;
	checkSum=br_ipv4Checksum(&igmpQueryBuf[34],8);
	igmpQueryBuf[36]=(checkSum&0xff00)>>8;
	igmpQueryBuf[37]=(checkSum&0x00ff);
	#endif
	
	return igmpQueryBuf;
	
	
}


void br_igmpQueryTimerExpired(unsigned long arg)
{
	struct net_bridge *br = (struct net_bridge*) arg;
	unsigned char *igmpBuf=NULL;
	struct sk_buff *skb;
	struct sk_buff *skb2;
	struct net_bridge_port *p, *n;
	struct net_bridge_port *prev;
	unsigned int fwdCnt=0;

	if(IGMPProxyOpened)
	{
		return ;
	}
	
	if(igmpQueryEnabled==0)
	{
		return;
	}

	
	
	skb=dev_alloc_skb(1024);
	if(skb==NULL)
	{
		return;
	}

	memset(skb->data,64,0);
	igmpBuf=br_generateIgmpQuery(br);
	if(igmpBuf==NULL)
	{
		return;
	}

	memcpy(skb->data,igmpBuf,64);

	skb->len = 0;
	#if defined (CONFIG_BR_IGMP_V3_QUERY)
	skb_put(skb, 50);
	#else
	skb_put(skb, 42);
	#endif
	skb->dev=br->dev;
	
	prev = NULL;
	fwdCnt=0;
	list_for_each_entry_safe(p, n, &br->port_list, list) 
	{ 
		if ((p->state == BR_STATE_FORWARDING) && (strncmp(p->dev->name, "peth",4)!=0) && (strncmp(p->dev->name, "pwlan",5)!=0)) 
		{
			if (prev != NULL) 
			{                                                                                       
				if ((skb2 = skb_clone(skb, GFP_ATOMIC)) == NULL) 
				{
					br->dev->stats.tx_dropped++;
					kfree_skb(skb);
					return 0;
				} 
				skb2->dev=prev->dev;
				#if defined(CONFIG_COMPAT_NET_DEV_OPS)
				prev->dev->hard_start_xmit(skb2, prev->dev);
				#else
				prev->dev->netdev_ops->ndo_start_xmit(skb2,prev->dev);
				#endif                  
				fwdCnt++;
			}
				                                                                               
			prev = p;
		}
	}

	if (prev != NULL) 
	{
		skb->dev=prev->dev;
	       #if defined(CONFIG_COMPAT_NET_DEV_OPS)
		prev->dev->hard_start_xmit(skb, prev->dev);
		#else
		prev->dev->netdev_ops->ndo_start_xmit(skb,prev->dev);
		#endif                            
		fwdCnt++;
	}

	if(fwdCnt==0)
	{
		/*to avoid memory leak*/
		kfree_skb(skb);
	}
	return;
}


#if defined (CONFIG_RTL_MLD_SNOOPING)
struct proc_dir_entry *procMldQuery=NULL;
int mldQueryEnabled=0;	
static int br_mldQueryRead_proc(char *page, char **start, off_t off, 
		int count, int *eof, void *data)
{

      int len;

      len = sprintf(page, "%c\n", mldQueryEnabled + '0');


      if (len <= off+count) *eof = 1;
      *start = page + off;
      len -= off;
      if (len>count) len = count;
      if (len<0) len = 0;
      return len;

}

static int br_mldQueryWrite_proc(struct file *file, const char *buffer,
		      unsigned long count, void *data)
{
      unsigned char tmp; 
      if (count < 2) 
	    return -EFAULT;
      
	if (buffer && !copy_from_user(&tmp, buffer, 1)) {
		mldQueryEnabled = tmp - '0';
		if(mldQueryEnabled)
		{
			mldQueryEnabled=1;
		}
		else
		{
			mldQueryEnabled=0;
		}
	    return count;
      }
      return -EFAULT;
}

static unsigned char mldQueryBuf[86]={	0x33,0x33,0x00,0x00,0x00,0x01,		/*destination mac*/
									0x00,0x00,0x00,0x00,0x00,0x00,		/*source mac*/	/*offset:6*/
									0x86,0xdd,						/*ether type*/	/*offset:12*/
									0x60,0x00,0x00,0x00,				/*version(1 byte)-traffic cliass(1 byte)- flow label(2 bytes)*/	/*offset:14*/
									0x00,0x20,0x00,0x01,				/*payload length(2 bytes)-next header(1 byte)-hop limit(value:1 1byte)*//*offset:18*/
									0xfe,0x80,0x00,0x00,				/*source address*/	/*offset:22*/
									0x00,0x00,0x00,0x00,				/*be zero*/	/*offset:26*/
									0x00,0x00,0x00,					/*upper 3 bytes mac address |0x02*/ /*offset:30*/
									0xff,0xfe,						/*fixed*/
									0x00,0x00,0x00,					/*lowert 3 bytes mac address*/	 /*offset:35*/
									0xff,0x02,0x00,0x00,				/*destination address is fixed as FF02::1*/	/*offset:38*/
									0x00,0x00,0x00,0x00,			
									0x00,0x00,0x00,0x00,			
									0x00,0x00,0x00,0x01,			
									0x3a,0x00,						/*icmp type(1 byte)-length(1 byte)*/	 /*offset:54*/
									0x05,0x02,0x00,0x00,				/*router alert option*/
									0x01,0x00,						/*padN*/
									0x82,0x00,						/*type(query:0x82)-code(0)*/	/*offset:62*/
									0x00,0x00,						/*checksum*/	/*offset:64*/
									0x00,0x0a,						/*maximum reponse code*/
									0x00,0x00,						/*reserved*/
									0x00,0x00,0x00,0x00,				/*multicast address,fixed as 0*/
									0x00,0x00,0x00,0x00,			
									0x00,0x00,0x00,0x00,			
									0x00,0x00,0x00,0x00
								};			

static unsigned char ipv6PseudoHdrBuf[40]=	{	
									0xfe,0x80,0x00,0x00,				/*source address*/
									0x00,0x00,0x00,0x00,			
									0x00,0x00,0x00,0xff,			
									0xfe,0x00,0x00,0x00,			 	
									0xff,0x02,0x00,0x00,				/*destination address*/
									0x00,0x00,0x00,0x00,		
									0x00,0x00,0x00,0x00,			
									0x00,0x00,0x00,0x01,				
									0x00,0x00,0x00,0x18,				/*upper layer packet length*/
									0x00,0x00,0x00,0x3a					/*zero padding(3 bytes)-next header(1 byte)*/
									};		

static unsigned short br_ipv6Checksum(unsigned char *pktBuf, unsigned int pktLen, unsigned char  *ipv6PseudoHdrBuf)
{
	unsigned int  checksum=0;
	unsigned int count=pktLen;
	unsigned short   *ptr;

	/*compute ipv6 pseudo-header checksum*/
	ptr= (unsigned short  *) (ipv6PseudoHdrBuf);	
	for(count=0; count<20; count++) /*the pseudo header is 40 bytes long*/
	{
		  checksum+= ntohs(*ptr);
		  ptr++;
	}
	
	/*compute the checksum of mld buffer*/
	 count=pktLen;
	 ptr=(unsigned short  *) (pktBuf);	
	 while(count>1)
	 {
		  checksum+= ntohs(*ptr);
		  ptr++;
		  count -= 2;
	 }
	 
	if(count>0)
	{
		checksum+= *(pktBuf+pktLen-1)<<8; /*the last odd byte is treated as bit 15~8 of unsigned short*/
	}

	/* Roll over carry bits */
	checksum = (checksum >> 16) + (checksum & 0xffff);
	checksum += (checksum >> 16);

	/* Return checksum */
	return ((uint16) ~ checksum);
	
}
static unsigned char* br_generateMldQuery(struct net_bridge * br)
{
	struct net_device* brDev = NULL;
	unsigned short checkSum=0;
	if(br==NULL)
	{
		return NULL;
	}
	
	brDev = br->dev;
	
	memcpy(&mldQueryBuf[6],brDev->dev_addr,6);			/*set source mac address*/
	
	memcpy(&mldQueryBuf[30],brDev->dev_addr,3);		/*set  mld query packet source ip address*/
	mldQueryBuf[30]=mldQueryBuf[30]|0x02;		
	memcpy(&mldQueryBuf[35],&brDev->dev_addr[3],3);		

	
	memcpy(ipv6PseudoHdrBuf,&mldQueryBuf[22],16);			/*set pseudo-header source ip*/

	mldQueryBuf[64]=0;/*reset checksum*/
	mldQueryBuf[65]=0;
	checkSum=br_ipv6Checksum(&mldQueryBuf[62],24,ipv6PseudoHdrBuf);
	
	mldQueryBuf[64]=(checkSum&0xff00)>>8;
	mldQueryBuf[65]=(checkSum&0x00ff);
	return mldQueryBuf;
	
	
}


void br_mldQueryTimerExpired(unsigned long arg)
{
	struct net_bridge *br = (struct net_bridge*) arg;
	struct sk_buff *skb;
	struct sk_buff *skb2;
	struct net_bridge_port *p, *n;
	struct net_bridge_port *prev;
	unsigned int fwdCnt=0;
	unsigned char *mldBuf=NULL;

	if(mldQueryEnabled==0)
	{
		return;
	}
	
	skb=dev_alloc_skb(1024);
	if(skb==NULL)
	{
		return;
	}
	
	memset(skb->data,86,0);
	mldBuf=br_generateMldQuery(br);
	if(mldBuf==NULL)
	{
		return;
	}
	
	memcpy(skb->data,mldBuf,86);
	skb->len = 0;
	skb_put(skb, 86);
 
	prev = NULL;
	fwdCnt=0;
	list_for_each_entry_safe(p, n, &br->port_list, list) 
	{ 
		if ((p->state == BR_STATE_FORWARDING) && (strncmp(p->dev->name, "peth",4)!=0) && (strncmp(p->dev->name, "pwlan",5)!=0)) 
		{
			if (prev != NULL) 
			{                                                                                       
				if ((skb2 = skb_clone(skb, GFP_ATOMIC)) == NULL) 
				{
					br->dev->stats.tx_dropped++;
					kfree_skb(skb);
					return 0;
				} 
				skb2->dev=prev->dev;
				#if defined(CONFIG_COMPAT_NET_DEV_OPS)
				prev->dev->hard_start_xmit(skb2, prev->dev);
				#else
				prev->dev->netdev_ops->ndo_start_xmit(skb2,prev->dev);
				#endif                  
				fwdCnt++;
			}
				                                                                               
			prev = p;
		}
	}

	if (prev != NULL) 
	{
		skb->dev=prev->dev;
	       #if defined(CONFIG_COMPAT_NET_DEV_OPS)
		prev->dev->hard_start_xmit(skb, prev->dev);
		#else
		prev->dev->netdev_ops->ndo_start_xmit(skb,prev->dev);
		#endif                            
		fwdCnt++;
	}

	if(fwdCnt==0)
	{
		/*to avoid memory leak*/
		kfree_skb(skb);
	}
	
	return;
}
#endif

static unsigned int mCastQueryTimerCnt=0;
void br_mCastQueryTimerExpired(unsigned long arg)
{
	struct net_bridge *br = (struct net_bridge*) arg;
	
	mod_timer(&br->mCastQuerytimer, jiffies+MCAST_QUERY_INTERVAL*HZ);
	
	if(mCastQueryTimerCnt%2==0)
	{
		br_igmpQueryTimerExpired(arg);
	}
	else
	{
		#if defined (CONFIG_RTL_MLD_SNOOPING)
		br_mldQueryTimerExpired(arg);
		#endif
	}
	mCastQueryTimerCnt++;
	
	return;
}

extern struct net_bridge *find_br_by_name(char *name);

void br_signal_igmpProxy(void)
{

	struct task_struct *task;
	struct net_bridge *br;

	br = find_br_by_name(RTL_PS_BR0_DEV_NAME);
	if(br==NULL)
	{
		return;
	}

	if(br->igmpProxy_pid==0)
	{
		return;
	}
	
	read_lock(&tasklist_lock);
//	task = find_task_by_pid(br->igmpProxy_pid);
	task = find_task_by_vpid(br->igmpProxy_pid);
	read_unlock(&tasklist_lock);
	if(task)
	{
		send_sig(SIGUSR2,task,0);
	}
	else {
	    //printk("Path selection daemon pid: %d does not exist\n", br->mesh_pathsel_pid);
	}
}

#endif

struct proc_dir_entry *procIgmpProxy = NULL;
static int br_igmpProxyRead_proc(char *page, char **start, off_t off, 
		int count, int *eof, void *data)
{
      int len;
      len = sprintf(page, "%c\n", IGMPProxyOpened + '0');

      if (len <= off+count) *eof = 1;
      *start = page + off;
      len -= off;
      if (len>count) len = count;
      if (len<0) len = 0;
      return len;

}
static int br_igmpProxyWrite_proc(struct file *file, const char *buffer,
		      unsigned long count, void *data)
{
    unsigned char chartmp; 
	  
    if (count > 1) {	//call from shell
      	if (buffer && !copy_from_user(&chartmp, buffer, 1)) {
	    	IGMPProxyOpened = chartmp - '0';			
	    }
	}else if(count==1){//call from demon(demon direct call br's ioctl)
			//memcpy(&chartmp,buffer,1);
			if(buffer){
				get_user(chartmp,buffer);	
		    		IGMPProxyOpened = chartmp - '0';
			}else
				return -EFAULT;

	}else{

		return -EFAULT;
	}
	return count;
}

static int __init br_init(void)
{
	int err;

	err = stp_proto_register(&br_stp_proto);
	if (err < 0) {
		printk(KERN_ERR "bridge: can't register sap for STP\n");
		return err;
	}

	err = br_fdb_init();
	if (err)
		goto err_out;

	err = register_pernet_subsys(&br_net_ops);
	if (err)
		goto err_out1;

#if defined (CONFIG_RTL865X_LANPORT_RESTRICTION)
	lan_restrict_init();
#endif

#ifdef CONFIG_RTL_EAP_RELAY	
		procHostMac = create_proc_entry("br_hostmac", 0, NULL);
		if (procHostMac) {
		    procHostMac->read_proc = br_hostmac_read_proc;
		    procHostMac->write_proc = br_hostmac_write_proc;
		}
#endif

#if defined(CONFIG_PROC_FS) && defined (CONFIG_RTL_WLAN_BLOCK_RELAY)
		procwlanblockrelay = create_proc_entry("br_wlanblock", 0, NULL);
		if(procwlanblockrelay) {
			procwlanblockrelay->read_proc = br_wlanblockread_proc;
			procwlanblockrelay->write_proc = br_wlanblockwrite_proc;
		}
#endif

#if defined (CONFIG_PROC_FS) && defined (CONFIG_RTL_IGMP_SNOOPING)	
		procigmp = create_proc_entry("br_igmpsnoop", 0, NULL);
		if (procigmp) {
		    procigmp->read_proc = br_igmpread_proc;
		    procigmp->write_proc = br_igmpwrite_proc;
		}

		procMCastFastFwd= create_proc_entry("br_mCastFastFwd", 0, NULL);
		if (procMCastFastFwd) {
		    procMCastFastFwd->read_proc = br_mCastFastFwdRead_proc;
		    procMCastFastFwd->write_proc = br_mCastFastFwdWrite_proc;
		}
	
		procIgmpQuery= create_proc_entry("br_igmpquery", 0, NULL);
		if (procIgmpQuery) {
		    procIgmpQuery->read_proc = br_igmpQueryRead_proc;
		    procIgmpQuery->write_proc = br_igmpQueryWrite_proc;
		}


#if defined (CONFIG_RTL_MLD_SNOOPING)
		procMldQuery= create_proc_entry("br_mldquery", 0, NULL);
		if (procMldQuery) {
		    procMldQuery->read_proc = br_mldQueryRead_proc;
		    procMldQuery->write_proc = br_mldQueryWrite_proc;
		}
#endif
#endif

#if  defined (CONFIG_PROC_FS) 	
		procIgmpProxy = create_proc_entry("br_igmpProxy", 0, NULL);
		if (procIgmpProxy) {
		    procIgmpProxy->read_proc = br_igmpProxyRead_proc;
		    procIgmpProxy->write_proc = br_igmpProxyWrite_proc;
		}
#endif
	err = br_netfilter_init();
	if (err)
		goto err_out2;

	err = register_netdevice_notifier(&br_device_notifier);
	if (err)
		goto err_out3;

	err = br_netlink_init();
	if (err)
		goto err_out4;

	brioctl_set(br_ioctl_deviceless_stub);
	br_handle_frame_hook = br_handle_frame;

	br_fdb_get_hook = br_fdb_get;
	br_fdb_put_hook = br_fdb_put;
#if defined(CONFIG_DOMAIN_NAME_QUERY_SUPPORT)
	br_filter_init();
#endif

	return 0;
err_out4:
	unregister_netdevice_notifier(&br_device_notifier);
err_out3:
	br_netfilter_fini();
err_out2:
	unregister_pernet_subsys(&br_net_ops);
err_out1:
	br_fdb_fini();
err_out:
	stp_proto_unregister(&br_stp_proto);
	return err;
}

static void __exit br_deinit(void)
{
	stp_proto_unregister(&br_stp_proto);

#if  defined (CONFIG_PROC_FS) && defined (CONFIG_RTL_IGMP_SNOOPING)
	if (procigmp) {
		remove_proc_entry("br_igmpsnoop", procigmp);		
		procigmp = NULL;
	}

	if (procMCastFastFwd) {
		remove_proc_entry("br_mCastFastFwd", procMCastFastFwd);		
		procMCastFastFwd = NULL;
	}

	if (procIgmpQuery) {
	 	 remove_proc_entry("br_igmpquery", procIgmpQuery);		
		procIgmpQuery = NULL;
	}

#if defined (CONFIG_RTL_MLD_SNOOPING)
	if (procMldQuery) {
		 remove_proc_entry("br_mldquery", procMldQuery);		
		procMldQuery = NULL;
	}
#endif	

#endif	

#if  defined (CONFIG_PROC_FS) 
	if (procIgmpProxy) {
		remove_proc_entry("br_igmpProxy", procIgmpProxy);		
		procIgmpProxy = NULL;
	}
#endif
	br_netlink_fini();
	unregister_netdevice_notifier(&br_device_notifier);
	brioctl_set(NULL);

	unregister_pernet_subsys(&br_net_ops);

	synchronize_net();

	br_netfilter_fini();
	br_fdb_get_hook = NULL;
	br_fdb_put_hook = NULL;

	br_handle_frame_hook = NULL;
	br_fdb_fini();
#if defined(CONFIG_DOMAIN_NAME_QUERY_SUPPORT)
	br_filter_exit();
#endif

}

EXPORT_SYMBOL(br_should_route_hook);

module_init(br_init)
module_exit(br_deinit)
MODULE_LICENSE("GPL");
MODULE_VERSION(BR_VERSION);
