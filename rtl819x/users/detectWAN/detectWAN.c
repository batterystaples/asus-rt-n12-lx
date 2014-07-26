/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 */

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/sysinfo.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/sockios.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>

//#include <nvram/bcmnvram.h>
//#include <semaphore_mfp.h>
#define HOME_GATEWAY
#include "apmib.h"

#define ETHER_ADDR_STR_LEN	18
#define MAC_BCAST_ADDR		(uint8_t *) "\xff\xff\xff\xff\xff\xff"
#define WAN_IF			"eth1"
#define LAN_IF			"br0"
//#define DEBUG		1

char *get_lan_ipaddr();
char *get_wan_ipaddr();

char wan_ipaddr_t[16];
char wan_hwaddr_t[18];
char wan_gateway_t[16];

typedef enum { IP_ADDR, SUBNET_MASK, DEFAULT_GATEWAY, HW_ADDR } ADDR_T;

void get_related_nvram();

#include<syslog.h>
#include<stdarg.h>
void logmessage(char *logheader, char *fmt, ...)
{
	va_list args;
	char buf[512];

	va_start(args, fmt);

	vsnprintf(buf, sizeof(buf), fmt, args);
	openlog(logheader, 0, 0);
	syslog(0, buf);
	closelog();
	va_end(args);
}

long uptime(void)
{
	struct sysinfo info;

	sysinfo(&info);
	return info.uptime;
}

int dhcp_renew = 0;

int isFileExist(char *file_name)
{
	struct stat status;

	if ( stat(file_name, &status) < 0)
		return 0;

	return 1;
}

void
chk_udhcpc()
{
	char *gateway_ip;
	int try_count;
	OPMODE_T opmode = -1;
	DHCP_T wan_proto;
	apmib_get(MIB_OP_MODE, (void *)&opmode);
	apmib_get(MIB_WAN_DHCP, (void *)&wan_proto);
	//if (	(nvram_match("wan_route_x", "IP_Routed") && nvram_match("wan0_proto", "dhcp") && !nvram_match("manually_disconnect_wan", "1")) ||
	//	nvram_match("wan_route_x", "IP_Bridged"))
	get_related_nvram();
	if ( (opmode == GATEWAY_MODE && wan_proto == DHCP_CLIENT) || opmode == BRIDGE_MODE)
	{
		/*if (nvram_match("wan_route_x", "IP_Routed"))
			gateway_ip = nvram_get("wan_gateway_t");
		else
			gateway_ip = nvram_get("lan_gateway_t");*/
		gateway_ip = wan_gateway_t;

		if (!gateway_ip || (strlen(gateway_ip) < 7) || (!strncmp(gateway_ip, "0.0.0.0", 7)))
		{
#ifdef DEBUG
			fprintf(stderr, "[detectWAN] invalid gateway ip\n");
#endif				
			return;
		}

		//if (nvram_match("wan_route_x", "IP_Routed"))
		if( opmode == GATEWAY_MODE)
		{
			//if (!strcmp(get_wan_ipaddr(), "0.0.0.0"))
			if (!strcmp(wan_ipaddr_t, "0.0.0.0"))
			{
#ifdef DEBUG
				fprintf(stderr, "[detectWAN] invalid gateway ip\n");
#endif
				return;
			}
		}
		else
		{
			//if (!strcmp(get_lan_ipaddr(), "0.0.0.0"))
			if (!strcmp(wan_ipaddr_t, "0.0.0.0"))
			{
#ifdef DEBUG
				fprintf(stderr, "[detectWAN] invalid gateway ip\n");
#endif
				return;
			}
		}

		//spinlock_lock(SPINLOCK_DHCPRenew);
		//if (nvram_match("dhcp_renew", "1"))
		//if( dhcp_renew == 1)
		if (isFileExist("/tmp/dhcp_renew") == 1)
		{
			//spinlock_unlock(SPINLOCK_DHCPRenew);
#ifdef DEBUG
			fprintf(stderr, "[detectWAN] skip udhcpc refresh...\n");
#endif
			return;
		}
		else
		{
			system("echo 1 > /tmp/dhcp_renew");
			//dhcp_renew = 1;
			//nvram_set("dhcp_renew", "1");
			//spinlock_unlock(SPINLOCK_DHCPRenew);
		}

#ifdef DEBUG
		fprintf(stderr, "[detectWAN] try to refresh udhcpc\n");
#endif
		//if (nvram_match("wan_route_x", "IP_Routed"))
		if (opmode == GATEWAY_MODE)
		{
			{
#if 0
				if (strcmp(get_wan_ipaddr(), "0.0.0.0"))
				{
					logmessage("detectWAN", "perform DHCP release");
					system("killall -SIGUSR2 udhcpc");

					sleep(1);
//					fprintf(stderr, "[detectWAN] wan_ipaddr_t: %s, wan_gateway_t: %s\n", nvram_safe_get("wan_ipaddr_t"), nvram_safe_get("wan_gateway_t"));
					kill_pidfile_s("/var/run/wanduck.pid", SIGUSR1);
					kill_pidfile_s("/var/run/wanduck.pid", SIGUSR2);
				}
#else
				//system("/sbin/stop_wanduck");
				//sleep(3);
#endif
				logmessage("detectWAN", "perform DHCP renew");
				//system("killall -SIGUSR1 udhcpc");
				system("sysconf wan_up &");
				
				try_count = 0;
				//system("/sbin/start_wanduck");

				//while (!pids("wanduck") && (++try_count < 3))
				//{
				//	system("/sbin/start_wanduck");
				//	sleep(2);
				//}
			}
		}
		else
		{
			logmessage("detectWAN", "perform DHCP renew");
			//system("killall -SIGUSR1 udhcpc");
			system("sysconf restart_lan &");
		}
	}
}

char *
get_lan_ipaddr()
{
	int s;
	struct ifreq ifr;
	struct sockaddr_in *inaddr;
	struct in_addr ip_addr;

	/* Retrieve IP info */
	if ((s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
		return strdup("0.0.0.0");

	strncpy(ifr.ifr_name, LAN_IF, IFNAMSIZ);
	inaddr = (struct sockaddr_in *)&ifr.ifr_addr;
	inet_aton("0.0.0.0", &inaddr->sin_addr);	

	/* Get IP address */
	ioctl(s, SIOCGIFADDR, &ifr);
	close(s);	

	ip_addr = ((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr;
	fprintf(stderr, "%s: current LAN IP address: %s\n", __FILE__,inet_ntoa(ip_addr));
	return inet_ntoa(ip_addr);
}

char *get_wan_ipaddr()
{
	int s;
	OPMODE_T opmode = -1;
	DHCP_T wan_proto;
	struct ifreq ifr;
	struct sockaddr_in *inaddr;
	struct in_addr ip_addr;
	
	apmib_get(MIB_OP_MODE, (void *)&opmode);
	if(opmode != GATEWAY_MODE)
		return strdup("0.0.0.0");

	/* Retrieve IP info */
	if ((s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
		return strdup("0.0.0.0");

	apmib_get( MIB_WAN_DHCP,  (void *)wan_proto);

	if(wan_proto == DHCP_CLIENT || wan_proto == DHCP_DISABLED)
		strncpy(ifr.ifr_name, WAN_IF, IFNAMSIZ);
	else
		strncpy(ifr.ifr_name, "ppp0", IFNAMSIZ);

	inaddr = (struct sockaddr_in *)&ifr.ifr_addr;
	inet_aton("0.0.0.0", &inaddr->sin_addr);	

	/* Get IP address */
	ioctl(s, SIOCGIFADDR, &ifr);
	close(s);	

	ip_addr = ((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr;
	fprintf("current WAN IP address: %s\n", inet_ntoa(ip_addr));
	return inet_ntoa(ip_addr);
}


struct arpMsg {
	/* Ethernet header */
	uint8_t  h_dest[6];			/* destination ether addr */
	uint8_t  h_source[6];			/* source ether addr */
	uint16_t h_proto;			/* packet type ID field */

	/* ARP packet */
	uint16_t htype;				/* hardware type (must be ARPHRD_ETHER) */
	uint16_t ptype;				/* protocol type (must be ETH_P_IP) */
	uint8_t  hlen;				/* hardware address length (must be 6) */
	uint8_t  plen;				/* protocol address length (must be 4) */
	uint16_t operation;			/* ARP opcode */
	uint8_t  sHaddr[6];			/* sender's hardware address */
	uint8_t  sInaddr[4];			/* sender's IP address */
	uint8_t  tHaddr[6];			/* target's hardware address */
	uint8_t  tInaddr[4];			/* target's IP address */
	uint8_t  pad[18];			/* pad for min. Ethernet payload (60 bytes) */
} ATTRIBUTE_PACKED;

/* args:	yiaddr - what IP to ping
 *		ip - our ip
 *		mac - our arp address
 *		interface - interface to use
 * retn:	1 addr free
 *		0 addr used
 *		-1 error
 */
                                                                                                              
static const int one = 1;

int setsockopt_broadcast(int fd)
{
    return setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one));
}

/* FIXME: match response against chaddr */
int arpping(/*uint32_t yiaddr, uint32_t ip, uint8_t *mac, char *interface*/)
{
	uint32_t yiaddr;
	uint32_t ip;
	uint8_t mac[6]={0};
	char wanmac[18]={0};
	char tmp[3]={0};
	int i, ret;
	char DEV[8]={0};
	char *gateway_ip=0;
	//char *pMacAddr=0;
	OPMODE_T opmode = -1;
	
	get_related_nvram();

	gateway_ip = wan_gateway_t;
#ifdef DEBUG
	printf("Get Default route = %s\n",gateway_ip);  //Router:WAN Default Route
#endif
	inet_aton(gateway_ip, &yiaddr);
	inet_aton(wan_ipaddr_t, &ip);
#ifdef DEBUG
	printf("Get WAN IP = %s\n",wan_ipaddr_t);  //WAN IP
#endif
	strcpy(wanmac,wan_hwaddr_t);
#ifdef DEBUG
	printf("Get wanmac = %s \n",wanmac);
#endif
			
        wanmac[17]=0;
        for(i=0;i<6;i++)
        {
                tmp[2]=0;
                strncpy(tmp, wanmac+i*3, 2);
                mac[i]=strtol(tmp, (char **)NULL, 16);
        }

	int	timeout = 2;
	int	s;			/* socket */
	int	rv = 0;			/* return value */
	struct sockaddr addr;		/* for interface name */
	struct arpMsg	arp;
	fd_set		fdset;
	struct timeval	tm;
	time_t		prevTime;

	s = socket(PF_PACKET, SOCK_PACKET, htons(ETH_P_ARP));
	if (s == -1) {
#ifdef DEBUG
		fprintf(stderr, "cannot create raw socket\n");
#endif
		return 0;
	}

	if (setsockopt_broadcast(s) == -1) {
#ifdef DEBUG		
		fprintf(stderr, "cannot setsocketopt on raw socket\n");
#endif
		close(s);
		return 0;
	}

	/* send arp request */
	memset(&arp, 0, sizeof(arp));
	memcpy(arp.h_dest, MAC_BCAST_ADDR, 6);		/* MAC DA */
	memcpy(arp.h_source, mac, 6);			/* MAC SA */
	arp.h_proto = htons(ETH_P_ARP);			/* protocol type (Ethernet) */
	arp.htype = htons(ARPHRD_ETHER);		/* hardware type */
	arp.ptype = htons(ETH_P_IP);			/* protocol type (ARP message) */
	arp.hlen = 6;					/* hardware address length */
	arp.plen = 4;					/* protocol address length */
	arp.operation = htons(ARPOP_REQUEST);		/* ARP op code */
	memcpy(arp.sInaddr, &ip, sizeof(ip));		/* source IP address */
	memcpy(arp.sHaddr, mac, 6);			/* source hardware address */
	memcpy(arp.tInaddr, &yiaddr, sizeof(yiaddr));	/* target IP address */

	memset(&addr, 0, sizeof(addr));
	memset(DEV, 0, sizeof(DEV));

	apmib_get(MIB_OP_MODE, (void *)&opmode);
	if (opmode == GATEWAY_MODE)
		strcpy(DEV, WAN0_IFNAME);
	else
		strcpy(DEV, LAN0_IFNAME);

	strncpy(addr.sa_data, DEV, sizeof(addr.sa_data));

	if (setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, DEV, IFNAMSIZ) != 0)	// J++
        {
#ifdef DEBUG
                fprintf(stderr, "setsockopt error: %s\n", DEV);
                perror("setsockopt set:");
#endif
        }

	ret = sendto(s, &arp, sizeof(arp), 0, &addr, sizeof(addr));

        if (setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, "", IFNAMSIZ) != 0)	// J++
        {
#ifdef DEBUG
                fprintf(stderr, "setsockopt error: %s\n", "");
                perror("setsockopt reset:");
#endif
        }

	if (ret < 0)
	{
		sleep(1);
		return 0;
	}

	/* wait arp reply, and check it */
	tm.tv_usec = 0;
	prevTime = uptime();
	while (timeout > 0) {
		FD_ZERO(&fdset);
		FD_SET(s, &fdset);
		tm.tv_sec = timeout;
		if (select(s + 1, &fdset, (fd_set *) NULL, (fd_set *) NULL, &tm) < 0) {
#ifdef DEBUG
			fprintf(stderr, "error on ARPING request\n");
#endif
			if (errno != EINTR) rv = 0;
		} else if (FD_ISSET(s, &fdset)) {
			if (recv(s, &arp, sizeof(arp), 0) < 0 ) rv = 0;
			if (arp.operation == htons(ARPOP_REPLY) &&
			    memcmp(arp.tHaddr, mac, 6) == 0 &&
			    *((uint32_t *) arp.sInaddr) == yiaddr) {
#ifdef DEBUG
				fprintf(stderr, "Valid arp reply from [%02X:%02X:%02X:%02X:%02X:%02X]\n",
					(unsigned char)arp.sHaddr[0],
					(unsigned char)arp.sHaddr[1],
					(unsigned char)arp.sHaddr[2],
					(unsigned char)arp.sHaddr[3],
					(unsigned char)arp.sHaddr[4],
					(unsigned char)arp.sHaddr[5]);
#endif
				close(s);
				rv = 1;
				return 1;
			}
		}
		timeout -= uptime() - prevTime;
		prevTime = uptime();
	}

	close(s);
#ifdef DEBUG
	fprintf(stderr, "%salid arp reply\n", rv ? "V" : "No v");
#endif
	return rv;
}

#if 0
int is_phyconnected()
{
	if (nvram_match("wan_route_x", "IP_Routed"))
	{
		if (nvram_match("link_wan", "1"))
			return 1;
		else
			return 0;
	}
	else
	{
		if (nvram_match("link_lan", "1"))
			return 1;
		else
			return 0;
	}
}
#endif


#define RTL8651_IOCTL_GETWANLINKSTATUS 2000
/* IOCTL system call */
static int re865xIoctl(char *name, unsigned int arg0, unsigned int arg1, unsigned int arg2, unsigned int arg3)
{
	unsigned int args[4];
  	struct ifreq ifr;
  	int sockfd;

  	args[0] = arg0;
  	args[1] = arg1;
  	args[2] = arg2;
  	args[3] = arg3;

  	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    	{
      		perror("fatal error socket\n");
      		return -3;
    	}
  
  	strcpy((char*)&ifr.ifr_name, name);
  	((unsigned int *)(&ifr.ifr_data))[0] = (unsigned int)args;

  	if (ioctl(sockfd, SIOCDEVPRIVATE, &ifr)<0)
    	{
      		perror("device ioctl:");
      		close(sockfd);
      		return -1;
    	}
  	close(sockfd);
  	return 0;
} /* end re865xIoctl */

int is_phyconnected()
{
	unsigned int    ret;
        unsigned int    args[0];
	re865xIoctl("eth1", RTL8651_IOCTL_GETWANLINKSTATUS, (unsigned int)(args), 0, (unsigned int)&ret) ;
	if(ret == 0)
		return 1;
        return 0;//return ret;
}

#define MAX_ARP_RETRY 3

int detectWAN_arp()
{
	int count;
	OPMODE_T opmode = -1;
	while (1)
	{
		count = 0;
		apmib_get(MIB_OP_MODE, (void *)&opmode);
		while (count < MAX_ARP_RETRY)
		{
			//if (nvram_match("wan_route_x", "IP_Routed") && !is_phyconnected())
			if (opmode == GATEWAY_MODE && !is_phyconnected())
			{
#ifdef DEBUG	
				fprintf(stderr, "[detectWAN] phy disconnected\n");
#endif
				count++;
				sleep(2);
			}
			else if (arpping())
			{
#ifdef DEBUG
				fprintf(stderr, "[detectWAN] got response from gateway\n");
#endif
				break;
			}
			else
			{
#ifdef DEBUG
				fprintf(stderr, "[detectWAN] no response from gateway\n");
#endif
				count++;
			}

#ifdef DEBUG
			fprintf(stderr, "[detectWAN] count: %d\n", count);
#endif
		}

		if (is_phyconnected() && (count >= MAX_ARP_RETRY))
		{
			chk_udhcpc();
		}

		sleep(20);
	}

	return 0;
}

#define _PATH_PROCNET_ROUTE	"/proc/net/route"
#define RTF_UP			0x0001          /* route usable                 */
#define RTF_GATEWAY		0x0002          /* destination is a gateway     */
int getInAddr( char *interface, ADDR_T type, void *pAddr )
{
    struct ifreq ifr;
    int skfd=0, found=0;
    struct sockaddr_in *addr;

    skfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(skfd==-1)
		return 0;
		
    strcpy(ifr.ifr_name, interface);
    if (ioctl(skfd, SIOCGIFFLAGS, &ifr) < 0){
    	close( skfd );
		return (0);
	}
    if (type == HW_ADDR) {
    	if (ioctl(skfd, SIOCGIFHWADDR, &ifr) >= 0) {
		memcpy(pAddr, &ifr.ifr_hwaddr, sizeof(struct sockaddr));
		found = 1;
	}
    }
    else if (type == IP_ADDR) {
	if (ioctl(skfd, SIOCGIFADDR, &ifr) == 0) {
		addr = ((struct sockaddr_in *)&ifr.ifr_addr);
		*((struct in_addr *)pAddr) = *((struct in_addr *)&addr->sin_addr);
		found = 1;
	}
    }
    else if (type == SUBNET_MASK) {
	if (ioctl(skfd, SIOCGIFNETMASK, &ifr) >= 0) {
		addr = ((struct sockaddr_in *)&ifr.ifr_addr);
		*((struct in_addr *)pAddr) = *((struct in_addr *)&addr->sin_addr);
		found = 1;
	}
    }
    close( skfd );
    return found;
}

int getDefaultGW(char *interface, struct in_addr *route)
{
	char buff[1024], iface[16];
	char gate_addr[128], net_addr[128], mask_addr[128];
	int num, iflags, metric, refcnt, use, mss, window, irtt;
	FILE *fp = fopen(_PATH_PROCNET_ROUTE, "r");
	char *fmt;
	int found=0;
	unsigned long addr;

	if (!fp) {
       		printf("Open %s file error.\n", _PATH_PROCNET_ROUTE);
		return 0;
    	}

	fmt = "%16s %128s %128s %X %d %d %d %128s %d %d %d";

	while (fgets(buff, 1023, fp)) {
		num = sscanf(buff, fmt, iface, net_addr, gate_addr,
		     		&iflags, &refcnt, &use, &metric, mask_addr, &mss, &window, &irtt);
		if (num < 10 || !(iflags & RTF_UP) || !(iflags & RTF_GATEWAY) || strcmp(iface, interface))
	    		continue;
		sscanf(gate_addr, "%lx", &addr );
		*route = *((struct in_addr *)&addr);

		found = 1;
		break;
	}

    	fclose(fp);
    	return found;
}

int getWanInfo(char *pWanIP, char *pWanMask, char *pWanDefIP, char *pWanHWAddr)
{
	DHCP_T dhcp;
	OPMODE_T opmode=-1;
	char *iface=NULL;
	struct in_addr	intaddr;
	struct sockaddr hwaddr;
	unsigned char *pMacAddr;
	
	if ( !apmib_get( MIB_WAN_DHCP, (void *)&dhcp) )
		return -1;
  
  	if ( !apmib_get( MIB_OP_MODE, (void *)&opmode) )
		return -1;

	DHCP_T wan_proto;
	apmib_get(MIB_WAN_DHCP, (void *)&wan_proto);

	if(opmode == GATEWAY_MODE)
	  {
	if(wan_proto == DHCP_CLIENT || wan_proto == DHCP_DISABLED)
			iface = WAN0_IFNAME;
	else
			iface = PPP0_IFNAME;

#ifdef DEBUG
		printf("%s:%s GATEWAY MODE\n", __FILE__,__FUNCTION__);
#endif
	  }
     	else if (opmode == BRIDGE_MODE)
	  {
			iface= LAN0_IFNAME;
#ifdef DEBUG
		printf("%s:%s BRIDGE MODE\n", __FILE__,__FUNCTION__);
#endif
	  }

	if ( iface && getInAddr(iface, IP_ADDR, (void *)&intaddr ) )
		sprintf(pWanIP,"%s",inet_ntoa(intaddr));
	else
		sprintf(pWanIP,"%s","0.0.0.0");
		
	if ( iface && getInAddr(iface, SUBNET_MASK, (void *)&intaddr ) )
		sprintf(pWanMask,"%s",inet_ntoa(intaddr));
	else
		sprintf(pWanMask,"%s","0.0.0.0");
		
	if ( iface && getDefaultGW(iface, &intaddr) )
		sprintf(pWanDefIP,"%s",inet_ntoa(intaddr));
	else
		sprintf(pWanDefIP,"%s","0.0.0.0");
	
	if ( getInAddr(iface, HW_ADDR, (void *)&hwaddr ) ) 
	{
		pMacAddr = hwaddr.sa_data;
		sprintf(pWanHWAddr,"%02x:%02x:%02x:%02x:%02x:%02x",pMacAddr[0], pMacAddr[1],pMacAddr[2], pMacAddr[3], pMacAddr[4], pMacAddr[5]);
	}
	else
		sprintf(pWanHWAddr,"%s","00:00:00:00:00:00");

	return 1;
}

/*void reinit_mib()
{
	fprintf(stderr, "[detectWAN] Reinit mib\n");
	apmib_reinit();
}*/

void get_related_nvram(){

	memset(wan_gateway_t, 0, 16);
	char wan_ipaddr[16];
	char wan_netmask[16];
	char wan_gateway[16];
	//char wan_subnet[11];
	char wan_hwaddr[18];
	getWanInfo(wan_ipaddr, wan_netmask, wan_gateway, wan_hwaddr);
#ifdef DEBUG
	printf("%s:%s:%d ipaddr = %s netmask = %s gateway = %s wan_hwaddr = %s\n", __FILE__,__FUNCTION__,__LINE__,wan_ipaddr,wan_netmask, wan_gateway, wan_hwaddr);
#endif
	strcpy(wan_ipaddr_t, wan_ipaddr);
	strcpy(wan_hwaddr_t, wan_hwaddr);

	strcpy(wan_gateway_t, wan_gateway);
}


int main(int argc, char *argv[])
{
	FILE *fp;
	int ret;
	char *gateway_ip;
	
	//signal(SIGUSR1, reinit_mib);
	
	/* write pid */
	if ((fp = fopen("/var/run/detectWan.pid", "w")) != NULL)
	{
		fprintf(fp, "%d", getpid());
		fclose(fp);
	}
	
	if ( apmib_init() == 0 )
		printf("Initialize AP MIB failed! Can't start detedtWAN\n");
	else
		printf("Start detectWAN!\n");
	
	//memset(wan_gateway_t, 0, 16);
	for(;;)
	{
		/*if (nvram_match("wan_route_x", "IP_Routed"))
			gateway_ip = nvram_get("wan_gateway_t");
		else
			gateway_ip = nvram_get("lan_gateway_t");*/
		//getWanInfo(wan_ipaddr, wan_netmask, wan_gateway, wan_hwaddr);
		//strcpy(wan_gateway_t, wan_gateway);
		get_related_nvram();
		gateway_ip = wan_gateway_t;
	
		/* if not valid gateway, poll for it at first */
		if (!gateway_ip || (strlen(gateway_ip) < 7) || (!strncmp(gateway_ip, "0.0.0.0", 7)))
		{
#ifdef DEBUG
			fprintf(stderr, "[detectWAN] no valid gateway\n");
#endif
			sleep(15);
		}
		/* valid gateway for now */
		else
		{
#ifdef DEBUG
			fprintf(stderr, "[detectWAN] got valid gateway\n");
#endif
			break;
		}
	}

	ret = detectWAN_arp();

	if (ret < 0)
		printf("Failure!\n");
	else
		printf("Success!\n");
	
	return 0;
}
