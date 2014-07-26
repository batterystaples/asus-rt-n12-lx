#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/ioctl.h> 
#include <net/if.h>
#define HOME_GATEWAY
#include "apmib.h"

#define RTL8651_IOCTL_GETWANLINKSTATUS 2000
#define	MAX_MAC_NUM	64
static int mac_num;
static char mac_clone[MAX_MAC_NUM][18];

int got_wan_ip()
{
	int s;
	struct ifreq ifr;
	struct sockaddr_in *inaddr;
	struct in_addr in_addr;

	/* Retrieve IP info */
	if ((s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
		return 0;

	DHCP_T wan_proto;
	apmib_get(MIB_WAN_DHCP, (void *)&wan_proto);
	if(wan_proto == DHCP_CLIENT || wan_proto == DHCP_DISABLED)
		strncpy(ifr.ifr_name, "eth1", IFNAMSIZ);
	else
		strncpy(ifr.ifr_name, "ppp0", IFNAMSIZ);

	inaddr = (struct sockaddr_in *)&ifr.ifr_addr;
	inet_aton("0.0.0.0", &inaddr->sin_addr);	

	/* Get IP address */
	ioctl(s, SIOCGIFADDR, &ifr);
	close(s);

	struct in_addr ip_addr = ((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr;
	if (strcmp("0.0.0.0", inet_ntoa(ip_addr)))
		return 1;
	else
		return 0;
}

int got_wan_hwaddr(void *pHwAddr)
{
	struct ifreq ifr;
    	int skfd=0, found=0;
    	struct sockaddr_in *addr;

	if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		return 0;
		
    	strcpy(ifr.ifr_name, "eth1");

    	if (ioctl(skfd, SIOCGIFHWADDR, &ifr) >= 0) {
		memcpy(pHwAddr, &ifr.ifr_hwaddr, sizeof(struct sockaddr));
		found = 1;
	}

	close(skfd);
    	return found;
}

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
      		perror("clonemac-device ioctl:");
      		close(sockfd);
      		return -1;
    	}
  	close(sockfd);
  	return 0;
} /* end re865xIoctl */

/* Wan link status detect */
int is_phyconnected()
{
        unsigned int    ret;
        unsigned int    args[0];
        re865xIoctl("eth1", RTL8651_IOCTL_GETWANLINKSTATUS, (unsigned int)(args), 0, (unsigned int)&ret) ;
	if(ret == 0)
		return 1;
        return 0;
}

void dumparptable()
{
	char buf[256];
	char ip_entry[32], hw_type[8], flags[8], hw_address[32], mask[32], device[8], wan_hwaddr[18];
	char macbuf[36];
	struct sockaddr hwaddr;
	unsigned char *pMacAddr;

	FILE *fp = fopen("/proc/net/arp", "r");
	if (!fp) {
		fprintf(stderr, "no proc fs mounted!\n");
		return;
	}

	mac_num = 0;

//	while (fgets(buf, 256, fp) && (mac_num < MAX_MAC_NUM - 1)) {
	while (fgets(buf, 256, fp) && (mac_num < MAX_MAC_NUM - 2)) {
		sscanf(buf, "%s %s %s %s %s %s", ip_entry, hw_type, flags, hw_address, mask, device);

		if (!strcmp(device, "br0"))
		{
			strcpy(mac_clone[mac_num++], hw_address);
//			fprintf(stderr, "%d %s\n", mac_num, mac_clone[mac_num - 1]);
		}
	}
	fclose(fp);

#if 0
	mac_conv("wan_hwaddr_x", -1, macbuf);
	if (nvram_invmatch("wan_hwaddr_x", "") && strcasecmp(macbuf, "FF:FF:FF:FF:FF:FF"))
		strcpy(mac_clone[mac_num++], macbuf);
//	else
		strcpy(mac_clone[mac_num++], nvram_safe_get("il1macaddr"));
#endif
	if ( got_wan_hwaddr((void *)&hwaddr ) ) 
	{
		pMacAddr = hwaddr.sa_data;
		sprintf(wan_hwaddr,"%02x:%02x:%02x:%02x:%02x:%02x",pMacAddr[0], pMacAddr[1],pMacAddr[2], pMacAddr[3], pMacAddr[4], pMacAddr[5]);
		strcpy(mac_clone[mac_num++], wan_hwaddr);
	}
	//else
	//	sprintf(wan_hwaddr,"%s","00:00:00:00:00:00");
	
	if (mac_num)
	{
		fprintf(stderr, "num of mac: %d\n", mac_num);
		int i;
		for (i = 0; i < mac_num; i++)
			fprintf(stderr, "mac to clone: %s\n", mac_clone[i]);
	}
}

char *mac_conv2(char *mac, char *buf)
{
	//char mac[32];
	int i, j;

	//sprintf(mac, mac_str);

	if(strlen(mac) == 0 || strlen(mac) != 17)
		buf[0] = 0;
	else{
		for(i = 0, j = 0; i < 17; ++i){
			if(i%3 != 2){
				buf[j] = mac[i];
				++j;
			}

			buf[j] = 0;
		}
	}

	return(buf);
}

static int _is_hex(char c)
{
    return (((c >= '0') && (c <= '9')) ||
            ((c >= 'A') && (c <= 'F')) ||
            ((c >= 'a') && (c <= 'f')));
}

static int string_to_hex(char *string, unsigned char *key, int len)
{
	char tmpBuf[4];
	int idx, ii=0;
	for (idx=0; idx<len; idx+=2) {
		tmpBuf[0] = string[idx];
		tmpBuf[1] = string[idx+1];
		tmpBuf[2] = 0;
		if ( !_is_hex(tmpBuf[0]) || !_is_hex(tmpBuf[1]))
			return 0;

		key[ii++] = (unsigned char) strtol(tmpBuf, (char**)NULL, 16);
	}
	return 1;
}

int main(int argc, char **argv){
	int had_try = 0;
	DHCP_T wan_proto_t;
	
	chdir("/");
	
	if ( apmib_init() == 0 )
		printf("Initialize AP MIB failed!\n");

	apmib_get(MIB_WAN_DHCP, (void *)&wan_proto_t);
	//if (nvram_invmatch("wan_proto", "dhcp"))
	//	return;
	if(wan_proto_t != DHCP_CLIENT)
		return;

	//sleep(15);
	//nvram_set("done_auto_mac", "0");
#if 1
	while (!got_wan_ip() && !had_try)
	{
		if (is_phyconnected() == 0)
		{
			sleep(5);
			continue;
		}

		dumparptable();

		if (mac_num > 1)
		{
			//nvram_set("mac_clone_en", "1");
			system("echo > /tmp/mac_clone_en");
			int i;
			for (i = 0; i < mac_num; i++)
			{
				//nvram_set("cl0macaddr", mac_clone[i]);
				char mac_str[18], mac_str_t[18], buf[18];
				sprintf(buf, "%s", mac_clone[i]);
				mac_conv2(buf, mac_str_t);
				printf("Conv mac: %s\n", mac_str_t);
				string_to_hex(mac_str_t, mac_str, 12);
				apmib_set(MIB_WAN_MAC_ADDR, (void *)mac_str);
				apmib_update(CURRENT_SETTING);

				//stop_wan();
				//start_wan();
				//system("init.sh gw wan &");
				system("sysconf restart_wan &");
				sleep(10);

				if (got_wan_ip())
				{
					//char buf[13];
					//memset(buf, 0, 13);
					//mac_conv2("cl0macaddr", -1, buf);
					//nvram_set("wan_hwaddr_x", buf);
					//fprintf(stderr, "stop mac cloning!\n");
					printf("stop mac cloning!\n");
					break;
				}
				else
				{
					sprintf(mac_str_t, "000000000000");
					string_to_hex(mac_str_t, mac_str, 12);
					apmib_set(MIB_WAN_MAC_ADDR, (void *)mac_str);
					apmib_update(CURRENT_SETTING);
				}

				if(i == mac_num-1)
					had_try = 1;
			}
			//nvram_set("mac_clone_en", "0");
			unlink("/tmp/mac_clone_en");
		}
	}
	//nvram_set("done_auto_mac", "1");
	//nvram_commit_safe();
	system("echo > /tmp/done_auto_mac");
#endif
}

