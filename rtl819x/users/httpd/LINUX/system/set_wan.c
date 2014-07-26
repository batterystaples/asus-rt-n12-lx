

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "../apmib.h"
#include "../mibtbl.h"
#include "sysconf.h"
#include "sys_utility.h"
#include "syswan.h"
#include <syslog.h>
#include <sys/klog.h>
extern int setFirewallIptablesRules(int argc, char** argv);
extern int Last_WAN_Mode;
void start_dns_relay(void);
void start_pppoe_relay(void);
void start_igmpproxy(char *wan_iface, char *lan_iface);
void del_routing(void);
void wan_connect(char *interface, char *option)
{
	char line[128], arg_buff[200];
	char *cmd_opt[16];
	int cmd_cnt = 0, intValue=0, x, dns_mode=0, index=0;
	int dns_found=0, wan_type=0, conn_type=0, ppp_mtu=0;
	struct in_addr wanaddr;
	char *strtmp=NULL;
	char wanip[32]={0}, mask[32]={0},remoteip[32]={0};
	char nameserver[32], nameserver_ip[32];
	char dns_server[5][32];
	char tmp_args[16]={0};
	int opmode=0, wisp_wan_id=0;
	char *token=NULL, *savestr1=NULL;
	FILE *fp1;

	char tmp_buf[64]={0};
	char ServerIp[32],netIp[32];
	unsigned int serverAddr,netAddr;
	struct in_addr tmpInAddr;
	unsigned int wanIpAddr, maskAddr, remoteIpAddr;

	RunSystemCmd(NULL_FILE, "killall", "dnrd", NULL_STR);
	if(isFileExist(DNRD_PID_FILE)){
		unlink(DNRD_PID_FILE);
	}
	apmib_get(MIB_WAN_DHCP,(void *)&wan_type);
	apmib_get( MIB_DNS_MODE, (void *)&dns_mode);
	apmib_get(MIB_OP_MODE,(void *)&opmode);
	apmib_get(MIB_WISP_WAN_ID,(void *)&wisp_wan_id);
	if(!strcmp(interface, "ppp0")){ 
		if(wan_type==PPTP || wan_type==L2TP){
			if(opmode==GATEWAY_MODE)
				RunSystemCmd(NULL_FILE, "route", "del", "default", "dev", "eth1", NULL_STR);
			if(opmode==WISP_MODE)
				RunSystemCmd(NULL_FILE, "route", "del", "default", "dev", "wlan0", NULL_STR);
		}

		if(wan_type==PPTP){
			apmib_get(MIB_PPTP_CONNECTION_TYPE, (void *)&conn_type);
			if(intValue==1){
				RunSystemCmd(PROC_PPTP_CONN_FILE, "echo", "5", NULL_STR);
			}else{
				RunSystemCmd(PROC_PPTP_CONN_FILE, "echo", "0", NULL_STR);
			}
		}
		if((wan_type==PPPOE)||(wan_type==PPTP)||(wan_type==L2TP))
		{
			intValue = getInAddr("ppp0", 0, (void *)&wanaddr);
			if(intValue==1){
				RunSystemCmd(NULL_FILE, "route", "del", "default", NULL_STR);
				strtmp = inet_ntoa(wanaddr);
				sprintf(remoteip, "%s",strtmp); 
				RunSystemCmd(NULL_FILE, "route", "add", "-net", "default", "gw", remoteip, "dev", "ppp0", NULL_STR);
			}
			
		}
		if(wan_type==PPTP || wan_type==L2TP){
			token=NULL;
			savestr1=NULL;	     
			sprintf(arg_buff, "%s", option);
		
			token = strtok_r(arg_buff," ", &savestr1);
			x=0;
			do{
				if (token == NULL){/*check if the first arg is NULL*/
					break;
				}else{   
					if(x==1){
						ppp_mtu = atoi(token);
						break;
					}
					if(!strcmp(token, "mtu"))
						x=1;
				}
			
				token = strtok_r(NULL, " ", &savestr1);
			}while(token !=NULL);  
		
		}
		if(wan_type==PPTP){
			apmib_get(MIB_PPTP_MTU_SIZE, (void *)&intValue);
			if(ppp_mtu > 0 && intValue > ppp_mtu)
				intValue = ppp_mtu;
			sprintf(tmp_args, "%d", intValue);
		}else if(wan_type==L2TP){
			apmib_get(MIB_L2TP_MTU_SIZE, (void *)&intValue);
			if(ppp_mtu > 0 && intValue > ppp_mtu)
				intValue = ppp_mtu;
			sprintf(tmp_args, "%d", intValue);
		}else if(wan_type==PPPOE){
			apmib_get(MIB_PPP_MTU_SIZE, (void *)&intValue);
			sprintf(tmp_args, "%d", intValue);
			
		}
		RunSystemCmd(NULL_FILE, "ifconfig", "ppp0", "mtu", tmp_args, "txqueuelen", "25",NULL_STR);

		if(dns_mode==1){
			start_dns_relay();
		}else{
			fp1= fopen(PPP_RESOLV_FILE, "r");
			if (fp1 != NULL){
				for (x=0;x<5;x++){
					memset(dns_server[x], '\0', 32);
				}
				while (fgets(line, sizeof(line), fp1) != NULL) {
						memset(nameserver_ip, '\0', 32);
						dns_found = 0;
						sscanf(line, "%s %s", nameserver, nameserver_ip);
						for(x=0;x<5;x++){
							if(dns_server[x][0] != '\0'){
								if(!strcmp(dns_server[x],nameserver_ip)){
									dns_found = 1; 
									break;
								}
							}
						}
						if(dns_found ==0){
							for(x=0;x<5;x++){
								if(dns_server[x][0] == '\0'){
									sprintf(dns_server[x], "%s", nameserver_ip);
									break;
								}
							}
						}
					
				}
				fclose(fp1);
			}
			cmd_opt[cmd_cnt++]="dnrd";
			cmd_opt[cmd_cnt++]="--cache=off";
			for(x=0;x<5;x++){
				if(dns_server[x][0] != '\0'){
					cmd_opt[cmd_cnt++]="-s";
					cmd_opt[cmd_cnt++]=&dns_server[x][0];
				}
			}
			cmd_opt[cmd_cnt++] = 0;
			RunSystemCmd(NULL_FILE, "cp", PPP_RESOLV_FILE, "/var/resolv.conf", NULL_STR);	
			DoCmd(cmd_opt, NULL_FILE);
		}
	}else if(strcmp(interface, "ppp0")){
		if(isFileExist(TEMP_WAN_CHECK) && isFileExist(TEMP_WAN_DHCP_INFO)){
			RunSystemCmd(NULL_FILE, "killall", "-9", "udhcpc", NULL_STR);	
		}
		for (x=0;x<5;x++){
			memset(dns_server[x], '\0', 32);
		}
		token=NULL;
		savestr1=NULL;	     
		sprintf(arg_buff, "%s", option);
	
		token = strtok_r(arg_buff," ", &savestr1);
		index=1;
		do{
			dns_found=0;
			if (token == NULL){/*check if the first arg is NULL*/
				break;
			}else{   
				if(index==2)
					sprintf(wanip, "%s", token); /*wan ip address */
				if(index==3)
					sprintf(mask, "%s", token); /*subnet mask*/
				if(index==4)
					sprintf(remoteip, "%s", token); /*gateway ip*/			
				if(index > 4){
					for(x=0;x<5;x++){
						if(dns_server[x][0] != '\0'){
							if(!strcmp(dns_server[x], token)){
								dns_found = 1; 
								break;
							}
						}
					}
					if(dns_found ==0){
						for(x=0;x<5;x++){
							if(dns_server[x][0] == '\0'){
								sprintf(dns_server[x], "%s", token);
								break;
							}
						}
					}
				}
			}
			index++;
			token = strtok_r(NULL, " ", &savestr1);
		}while(token !=NULL);  
		
		RunSystemCmd(NULL_FILE, "ifconfig", interface, wanip, "netmask", mask, NULL_STR);
		if(wan_type != PPTP && wan_type != L2TP){	
		RunSystemCmd(NULL_FILE, "route", "add", "-net", "default", "gw", remoteip, "dev", interface, NULL_STR);
		if(dns_mode==1){
			start_dns_relay();
		}else{
			cmd_opt[cmd_cnt++]="dnrd";
			cmd_opt[cmd_cnt++]="--cache=off";
			for(x=0;x<5;x++){
				if(dns_server[x][0] != '\0'){
					cmd_opt[cmd_cnt++]="-s";
					cmd_opt[cmd_cnt++]=&dns_server[x][0];
					sprintf(line,"nameserver %s\n", dns_server[x]);
					if(x==0)
						write_line_to_file(RESOLV_CONF, 1, line);
					else
						write_line_to_file(RESOLV_CONF, 2, line);
				}
			}
			cmd_opt[cmd_cnt++] = 0;
			DoCmd(cmd_opt, NULL_FILE);
		}
#ifdef CONFIG_POCKET_AP_SUPPORT
#else
		setFirewallIptablesRules(0, NULL);
#endif	//CONFIG_POCKET_AP_SUPPORT
	}

	if(wan_type == PPTP || wan_type == L2TP){
			RunSystemCmd(NULL_FILE, "route", "del", "default", "dev", interface, NULL_STR);
			if(isFileExist(TEMP_WAN_CHECK) && isFileExist(TEMP_WAN_DHCP_INFO)){
				if(wan_type == PPTP){
					apmib_get(MIB_PPTP_SERVER_IP_ADDR,  (void *)tmp_buf);
					strtmp= inet_ntoa(*((struct in_addr *)tmp_buf));
					sprintf(ServerIp, "%s", strtmp);
					serverAddr=((struct in_addr *)tmp_buf)->s_addr;
					
					inet_aton(wanip, &tmpInAddr);
					wanIpAddr=tmpInAddr.s_addr;

					inet_aton(mask, &tmpInAddr);
					maskAddr=tmpInAddr.s_addr;

					inet_aton(remoteip, &tmpInAddr);
					remoteIpAddr=tmpInAddr.s_addr;

					if((serverAddr & maskAddr) != (wanIpAddr & maskAddr)){
						//Patch for our router under another router to dial up pptp
						//let pptp pkts via pptp default gateway
						netAddr = (serverAddr & maskAddr);
						((struct in_addr *)tmp_buf)->s_addr=netAddr;
						strtmp= inet_ntoa(*((struct in_addr *)tmp_buf));
						sprintf(netIp, "%s", strtmp);
						RunSystemCmd(NULL_FILE, "route", "add", "-net", netIp, "netmask", mask,"gw", remoteip,NULL_STR);
					}
				}
				else if(wan_type == L2TP){
					apmib_get(MIB_L2TP_SERVER_IP_ADDR,  (void *)tmp_buf);
					strtmp= inet_ntoa(*((struct in_addr *)tmp_buf));
					sprintf(ServerIp, "%s", strtmp);
					serverAddr=((struct in_addr *)tmp_buf)->s_addr;
					
					inet_aton(wanip, &tmpInAddr);
					wanIpAddr=tmpInAddr.s_addr;

					inet_aton(mask, &tmpInAddr);
					maskAddr=tmpInAddr.s_addr;

					inet_aton(remoteip, &tmpInAddr);
					remoteIpAddr=tmpInAddr.s_addr;

					if((serverAddr & maskAddr) != (wanIpAddr & maskAddr)){
						//Patch for our router under another router to dial up pptp
						//let l2tp pkts via pptp default gateway
						netAddr = (serverAddr & maskAddr);
						((struct in_addr *)tmp_buf)->s_addr=netAddr;
						strtmp= inet_ntoa(*((struct in_addr *)tmp_buf));
						sprintf(netIp, "%s", strtmp);
						RunSystemCmd(NULL_FILE, "route", "add", "-net", netIp, "netmask", mask,"gw", remoteip,NULL_STR);
					}
				}
				
				unlink(TEMP_WAN_CHECK);
				unlink(TEMP_WAN_DHCP_INFO);
			}

			if(isFileExist(PPP_CONNECT_FILE)){
				unlink(PPP_CONNECT_FILE);
			}
			
			//start pptp/l2tp dial up
			for(x=0;x<5;x++){
				if(dns_server[x][0] != '\0'){
					sprintf(line,"nameserver %s\n", dns_server[x]);
					if(x==0){
						write_line_to_file(RESOLV_CONF, 1, line);
						
					}else{
						write_line_to_file(RESOLV_CONF, 2, line);
					}
				}
			}
			if(wan_type == PPTP){
				set_pptp(opmode, interface, "br0", wisp_wan_id, 1);
				intValue = getInAddr("ppp0", 0, (void *)&wanaddr);
				if(intValue==1){
				RunSystemCmd(NULL_FILE, "route", "del", "default", NULL_STR);
				strtmp = inet_ntoa(wanaddr);
				sprintf(remoteip, "%s",strtmp); 
				RunSystemCmd(NULL_FILE, "route", "add", "-net", "default", "gw", remoteip, "dev", "ppp0", NULL_STR);
			}
			}
			if(wan_type == L2TP){
				set_l2tp(opmode, interface, "br0", wisp_wan_id, 1);
			}
				
			return;
		}
	}	

#ifdef CONFIG_POCKET_AP_SUPPORT
#else
	printf("WAN Connected\n");
	start_ntp();
	start_ddns();
	start_igmpproxy(interface, "br0");
#endif	//CONFIG_POCKET_AP_SUPPORT
#if defined(ROUTE_SUPPORT)
	del_routing();
	start_routing(interface);
#endif
	start_pppoe_relay();
	if(isFileExist(DHCP_RENEW_TEMP_FILE))
		unlink(DHCP_RENEW_TEMP_FILE);
	if(wan_type == DHCP_CLIENT)
		system("detectWAN &");
}
void wan_disconnect(char *option)
{
	int intValue=0;
	int wan_type=0;
	int Last_WAN_Mode=0;
	FILE *fp;
	if(isFileExist(LAST_WAN_TYPE_FILE)){
		fp= fopen(LAST_WAN_TYPE_FILE, "r");
		if (!fp) {
	        	printf("can not /var/system/last_wan\n");
			return; 
	   	}
		fscanf(fp,"%d",&Last_WAN_Mode);
		fclose(fp);
	}
	RunSystemCmd("/var/disc", "echo", "enter", NULL_STR); 
	
	apmib_get(MIB_WAN_DHCP,(void *)&wan_type);
	
	RunSystemCmd(NULL_FILE, "killall", "-15", "routed", NULL_STR); 
	
	RunSystemCmd(NULL_FILE, "killall", "-9", "ntp_inet", NULL_STR);
	if(isFileExist("/var/ntp_run")){
		unlink("/var/ntp_run");
	} 
	
	RunSystemCmd(NULL_FILE, "killall", "-15", "ddns_inet", NULL_STR); 
	RunSystemCmd(NULL_FILE, "killall", "-9", "updatedd", NULL_STR);
	RunSystemCmd(NULL_FILE, "killall", "-9", "ntpclient", NULL_STR);
	
	#if	defined(CONFIG_DOMAIN_NAME_QUERY_SUPPORT)
		if(!strcmp(option, "all")){
	RunSystemCmd(NULL_FILE, "killall", "-9", "dnrd", NULL_STR);
	if(isFileExist(DNRD_PID_FILE)){
		unlink(DNRD_PID_FILE);
	}
		}else{
			if(isFileExist(PPPLINKFILE)){ //Last state, ppp0 is not connected, we do not kill dnrd
				RunSystemCmd(NULL_FILE, "killall", "-9", "dnrd", NULL_STR);
				if(isFileExist(DNRD_PID_FILE)){
					unlink(DNRD_PID_FILE);
				}
			}
		}
	#else

	RunSystemCmd(NULL_FILE, "killall", "-9", "dnrd", NULL_STR);
	if(isFileExist(DNRD_PID_FILE)){
		unlink(DNRD_PID_FILE);
	}
	#endif
	
	RunSystemCmd(NULL_FILE, "killall", "-9", "igmpproxy", NULL_STR);
	if(isFileExist(IGMPPROXY_PID_FILE)){
		unlink(IGMPPROXY_PID_FILE);
	}
	RunSystemCmd(PROC_BR_MCASTFASTFWD, "echo", "1,0", NULL_STR);
	if(!strcmp(option, "all"))
		RunSystemCmd(NULL_FILE, "killall", "-9", "ppp_inet", NULL_STR); 
	if(Last_WAN_Mode==PPPOE){
		RunSystemCmd(NULL_FILE, "killall", "-15", "pppd", NULL_STR);
	}else{
		RunSystemCmd(NULL_FILE, "killall", "-9", "pppd", NULL_STR);
	}
	sleep(3);

	if((wan_type!=L2TP)&&(Last_WAN_Mode==L2TP)){
		RunSystemCmd(NULL_FILE, "killall", "-9", "l2tpd", NULL_STR);
	}
	RunSystemCmd(NULL_FILE, "killall", "-9", "pptp", NULL_STR);
	RunSystemCmd(NULL_FILE, "killall", "-9", "pppoe", NULL_STR);
	if(isFileExist(PPPD_PID_FILE)){
		unlink(PPPD_PID_FILE);
	} 

	if(wan_type==L2TP && !strcmp(option, "option") && isFileExist(PPPLINKFILE)){
		apmib_get( MIB_L2TP_CONNECTION_TYPE, (void *)&intValue);
		if(intValue==1){
			if(isFileExist("/var/disc_l2tp")){
				system("echo\"d client\" > /var/run/l2tp-control &");
				system("echo \"l2tpdisc\" > /var/disc_l2tp");
			}
		}
	}
/*clean pptp_info in fastpptp*/
	if(wan_type==PPTP)
		system("echo 1 > /proc/fast_pptp");

	if(isFileExist(FIRSTDDNS)){
	 	unlink(FIRSTDDNS);
	}

	if(!strcmp(option, "option") && isFileExist(PPPLINKFILE)){
		RunSystemCmd(NULL_FILE, "rm", "-f", "/etc/ppp/first", NULL_STR);
		RunSystemCmd(NULL_FILE, "rm", "-f", "/etc/ppp/firstpptp", NULL_STR);
		RunSystemCmd(NULL_FILE, "rm", "-f", "/etc/ppp/firstl2tp", NULL_STR);
		RunSystemCmd(NULL_FILE, "rm", "-f", "/etc/ppp/firstdemand", NULL_STR);
	}
	if(isFileExist(PPPLINKFILE)){
	 	unlink(PPPLINKFILE);
	}
	/*in PPPOE and PPTP mode do this in pppd , not here !!*/
	if(wan_type !=PPPOE || strcmp(option, "option")){
		if(isFileExist(PPP_CONNECT_FILE)){
	 		unlink(PPP_CONNECT_FILE);
		}
	}
	if(wan_type==PPTP){
		apmib_get(MIB_PPTP_CONNECTION_TYPE, (void *)&intValue);
		if(intValue==1){
			RunSystemCmd(PROC_PPTP_CONN_FILE, "echo", "3", NULL_STR);
		}else{
			RunSystemCmd(PROC_PPTP_CONN_FILE, "echo", "0", NULL_STR);
		}
	}
	RunSystemCmd(NULL_FILE, "rm", "-f", "/var/disc", NULL_STR);
	RunSystemCmd(NULL_FILE, "rm", "-f", "/var/disc_l2tp", NULL_STR);
	
}

/*write dns server ip address to resolv.conf file and start dnrd
* 
*/
void start_dns_relay(void)
{
	char tmpBuff1[32]={0}, tmpBuff2[32]={0}, tmpBuff3[32]={0};
	int intValue=0;
	char line_buffer[100]={0};
	char tmp1[32]={0}, tmp2[32]={0}, tmp3[32]={0};
	char *strtmp=NULL;
	
	RunSystemCmd(NULL_FILE, "killall", "-9", "dnrd", NULL_STR);
	apmib_get( MIB_DNS1,  (void *)tmpBuff1);
	apmib_get( MIB_DNS2,  (void *)tmpBuff2);
	apmib_get( MIB_DNS3,  (void *)tmpBuff3);
	
	if (memcmp(tmpBuff1, "\x0\x0\x0\x0", 4))
		intValue++;
	if (memcmp(tmpBuff2, "\x0\x0\x0\x0", 4))
		intValue++;
	if (memcmp(tmpBuff3, "\x0\x0\x0\x0", 4))
		intValue++;	
			
	if(intValue==1){
		strtmp= inet_ntoa(*((struct in_addr *)tmpBuff1));
		sprintf(tmp1,"%s",strtmp);
		sprintf(line_buffer,"nameserver %s\n",strtmp);
		write_line_to_file(RESOLV_CONF,1, line_buffer);
		RunSystemCmd(NULL_FILE, "dnrd", "--cache=off", "-s", tmp1, NULL_STR);
		
	}else if(intValue==2){
		strtmp= inet_ntoa(*((struct in_addr *)tmpBuff1));
		sprintf(tmp1,"%s",strtmp);
		sprintf(line_buffer,"nameserver %s\n",strtmp);
		write_line_to_file(RESOLV_CONF,1, line_buffer);
		
		strtmp= inet_ntoa(*((struct in_addr *)tmpBuff2));
		sprintf(tmp2,"%s",strtmp);
		sprintf(line_buffer,"nameserver %s\n", strtmp);
		write_line_to_file(RESOLV_CONF,2, line_buffer);
		RunSystemCmd(NULL_FILE, "dnrd", "--cache=off", "-s", tmp1, "-s", tmp2, NULL_STR);
	}else if(intValue==3){
		strtmp= inet_ntoa(*((struct in_addr *)tmpBuff1));
		sprintf(tmp1,"%s",strtmp);
		sprintf(line_buffer,"nameserver %s\n",strtmp);
		write_line_to_file(RESOLV_CONF,1, line_buffer);
		
		strtmp= inet_ntoa(*((struct in_addr *)tmpBuff2));
		sprintf(tmp2,"%s",strtmp);
		sprintf(line_buffer,"nameserver %s\n", strtmp);
		write_line_to_file(RESOLV_CONF, 2, line_buffer);
		
		strtmp= inet_ntoa(*((struct in_addr *)tmpBuff3));
		sprintf(tmp3,"%s",strtmp);
		sprintf(line_buffer,"nameserver %s\n", strtmp);
		write_line_to_file(RESOLV_CONF, 2, line_buffer);
		
		RunSystemCmd(NULL_FILE, "dnrd", "--cache=off", "-s", tmp1, "-s", tmp2, "-s", tmp3, NULL_STR);
	}else{
		printf("Invalid DNS server setting\n");
	}	
}
void start_upnp_igd(int wantype, int sys_opmode, int wisp_id, char *lan_interface)
{
	int intValue=0;
	char tmp1[16]={0};
	char tmp2[16]={0};
	apmib_get(MIB_UPNP_ENABLED, (void *)&intValue);
	RunSystemCmd(NULL_FILE, "killall", "-15", "miniigd", NULL_STR); 
	if(intValue==1){
		syslog(LOG_NOTICE, " UPnP: start_UPnP");	/*Edison 2011.6.3*/
		RunSystemCmd(NULL_FILE, "route", "del", "-net", "239.255.255.250", "netmask", "255.255.255.255", lan_interface, NULL_STR); 
		RunSystemCmd(NULL_FILE, "route", "add", "-net", "239.255.255.250", "netmask", "255.255.255.255", lan_interface, NULL_STR); 
		sprintf(tmp1, "%d", wantype);
		sprintf(tmp2, "%d", wisp_id);
		if(sys_opmode==2)
			RunSystemCmd(NULL_FILE, "miniigd", "-e", tmp1, "-i", lan_interface, "-w", tmp2, NULL_STR); 
		else	
			RunSystemCmd(NULL_FILE, "miniigd", "-e", tmp1, "-i", lan_interface, NULL_STR); 
		
	}
	
}
void start_ddns(void)
{
	unsigned int ddns_onoff;
	unsigned int ddns_type;
	unsigned char ddns_domanin_name[MAX_DOMAIN_LEN];
	unsigned char ddns_user_name[MAX_DOMAIN_LEN];
	unsigned char ddns_password[MAX_DOMAIN_LEN];

	RunSystemCmd(NULL_FILE, "killall", "-9", "ddns_inet", NULL_STR);
	
	apmib_get( MIB_DDNS_ENABLED,  (void *)&ddns_onoff);

	if(ddns_onoff == 1)
	{

		syslog(LOG_NOTICE, " ddns: start_ddns");	/*Edison 2011.5.31*/

		apmib_get( MIB_DDNS_TYPE,  (void *)&ddns_type);

		apmib_get( MIB_DDNS_DOMAIN_NAME,  (void *)ddns_domanin_name);

		apmib_get( MIB_DDNS_USER,  (void *)ddns_user_name);

		apmib_get( MIB_DDNS_PASSWORD,  (void *)ddns_password);		

		if(ddns_type == 0) // 0:ddns; 1:tzo 2:ZONEEDIT 3:ASUS DDNS	Edison 2011.5.18
			RunSystemCmd(NULL_FILE, "ddns_inet", "-x", "dyndns", ddns_user_name, ddns_password, ddns_domanin_name, NULL_STR);
		else if(ddns_type == 1)
			RunSystemCmd(NULL_FILE, "ddns_inet", "-x", "tzo", ddns_user_name, ddns_password, ddns_domanin_name, NULL_STR);
		else if(ddns_type == 2)
			RunSystemCmd(NULL_FILE, "ddns_inet", "-x", "zoneedit", ddns_user_name, ddns_password, ddns_domanin_name, NULL_STR);
	}

}

#define NTPTMP_FILE "/tmp/ntp_tmp"
#define TZ_FILE "/var/TZ"
void start_ntp(void)
{
	unsigned int ntp_onoff=0;
	unsigned char buffer[500];

	unsigned int ntp_server_id;
	unsigned char	ntp_server[40];
	unsigned int daylight_save = 1;
	unsigned char daylight_save_str[5];
	unsigned char time_zone[8];

	unsigned char command[100], str_datnight[100];
	unsigned char *str_tz1;
	
	apmib_get(MIB_NTP_ENABLED, (void *)&ntp_onoff);
	RunSystemCmd(NULL_FILE, "rm", NTPTMP_FILE, NULL_STR);
	RunSystemCmd(NULL_FILE, "rm", TZ_FILE, NULL_STR);
	if(ntp_onoff == 1)
	{
		RunSystemCmd(NULL_FILE, "echo", "Start NTP daemon", NULL_STR);
		/* prepare requested info for ntp daemon */
		apmib_get( MIB_NTP_SERVER_ID,  (void *)&ntp_server_id);

//2011.5.5 Emily
		
		apmib_get( MIB_NTP_SERVER_IP2,  (void *)&buffer);
		sprintf(ntp_server, "%s", buffer);

		apmib_get( MIB_DAYLIGHT_SAVE,  (void *)&daylight_save);
		memset(daylight_save_str, 0x00, sizeof(daylight_save_str));
		sprintf(daylight_save_str,"%u",daylight_save);
		
		apmib_get( MIB_NTP_TIMEZONE,  (void *)&time_zone);

		if(daylight_save == 0)
			sprintf( str_datnight, "%s", "");
		else if(strcmp(time_zone,"9 1") == 0)
			sprintf( str_datnight, "%s", "PDT,M4.1.0/02:00:00,M10.5.0/02:00:00");
		else if(strcmp(time_zone,"8 1") == 0)
			sprintf( str_datnight, "%s", "PDT,M4.1.0/02:00:00,M10.5.0/02:00:00");
		else if(strcmp(time_zone,"7 2") == 0)
                        sprintf( str_datnight, "%s", "PDT,M4.1.0/02:00:00,M10.5.0/02:00:00");
               else if(strcmp(time_zone,"6 1") == 0)
                        sprintf( str_datnight, "%s", "PDT,M4.1.0/02:00:00,M10.5.0/02:00:00");
               else if(strcmp(time_zone,"6 2") == 0)
                        sprintf( str_datnight, "%s", "PDT,M4.1.0/02:00:00,M10.5.0/02:00:00");
               else if(strcmp(time_zone,"5 2") == 0)
                        sprintf( str_datnight, "%s", "PDT,M4.1.0/02:00:00,M10.5.0/02:00:00");
               else if(strcmp(time_zone,"5 3") == 0)
                        sprintf( str_datnight, "%s", "PDT,M4.1.0/02:00:00,M10.5.0/02:00:00");
               else if(strcmp(time_zone,"4 3") == 0)
                        sprintf( str_datnight, "%s", "PDT,M10.2.0/00:00:00,M3.2.0/00:00:00");
               else if(strcmp(time_zone,"3 1") == 0)
                        sprintf( str_datnight, "%s", "PDT,M4.1.0/00:00:00,M10.5.0/00:00:00");
               else if(strcmp(time_zone,"3 2") == 0)
                        sprintf( str_datnight, "%s", "PDT,M2.2.0/00:00:00,M10.2.0/00:00:00");
               else if(strcmp(time_zone,"1 1") == 0)
                        sprintf( str_datnight, "%s", "PDT,M3.5.0/00:00:00,M10.5.0/01:00:00");
               else if(strcmp(time_zone,"0 2") == 0)
                        sprintf( str_datnight, "%s", "PDT,M3.5.0/01:00:00,M10.5.0/02:00:00");
               else if(strcmp(time_zone,"-1") == 0)
                        sprintf( str_datnight, "%s", "PDT,M3.5.0/02:00:00,M10.5.0/03:00:00");
               else if(strcmp(time_zone,"-2 1") == 0)
                        sprintf( str_datnight, "%s", "PDT,M3.5.0/02:00:00,M10.5.0/03:00:00");
               else if(strcmp(time_zone,"-2 2") == 0)
                        sprintf( str_datnight, "%s", "PDT,M3.5.0/03:00:00,M10.5.0/04:00:00");
               else if(strcmp(time_zone,"-2 3") == 0)
                        sprintf( str_datnight, "%s", "PDT,M4.5.5/00:00:00,M9.5.5/00:00:00");
               else if(strcmp(time_zone,"-2 5") == 0)
                        sprintf( str_datnight, "%s", "PDT,M3.5.0/03:00:00,M10.5.5/04:00:00");
               else if(strcmp(time_zone,"-2 6") == 0)
                        sprintf( str_datnight, "%s", "PDT,M3.5.5/02:00:00,M10.1.0/02:00:00");
               else if(strcmp(time_zone,"-3 2") == 0)
                        sprintf( str_datnight, "%s", "PDT,M3.5.0/02:00:00,M10.5.0/03:00:00");
               else if(strcmp(time_zone,"-4 2") == 0)
                        sprintf( str_datnight, "%s", "PDT,M3.5.0/04:00:00,M10.5.0/05:00:00");
               else if(strcmp(time_zone,"-9 4") == 0)
                        sprintf( str_datnight, "%s", "PDT,M10.5.0/02:00:00,M4.1.0/03:00:00");
               else if(strcmp(time_zone,"-10 2") == 0)
                        sprintf( str_datnight, "%s", "PDT,M10.5.0/02:00:00,M4.1.0/03:00:00");
               else if(strcmp(time_zone,"-10 4") == 0)
                        sprintf( str_datnight, "%s", "PDT,M10.1.0/02:00:00,M4.1.0/03:00:00");
               else if(strcmp(time_zone,"-10 5") == 0)
                        sprintf( str_datnight, "%s", "PDT,M3.5.0/02:00:00,M10.5.0/03:00:00");
               else if(strcmp(time_zone,"-12 1") == 0)
                        sprintf( str_datnight, "%s", "PDT,M3.2.0/03:00:00,M10.1.0/02:00:00");
               else
                        sprintf( str_datnight, "%s", "");

		str_tz1 = gettoken(time_zone, 0, ' ');
		
		if(strcmp(time_zone,"3 1") == 0 ||
			strcmp(time_zone,"-3 4") == 0 ||
		 	strcmp(time_zone,"-4 3") == 0 ||
		 	strcmp(time_zone,"-5 3") == 0 ||
		 	strcmp(time_zone,"-9 4") == 0 ||
		 	strcmp(time_zone,"-9 5") == 0
		)
		{
                       sprintf( command, "GMT%s:30%s", str_tz1, str_datnight);
		}
		else
			sprintf( command, "GMT%s%s", str_tz1, str_datnight); 
		
		RunSystemCmd(NULL_FILE, "ntp_inet", "-x", ntp_server, command, daylight_save_str, NULL_STR);
}



}

#if defined(ROUTE_SUPPORT)
void del_routing(void)
{
	int intValue=0, i;
	char	ip[32], netmask[32], gateway[32], *tmpStr=NULL;	
	int entry_Num=0;
	STATICROUTE_T entry;
	
	apmib_get(MIB_STATICROUTE_TBL_NUM, (void *)&entry_Num);
	if(entry_Num > 0){
		for (i=1; i<=entry_Num; i++) {
			*((char *)&entry) = (char)i;
			apmib_get(MIB_STATICROUTE_TBL, (void *)&entry);
	
			tmpStr = inet_ntoa(*((struct in_addr *)entry.dstAddr));
			sprintf(ip, "%s", tmpStr);
			tmpStr = inet_ntoa(*((struct in_addr *)entry.netmask));
			sprintf(netmask, "%s", tmpStr);
			tmpStr = inet_ntoa(*((struct in_addr *)entry.gateway));
			sprintf(gateway, "%s", tmpStr);
			
			RunSystemCmd(NULL_FILE, "route", "del", "-net", ip, "netmask", netmask, "gw",  gateway, NULL_STR);
		}
	}
	
	
	
}
void start_routing(char *interface)
{
	int intValue=0, i;
	char line_buffer[64]={0};
	char tmp_args[16]={0};
	char	ip[32], netmask[32], gateway[32], *tmpStr=NULL;	
	int entry_Num=0;
	STATICROUTE_T entry;
	int nat_enabled=0, rip_enabled=0, rip_wan_tx=0;
	int rip_wan_rx=0, rip_lan_tx=0, rip_lan_rx=0;
	int start_routed=1;
	
	RunSystemCmd(NULL_FILE, "killall", "-15", "routed", NULL_STR); 
	apmib_get(MIB_NAT_ENABLED, (void *)&nat_enabled);
	apmib_get(MIB_RIP_ENABLED, (void *)&rip_enabled);
	apmib_get(MIB_RIP_LAN_TX, (void *)&rip_lan_tx);
	apmib_get(MIB_RIP_LAN_RX, (void *)&rip_lan_rx);
	apmib_get(MIB_RIP_WAN_TX, (void *)&rip_wan_tx);
	apmib_get(MIB_RIP_WAN_RX, (void *)&rip_wan_rx);
	line_buffer[0]=0x0d;
	line_buffer[1]=0x0a;
	write_line_to_file(ROUTED_CONF_FILE,1, line_buffer);
	memset(line_buffer, 0x00, 64);
	if(nat_enabled==0){
		if(rip_lan_tx !=0 && rip_lan_rx==0){
			sprintf(line_buffer,"network br0 0 %d\n",rip_lan_tx);
			write_line_to_file(ROUTED_CONF_FILE, 2 , line_buffer);
			sprintf(line_buffer,"network %s 0 %d\n",interface, rip_lan_tx);
			write_line_to_file(ROUTED_CONF_FILE, 2 , line_buffer);
			
		}else if(rip_lan_tx !=0 && rip_lan_rx !=0){
				sprintf(line_buffer,"network br0 %d %d\n",rip_lan_rx, rip_lan_tx);
				write_line_to_file(ROUTED_CONF_FILE, 2 , line_buffer);
				sprintf(line_buffer,"network %s %d %d\n",interface, rip_lan_rx, rip_lan_tx);
				write_line_to_file(ROUTED_CONF_FILE, 2 , line_buffer);
			
		}else{
			if( rip_lan_rx !=0){
				sprintf(line_buffer,"network br0 %d 0\n",rip_lan_rx);
				write_line_to_file(ROUTED_CONF_FILE, 2 , line_buffer);
				sprintf(line_buffer,"network %s %d 0\n",interface, rip_lan_rx);
				write_line_to_file(ROUTED_CONF_FILE, 2 , line_buffer);
			}else
				start_routed=0;
		}
	}else{
		if( rip_lan_rx !=0){
			sprintf(line_buffer,"network br0 %d 0\n",rip_lan_rx);
			write_line_to_file(ROUTED_CONF_FILE, 2 , line_buffer);
			sprintf(line_buffer,"network %s %d 0\n",interface, rip_lan_rx);
			write_line_to_file(ROUTED_CONF_FILE, 2 , line_buffer);
		}else
			start_routed=0;
	}
	apmib_get(MIB_STATICROUTE_ENABLED, (void *)&intValue);
	apmib_get(MIB_STATICROUTE_TBL_NUM, (void *)&entry_Num);
	if(intValue > 0 && entry_Num > 0){
		for (i=1; i<=entry_Num; i++) {
			*((char *)&entry) = (char)i;
			apmib_get(MIB_STATICROUTE_TBL, (void *)&entry);
	
			tmpStr = inet_ntoa(*((struct in_addr *)entry.dstAddr));
			sprintf(ip, "%s", tmpStr);
			tmpStr = inet_ntoa(*((struct in_addr *)entry.netmask));
			sprintf(netmask, "%s", tmpStr);
			tmpStr = inet_ntoa(*((struct in_addr *)entry.gateway));
			sprintf(gateway, "%s", tmpStr);
			sprintf(tmp_args, "%d", entry.metric);
			if(!strcmp(interface, "ppp0")){
				if(entry.interface==1){//wan interface
					RunSystemCmd(NULL_FILE, "route", "add", "-net", ip, "netmask", netmask, "metric", tmp_args, "dev", interface,  NULL_STR);
				}else{
					RunSystemCmd(NULL_FILE, "route", "add", "-net", ip, "netmask", netmask, "gw",  gateway, "metric", tmp_args, "dev", "br0",  NULL_STR);
				}
			}else{
				if(entry.interface==1){//wan interface
					RunSystemCmd(NULL_FILE, "route", "add", "-net", ip, "netmask", netmask, "gw",  gateway, "metric", tmp_args, "dev", interface,  NULL_STR);
				}else if(entry.interface==0){
					RunSystemCmd(NULL_FILE, "route", "add", "-net", ip, "netmask", netmask, "gw",  gateway, "metric", tmp_args, "dev", "br0",  NULL_STR);
				}
			}
		}
	}
	
	if(rip_enabled !=0 && start_routed==1)
		RunSystemCmd(NULL_FILE, "routed", "-s",  NULL_STR);
	
	if(nat_enabled==0){
		if(isFileExist(IGMPPROXY_PID_FILE)){
			unlink(IGMPPROXY_PID_FILE);
		}
		RunSystemCmd(NULL_FILE, "killall", "-9", "igmpproxy", NULL_STR);
		RunSystemCmd(PROC_BR_MCASTFASTFWD, "echo", "1,0", NULL_STR);
	}
}
#endif

void start_igmpproxy(char *wan_iface, char *lan_iface)
{
	int intValue=0;
	apmib_get(MIB_IGMP_PROXY_DISABLED, (void *)&intValue);
	RunSystemCmd(NULL_FILE, "killall", "-9", "igmpproxy", NULL_STR);
	RunSystemCmd(PROC_BR_MCASTFASTFWD, "echo", "1,0", NULL_STR);
	if(intValue==0) {
		RunSystemCmd(NULL_FILE, "igmpproxy", wan_iface, lan_iface, NULL_STR);
		RunSystemCmd(PROC_IGMP_MAX_MEMBERS, "echo", "128", NULL_STR);
		RunSystemCmd(PROC_BR_MCASTFASTFWD, "echo", "1,1", NULL_STR);
	}
	
}
void start_wan_dhcp_client(char *iface)
{
	char hostname[100];
	char cmdBuff[200];
	char script_file[100], deconfig_script[100], pid_file[100];
	
	sprintf(script_file, "/usr/share/udhcpc/%s.sh", iface); /*script path*/
	sprintf(deconfig_script, "/usr/share/udhcpc/%s.deconfig", iface);/*deconfig script path*/
	sprintf(pid_file, "/etc/udhcpc/udhcpc-%s.pid", iface); /*pid path*/
	Create_script(deconfig_script, iface, WAN_NETWORK, 0, 0, 0);
	memset(hostname, 0x00, 100);
	apmib_get( MIB_HOST_NAME, (void *)&hostname);
	
	if(hostname[0]){
		sprintf(cmdBuff, "udhcpc -i %s -p %s -s %s -h %s -a 30 &", iface, pid_file, script_file, hostname);
	}else{
		sprintf(cmdBuff, "udhcpc -i %s -p %s -s %s -a 30 &", iface, pid_file, script_file);
	}
	system(cmdBuff);
}
void set_staticIP(int sys_op, char *wan_iface, char *lan_iface, int wisp_id, int act_source)
{
	int intValue=0;
	char tmpBuff[200];
	char tmp_args[16];
	char Ip[32], Mask[32], Gateway[32];
	
	apmib_get( MIB_WAN_IP_ADDR,  (void *)tmpBuff);
	sprintf(Ip, "%s", inet_ntoa(*((struct in_addr *)tmpBuff)));
	apmib_get( MIB_WAN_SUBNET_MASK,  (void *)tmpBuff);
	sprintf(Mask, "%s", inet_ntoa(*((struct in_addr *)tmpBuff)));
	apmib_get(MIB_WAN_DEFAULT_GATEWAY,  (void *)tmpBuff);
				
	if (!memcmp(tmpBuff, "\x0\x0\x0\x0", 4))
		memset(Gateway, 0x00, 32);
	else
		sprintf(Gateway, "%s", inet_ntoa(*((struct in_addr *)tmpBuff)));
			
	RunSystemCmd(NULL_FILE, "ifconfig", wan_iface, Ip, "netmask", Mask, NULL_STR);
		
	if(Gateway[0]){
		RunSystemCmd(NULL_FILE, "route", "del", "default", wan_iface, NULL_STR);
		RunSystemCmd(NULL_FILE, "route", "add", "-net", "default", "gw", Gateway, "dev", wan_iface, NULL_STR);
	}	
		apmib_get(MIB_FIXED_IP_MTU_SIZE, (void *)&intValue);
		sprintf(tmp_args, "%d", intValue);
		RunSystemCmd(NULL_FILE, "ifconfig", wan_iface, "mtu", tmp_args, NULL_STR);
		start_dns_relay();
		start_upnp_igd(DHCP_DISABLED, sys_op, wisp_id, lan_iface);
		setFirewallIptablesRules(0, NULL);
		
		start_ntp();
		start_ddns();
		start_igmpproxy(wan_iface, lan_iface);
#if defined(ROUTE_SUPPORT)
		del_routing();
		start_routing(wan_iface);
		start_pppoe_relay();

#endif
}
void set_dhcp_client(int sys_op, char *wan_iface, char *lan_iface, int wisp_id, int act_source)
{
	int intValue=0;
	char tmp_args[16];
	
	apmib_get(MIB_DHCP_MTU_SIZE, (void *)&intValue);
	sprintf(tmp_args, "%d", intValue);
	RunSystemCmd(NULL_FILE, "ifconfig", wan_iface, "mtu", tmp_args, NULL_STR);
	start_wan_dhcp_client(wan_iface);
	start_upnp_igd(DHCP_CLIENT, sys_op, wisp_id, lan_iface);
	start_pppoe_relay();
}
void set_pppoe(int sys_op, char *wan_iface, char *lan_iface, int wisp_id, int act_source)
{
	int intValue=0, cmdRet=-1;
	char line_buffer[100]={0};
	char tmp_args[64]={0};
	char tmp_args1[32]={0};
	int connect_type=0, idle_time=0;
	
	RunSystemCmd(NULL_FILE, "ifconfig", wan_iface, "0.0.0.0", NULL_STR);
	cmdRet = RunSystemCmd(NULL_FILE, "flash", "gen-pppoe", PPP_OPTIONS_FILE, PPP_PAP_FILE, PPP_CHAP_FILE,NULL_STR);
	
	if(cmdRet==0){
		sprintf(line_buffer,"%s\n", "noauth");
		write_line_to_file(PPP_OPTIONS_FILE,2, line_buffer);
		sprintf(line_buffer,"%s\n", "nomppc");
		write_line_to_file(PPP_OPTIONS_FILE,2, line_buffer);
		sprintf(line_buffer,"%s\n", "noipdefault");
		write_line_to_file(PPP_OPTIONS_FILE,2, line_buffer);
		sprintf(line_buffer,"%s\n", "hide-password");
		write_line_to_file(PPP_OPTIONS_FILE,2, line_buffer);
		sprintf(line_buffer,"%s\n", "defaultroute");
		write_line_to_file(PPP_OPTIONS_FILE,2, line_buffer);
		sprintf(line_buffer,"%s\n", "persist");
		write_line_to_file(PPP_OPTIONS_FILE,2, line_buffer);
		sprintf(line_buffer,"%s\n", "ipcp-accept-remote");
		write_line_to_file(PPP_OPTIONS_FILE,2, line_buffer);
		sprintf(line_buffer,"%s\n", "ipcp-accept-local");
		write_line_to_file(PPP_OPTIONS_FILE,2, line_buffer);
		sprintf(line_buffer,"%s\n", "nodetach");
		write_line_to_file(PPP_OPTIONS_FILE,2, line_buffer);
		sprintf(line_buffer,"%s\n", "usepeerdns");
		write_line_to_file(PPP_OPTIONS_FILE,2, line_buffer);
		
		apmib_get(MIB_PPP_MTU_SIZE, (void *)&intValue);
		sprintf(line_buffer,"mtu %d\n", intValue);
		write_line_to_file(PPP_OPTIONS_FILE,2, line_buffer);
		sprintf(line_buffer,"mru %d\n", intValue);
		write_line_to_file(PPP_OPTIONS_FILE,2, line_buffer);
		sprintf(line_buffer,"%s\n", "lcp-echo-interval 20");
		write_line_to_file(PPP_OPTIONS_FILE,2, line_buffer);
		sprintf(line_buffer,"%s\n", "lcp-echo-failure 3");
		write_line_to_file(PPP_OPTIONS_FILE,2, line_buffer);
		sprintf(line_buffer,"%s\n", "wantype 3");
		write_line_to_file(PPP_OPTIONS_FILE,2, line_buffer);
		sprintf(line_buffer,"%s\n", "holdoff 10");
		write_line_to_file(PPP_OPTIONS_FILE,2, line_buffer);
		apmib_get( MIB_PPP_SERVICE_NAME,  (void *)tmp_args);
		if(tmp_args[0]){
			sprintf(line_buffer,"plugin /etc/ppp/plubins/libplugin.a rp_pppoe_service %s %s\n",tmp_args, wan_iface);
		}else{
			sprintf(line_buffer,"plugin /etc/ppp/plubins/libplugin.a %s\n", wan_iface);
		}
		write_line_to_file(PPP_OPTIONS_FILE,2, line_buffer);
		
		apmib_get(MIB_PPP_CONNECT_TYPE, (void *)&connect_type);
		if(connect_type==1){
			apmib_get(MIB_PPP_IDLE_TIME, (void *)&idle_time);
			sprintf(line_buffer,"%s\n", "demand");
			write_line_to_file(PPP_OPTIONS_FILE,2, line_buffer);
			sprintf(line_buffer,"idle %d\n", idle_time);
			write_line_to_file(PPP_OPTIONS_FILE,2, line_buffer);
		}else if(connect_type==2 && act_source==1) //manual mode we do not dial up from init.sh
				return;
			
		if(isFileExist(PPP_FILE)){
			unlink(PPP_FILE);
		} 
		sprintf(tmp_args, "%s", "3");/*wan type*/
		sprintf(tmp_args1, "%d", connect_type);/*connect type*/
		RunSystemCmd(NULL_FILE, "ppp_inet", "-t", tmp_args,  "-c", tmp_args1, "-x", NULL_STR);
		start_upnp_igd(PPPOE, sys_op, wisp_id, lan_iface);
		start_pppoe_relay();
		
	}
}

int getPPTPConnect()
{
        
      	FILE *fp;
        char c=0;
        fp=fopen(PPPConnectFILE, "r");

	if (fp != NULL)
        {
        	while((c=fgetc(fp))!=EOF)
		{
          		fclose(fp);	  		
			return c;
		}
	}
	else
		return 0;

}

void set_pptp(int sys_op, char *wan_iface, char *lan_iface, int wisp_id, int act_source)
{
	int intValue=0, intValue1=0, cmdRet=-1;
	char line_buffer[100]={0};
	char tmp_args[64]={0};
	char tmp_args1[32]={0};
	char Ip[32], Mask[32], ServerIp[32];
	int connect_type=0, idle_time=0;
	char *strtmp=NULL;
	int refuse_eap = 0;	//2011.04.20 Jerry

	char pptpDefGw[32], netIp[32];
	unsigned int ipAddr, netAddr, netMask, serverAddr;
	int pptp_wanip_dynamic=0;
	
	apmib_get(MIB_PPTP_WAN_IP_DYNAMIC, (void *)&pptp_wanip_dynamic);

	apmib_get(MIB_PPTP_SERVER_IP_ADDR,  (void *)tmp_args);
	strtmp= inet_ntoa(*((struct in_addr *)tmp_args));
	sprintf(ServerIp, "%s", strtmp);
	serverAddr=((struct in_addr *)tmp_args)->s_addr;
	
	if(pptp_wanip_dynamic==STATIC_IP){	//pptp use static wan ip
		apmib_get(MIB_PPTP_IP_ADDR,  (void *)tmp_args);
		strtmp= inet_ntoa(*((struct in_addr *)tmp_args));
		sprintf(Ip, "%s", strtmp);
		ipAddr=((struct in_addr *)tmp_args)->s_addr;
	
		apmib_get(MIB_PPTP_SUBNET_MASK,  (void *)tmp_args);
		strtmp= inet_ntoa(*((struct in_addr *)tmp_args));
		sprintf(Mask, "%s", strtmp);
		netMask=((struct in_addr *)tmp_args)->s_addr;

		apmib_get(MIB_PPTP_DEFAULT_GW,  (void *)tmp_args);
		strtmp= inet_ntoa(*((struct in_addr *)tmp_args));
		sprintf(pptpDefGw, "%s", strtmp);
	
		RunSystemCmd(NULL_FILE, "ifconfig", wan_iface, Ip, "netmask", Mask, NULL_STR);
		RunSystemCmd(NULL_FILE, "route", "del", "default", "gw", "0.0.0.0", NULL_STR);

		if((serverAddr & netMask) != (ipAddr & netMask)){
			//Patch for our router under another router to dial up pptp
			//let pptp dialing pkt via pptp default gateway
			netAddr = (serverAddr & netMask);
			((struct in_addr *)tmp_args)->s_addr=netAddr;
			strtmp= inet_ntoa(*((struct in_addr *)tmp_args));
			sprintf(netIp, "%s", strtmp);
			RunSystemCmd(NULL_FILE, "route", "add", "-net", netIp, "netmask", Mask,"gw", pptpDefGw,NULL_STR);
		}
	}
	
	cmdRet = RunSystemCmd(NULL_FILE, "flash", "gen-pptp", PPP_OPTIONS_FILE, PPP_PAP_FILE, PPP_CHAP_FILE,NULL_STR);
	
	if(cmdRet==0){

		sprintf(line_buffer,"%s\n", "lock");
		write_line_to_file(PPP_OPTIONS_FILE,2, line_buffer);
		//2011.04.20 Jerry {
		apmib_get(MIB_REFUSE_EAP, (void *)&refuse_eap);
		if(refuse_eap == 1)
			sprintf(line_buffer,"%s\n", "noauth refuse-eap");
		else
			sprintf(line_buffer,"%s\n", "noauth");
		//2011.04.20 Jerry {
		write_line_to_file(PPP_OPTIONS_FILE,2, line_buffer);
		
		sprintf(line_buffer,"%s\n", "nobsdcomp");
		write_line_to_file(PPP_OPTIONS_FILE,2, line_buffer);
		
		sprintf(line_buffer,"%s\n", "nodeflate");
		write_line_to_file(PPP_OPTIONS_FILE,2, line_buffer);
		
		sprintf(line_buffer,"%s\n", "usepeerdns");
		write_line_to_file(PPP_OPTIONS_FILE,2, line_buffer);
		
		sprintf(line_buffer,"%s\n", "lcp-echo-interval 20");
		write_line_to_file(PPP_OPTIONS_FILE,2, line_buffer);
		
		sprintf(line_buffer,"%s\n", "lcp-echo-failure 3");
		write_line_to_file(PPP_OPTIONS_FILE,2, line_buffer);
		
		sprintf(line_buffer,"%s\n", "wantype 4");
		write_line_to_file(PPP_OPTIONS_FILE,2, line_buffer);
		
		apmib_get(MIB_PPTP_MTU_SIZE, (void *)&intValue);
		sprintf(line_buffer,"mtu %d\n", intValue);
		write_line_to_file(PPP_OPTIONS_FILE,2, line_buffer);
		
		sprintf(line_buffer,"%s\n", "holdoff 2");
		write_line_to_file(PPP_OPTIONS_FILE,2, line_buffer);
		
		sprintf(line_buffer,"%s\n", "refuse-eap");
		write_line_to_file(PPP_OPTIONS_FILE,2, line_buffer);
		
		sprintf(line_buffer,"%s\n", "remotename PPTP");
		write_line_to_file(PPTP_PEERS_FILE,1, line_buffer);
		
		sprintf(line_buffer,"%s\n", "linkname PPTP");
		write_line_to_file(PPTP_PEERS_FILE,2, line_buffer);
		
		sprintf(line_buffer,"%s\n", "ipparam PPTP");
		write_line_to_file(PPTP_PEERS_FILE,2, line_buffer);
		
		sprintf(tmp_args, "pty \"pptp %s --nolaunchpppd\"", ServerIp);
		sprintf(line_buffer,"%s\n", tmp_args);
		write_line_to_file(PPTP_PEERS_FILE,2, line_buffer);
		
		apmib_get( MIB_PPTP_USER_NAME,  (void *)tmp_args);
		sprintf(line_buffer,"name %s\n", tmp_args);
		write_line_to_file(PPTP_PEERS_FILE,2, line_buffer);
		
		apmib_get( MIB_PPTP_SECURITY_ENABLED, (void *)&intValue);
		if(intValue==1){
			sprintf(line_buffer,"%s\n", "+mppe required,stateless");
			write_line_to_file(PPTP_PEERS_FILE,2, line_buffer);
			
		}
		apmib_get( MIB_PPTP_MPPC_ENABLED, (void *)&intValue1);
		if(intValue1==1){
			sprintf(line_buffer,"%s\n", "mppc");
			write_line_to_file(PPTP_PEERS_FILE,2, line_buffer);
			sprintf(line_buffer,"%s\n", "stateless");
			write_line_to_file(PPTP_PEERS_FILE,2, line_buffer);
		}else{
			sprintf(line_buffer,"%s\n", "nomppc");
			write_line_to_file(PPTP_PEERS_FILE,2, line_buffer);
		}
		if(intValue ==0 && intValue1==0){
			sprintf(line_buffer,"%s\n", "noccp");
			write_line_to_file(PPTP_PEERS_FILE,2, line_buffer);
		}
		
		sprintf(line_buffer,"%s\n", "persist");
		write_line_to_file(PPTP_PEERS_FILE,2, line_buffer);
		
		//2011.04.20 Jerry {
		apmib_get(MIB_REFUSE_EAP, (void *)&refuse_eap);
		if(refuse_eap == 1)
			sprintf(line_buffer,"%s\n", "noauth refuse-eap");
		else
			sprintf(line_buffer,"%s\n", "noauth");
		//2011.04.20 Jerry {
		write_line_to_file(PPTP_PEERS_FILE,2, line_buffer);
		
		sprintf(line_buffer,"%s\n", "file /etc/ppp/options");
		write_line_to_file(PPTP_PEERS_FILE,2, line_buffer);
		
		sprintf(line_buffer,"%s\n", "nobsdcomp");
		write_line_to_file(PPTP_PEERS_FILE,2, line_buffer);
		
		sprintf(line_buffer,"%s\n", "nodetach");
		write_line_to_file(PPTP_PEERS_FILE,2, line_buffer);
		
		sprintf(line_buffer,"%s\n", "novj");
		write_line_to_file(PPTP_PEERS_FILE,2, line_buffer);
		
		
		apmib_get(MIB_PPTP_CONNECTION_TYPE, (void *)&connect_type);
		if(connect_type==1){			
			sprintf(line_buffer,"%s\n", "persist");
			write_line_to_file(PPP_OPTIONS_FILE,2, line_buffer);
			
			sprintf(line_buffer,"%s\n", "nodetach");
			write_line_to_file(PPP_OPTIONS_FILE,2, line_buffer);
			
			sprintf(line_buffer,"%s\n", "connect /etc/ppp/true");
			write_line_to_file(PPP_OPTIONS_FILE,2, line_buffer);
			
			sprintf(line_buffer,"%s\n", "demand");
			write_line_to_file(PPP_OPTIONS_FILE,2, line_buffer);
			
			apmib_get(MIB_PPTP_IDLE_TIME, (void *)&idle_time);
			sprintf(line_buffer,"idle %d\n", idle_time);
			write_line_to_file(PPP_OPTIONS_FILE,2, line_buffer);
			
			sprintf(line_buffer,"%s\n", "ktune");
			write_line_to_file(PPP_OPTIONS_FILE,2, line_buffer);
			
			sprintf(line_buffer,"%s\n", "ipcp-accept-remote");
			write_line_to_file(PPP_OPTIONS_FILE,2, line_buffer);
			
			sprintf(line_buffer,"%s\n", "ipcp-accept-local");
			write_line_to_file(PPP_OPTIONS_FILE,2, line_buffer);
			
			sprintf(line_buffer,"%s\n", "noipdefault");
			write_line_to_file(PPP_OPTIONS_FILE,2, line_buffer);
			
			sprintf(line_buffer,"%s\n", "hide-password");
			write_line_to_file(PPP_OPTIONS_FILE,2, line_buffer);
			
			sprintf(line_buffer,"%s\n", "defaultroute");
			write_line_to_file(PPP_OPTIONS_FILE,2, line_buffer);
		}else if(connect_type==2 && act_source==1) //manual mode we do not dial up from init.sh
		{
			if(isFileExist(PPP_FILE)){
			unlink(PPP_FILE);
			} 
			
			sprintf(tmp_args, "%s", "4");/*wan type*/
			sprintf(tmp_args1, "%d", connect_type);/*connect type*/

			if(getPPTPConnect()=='1')
				RunSystemCmd(NULL_FILE, "ppp_inet", "-t", tmp_args,  "-c", tmp_args1, "-x", NULL_STR);

			if(isFileExist(PPPConnectFILE))
				unlink(PPPConnectFILE);
 			
			start_upnp_igd(PPTP, sys_op, wisp_id, lan_iface);
			start_pppoe_relay();
			return;
		}

	
		if(isFileExist(PPP_FILE)){
			unlink(PPP_FILE);
		} 
		sprintf(tmp_args, "%s", "4");/*wan type*/
		sprintf(tmp_args1, "%d", connect_type);/*connect type*/

		RunSystemCmd(NULL_FILE, "ppp_inet", "-t", tmp_args,  "-c", tmp_args1, "-x", NULL_STR);
	}
	start_upnp_igd(PPTP, sys_op, wisp_id, lan_iface);
	start_pppoe_relay();
}

void set_l2tp(int sys_op, char *wan_iface, char *lan_iface, int wisp_id, int act_source)
{
	int intValue=0;
	char line_buffer[100]={0};
	char tmp_args[64]={0};
	char tmp_args1[32]={0};
	char Ip[32], Mask[32], ServerIp[32];
	int connect_type=0, idle_time=0;
	char *strtmp=NULL;
	int pwd_len=0;
	int refuse_eap = 0;	//2011.04.20 Jerry

	char l2tpDefGw[32], netIp[32];
	unsigned int ipAddr, netAddr, netMask, serverAddr;
	int l2tp_wanip_dynamic=0;
	
	apmib_get(MIB_L2TP_WAN_IP_DYNAMIC, (void *)&l2tp_wanip_dynamic);

	apmib_get(MIB_L2TP_SERVER_IP_ADDR,  (void *)tmp_args);
	strtmp= inet_ntoa(*((struct in_addr *)tmp_args));
	sprintf(ServerIp, "%s", strtmp);
	serverAddr=((struct in_addr *)tmp_args)->s_addr;

	if(l2tp_wanip_dynamic==STATIC_IP){//l2tp use static wan ip

		apmib_get(MIB_L2TP_IP_ADDR,  (void *)tmp_args);
		strtmp= inet_ntoa(*((struct in_addr *)tmp_args));
		sprintf(Ip, "%s", strtmp);
		ipAddr=((struct in_addr *)tmp_args)->s_addr;
		
		apmib_get(MIB_L2TP_SUBNET_MASK,  (void *)tmp_args);
		strtmp= inet_ntoa(*((struct in_addr *)tmp_args));
		sprintf(Mask, "%s", strtmp);
		netMask=((struct in_addr *)tmp_args)->s_addr;
	
		apmib_get(MIB_L2TP_DEFAULT_GW,  (void *)tmp_args);
		strtmp= inet_ntoa(*((struct in_addr *)tmp_args));
		sprintf(l2tpDefGw, "%s", strtmp);
	
		RunSystemCmd(NULL_FILE, "ifconfig", wan_iface, Ip, "netmask", Mask, NULL_STR);
		RunSystemCmd(NULL_FILE, "route", "del", "default", "gw", "0.0.0.0", NULL_STR);
		
		if((serverAddr & netMask) != (ipAddr & netMask)){
			//Patch for our router under another router to dial up l2tp
			//let l2tp dialing pkt via l2tp default gateway
			netAddr = (serverAddr & netMask);
			((struct in_addr *)tmp_args)->s_addr=netAddr;
			strtmp= inet_ntoa(*((struct in_addr *)tmp_args));
			sprintf(netIp, "%s", strtmp);
			RunSystemCmd(NULL_FILE, "route", "add", "-net", netIp, "netmask", Mask,"gw", l2tpDefGw,NULL_STR);
		}
	}
	


	apmib_get( MIB_L2TP_USER_NAME,  (void *)tmp_args);
	apmib_get( MIB_L2TP_PASSWORD,  (void *)tmp_args1);
	pwd_len = strlen(tmp_args1);
	/*options file*/
	sprintf(line_buffer,"user \"%s\"\n",tmp_args);
	write_line_to_file(PPP_OPTIONS_FILE, 1, line_buffer);
	
	/*secrets files*/
	sprintf(line_buffer,"%s\n","#################################################");
	write_line_to_file(PPP_PAP_FILE, 1, line_buffer);
	
	sprintf(line_buffer, "\"%s\"	*	\"%s\"\n",tmp_args, tmp_args1);
	write_line_to_file(PPP_PAP_FILE, 2, line_buffer);
	
	sprintf(line_buffer,"%s\n","#################################################");
	write_line_to_file(PPP_CHAP_FILE, 1, line_buffer);
	
	sprintf(line_buffer, "\"%s\"	*	\"%s\"\n",tmp_args, tmp_args1);
	write_line_to_file(PPP_CHAP_FILE, 2, line_buffer);
	
	sprintf(line_buffer,"%s\n", "lock");
	write_line_to_file(PPP_OPTIONS_FILE,2, line_buffer);
	//2011.04.20 Jerry {
	apmib_get(MIB_REFUSE_EAP, (void *)&refuse_eap);
	if(refuse_eap == 1)
		sprintf(line_buffer,"%s\n", "noauth refuse-eap");
	else
		sprintf(line_buffer,"%s\n", "noauth");
	//2011.04.20 Jerry {
	write_line_to_file(PPP_OPTIONS_FILE,2, line_buffer);
	sprintf(line_buffer,"%s\n", "defaultroute");
	write_line_to_file(PPP_OPTIONS_FILE,2, line_buffer);
	sprintf(line_buffer,"%s\n", "usepeerdns");
	write_line_to_file(PPP_OPTIONS_FILE,2, line_buffer);
	sprintf(line_buffer,"%s\n", "lcp-echo-interval 0");
	write_line_to_file(PPP_OPTIONS_FILE,2, line_buffer);
	sprintf(line_buffer,"%s\n", "wantype 6");
	write_line_to_file(PPP_OPTIONS_FILE,2, line_buffer);
	
	apmib_get(MIB_L2TP_MTU_SIZE, (void *)&intValue);
	sprintf(line_buffer,"mtu %d\n", intValue);
	write_line_to_file(PPP_OPTIONS_FILE,2, line_buffer);
	
	apmib_get( MIB_L2TP_USER_NAME,  (void *)tmp_args);
	sprintf(line_buffer,"name %s\n", tmp_args);
	write_line_to_file(PPP_OPTIONS_FILE,2, line_buffer);	
	
	sprintf(line_buffer,"%s\n", "nodeflate");
	write_line_to_file(PPP_OPTIONS_FILE,2, line_buffer);
	
	sprintf(line_buffer,"%s\n", "nobsdcomp");
	write_line_to_file(PPP_OPTIONS_FILE,2, line_buffer);
	
	sprintf(line_buffer,"%s\n", "nodetach");
	write_line_to_file(PPP_OPTIONS_FILE,2, line_buffer);
	
	sprintf(line_buffer,"%s\n", "novj");
	write_line_to_file(PPP_OPTIONS_FILE,2, line_buffer);
	
	sprintf(line_buffer,"%s\n", "default-asyncmap");
	write_line_to_file(PPP_OPTIONS_FILE,2, line_buffer);
	
	sprintf(line_buffer,"%s\n", "nopcomp");
	write_line_to_file(PPP_OPTIONS_FILE,2, line_buffer);
	
	sprintf(line_buffer,"%s\n", "noaccomp");
	write_line_to_file(PPP_OPTIONS_FILE,2, line_buffer);
	
	sprintf(line_buffer,"%s\n", "noccp");
	write_line_to_file(PPP_OPTIONS_FILE,2, line_buffer);
	
	sprintf(line_buffer,"%s\n", "novj");
	write_line_to_file(PPP_OPTIONS_FILE,2, line_buffer);

	sprintf(line_buffer,"%s\n", "refuse-eap");
	write_line_to_file(PPP_OPTIONS_FILE,2, line_buffer);
	
	if(pwd_len > 35){
		sprintf(line_buffer,"%s\n", "-mschap");
		write_line_to_file(PPP_OPTIONS_FILE,2, line_buffer);
		
		sprintf(line_buffer,"%s\n", "-mschap-v2");
		write_line_to_file(PPP_OPTIONS_FILE,2, line_buffer);
	}
	
	sprintf(line_buffer,"%s\n", "[global]");
	write_line_to_file(L2TPCONF,1, line_buffer);
	
	sprintf(line_buffer,"%s\n", "port = 1701");
	write_line_to_file(L2TPCONF,2, line_buffer);
	
	sprintf(line_buffer,"auth file = %s\n", PPP_CHAP_FILE);
	write_line_to_file(L2TPCONF,2, line_buffer);
	
	sprintf(line_buffer,"%s\n", "[lac client]");
	write_line_to_file(L2TPCONF,2, line_buffer);
	
	sprintf(line_buffer,"lns=%s\n", ServerIp);
	write_line_to_file(L2TPCONF,2, line_buffer);

	sprintf(line_buffer,"%s\n", "require chap = yes");
	write_line_to_file(L2TPCONF,2, line_buffer);
	
	apmib_get( MIB_L2TP_USER_NAME,  (void *)tmp_args);
	sprintf(line_buffer,"name = %s\n", tmp_args);
	write_line_to_file(L2TPCONF,2, line_buffer);
	
	sprintf(line_buffer,"%s\n", "pppoptfile = /etc/ppp/options");
	write_line_to_file(L2TPCONF, 2, line_buffer);

	RunSystemCmd(NULL_FILE, "killall", "l2tpd", NULL_STR);
	sleep(1);	
	system("l2tpd&");
	sleep(3);
	
	apmib_get(MIB_L2TP_CONNECTION_TYPE, (void *)&connect_type);
	if(connect_type==1){
			
		sprintf(line_buffer,"%s\n", "connect /etc/ppp/true");
		write_line_to_file(PPP_OPTIONS_FILE,2, line_buffer);
			
		sprintf(line_buffer,"%s\n", "demand");
		write_line_to_file(PPP_OPTIONS_FILE,2, line_buffer);
			
		apmib_get(MIB_L2TP_IDLE_TIME, (void *)&idle_time);
		sprintf(line_buffer,"idle %d\n", idle_time);
		write_line_to_file(PPP_OPTIONS_FILE,2, line_buffer);
			
		}else if(connect_type==2 && act_source==1) //manual mode we do not dial up from init.sh
		{
			
			if(isFileExist(PPP_FILE)){
			unlink(PPP_FILE);
		}

			sprintf(tmp_args, "%s", "6");/*wan type*/
			sprintf(tmp_args1, "%d", connect_type);/*connect type*/

			if(getPPTPConnect()=='1')
			{
				RunSystemCmd(NULL_FILE, "ppp_inet", "-t", tmp_args,  "-c", tmp_args1, "-x", NULL_STR);
			}

			if(isFileExist(PPPConnectFILE))
				unlink(PPPConnectFILE);
				
			start_upnp_igd(L2TP, sys_op, wisp_id, lan_iface);
			start_pppoe_relay();	
			return;
		}
			
		if(isFileExist(PPP_FILE)){
			unlink(PPP_FILE);
		} 
		sprintf(tmp_args, "%s", "6");/*wan type*/
		sprintf(tmp_args1, "%d", connect_type);/*connect type*/
		RunSystemCmd(NULL_FILE, "ppp_inet", "-t", tmp_args,  "-c", tmp_args1, "-x", NULL_STR);
		start_upnp_igd(L2TP, sys_op, wisp_id, lan_iface);
		start_pppoe_relay();
}
int start_wan(int wan_mode, int sys_op, char *wan_iface, char *lan_iface, int wisp_id, int act_source)
{
	int pptp_wanip_dynamic=0, l2tp_wanip_dynamic=0;

	printf("Init WAN Interface...\n");
	
	if(wan_mode == DHCP_DISABLED)
		set_staticIP(sys_op, wan_iface, lan_iface, wisp_id, act_source);
	else if(wan_mode == DHCP_CLIENT)
		set_dhcp_client(sys_op, wan_iface, lan_iface, wisp_id, act_source);
	else if(wan_mode == PPPOE){
		set_pppoe(sys_op, wan_iface, lan_iface, wisp_id, act_source);
	}else if(wan_mode == PPTP){
		apmib_get(MIB_PPTP_WAN_IP_DYNAMIC, (void *)&pptp_wanip_dynamic);
		if(pptp_wanip_dynamic==STATIC_IP){
			set_pptp(sys_op, wan_iface, lan_iface, wisp_id, act_source);
		}else{
			{
				RunSystemCmd(TEMP_WAN_CHECK, "echo", "dhcpc", NULL_STR);
				set_dhcp_client(sys_op, wan_iface, lan_iface, wisp_id, act_source);
			}
		}
	}else if(wan_mode == L2TP){
		apmib_get(MIB_L2TP_WAN_IP_DYNAMIC, (void *)&l2tp_wanip_dynamic);
		if(l2tp_wanip_dynamic==STATIC_IP){
			set_l2tp(sys_op, wan_iface, lan_iface, wisp_id, act_source);
		}else{
			{
				RunSystemCmd(TEMP_WAN_CHECK, "echo", "dhcpc", NULL_STR);	
				set_dhcp_client(sys_op, wan_iface, lan_iface, wisp_id, act_source);
			}
		}
	}	
	return 0;
}

//2011.07.05 Jerry
void start_dnrd()
{
	int cmd_cnt = 0, dns_mode = 0, dns_found = 0, x;
	char dns_server[5][32];
	FILE *fp1;
	char line[128];
	char *cmd_opt[16];
	char nameserver[32], nameserver_ip[32];
	apmib_get( MIB_DNS_MODE, (void *)&dns_mode);
	if(dns_mode==1){
		start_dns_relay();
	}else{
		fp1= fopen("/var/resolv.conf", "r");
		if (fp1 != NULL){
			for (x=0;x<5;x++){
				memset(dns_server[x], '\0', 32);
			}
			while (fgets(line, sizeof(line), fp1) != NULL) {
				memset(nameserver_ip, '\0', 32);
				dns_found = 0;
				sscanf(line, "%s %s", nameserver, nameserver_ip);
				for(x=0;x<5;x++){
					if(dns_server[x][0] != '\0'){
						if(!strcmp(dns_server[x],nameserver_ip)){
							dns_found = 1; 
							break;
						}
					}
				}
				if(dns_found ==0){
					for(x=0;x<5;x++){
						if(dns_server[x][0] == '\0'){
							sprintf(dns_server[x], "%s", nameserver_ip);
							break;
						}
					}
				}		
			}
			fclose(fp1);
		}
		cmd_opt[cmd_cnt++]="dnrd";
		cmd_opt[cmd_cnt++]="--cache=off";
		for(x=0;x<5;x++){
			if(dns_server[x][0] != '\0'){
				cmd_opt[cmd_cnt++]="-s";
				cmd_opt[cmd_cnt++]=&dns_server[x][0];
			}
		}
		cmd_opt[cmd_cnt++] = 0;
		DoCmd(cmd_opt, NULL_FILE);
	}
}
//2011.07.05 Jerry

void start_pppoe_relay()
{
	int pppoe_relay=0, pppoe_pid=0;
	
	apmib_get( MIB_PPPOE_RELAY_ENABLED, (void *)&pppoe_relay);

	pppoe_pid = find_pid_by_name("pppoe-relay");
	if(pppoe_pid > 0)
	{
		system("killall pppoe-relay");
	}

	if(pppoe_relay==1)	
	{		
		RunSystemCmd(NULL_FILE, "/bin/pppoe-relay", "-C", LAN0_IFNAME,  "-S", WAN0_IFNAME, NULL_STR);
	}
}



 
 
 
 
 
 
 
 
 
 
 
