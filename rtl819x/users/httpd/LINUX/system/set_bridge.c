/*
 *      Utiltiy function for setting bridge 
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "../apmib.h"
#include "sysconf.h"
#include "sys_utility.h"
extern int wlan_idx;	// interface index 
extern int vwlan_idx;	// initially set interface index to root   
extern int apmib_initialized;
#define BR_IFACE_FILE "/var/system/br_iface"
#define MESH_PATHSEL "/bin/pathsel" 
#define BR_INIT_FILE "/tmp/bridge_init"
#define ETH_VLAN_SWITCH "/proc/disable_l2_table"
#define DHCPD_CONF_FILE "/var/udhcpd.conf"
#define DHCPD_LEASE_FILE "/var/lib/misc/udhcpd.leases"

int SetWlan_idx(char * wlan_iface_name);

char wlan_wan_iface[20];
/*

//eth0 eth1 eth2 eth3 eth4 wlan0 wlan0-msh wlan0-va0 wlan0-va1 wlan0-va2 wlan0-va3 wlan0-vxd
//wlan0-wds0 wlan0-wds1 wlan0-wds2 wlan0-wds3 wlan0-wds4 wlan0-wds5 wlan0-wds6 wlan0-wds7
*/

void start_lan_dhcpd(char *interface)
{
	char tmpBuff1[32]={0}, tmpBuff2[32]={0};
	int intValue=0, dns_mode=0;
	char line_buffer[100]={0};
	char tmp1[64]={0};
	char tmp2[64]={0};
	char *strtmp=NULL, *strtmp1=NULL;
	DHCPRSVDIP_T entry;
	int i, entry_Num=0;
#ifdef   HOME_GATEWAY
	char tmpBuff3[32]={0};
#endif
	sprintf(line_buffer,"interface %s\n",interface);
	write_line_to_file(DHCPD_CONF_FILE, 1, line_buffer);
	
	apmib_get(MIB_DHCP_CLIENT_START,  (void *)tmp1);
	strtmp= inet_ntoa(*((struct in_addr *)tmp1));
	sprintf(line_buffer,"start %s\n",strtmp);
	write_line_to_file(DHCPD_CONF_FILE, 2, line_buffer);
	
	apmib_get(MIB_DHCP_CLIENT_END,  (void *)tmp1);
	strtmp= inet_ntoa(*((struct in_addr *)tmp1));
	sprintf(line_buffer,"end %s\n",strtmp);
	write_line_to_file(DHCPD_CONF_FILE, 2, line_buffer);
	
	apmib_get(MIB_SUBNET_MASK,  (void *)tmp1);
	strtmp= inet_ntoa(*((struct in_addr *)tmp1));
	sprintf(line_buffer,"opt subnet %s\n",strtmp);
	write_line_to_file(DHCPD_CONF_FILE, 2, line_buffer);

		apmib_get(MIB_IP_ADDR,  (void *)tmp1);
		strtmp= inet_ntoa(*((struct in_addr *)tmp1));
		sprintf(line_buffer,"opt router %s\n",strtmp);
		write_line_to_file(DHCPD_CONF_FILE, 2, line_buffer);
		
		sprintf(line_buffer,"opt dns %s\n",strtmp); /*now strtmp is ip address value */
		write_line_to_file(DHCPD_CONF_FILE, 2, line_buffer);

		memset(tmp1, 0x00, 64);
		apmib_get( MIB_DOMAIN_NAME, (void *)&tmp1);
		if(tmp1[0]){
			sprintf(line_buffer,"opt domain %s\n",tmp1);
			write_line_to_file(DHCPD_CONF_FILE, 2, line_buffer);
		}

	/* may not need to set ip again*/
	apmib_get(MIB_IP_ADDR,  (void *)tmp1);
	strtmp= inet_ntoa(*((struct in_addr *)tmp1));
	sprintf(tmpBuff1, "%s", strtmp);
	apmib_get(MIB_SUBNET_MASK,  (void *)tmp2);
	strtmp1= inet_ntoa(*((struct in_addr *)tmp2));
	sprintf(tmpBuff2, "%s", strtmp1);
	RunSystemCmd(NULL_FILE, "ifconfig", interface, tmpBuff1, "netmask", tmpBuff2,  NULL_STR);	
	/*start dhcp server*/
	RunSystemCmd(NULL_FILE, "udhcpd", DHCPD_CONF_FILE, NULL_STR);	


}


int SetWlan_idx(char * wlan_iface_name)
{
	int idx;
	
		idx = atoi(&wlan_iface_name[4]);
		if (idx >= NUM_WLAN_INTERFACE) {
				printf("invalid wlan interface index number!\n");
				return 0;
		}
		wlan_idx = idx;
		vwlan_idx = 0;
	
#ifdef MBSSID		
		
		if (strlen(wlan_iface_name) >= 9 && wlan_iface_name[5] == '-' &&
				wlan_iface_name[6] == 'v' && wlan_iface_name[7] == 'a') {
				idx = atoi(&wlan_iface_name[8]);
				if (idx >= NUM_VWLAN_INTERFACE) {
					printf("invalid virtual wlan interface index number!\n");
					return 0;
				}
				
				vwlan_idx = idx+1;
				idx = atoi(&wlan_iface_name[4]);
				wlan_idx = idx;
		}
#endif		

#ifdef UNIVERSAL_REPEATER
				if (strlen(wlan_iface_name) >= 9 && wlan_iface_name[5] == '-' &&
						!memcmp(&wlan_iface_name[6], "vxd", 3)) {
					vwlan_idx = NUM_VWLAN_INTERFACE;
					idx = atoi(&wlan_iface_name[4]);
					wlan_idx = idx;
				}
#endif				

//printf("\r\n wlan_iface_name=[%s],wlan_idx=[%u],vwlan_idx=[%u],__[%s-%u]\r\n",wlan_iface_name,wlan_idx,vwlan_idx,__FILE__,__LINE__);

return 1;		
}		

void set_lan_dhcpd(char *interface, int mode)
{
	char tmpBuff1[32]={0}, tmpBuff2[32]={0};
	int intValue=0, dns_mode=0, dhcpLeaseTime=0;
	char line_buffer[100]={0};
	char tmp1[64]={0};
	char tmp2[64]={0};
	char *strtmp=NULL, *strtmp1=NULL;
	DHCPRSVDIP_T entry;
	int i, entry_Num=0;
#ifdef   HOME_GATEWAY
	char tmpBuff3[32]={0};
#endif
	sprintf(line_buffer,"interface %s\n",interface);
	write_line_to_file(DHCPD_CONF_FILE, 1, line_buffer);
	
	apmib_get(MIB_DHCP_CLIENT_START,  (void *)tmp1);
	strtmp= inet_ntoa(*((struct in_addr *)tmp1));
	sprintf(line_buffer,"start %s\n",strtmp);
	write_line_to_file(DHCPD_CONF_FILE, 2, line_buffer);
	
	apmib_get(MIB_DHCP_CLIENT_END,  (void *)tmp1);
	strtmp= inet_ntoa(*((struct in_addr *)tmp1));
	sprintf(line_buffer,"end %s\n",strtmp);
	write_line_to_file(DHCPD_CONF_FILE, 2, line_buffer);
	
	apmib_get(MIB_SUBNET_MASK,  (void *)tmp1);
	strtmp= inet_ntoa(*((struct in_addr *)tmp1));
	sprintf(line_buffer,"opt subnet %s\n",strtmp);
	write_line_to_file(DHCPD_CONF_FILE, 2, line_buffer);
	
	if(mode==1){//ap
		apmib_get( MIB_DEFAULT_GATEWAY,  (void *)tmp2);
		if (memcmp(tmp2, "\x0\x0\x0\x0", 4)){
			strtmp= inet_ntoa(*((struct in_addr *)tmp2));
			sprintf(line_buffer,"opt router %s\n",strtmp);
			write_line_to_file(DHCPD_CONF_FILE, 2, line_buffer);
		}
		
		
	}else{
		apmib_get(MIB_IP_ADDR,  (void *)tmp1);
		strtmp= inet_ntoa(*((struct in_addr *)tmp1));
		sprintf(line_buffer,"opt router %s\n",strtmp);
		write_line_to_file(DHCPD_CONF_FILE, 2, line_buffer);
#ifdef   HOME_GATEWAY
		apmib_get( MIB_DNS_MODE, (void *)&dns_mode);
		if(dns_mode==0){
			sprintf(line_buffer,"opt dns %s\n",strtmp); /*now strtmp is ip address value */
			write_line_to_file(DHCPD_CONF_FILE, 2, line_buffer);
		}
#endif
	}	
	if((mode==1) ||(mode==2 && dns_mode==1)){
#ifdef   HOME_GATEWAY
		apmib_get( MIB_DNS1,  (void *)tmpBuff1);
		apmib_get( MIB_DNS2,  (void *)tmpBuff2);
		apmib_get( MIB_DNS3,  (void *)tmpBuff3);
	
		if (memcmp(tmpBuff1, "\x0\x0\x0\x0", 4)){
			strtmp= inet_ntoa(*((struct in_addr *)tmpBuff1));
			sprintf(line_buffer,"opt dns %s\n",strtmp);
			write_line_to_file(DHCPD_CONF_FILE, 2, line_buffer);
			intValue++;
		}
		if (memcmp(tmpBuff2, "\x0\x0\x0\x0", 4)){
			strtmp= inet_ntoa(*((struct in_addr *)tmpBuff2));
			sprintf(line_buffer,"opt dns %s\n",strtmp);
			write_line_to_file(DHCPD_CONF_FILE, 2, line_buffer);
			intValue++;
		}
		if (memcmp(tmpBuff3, "\x0\x0\x0\x0", 4)){
			strtmp= inet_ntoa(*((struct in_addr *)tmpBuff3));
			sprintf(line_buffer,"opt dns %s\n",strtmp);
			write_line_to_file(DHCPD_CONF_FILE, 2, line_buffer);
			intValue++;
		}
#endif		
		if(intValue==0){ /*no dns option for dhcp server, use default gatewayfor dns opt*/
			
			if(mode==1){
				apmib_get( MIB_DEFAULT_GATEWAY,  (void *)tmp2);
				if (memcmp(tmp2, "\x0\x0\x0\x0", 4)){
					strtmp= inet_ntoa(*((struct in_addr *)tmp2));
					sprintf(line_buffer,"opt dns %s\n",strtmp);
					write_line_to_file(DHCPD_CONF_FILE, 2, line_buffer);
				}
			}else {
				apmib_get( MIB_IP_ADDR,  (void *)tmp2);
				if (memcmp(tmp2, "\x0\x0\x0\x0", 4)){
					strtmp= inet_ntoa(*((struct in_addr *)tmp2));
					sprintf(line_buffer,"opt dns %s\n",strtmp);
					write_line_to_file(DHCPD_CONF_FILE, 2, line_buffer);
				}
			}
		}
	}
	memset(tmp1, 0x00, 64);
	apmib_get( MIB_DOMAIN_NAME, (void *)&tmp1);
	if(tmp1[0]){
		sprintf(line_buffer,"opt domain %s\n",tmp1);
		write_line_to_file(DHCPD_CONF_FILE, 2, line_buffer);
	}
	//2011.06.01 Jerry {
	apmib_get( MIB_DHCP_LEASE, (void *)&dhcpLeaseTime);
	sprintf(line_buffer,"opt lease %d\n", dhcpLeaseTime);
	write_line_to_file(DHCPD_CONF_FILE, 2, line_buffer);
	//2011.06.01 Jerry }
/*static dhcp entry static_lease 000102030405 192.168.1.199*/
	intValue=0;
	apmib_get(MIB_DHCPRSVDIP_ENABLED, (void *)&intValue);
	if(intValue==1){
		apmib_get(MIB_DHCPRSVDIP_TBL_NUM, (void *)&entry_Num);
		if(entry_Num>0){
			for (i=1; i<=entry_Num; i++) {
				*((char *)&entry) = (char)i;
				apmib_get(MIB_DHCPRSVDIP_TBL, (void *)&entry);
				sprintf(line_buffer, "static_lease %02x%02x%02x%02x%02x%02x %s\n", entry.macAddr[0], entry.macAddr[1], entry.macAddr[2], 
				entry.macAddr[3], entry.macAddr[4], entry.macAddr[5], inet_ntoa(*((struct in_addr*)entry.ipAddr)));
				write_line_to_file(DHCPD_CONF_FILE, 2, line_buffer);
			}
		}
	}
	/* may not need to set ip again*/
	apmib_get(MIB_IP_ADDR,  (void *)tmp1);
	strtmp= inet_ntoa(*((struct in_addr *)tmp1));
	sprintf(tmpBuff1, "%s", strtmp);
	apmib_get(MIB_SUBNET_MASK,  (void *)tmp2);
	strtmp1= inet_ntoa(*((struct in_addr *)tmp2));
	sprintf(tmpBuff2, "%s", strtmp1);
	RunSystemCmd(NULL_FILE, "ifconfig", interface, tmpBuff1, "netmask", tmpBuff2,  NULL_STR);	
	/*start dhcp server*/
	char tmpBuff4[100];
	sprintf(tmpBuff4,"udhcpd %s\n",DHCPD_CONF_FILE);
	system(tmpBuff4);
	//RunSystemCmd(stdout, "udhcpd", DHCPD_CONF_FILE, NULL_STR);	
	
	
}
void set_lan_dhcpc(char *iface)
{
	char script_file[100], deconfig_script[100], pid_file[100];
	char *strtmp=NULL;
	char tmp[32], Ip[32], Mask[32], Gateway[32];
	char cmdBuff[200];
#ifdef  HOME_GATEWAY
	int intValue=0;
#endif
	sprintf(script_file, "/usr/share/udhcpc/%s.sh", iface); /*script path*/
	sprintf(deconfig_script, "/usr/share/udhcpc/%s.deconfig", iface);/*deconfig script path*/
	sprintf(pid_file, "/etc/udhcpc/udhcpc-%s.pid", iface); /*pid path*/
	apmib_get( MIB_IP_ADDR,  (void *)tmp);
	strtmp= inet_ntoa(*((struct in_addr *)tmp));
	sprintf(Ip, "%s",strtmp);
	
	apmib_get( MIB_SUBNET_MASK,  (void *)tmp);
	strtmp= inet_ntoa(*((struct in_addr *)tmp));
	sprintf(Mask, "%s",strtmp);
	
	apmib_get( MIB_DEFAULT_GATEWAY,  (void *)tmp);
	strtmp= inet_ntoa(*((struct in_addr *)tmp));
	sprintf(Gateway, "%s",strtmp);
	 
		
	Create_script(deconfig_script, iface, LAN_NETWORK, Ip, Mask, Gateway);
	
	//RunSystemCmd(NULL_FILE, "udhcpc", "-i", iface, "-p", pid_file, "-s", script_file,  "-n", "-x", NULL_STR);
	sprintf(cmdBuff, "udhcpc -i %s -p %s -s %s -n &", iface, pid_file, script_file);
	system(cmdBuff);
}










int setbridge(char *argv)
{
	FILE *fp=NULL;	
	int j;
	int opmode=-1;
	char bridge_iface[300], tmpBuff[200], cmdBuffer[100];
	char iface_name[16], tmp_iface[16];
	char *token=NULL, *savestr1=NULL;
	int intVal=0;
	int iface_index=0;
	int vlan_enabled=0, wlan_disabled=0;
	int wlan_mode=0, wisp_wan_id=0;
	int iswlan_va=0, wlan_wds_enabled=0;
	int wlan_wds_num=0, wlan_mesh_enabled=0;
	int br_stp_enabled=0, dhcp_mode=0;
	char lanIp[30], lanMask[30], lanGateway[30];
	int lan_addr,lan_mask;
	
#if defined(VLAN_CONFIG_SUPPORTED) 	
	VLAN_CONFIG_T vlan_entry;
	int entry_num=0;
	int i;
	int VlanisLan=0;
#endif	
	printf("Init bridge interface...\n");
	apmib_get(MIB_OP_MODE,(void *)&opmode);
	apmib_get(MIB_WISP_WAN_ID,(void *)&wisp_wan_id);
	apmib_get(MIB_DHCP,(void *)&dhcp_mode);
//delete interface of bridge	
	if(isFileExist(BR_IFACE_FILE)){
		memset(bridge_iface,0x00,sizeof(bridge_iface));
		fp=fopen(BR_IFACE_FILE, "r");
		if(fp!=NULL){
			fgets(bridge_iface,sizeof(bridge_iface),fp);
			for(iface_index=0;iface_index<strlen(bridge_iface);iface_index++){
				if(bridge_iface[iface_index]==0x0a)
					bridge_iface[iface_index]=0;
			}
			//printf("briface=%s\n",bridge_iface);
			bridge_iface[strlen(bridge_iface)]=0;
			token = strtok_r(bridge_iface,":", &savestr1);
			
			do{
				//printf("token=%s\n",token);
				if (token == NULL){
					break;
				}else{
					//RunSystemCmd(NULL_FILE, "ifconfig", token, "down", NULL_STR);
					//2011.04.16 Jerry {
					if(restart_lan_flag == 1 && !strcmp(token, "wlan0") || restart_wlan_flag == 1 && !strcmp(token, "eth0"))
						printf("Match interface!!!\n");
					else
						RunSystemCmd(NULL_FILE, "ifconfig", token, "down", NULL_STR);
					//2011.04.16 Jerry }
					
					if( memcmp(token, "br0", 3) != 0 ) 
						RunSystemCmd(NULL_FILE, "brctl", "delif", "br0" ,token, NULL_STR);
				}	
				token = strtok_r(NULL, ":", &savestr1);
			}while(token !=NULL);
			fclose(fp);
		}
	}
	else{
		if(setInAddr( "br0", 0,0,0, IFACE_FLAG_T)==0){
			token=NULL;
			savestr1=NULL;
			sprintf(bridge_iface, "%s", argv);
			token = strtok_r(bridge_iface," ", &savestr1);
			do{
				if (token == NULL){/*chec if the first arg is NULL*/
					break;
				}else{
					RunSystemCmd(NULL_FILE, "ifconfig", token, "down", NULL_STR);
					if( memcmp(token, "br0", 3) != 0 ) {
						RunSystemCmd(NULL_FILE, "brctl", "delif", "br0" ,token, NULL_STR);
					}
				}
				token = strtok_r(NULL, " ", &savestr1);
			}while(token !=NULL);
		}
	}

#if defined(VLAN_CONFIG_SUPPORTED) && defined(CONFIG_RTL_MULTI_LAN_DEV)
	RunSystemCmd(NULL_FILE, "ifconfig", "eth2", "down", NULL_STR);
	RunSystemCmd(NULL_FILE, "ifconfig", "eth3", "down", NULL_STR);
	RunSystemCmd(NULL_FILE, "ifconfig", "eth4", "down", NULL_STR);

	RunSystemCmd(NULL_FILE, "brctl", "delif", "br0", "eth2", NULL_STR);
	RunSystemCmd(NULL_FILE, "brctl", "delif", "br0", "eth3", NULL_STR);
	RunSystemCmd(NULL_FILE, "brctl", "delif", "br0", "eth4", NULL_STR);
#endif
	
	if(isFileExist(MESH_PATHSEL)){
		apmib_get(MIB_MESH_ENABLE,(void *)&intVal);
		if(intVal==1){
			wlan_mesh_enabled=1;
		}
		RunSystemCmd(NULL_FILE,"ifconfig", "wlan0-msh0", "down", NULL_STR);
		RunSystemCmd(NULL_FILE,"brctl", "delif", "br0" ,"wlan0-msh0", NULL_STR);

	}
	if(setInAddr( "br0", 0,0,0, IFACE_FLAG_T)==0){
		RunSystemCmd(NULL_FILE,"brctl", "delif", "br0" ,"eth1", NULL_STR);
		RunSystemCmd(NULL_FILE,"brctl", "delif", "br0" ,"wlan0", NULL_STR);
	}
	if(isFileExist(BR_INIT_FILE)==0){//bridge init file is not exist
		RunSystemCmd(NULL_FILE,"brctl", "delbr", "br0", NULL_STR);
		RunSystemCmd(NULL_FILE,"brctl", "addbr", "br0", NULL_STR);
	}
	apmib_get(MIB_STP_ENABLED,(void *)&br_stp_enabled);
	if(br_stp_enabled==1){
		RunSystemCmd(NULL_FILE,"brctl", "setfd", "br0", "4", NULL_STR);
		RunSystemCmd(NULL_FILE,"brctl", "stp", "br0", "1", NULL_STR);
	}else{
		RunSystemCmd(NULL_FILE,"brctl", "setfd", "br0", "0", NULL_STR);
		RunSystemCmd(NULL_FILE,"brctl", "stp", "br0", "0", NULL_STR);
	}

	
#if defined(VLAN_CONFIG_SUPPORTED)
		apmib_get(MIB_VLANCONFIG_ENABLED,(void *)&vlan_enabled);

		if(vlan_enabled !=0 )
			RunSystemCmd("/proc/rtk_vlan_support", "echo", "1", NULL_STR);
		else
			RunSystemCmd("/proc/rtk_vlan_support", "echo", "0", NULL_STR);

		//apmib_get(MIB_VLANCONFIG_NUM,(void *)&entry_num);
		apmib_get(MIB_VLANCONFIG_TBL_NUM,(void *)&entry_num);
		//printf("*********************vlan tbl=%d,vlan_enable(%d)\n", entry_num,vlan_enabled);
		for (i=1; i<=entry_num; i++) {
			*((char *)&vlan_entry) = (char)i;
			apmib_get(MIB_VLANCONFIG_TBL, (void *)&vlan_entry);
			sprintf(tmpBuff, "/proc/%s/mib_vlan", vlan_entry.netIface);
			if(isFileExist(tmpBuff)){
	
            #ifdef RTK_USB3G_PORT5_LAN
                DHCP_T wan_dhcp = -1;
                apmib_get( MIB_DHCP, (void *)&wan_dhcp);
            #endif

				if(strncmp(vlan_entry.netIface,"eth1",strlen("eth1")) == 0){			
            #ifdef RTK_USB3G_PORT5_LAN
					if(opmode == WISP_MODE || opmode == BRIDGE_MODE || wan_dhcp == USB3G)
            #else
					if(opmode == WISP_MODE || opmode == BRIDGE_MODE)
            #endif
						VlanisLan=1;
					else
						VlanisLan=0;
				}else if(strncmp("wlan0",vlan_entry.netIface, strlen(vlan_entry.netIface)) == 0){						
					if(opmode == WISP_MODE)
						VlanisLan=0;
					else
						VlanisLan=1;
				}else{						
					VlanisLan=1;
				}
				
				if(vlan_enabled==1){				//global_vlan, is_lan,vlan, tag, id, pri, cfi
					sprintf(cmdBuffer,"echo \"1 %d %d %d %d %d %d\" > %s", VlanisLan,vlan_entry.enabled, vlan_entry.tagged, vlan_entry.vlanId, vlan_entry.priority, vlan_entry.cfi, tmpBuff);
					system(cmdBuffer);
				}	
				else{
					sprintf(cmdBuffer,"echo \"0 %d %d %d %d %d %d\" > %s", VlanisLan,vlan_entry.enabled, vlan_entry.tagged, vlan_entry.vlanId, vlan_entry.priority, vlan_entry.cfi, tmpBuff);
					system(cmdBuffer);
				}
					
			}
		}
#endif
	
	if(isFileExist(BR_IFACE_FILE)){
		unlink(BR_IFACE_FILE);
	}
	memset(bridge_iface,0x00,sizeof(bridge_iface));
	token=NULL;
	savestr1=NULL;	     
	sprintf(tmpBuff, "%s", argv);                                  
	token = strtok_r(tmpBuff," ", &savestr1);
	do{
		if (token == NULL){/*check if the first arg is NULL*/
			break;
		}else{	
			sprintf(iface_name,"%s", token);                                                             		
			if(strncmp(iface_name, "eth", 3)==0){//ether iface                                                       		
				intVal=1;                                                     
//				if(isFileExist(ETH_VLAN_SWITCH)){ 
#if defined(CONFIG_RTL_MULTI_LAN_DEV)
#else
					if((vlan_enabled==0)&&(iface_name[3]=='2' || iface_name[3]=='3' || iface_name[3]=='4')){         		
						intVal=0;                                                                                    		
					}        
#endif
//				}                                                                                        		
					if(intVal==1){             
						//printf("add iface to br %s\n", iface_name);                                                                               		
						RunSystemCmd(NULL_FILE, "brctl", "addif", "br0" ,iface_name, NULL_STR);		
						RunSystemCmd(NULL_FILE, "ifconfig", iface_name, "0.0.0.0", NULL_STR); 
						if(bridge_iface[0]){
							strcat(bridge_iface, iface_name);
							strcat(bridge_iface, ":");
						}else{
							sprintf(bridge_iface, "%s", iface_name);
							strcat(bridge_iface, ":");
						}                                            		
					}                                                                                                		
			}                                                                                                        		
		}
		token = strtok_r(NULL, " ", &savestr1);
	}while(token !=NULL);

	token=NULL;
	savestr1=NULL;	
	sprintf(tmpBuff, "%s", argv); 	
	token = strtok_r(tmpBuff," ", &savestr1);
	do{
		if (token == NULL){/*check if the first arg is NULL*/
			break;
		}else{	
	          	sprintf(iface_name,"%s", token);    
			if(strncmp(iface_name, "wlan", 4)==0){//wlan iface                                                       		
				if (strlen(iface_name) >= 9 && iface_name[5] == '-' &&
						iface_name[6] == 'v' && iface_name[7] == 'a') 
				{
					char wlanRootName[16];					
					memset(wlanRootName, 0x00, sizeof(wlanRootName));					
					strncpy(wlanRootName,iface_name, 5);

					if(SetWlan_idx(wlanRootName)){
						apmib_get( MIB_WLAN_WLAN_DISABLED, (void *)&intVal);//get root if enable/disable
						apmib_get( MIB_WLAN_MODE, (void *)&wlan_mode); //get root if mode
						if(intVal==0){
							if(wlan_mode != 0 && wlan_mode != 3)
								wlan_disabled=1;//root if is disabled
							else{
								if(SetWlan_idx( iface_name)){
									apmib_get( MIB_WLAN_WLAN_DISABLED, (void *)&intVal);//get va if enable/disable
									if(intVal==0)	
										wlan_disabled=0;
									else
										wlan_disabled=1;								
								}else
										wlan_disabled=1;
							}
						}else
							wlan_disabled=1;
					}else
						wlan_disabled=1;//root if is disabled
				}else{
					if(SetWlan_idx( iface_name)){
						apmib_get( MIB_WLAN_WLAN_DISABLED, (void *)&intVal);
						wlan_disabled=intVal;
					}else
						wlan_disabled=1;
					}
				if(wlan_disabled==0){ //wlan if is enabled
					sprintf(wlan_wan_iface,"wlan%d", wisp_wan_id);
					if(strlen(iface_name) >= 9 && iface_name[5] == '-' && 
						iface_name[6] == 'v' && iface_name[7] == 'a')
						iswlan_va=1;
					
					if((iswlan_va==1) || (opmode != 2) || (strcmp(wlan_wan_iface, iface_name))){//do not add wlan wan  iface to br0
						RunSystemCmd(NULL_FILE, "brctl", "addif", "br0" ,iface_name, NULL_STR);		
						RunSystemCmd(NULL_FILE, "ifconfig", iface_name, "0.0.0.0", NULL_STR); 
							if(bridge_iface[0]){
								strcat(bridge_iface, iface_name);
								strcat(bridge_iface, ":");
							}else{
								sprintf(bridge_iface, "%s", iface_name);
								strcat(bridge_iface, ":");
							}      
					}else{
						RunSystemCmd(NULL_FILE, "ifconfig", iface_name, "up", NULL_STR); 
					}
					
					if(SetWlan_idx( iface_name)){
						apmib_get( MIB_WLAN_WDS_ENABLED, (void *)&wlan_wds_enabled);
						apmib_get( MIB_WLAN_WDS_NUM, (void *)&wlan_wds_num);
						apmib_get( MIB_WLAN_MODE, (void *)&wlan_mode); //get wlan if mode
						if(wlan_wds_enabled !=0 && wlan_wds_num !=0 && (wlan_mode==2 || wlan_mode==3)){//add wds inface to br0
							for(j=0;j<wlan_wds_num;j++){
								sprintf(tmp_iface, "%s-wds%d", iface_name, j);
								RunSystemCmd(NULL_FILE, "brctl", "addif", "br0" ,tmp_iface, NULL_STR);		
								RunSystemCmd(NULL_FILE, "ifconfig", tmp_iface, "0.0.0.0", NULL_STR); 
								if(bridge_iface[0]){
									strcat(bridge_iface, tmp_iface);
									strcat(bridge_iface, ":");
								}else{
									sprintf(bridge_iface, "%s", tmp_iface);
									strcat(bridge_iface, ":");
								}      
							}
						}
					}
				}	
			}	
		}
		token = strtok_r(NULL, " ", &savestr1);
	}while(token !=NULL);
			
	if(wlan_mesh_enabled==1){
		if(SetWlan_idx( "wlan0")){
			apmib_get( MIB_WLAN_MODE, (void *)&wlan_mode); //get root if mode
			sprintf(tmp_iface, "%s","wlan0-msh0"); 
			if(wlan_mode > 3){
				RunSystemCmd(NULL_FILE, "brctl", "addif", "br0" ,tmp_iface, NULL_STR);		
				RunSystemCmd(NULL_FILE, "ifconfig", tmp_iface, "0.0.0.0", NULL_STR); 
				if(bridge_iface[0]){
					strcat(bridge_iface, tmp_iface);
					strcat(bridge_iface, ":");
				}else{
					sprintf(bridge_iface, "%s", tmp_iface);
					strcat(bridge_iface, ":");
				}      
			}
		}
	}
	RunSystemCmd(BR_IFACE_FILE, "echo", bridge_iface, NULL_STR);
	
	if(br_stp_enabled==0){
		
		apmib_get(MIB_ELAN_MAC_ADDR,  (void *)tmpBuff);
		
		
		if(!memcmp(tmpBuff, "\x00\x00\x00\x00\x00\x00", 6)){
			apmib_get(MIB_HW_NIC0_ADDR,  (void *)tmpBuff);
		}
		sprintf(cmdBuffer, "%02x%02x%02x%02x%02x%02x", (unsigned char)tmpBuff[0], (unsigned char)tmpBuff[1], (unsigned char)tmpBuff[2], (unsigned char)tmpBuff[3], (unsigned char)tmpBuff[4], (unsigned char)tmpBuff[5]);
		RunSystemCmd(NULL_FILE, "ifconfig", "br0", "hw", "ether",cmdBuffer, NULL_STR);
	}
	if(isFileExist(BR_INIT_FILE)==0){//bridge init file is not exist
		RunSystemCmd(NULL_FILE, "ifconfig", "br0", "0.0.0.0", NULL_STR);
		RunSystemCmd(BR_INIT_FILE, "echo", "1", NULL_STR);
	}
#ifdef CONFIG_DOMAIN_NAME_QUERY_SUPPORT
	if(dhcp_mode==0 || dhcp_mode==2 || dhcp_mode==15)//dhcp disabled or server mode or auto
#else
	if(dhcp_mode==0 || dhcp_mode==2)//dhcp disabled or server mode 
#endif	
	{
		apmib_get(MIB_IP_ADDR,  (void *)tmpBuff);
		sprintf(lanIp,"%s",inet_ntoa(*((struct in_addr *)tmpBuff)));
		
		apmib_get(MIB_SUBNET_MASK,  (void *)tmpBuff);
		sprintf(lanMask,"%s",inet_ntoa(*((struct in_addr *)tmpBuff)));
		
		apmib_get(MIB_DEFAULT_GATEWAY,  (void *)tmpBuff);
		sprintf(lanGateway,"%s",inet_ntoa(*((struct in_addr *)tmpBuff)));
		RunSystemCmd(NULL_FILE, "ifconfig", "br0", lanIp, "netmask",lanMask, NULL_STR);
		//hyking:sure the hw l3 table is correct, delete lan route & add lan route
		apmib_get(MIB_IP_ADDR,  &lan_addr);
		apmib_get(MIB_SUBNET_MASK,&lan_mask);		
		lan_addr &= lan_mask;
		sprintf(lanIp,"%s",inet_ntoa(*((struct in_addr *)(&lan_addr))));		
		RunSystemCmd(NULL_FILE, "route", "del", "-net",lanIp, "netmask",lanMask, NULL_STR);
		RunSystemCmd(NULL_FILE, "route", "add", "-net",lanIp, "netmask",lanMask, "dev","br0",NULL_STR);
		//end hyking added
		
		if(strcmp(lanGateway,"0.0.0.0")){
			RunSystemCmd(NULL_FILE, "route", "del", "default", "dev","br0", NULL_STR);
			RunSystemCmd(NULL_FILE, "route", "add", "-net", "default","gw", lanGateway, "dev", "br0", NULL_STR);
		}
	}else if(dhcp_mode==1){//dhcp client

//		if(br_stp_enabled==1){		/* Comment here because br0 entering forwarding state always need some time especially booting up.*/
			printf("wait for bridge initialization...\n");
			intVal=10;
			do{
				intVal--;
				sleep(1);
			}while(intVal !=0);
//		}
		//RunSystemCmd(NULL_FILE, "dhcpc.sh", "br0", "no", NULL_STR);
		set_lan_dhcpc("br0");
	}    
	return 0;
}

 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
