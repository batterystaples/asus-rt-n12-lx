#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <dirent.h>
#include "../apmib.h"
#include "../mibtbl.h"
#include "../upmib.h"
#include "sysconf.h"
#include "sys_utility.h"
#include "syswan.h"
#include <signal.h>	//2011.04.25 Jerry
//extern int wlan_idx;	// interface index 
//extern int vwlan_idx;	// initially set interface index to root   
extern int set_QoS(int operation, int wan_type, int wisp_wan_id);
extern int setbridge(char *argv);
extern int setWlan_Applications(char *action, char *argv);
extern int SetWlan_idx(char *wlan_iface_name);
extern int setFirewallIptablesRules(int argc, char** argv);
extern void set_lan_dhcpd(char *interface, int mode);
extern void wan_disconnect(char *option);
extern void set_ipv6();
void set_log(void);
#if defined(CONFIG_DOMAIN_NAME_QUERY_SUPPORT)
extern void Init_Domain_Query_settings(int operation_mode, int wlan_mode, int lan_dhcp_mode, char *lan_mac);
extern void domain_query_start_dnrd(int wlan_mode, int start_dnrd);
#endif
/*

//eth0 eth1 eth2 eth3 eth4 wlan0 wlan0-msh wlan0-va0 wlan0-va1 wlan0-va2 wlan0-va3 wlan0-vxd
//wlan0-wds0 wlan0-wds1 wlan0-wds2 wlan0-wds3 wlan0-wds4 wlan0-wds5 wlan0-wds6 wlan0-wds7

WLAN=>>> wlan0
WLANVXD=>>>wlan0-vxd
WLANVIRTUAL=>> wlan0-va0 wlan0-va1 wlan0-va2 wlan0-va3 wlan0-vxd
NUM_=>>>1
VIRTUALNUL=>>>4

*/

int gateway=0;
int enable_wan=0;
int enable_br=0;
char br_interface[16]={0};
char br_lan1_interface[16]={0};
char br_lan2_interface[16]={0};
char br_lan3_interface[16]={0};
char wan_interface[16]={0};
char vlan_interface[32]={0};
static char wlan_interface[16]={0};
char wlan_valid_interface[512]={0};
char wlan_virtual_interface[80]={0};
static char wlan_vxd_interface[16]={0};
int num_wlan_interface=0;
int num_wlan_virtual_interface=0;
int num_wlan_vxd_interface=0;

void set_br_interface(unsigned char *brif)
{
	int opmode=-1, root_mode=-1;
	unsigned char tmpBuff[512]={0};
  	apmib_get(MIB_OP_MODE,(void *)&opmode);
	apmib_get(MIB_WLAN_MODE,(void *)&root_mode);
	
			if(vlan_interface[0]){
				strcat(tmpBuff, vlan_interface);
				strcat(tmpBuff, " ");
			}
			if(wlan_interface[0]){
				strcat(tmpBuff, wlan_interface);
				strcat(tmpBuff, " ");
			}			
			if(wlan_virtual_interface[0]){
				strcat(tmpBuff, wlan_virtual_interface);
				strcat(tmpBuff, " ");
			}
#if defined(UNIVERSAL_REPEATER) &&  defined(CONFIG_REPEATER_WISP_WAN)
			/*add wlan0-vxd to bridge when vxd as repeater AP*/
			if( (root_mode == AP_MODE) && (opmode == WISP_MODE) )
			{
				/*don't add wlan0-vxd to bridge for it should connect to ISP*/
			}
			else
			{
			if(wlan_vxd_interface[0]){
				strcat(tmpBuff, wlan_vxd_interface);
				strcat(tmpBuff, " ");
			}
			}
#else
			if(wlan_vxd_interface[0]){
				strcat(tmpBuff, wlan_vxd_interface);
				strcat(tmpBuff, " ");
			}
#endif
			strcat(tmpBuff, br_interface);
			strcat(tmpBuff, " ");
#if defined(CONFIG_RTL_MULTI_LAN_DEV)
			if(opmode==0)
			{
				strcat(tmpBuff, "eth0 eth2 eth3 eth4");
			}
			else
			{
				strcat(tmpBuff, "eth0 eth1 eth2 eth3 eth4");
			}	
#else
	
			strcat(tmpBuff, br_lan1_interface);

#if defined(CONFIG_RTL_IVL_SUPPORT)
			/*add eth1 to br0 when in bridge&wisp mode*/
			if(opmode ==1 || opmode == 2) 
			{
				strcat(tmpBuff, " ");
				strcat(tmpBuff, br_lan2_interface);
			}
#endif		
#endif
			memcpy(brif, tmpBuff, sizeof(tmpBuff));
			return;

}


int up_mib_value()
{
        int old_ver=0;
        int new_ver=0;
        int i=0;
 
        apmib_get(MIB_MIB_VER, (void *)&old_ver);
        new_ver = atoi(update_mib[0].value);
        if(old_ver == new_ver)
        {
                return -1;
        }
        else
                printf("MIB Version update\n");
 
        i=0;
        while(new_mib[i].id != 0)
        {
                RunSystemCmd(NULL_FILE, "flash", "set", new_mib[i].name, new_mib[i].value, NULL_STR);
                i++;
        }
 
        i=0;
        while(update_mib[i].id != 0)
        {
                RunSystemCmd(NULL_FILE, "flash", "set", update_mib[i].name, update_mib[i].value, NULL_STR);
                i++;
        }
 
        return 0;
 
}


void set_log(void)
{
	int intValue=0,  intValue1=0;
	char tmpBuffer[32];
	char syslog_para[32];
	
	apmib_get(MIB_SCRLOG_ENABLED, (void*)&intValue);
	if(intValue !=0 && intValue !=2 && intValue !=4 && intValue !=6 && intValue !=8 &&
		intValue !=10 && intValue !=12 && intValue !=14) {
			apmib_get(MIB_REMOTELOG_ENABLED, (void*)&intValue1);
			if(intValue1 != 0){
				apmib_get(MIB_REMOTELOG_SERVER,  (void *)&tmpBuffer);
				printf("%s:%s start remote log\n", __FILE__,__FUNCTION__);
				RunSystemCmd(NULL_FILE, "syslogd", "-L", "-R", tmpBuffer, NULL_STR);			
			}else{
				RunSystemCmd(NULL_FILE, "syslogd", "-L", NULL_STR);
			}
			RunSystemCmd(NULL_FILE, "klogd", NULL_STR);
		} 
		 
	
	return;
}

void start_wlanapp(int action)
{
	char tmpBuff[128];

	memset(tmpBuff, 0x00, sizeof(tmpBuff));
	if(action==1){
		if(wlan_interface[0] && wlan_virtual_interface[0] && wlan_vxd_interface[0] && br_interface[0])
		sprintf(tmpBuff, "%s %s %s %s", wlan_interface, wlan_virtual_interface, wlan_vxd_interface, br_interface); 			
		else if(wlan_interface[0] && wlan_virtual_interface[0] && !wlan_vxd_interface[0] && br_interface[0])
			sprintf(tmpBuff, "%s %s %s", wlan_interface, wlan_virtual_interface, br_interface); 
		else if(wlan_interface[0] && !wlan_virtual_interface[0] && wlan_vxd_interface[0] && br_interface[0])
			sprintf(tmpBuff, "%s %s %s", wlan_interface, wlan_vxd_interface, br_interface); 	
		else if(wlan_interface[0] && !wlan_virtual_interface[0] && !wlan_vxd_interface[0] && br_interface[0])
			sprintf(tmpBuff, "%s %s", wlan_interface, br_interface); 						
	}else {
		//V_WLAN_APP_ENABLE=0 or para2=wlan_app
		if(wlan_interface[0] && br_interface[0])
		sprintf(tmpBuff, "%s %s", wlan_interface, br_interface); 	
	}

	RunSystemCmd(PROC_GPIO, "echo", "I", NULL_STR);

	if(tmpBuff[0])
		setWlan_Applications("start", tmpBuff);

	#if defined(CONFIG_DOMAIN_NAME_QUERY_SUPPORT)
		system("rm -f  /var/system/start_init 2> /dev/null");
	#endif

}

void start_upnpd(int isgateway, int sys_op)
{
#ifdef   HOME_GATEWAY	
	int intValue=0,  intValue1=0;
	if(SetWlan_idx("wlan0")){
		apmib_get(MIB_WLAN_WSC_DISABLE, (void *)&intValue);
	}
	if(isgateway==1 && sys_op !=1)
		apmib_get(MIB_UPNP_ENABLED, (void *)&intValue1);
	else 
		intValue1=0;
	if(intValue==0 && intValue1==0){//wps enabled and upnp igd is disabled
		RunSystemCmd(NULL_FILE, "mini_upnpd", "-wsc", "/tmp/wscd_config", "-daemon", NULL_STR);
	}else if(intValue==1 && intValue1==1){//wps is disabled, and upnp igd is enabled
		RunSystemCmd(NULL_FILE, "mini_upnpd", "-igd", "/tmp/igd_config", "-daemon", NULL_STR);
	}else if(intValue==0 && intValue1==1){//both wps and upnp igd are enabled
		RunSystemCmd(NULL_FILE, "mini_upnpd", "-wsc", "/tmp/wscd_config", "-igd", "/tmp/igd_config","-daemon",  NULL_STR);
	}else if(intValue==1 && intValue1==0){//both wps and upnp igd are disabled
		/*do nothing*/
	}
#endif		
}
/*method to start reload is co-operate to parse rule of reload.c*/
void start_wlan_by_schedule(int index)
{
	int intValue=0,  intValue1=0, i=0, entryNum=0, bak_idx=0, bak_vidx=0;
	char tmp1[64]={0};
	SCHEDULE_T wlan_sched;
	int newfile=1;

	bak_idx=wlan_idx;
	wlan_idx=index;
	bak_idx=vwlan_idx;
	vwlan_idx=0;
	apmib_get(MIB_WLAN_WLAN_DISABLED, (void *)&intValue);
#if defined(NEW_SCHEDULE_SUPPORT)
	#define WLAN_SCHEDULE_FILE "/var/wlsch.conf"
	sprintf(tmp1,WLAN_SCHEDULE_FILE"%d",index);
	unlink(tmp1);
#endif	
	if(intValue==0){
		apmib_get(MIB_WLAN_SCHEDULE_ENABLED, (void *)&intValue1);
		apmib_get(MIB_WLAN_SCHEDULE_TBL_NUM, (void *)&entryNum);

		if(intValue1==1 && entryNum > 0){
			
			for (i=1; i<=entryNum; i++) {
				*((char *)&wlan_sched) = (char)i;
				apmib_get(MIB_WLAN_SCHEDULE_TBL, (void *)&wlan_sched);
#if defined(NEW_SCHEDULE_SUPPORT)

				char line_buffer[100]={0};
				if(wlan_sched.eco == 1 && !(wlan_sched.fTime == 0 && wlan_sched.tTime == 0))
				{
					sprintf(line_buffer,"%d,%d,%d,%d\n",i,wlan_sched.day,wlan_sched.fTime, wlan_sched.tTime);
					sprintf(tmp1,WLAN_SCHEDULE_FILE"%d",index);
					write_line_to_file(tmp1, (newfile==1?1:2), line_buffer);
					newfile = 2;
				}
#endif				
			}
			if(index == (NUM_WLAN_INTERFACE-1)){
#if defined(NEW_SCHEDULE_SUPPORT)
			sprintf(tmp1, "reload -k %s &", WLAN_SCHEDULE_FILE);
#else			
			sprintf(tmp1, "reload -e %d,%d,%d,%d,%s &", wlan_sched.eco, wlan_sched.fTime, wlan_sched.tTime, wlan_sched.day, wlan_sched.text);
#endif			
			system(tmp1);			
			}
		}
		else{ /* do not care schedule*/

			if(index == (NUM_WLAN_INTERFACE-1)){
#if defined(NEW_SCHEDULE_SUPPORT)
				sprintf(tmp1, "reload -k %s &", WLAN_SCHEDULE_FILE);
				system(tmp1);
#else

			system("reload &");
#endif
			}
		}
		}
	else{
		/*wlan is disabled, we do not care wlan schedule*/
		system("reload &");
	}
	vwlan_idx=bak_vidx;
	wlan_idx=bak_idx;
}
void clean_process(int sys_opmode,int wan_dhcp_mode,int gateway, int enable_wan, char *lanInterface, char *wlanInterface, char *wanInterface)
{
	char strPID[10], tmpBuff[200];
	int pid=-1;
/*clean the process before take new setting*/	
#ifdef   HOME_GATEWAY
#ifdef CONFIG_POCKET_AP_SUPPORT
#else
	if(isFileExist(HW_NAT_FILE)){/*hw nat supported*/
		/*cleanup hardware tables*/
		if(sys_opmode==0)
			RunSystemCmd(HW_NAT_FILE, "echo", "1", NULL_STR);	/*gateway mode*/
		else if(sys_opmode==1)
			RunSystemCmd(HW_NAT_FILE, "echo", "2", NULL_STR);	/*bridge mode*/
		else if(sys_opmode==2)
			RunSystemCmd(HW_NAT_FILE, "echo", "3", NULL_STR);	/*wisp mode*/
		else if(sys_opmode==3)
			RunSystemCmd(HW_NAT_FILE, "echo", "4", NULL_STR);	/*bridge mode with multiple vlan*/
		else
			RunSystemCmd(HW_NAT_FILE, "echo", "5", NULL_STR); /*wisp mode with multiple vlan*/
		
	}else{/*software nat supported*/ 
		if(sys_opmode==0)
		{
			#ifdef RTK_USB3G
    		        if(wan_dhcp_mode == USB3G)
                        	RunSystemCmd(SOFTWARE_NAT_FILE, "echo", "1", NULL_STR);
			else
        		#endif
			RunSystemCmd(SOFTWARE_NAT_FILE, "echo", "0", NULL_STR);
		}
		if(sys_opmode==1)
			RunSystemCmd(SOFTWARE_NAT_FILE, "echo", "1", NULL_STR);
		if(sys_opmode==2)
			RunSystemCmd(SOFTWARE_NAT_FILE, "echo", "2", NULL_STR);
		if(sys_opmode==3)
			RunSystemCmd(SOFTWARE_NAT_FILE, "echo", "3", NULL_STR);
		if(sys_opmode==4)
			RunSystemCmd(SOFTWARE_NAT_FILE, "echo", "4", NULL_STR);
		
	}
#endif	//CONFIG_POCKET_AP_SUPPORT
#endif	
	
		RunSystemCmd(NULL_FILE, "killall", "-15", "miniigd", NULL_STR);
		if(isFileExist(IGD_PID_FILE)){
			unlink(IGD_PID_FILE);
		}		
		RunSystemCmd(NULL_FILE, "killall", "-15", "routed", NULL_STR);
		if(isFileExist(RIP_PID_FILE)){
			unlink(RIP_PID_FILE);
		}
		/*dont support tr069 in jungle now*/
		if(isFileExist(TR069_PID_FILE)){
			pid=getPid_fromFile(TR069_PID_FILE);
			if(pid != -1){
				sprintf(strPID, "%d", pid);
				RunSystemCmd(NULL_FILE, "kill", "-9", strPID, NULL_STR);
			}
			unlink(TR069_PID_FILE);
		}
		RunSystemCmd(NULL_FILE, "rm", "-f", "/etc/ppp/first", NULL_STR);
		RunSystemCmd(NULL_FILE, "rm", "-f", "/etc/ppp/firstpptp", NULL_STR);
		RunSystemCmd(NULL_FILE, "rm", "-f", "/etc/ppp/firstl2tp", NULL_STR);
		RunSystemCmd(NULL_FILE, "rm", "-f", "/etc/ppp/firstdemand", NULL_STR);
#ifdef   HOME_GATEWAY		
		wan_disconnect("all");
#endif			
	if(enable_br == 1) {	//2011.03.16 Jerry
	RunSystemCmd(NULL_FILE, "killall", "-9", "ntp_inet", NULL_STR);	
	RunSystemCmd(NULL_FILE, "killall", "-9", "ddns.sh", NULL_STR);
	RunSystemCmd(NULL_FILE, "killall", "-9", "syslogd", NULL_STR);
	RunSystemCmd(NULL_FILE, "killall", "-9", "klogd", NULL_STR);
	RunSystemCmd(NULL_FILE, "killall", "-9", "mini_upnpd", NULL_STR);
	RunSystemCmd(NULL_FILE, "killall", "-9", "reload", NULL_STR);
	}

	if(isFileExist(L2TPD_PID_FILE)){
			pid=getPid_fromFile(L2TPD_PID_FILE);
			if(pid != 0){
				sprintf(strPID, "%d", pid);
				RunSystemCmd(NULL_FILE, "kill", "-9", strPID, NULL_STR);
			}
			unlink(L2TPD_PID_FILE);
	}
/*kill dhcp client if br interface is dhcp client*/	
	sprintf(tmpBuff, "/etc/udhcpc/udhcpc-%s.pid", lanInterface);
	if(isFileExist(tmpBuff)){
			pid=getPid_fromFile(tmpBuff);
			if(pid != 0){
				sprintf(strPID, "%d", pid);
				RunSystemCmd(NULL_FILE, "kill", "-9", strPID, NULL_STR);
			}
			unlink(tmpBuff);
	}
	sprintf(tmpBuff, "/etc/udhcpc/udhcpc-%s.pid", wanInterface);
	if(isFileExist(tmpBuff)){
			pid=getPid_fromFile(tmpBuff);
			if(pid !=0){
				sprintf(strPID, "%d", pid);
				RunSystemCmd(NULL_FILE, "kill", "-9", strPID, NULL_STR);
			}
			unlink(tmpBuff);
	}
	if(wlanInterface[0]){
	sprintf(tmpBuff, "/etc/udhcpc/udhcpc-%s.pid", wlanInterface);
	if(isFileExist(tmpBuff)){
			pid=getPid_fromFile(tmpBuff);
			if(pid != 0){
				sprintf(strPID, "%d", pid);
				RunSystemCmd(NULL_FILE, "kill", "-9", strPID, NULL_STR);
			}
			unlink(tmpBuff);
	}
	}
	if(isFileExist(DNRD_PID_FILE)){
			pid=getPid_fromFile(DNRD_PID_FILE);
			if(pid != 0){
				sprintf(strPID, "%d", pid);
				RunSystemCmd(NULL_FILE, "kill", "-9", strPID, NULL_STR);
			}
			unlink(DNRD_PID_FILE);
	}
	if(isFileExist(IGMPPROXY_PID_FILE)){
			pid=getPid_fromFile(IGMPPROXY_PID_FILE);
			if(pid != 0){
				sprintf(strPID, "%d", pid);
				RunSystemCmd(NULL_FILE, "kill", "-9", strPID, NULL_STR);
			}
			unlink(IGMPPROXY_PID_FILE);
			RunSystemCmd(PROC_BR_MCASTFASTFWD, "echo", "1,0", NULL_STR);
	}
	if(isFileExist(LLTD_PID_FILE)){
			pid=getPid_fromFile(LLTD_PID_FILE);
			if(pid != 0){
				sprintf(strPID, "%d", pid);
				RunSystemCmd(NULL_FILE, "kill", "-9", strPID, NULL_STR);
			}
			unlink(LLTD_PID_FILE);
	}
	if(isFileExist(DHCPD_PID_FILE) && enable_br == 1){	//2011.03.16 Jerry
			pid=getPid_fromFile(DHCPD_PID_FILE);
			if(pid != 0){
				sprintf(strPID, "%d", pid);
				RunSystemCmd(NULL_FILE, "kill", "-16", strPID, NULL_STR);/*inform dhcp server write lease table to file*/
				sleep(1);
				RunSystemCmd(NULL_FILE, "kill", "-9", strPID, NULL_STR);
			}
			unlink(DHCPD_PID_FILE);
	}
	
/*end of clean the process before take new setting*/		
	
#if defined(CONFIG_POCKET_ROUTER_SUPPORT)
	/* Reset Firewall Rules*/
	system("iptables -F");
	system("iptables -F -t nat");
	system("iptables -F -t mangle");
	sprintf(tmpBuff, "iptables -A INPUT -i %s -j ACCEPT", lanInterface);
	system(tmpBuff);
	if(sys_opmode==1){
		system("iptables -P INPUT ACCEPT");
		system("iptables -P FORWARD ACCEPT");
	}
#endif	
	
	
}
#if defined(CONFIG_APP_USBMOUNT)
#define	PARTITION_FILE "/proc/partitions"

int get_blockDevPartition(char *str, char *partition)
{

	unsigned char tk[50];
	unsigned int i,j;
	unsigned int curCnt,preCnt;
	
	if(str==NULL)
	{
		return -1;
	}
	
	memset(tk,0, sizeof(tk));

	/*	partition table format:
		major minor  #blocks  name
	*/
	
	preCnt=0;
	curCnt=0;
	for (i=0;i<strlen(str);i++)
	{          
		if( (str[i]!=' ') && (str[i]!='\n') && (str[i]!='\r'))
		{
			if(preCnt==curCnt)
			{
				tk[curCnt]=i;
				curCnt++;
			}
		}
		else if((str[i]==' ') || (str[i]=='\n') ||(str[i]=='\r') )
		{
			preCnt=curCnt;
		}
	}
	
	/*to check device major number is 8*/
	
	if(!isdigit(str[tk[0]]))
	{
		return -1;
	}

	if(tk[1]==0)
	{
		return -1;
	}

	if(tk[1]<=tk[0])
	{
		return -1;
	}

	if((str[tk[0]]!='8') ||(str[tk[0]+1]!=' '))
	{
		return -1;
	}
	
	if(tk[3]==0)
	{
		return -1;
	}

	/*to get partition name*/
	j=0;
	for(i=tk[3]; i<strlen(str); i++)
	{
		
		if((str[i]==' ') || (str[i]=='\n') ||(str[i]=='\n'))
		{
			partition[j]='\0';
			return 0;
		}
		else
		{
			partition[j]=str[i];
			j++;
		}
			
	}
	return 0;
}
int Check_shouldMount(char *partition_name)
{
	DIR *dir=NULL;
	struct dirent *next;
	int found=0;
	dir = opendir("/tmp/usb");
	if (!dir) {
		printf("Cannot open %s", "/tmp/usb");
		return -1;
	}
	while ((next = readdir(dir)) != NULL) {
		//printf("Check_shouldMount:next->d_reclen=%d, next->d_name=%s\n",next->d_reclen, next->d_name);
			/* Must skip ".." */
			if (strcmp(next->d_name, "..") == 0)
				continue;
			if (strcmp(next->d_name, ".") == 0)
				continue;
			if (strcmp(next->d_name, "mnt_map") == 0)
				continue;
			if(!strcmp(next->d_name, partition_name)){
				found=1;
				break;
			}
	}
	closedir(dir);
	return found;
}
void autoMountOnBootUp(void)
{
	FILE *fp;
	
	int line=0;
	char buf[512];
	char partition[32];
	char usbMntCmd[64];
	int ret=-1;
	if(isFileExist(PARTITION_FILE)){
		fp= fopen(PARTITION_FILE, "r");
		if (!fp) {
	        	printf("can not  open /proc/partitions\n");
			return; 
	   	}

		while (fgets(buf, sizeof(buf), fp)) 
		{
			ret=get_blockDevPartition(buf, &partition);
			if(ret==0)
			{
				if(Check_shouldMount(partition)==0){
				sprintf(usbMntCmd, "DEVPATH=/sys/block/sda/%s ACTION=add usbmount block", partition);
				RunSystemCmd(NULL_FILE,  "echo", usbMntCmd, NULL_STR);
				system(usbMntCmd);
			}
			}
			
		}
	
		fclose(fp);
	}
	

}

void start_mount()
{
#if defined(HTTP_FILE_SERVER_SUPPORTED)
	RunSystemCmd("/proc/sys/vm/min_free_kbytes", "echo", "384", NULL_STR);
	RunSystemCmd("/proc/sys/net/core/rmem_max", "echo", "1048576", NULL_STR);
	RunSystemCmd("/proc/sys/net/core/wmem_max", "echo", "1048576", NULL_STR);
	RunSystemCmd("/proc/sys/net/ipv4/tcp_rmem", "echo", "4096 108544 4194304", NULL_STR);
	RunSystemCmd("/proc/sys/net/ipv4/tcp_wmem", "echo", "4096 108544 4194304", NULL_STR);
	RunSystemCmd("/proc/sys/net/ipv4/tcp_moderate_rcvbuf", "echo", "0", NULL_STR);
#else
	/*config linux parameter for improving samba performance*/
	RunSystemCmd("/proc/sys/vm/min_free_kbytes", "echo", "1024", NULL_STR);
	
	RunSystemCmd("/proc/sys/net/core/netdev_max_backlog", "echo", "8192", NULL_STR);
	RunSystemCmd("/proc/sys/net/core/optmem_max", "echo", "131072", NULL_STR);
	RunSystemCmd("/proc/sys/net/core/rmem_default", "echo", "524288", NULL_STR);
	RunSystemCmd("/proc/sys/net/core/rmem_max", "echo", "524288", NULL_STR);
	RunSystemCmd("/proc/sys/net/core/wmem_default", "echo", "524288", NULL_STR);
	RunSystemCmd("/proc/sys/net/core/wmem_max", "echo", "524288", NULL_STR);
	RunSystemCmd("/proc/sys/net/ipv4/tcp_rmem", "echo", "131072 262144 393216", NULL_STR);
	RunSystemCmd("/proc/sys/net/ipv4/tcp_wmem", "echo", "131072 262144 393216", NULL_STR);
	RunSystemCmd("/proc/sys/net/ipv4/tcp_mem", "echo", "768 1024 1380", NULL_STR);
#endif
	/*config hot plug and auto-mount*/
	RunSystemCmd("/proc/sys/kernel/hotplug", "echo", "/usr/hotplug", NULL_STR);
	RunSystemCmd(NULL_FILE, "mkdir", "-p /tmp/usb/", NULL_STR);

	/*force kernel to write data to disk, don't cache in memory for a long time*/
	RunSystemCmd("/proc/sys/vm/vfs_cache_pressure", "echo", "10000", NULL_STR);
	RunSystemCmd("/proc/sys/vm/dirty_background_ratio", "echo", "5", NULL_STR);
	RunSystemCmd("/proc/sys/vm/dirty_writeback_centisecs", "echo", "100", NULL_STR);
	/*automatically mount partions listed in /proc/partitions*/
	autoMountOnBootUp();

}
#endif

#if defined(CONFIG_APP_SAMBA)
void start_samba()
{
	/*start samba*/
	RunSystemCmd(NULL_FILE,  "echo", "start samba", NULL_STR);
	RunSystemCmd(NULL_FILE,  "cp", "/etc/smb.conf", "/var/config/smb.conf",  NULL_STR);
	RunSystemCmd("/var/group",  "echo", " ",  NULL_STR);
        RunSystemCmd(NULL_FILE,  "cp", "/etc/group", "/var/group",  NULL_STR);
	RunSystemCmd(NULL_FILE,  "smbd", "-D", NULL_STR);
}
#endif

int setinit(int argc, char** argv)
{
	int i, cmdRet=-1;
	int opmode=-1, v_wlan_app_enabled=1, intValue=0, intValue1=0;
	char cmdBuffer[100], tmpBuff[512];
	int repeater_enabled1=0, repeater_enabled2=0;
	char *token=NULL, *savestr1=NULL;
	char tmp_args[16];
	int wisp_wan_id=0;
	int lan_dhcp_mode=0;
	int wan_dhcp_mode=0;
	char Ip[32], Mask[32], Gateway[32];
	int wlan_mode_root=0, wlan_root_disabled=0;
	char strPID[32];
	int pid = 0;
	int wlan_support = 0;
	int index;
	int old_wlan_idx; 
#if defined(CONFIG_RTL_92D_SUPPORT)
	int wlan_mode_root1=0, wlan_root1_disabled=0;
#endif
#if defined(CONFIG_RTL_92D_SUPPORT)
	int wispWanId=0;
#endif
	up_mib_value();

	if(isFileExist(SET_TIME)==0){
		RunSystemCmd(NULL_FILE, "flash", "settime", NULL_STR);
	}

#ifdef CONFIG_RTL_802_1X_CLIENT_SUPPORT
	if(isFileExist(RS_USER_CERT)==0 && isFileExist(RS_ROOT_CERT)==0 ){
		RunSystemCmd(NULL_FILE, "rsCert","-rd", NULL_STR);
	}
#endif

#ifdef CONFIG_RTL_WAPI_SUPPORT
#ifdef CONFIG_RTL_WAPI_LOCAL_AS_SUPPORT
	if(isFileExist(CA_CERT_FILE)==0){
		RunSystemCmd(NULL_FILE, "loadWapiFiles", NULL_STR);
	}
#else
	if(isFileExist(CA4AP_CERT_FILE)==0 && isFileExist(AP_CERT_FILE)==0 ){		
		RunSystemCmd(NULL_FILE, "loadWapiFiles", NULL_STR);
	}
#endif
#endif
	
	#if defined(CONFIG_DOMAIN_NAME_QUERY_SUPPORT)
		system("echo 1 > /var/system/start_init");
	#endif 	

	printf("Init Start...\n");

	//Added for pptp/l2tp use dynamic wan ip
	if(isFileExist(TEMP_WAN_CHECK))
		unlink(TEMP_WAN_CHECK);
	if(isFileExist(TEMP_WAN_DHCP_INFO))
		unlink(TEMP_WAN_DHCP_INFO);

	apmib_get(MIB_OP_MODE,(void *)&opmode);
	apmib_get(MIB_WISP_WAN_ID,(void *)&wisp_wan_id);
	apmib_get(MIB_DHCP,(void *)&lan_dhcp_mode);
#ifdef   HOME_GATEWAY	
	apmib_get(MIB_WAN_DHCP,(void *)&wan_dhcp_mode);
#endif	
	memset(br_lan2_interface, 0x00, sizeof(br_lan2_interface));
	memset(br_lan3_interface, 0x00, sizeof(br_lan3_interface));
	memset(vlan_interface, 0x00, sizeof(vlan_interface));
	if(opmode==0)
		RunSystemCmd("/var/sys_op", "echo", "0", NULL_STR);
	if(opmode==1)
		RunSystemCmd("/var/sys_op", "echo", "1", NULL_STR);
	if(opmode==2)
		RunSystemCmd("/var/sys_op", "echo", "2", NULL_STR);

#if defined(CONFIG_RTL_92D_SUPPORT)
	if(SetWlan_idx("wlan1")){
			apmib_get( MIB_WLAN_MODE, (void *)&wlan_mode_root1); 
			apmib_get( MIB_WLAN_WLAN_DISABLED, (void *)&wlan_root1_disabled);	  
		}
#endif
	if(SetWlan_idx("wlan0")){
		apmib_get( MIB_WLAN_MODE, (void *)&wlan_mode_root); 
		apmib_get( MIB_WLAN_WLAN_DISABLED, (void *)&wlan_root_disabled);	  
	}
	
/* set interface name  start*/		
	sprintf(tmp_args,"%s", argv[2]);  
	if(!strcmp(tmp_args, "ap")){
		sprintf(br_interface, "%s", "br0");
		sprintf(br_lan1_interface, "%s" , "eth0");
		if(opmode==1)
			sprintf(br_lan2_interface, "%s", "eth1");
		gateway=0;
	}	
	if(!strcmp(tmp_args, "gw")){		
		gateway=1;
		if(opmode==2)
		{
#if defined(UNIVERSAL_REPEATER) && defined(CONFIG_REPEATER_WISP_WAN) 
			if(wlan_mode_root == AP_MODE)			
				sprintf(wan_interface, "wlan%d-vxd", wisp_wan_id);
			else
			sprintf(wan_interface, "wlan%d", wisp_wan_id);
#else
			sprintf(wan_interface, "wlan%d", wisp_wan_id);
#endif
        	}
		else
		{
#if defined(CONFIG_POCKET_ROUTER_SUPPORT)
			if(opmode == 0)
				sprintf(wan_interface, "%s", "eth1");
			
#else
			sprintf(wan_interface, "%s", "eth1");
#endif
		}
			
		sprintf(br_interface, "%s", "br0");
#if defined(CONFIG_POCKET_ROUTER_SUPPORT)
		if(opmode != 0)
			sprintf(br_lan1_interface, "%s" , "eth0");
#else
		sprintf(br_lan1_interface, "%s" , "eth0");
#endif

		if(opmode ==1 || opmode == 2) {
#if defined(CONFIG_POCKET_ROUTER_SUPPORT)
#else
			sprintf(br_lan2_interface, "%s", "eth1");
#if defined(UNIVERSAL_REPEATER) && defined(CONFIG_REPEATER_WISP_WAN) 
			if( (wlan_mode_root == AP_MODE)	&& (opmode == WISP_MODE))
				sprintf(br_lan3_interface, "%s", "wlan0");
#endif
#endif
		}

	}

	RunSystemCmd(PROC_BR_IGMPPROXY, "echo", "0", NULL_STR);
	
#if defined(VLAN_CONFIG_SUPPORTED)
	apmib_get(MIB_VLANCONFIG_ENABLED, (void *)&intValue);
	if(intValue !=0) {
#if defined(CONFIG_POCKET_ROUTER_SUPPORT)
#else
#if defined(CONFIG_CABINO_MODE)
		sprintf(vlan_interface, "%s %s %s %s", "eth2", "eth3", "eth4","eth5");
#else
		sprintf(vlan_interface, "%s %s %s", "eth2", "eth3", "eth4");
#endif
#endif
	}
	else		
		memset(vlan_interface, 0x00, sizeof(vlan_interface));
#endif	
	memset(wlan_interface, 0x00, sizeof(wlan_interface));
	memset(wlan_virtual_interface, 0x00, sizeof(wlan_virtual_interface));
	memset(wlan_vxd_interface, 0x00, sizeof(wlan_vxd_interface));
	memset(wlan_valid_interface, 0x00, sizeof(wlan_valid_interface));
	
	for(i=0;i<NUM_WLAN_INTERFACE;i++){
		if(wlan_interface[0]==0x00)
			sprintf(wlan_interface, "wlan%d", i);
		else{
			sprintf(tmp_args, " wlan%d", i);
			strcat(wlan_interface, tmp_args); 
		}
	}
	num_wlan_interface=NUM_WLAN_INTERFACE;
	num_wlan_virtual_interface=if_readlist_proc(wlan_virtual_interface, "va", 0);
	num_wlan_vxd_interface=if_readlist_proc(wlan_vxd_interface, "vxd", 0);
	wlan_support = if_readlist_proc(wlan_valid_interface, "wlan", 0);
	if(wlan_support==0)
		memset(wlan_interface, 0x00, sizeof(wlan_interface));
/* set interface name  end*/			
	
	sprintf(tmp_args,"%s", argv[3]);
	if(strcmp(tmp_args, "wlan_app") != 0)
	{
		clean_process(opmode,wan_dhcp_mode,gateway, enable_wan, br_interface, wlan_interface, wan_interface);
	}
	
	
	/*init wlan interface*/
	if (wlan_support != 0)
	{
		int br_wlan_block=0;
		memset(wlan_interface, 0x00, sizeof(wlan_interface));
		for(i=0;i<NUM_WLAN_INTERFACE;i++)
		{
			int wlan_disable = 1;			
			unsigned char wlan_name[10];
			memset(wlan_name,0x00,sizeof(wlan_name));
			sprintf(wlan_name, "wlan%d",i);
			if(SetWlan_idx(wlan_name))
			{			
				apmib_get( MIB_WLAN_WLAN_DISABLED, (void *)&wlan_disable);	  

				
				if(wlan_disable == 1)
				{
					RunSystemCmd(NULL_FILE, "iwpriv", wlan_name, "radio_off", NULL_STR);					
				}
				else
				{
					if(wlan_interface[0]==0x00)
						sprintf(wlan_interface, "%s", wlan_name);
					else
					{
						sprintf(tmp_args, " %s", wlan_name);
						strcat(wlan_interface, tmp_args); 
					}							
				}
			}
		}				
	}
	
/*currently, we just support init gw/ap all */	
	sprintf(tmp_args,"%s", argv[3]);  
	
	if(!strcmp(tmp_args, "all")){
		enable_wan=1;
		enable_br=1;
	}else if(!strcmp(tmp_args, "wan")){
		enable_wan=1;
		//enable_br=1;
		enable_br=0;	//2011.03.16 Jerry
	}else if(!strcmp(tmp_args, "bridge")){
		enable_wan=1;
		enable_br=1;
	}else if(!strcmp(tmp_args, "wlan_app")){
		start_wlanapp(0);
		return 0;
	}
	clean_process(opmode,wan_dhcp_mode,gateway, enable_wan, br_interface, wlan_interface, wan_interface);
	/*save the last wan type*/ /*no this operate in shell script*/
	sprintf(tmp_args, "%d", wan_dhcp_mode);
	RunSystemCmd("/var/system/last_wan", "echo", tmp_args, NULL_STR);
	if(enable_br == 1)	//2011.03.16 Jerry
		RunSystemCmd(NULL_FILE, "ifconfig", "eth0", "down", NULL_STR);
	RunSystemCmd(NULL_FILE, "ifconfig", "eth1", "down", NULL_STR);
	RunSystemCmd(NULL_FILE, "ifconfig", "peth0", "down", NULL_STR);
	
	apmib_get(MIB_REPEATER_ENABLED1,(void *)&repeater_enabled1);
	apmib_get(MIB_REPEATER_ENABLED2,(void *)&repeater_enabled2);

	if(wlan_mode_root != AP_MODE && wlan_mode_root != AP_WDS_MODE && repeater_enabled1 == 0 && repeater_enabled2 == 0){
		v_wlan_app_enabled=0; // no virtual and repeat
	}
	if((repeater_enabled1 == 0 && repeater_enabled2 == 0) ||(wlan_mode_root >= 4 && wlan_mode_root <=7) ||(wlan_mode_root == 2)) 
		memset(wlan_vxd_interface, 0x00, sizeof(wlan_vxd_interface));

	apmib_get(MIB_ELAN_MAC_ADDR,  (void *)tmpBuff);
	if(!memcmp(tmpBuff, "\x00\x00\x00\x00\x00\x00", 6))
		apmib_get(MIB_HW_NIC0_ADDR,  (void *)tmpBuff);
	sprintf(cmdBuffer, "%02x%02x%02x%02x%02x%02x", (unsigned char)tmpBuff[0], (unsigned char)tmpBuff[1], 
		(unsigned char)tmpBuff[2], (unsigned char)tmpBuff[3], (unsigned char)tmpBuff[4], (unsigned char)tmpBuff[5]);
#if defined(CONFIG_RTL_MULTI_LAN_DEV)
	RunSystemCmd(NULL_FILE, "ifconfig", "eth0", "hw", "ether", cmdBuffer, NULL_STR);/*set eth0 mac address*/
	RunSystemCmd(NULL_FILE, "ifconfig", "eth2", "hw", "ether", cmdBuffer, NULL_STR);/*set eth0 mac address*/
	RunSystemCmd(NULL_FILE, "ifconfig", "eth3", "hw", "ether", cmdBuffer, NULL_STR);/*set eth0 mac address*/
	RunSystemCmd(NULL_FILE, "ifconfig", "eth4", "hw", "ether", cmdBuffer, NULL_STR);/*set eth0 mac address*/
#else
	if(br_lan1_interface[0])
		RunSystemCmd(NULL_FILE, "ifconfig", br_lan1_interface, "hw", "ether", cmdBuffer, NULL_STR);/*set eth0 mac address*/
#endif
	
#if defined(CONFIG_DOMAIN_NAME_QUERY_SUPPORT)
	Init_Domain_Query_settings(opmode, wlan_mode_root, lan_dhcp_mode, cmdBuffer);
#endif
	if(opmode == 1 || opmode == 2){
		apmib_get(MIB_ELAN_MAC_ADDR,  (void *)tmpBuff);
		if(!memcmp(tmpBuff, "\x00\x00\x00\x00\x00\x00", 6))
			apmib_get(MIB_HW_NIC1_ADDR,  (void *)tmpBuff);
		sprintf(cmdBuffer, "%02x%02x%02x%02x%02x%02x", (unsigned char)tmpBuff[0], (unsigned char)tmpBuff[1], 
			(unsigned char)tmpBuff[2], (unsigned char)tmpBuff[3], (unsigned char)tmpBuff[4], (unsigned char)tmpBuff[5]);
		if(br_lan2_interface[0])	
			RunSystemCmd(NULL_FILE, "ifconfig", br_lan2_interface, "hw", "ether", cmdBuffer, NULL_STR);/*set eth1 mac address when bridge mode*/
		if(br_lan3_interface[0])	
			RunSystemCmd(NULL_FILE, "ifconfig", br_lan3_interface, "hw", "ether", cmdBuffer, NULL_STR);/*set eth1 mac address when bridge mode*/
	} 
#ifdef   HOME_GATEWAY	
	if(gateway ==1 && opmode != 1){
		apmib_get(MIB_WAN_MAC_ADDR,  (void *)tmpBuff);
		if(!memcmp(tmpBuff, "\x00\x00\x00\x00\x00\x00", 6)){
			if(opmode == 2)
			{
				apmib_get(MIB_WISP_WAN_ID, (void *)&index);
				old_wlan_idx=wlan_idx;
				wlan_idx = index;
				apmib_get(MIB_HW_WLAN_ADDR,  (void *)tmpBuff);
				wlan_idx=old_wlan_idx;
			}
			else
				apmib_get(MIB_HW_NIC1_ADDR,  (void *)tmpBuff);
		}
		sprintf(cmdBuffer, "%02x%02x%02x%02x%02x%02x", (unsigned char)tmpBuff[0], (unsigned char)tmpBuff[1], 
			(unsigned char)tmpBuff[2], (unsigned char)tmpBuff[3], (unsigned char)tmpBuff[4], (unsigned char)tmpBuff[5]);
		if(wan_interface[0])
			RunSystemCmd(NULL_FILE, "ifconfig", wan_interface, "hw", "ether", cmdBuffer, NULL_STR);/*set wan mac address when it not bridge mode*/
	}
#endif	
	/*init wlan interface*/
	//if (wlan_support != 0)
	if (wlan_support != 0 && enable_br == 1)	//2011.03.16 Jerry
	{
		int br_wlan_block=0;
		memset(wlan_interface, 0x00, sizeof(wlan_interface));
		for(i=0;i<NUM_WLAN_INTERFACE;i++)
		{
			int wlan_disable = 1;
			int wlan_blockrelay=0;
			unsigned char wlan_name[10];
			memset(wlan_name,0x00,sizeof(wlan_name));
			sprintf(wlan_name, "wlan%d",i);
			if(SetWlan_idx(wlan_name))
			{
			
				apmib_get( MIB_WLAN_WLAN_DISABLED, (void *)&wlan_disable);	  
				if(wlan_disable == 1)
				{
					RunSystemCmd(NULL_FILE, "iwpriv", wlan_name, "radio_off", NULL_STR);					
				}
				else
				{
	                if(wlan_interface[0]==0x00)
        	            sprintf(wlan_interface, "%s", wlan_name);
                	else
	                {
						sprintf(tmp_args, " %s", wlan_name);
	        	        strcat(wlan_interface, tmp_args); 
        	        }	
						
					RunSystemCmd(NULL_FILE, "ifconfig", wlan_name, "down", NULL_STR);
					cmdRet=RunSystemCmd(NULL_FILE, "flash", "set_mib", wlan_name, NULL_STR);
			
					if(cmdRet != 0)
					{
						printf("init %s failed!\n", wlan_name);
						continue;
					}

				}
				
				apmib_get( MIB_WLAN_BLOCK_RELAY,(void *)&wlan_blockrelay);
				/*if all wlan interface block then enable br_wlan_block*/
				if(wlan_blockrelay)
				{
					if(!br_wlan_block)
						br_wlan_block=1;
				}
				else
					br_wlan_block=0;

			}
		}
		
		if(br_wlan_block)
		{
			RunSystemCmd("/proc/br_wlanblock", "echo","1",NULL_STR);
		}
		else
		{
			RunSystemCmd("/proc/br_wlanblock", "echo","0",NULL_STR);
		}
	}
				
	if(wlan_interface[0] && enable_br == 1)	//2011.03.16 Jerry
	{				
		if(wlan_vxd_interface[0]) {
			RunSystemCmd(NULL_FILE, "ifconfig", wlan_vxd_interface, "down", NULL_STR);
			RunSystemCmd(NULL_FILE, "flash", "set_mib", wlan_vxd_interface, NULL_STR);/*set vxd wlan iface*/
		}
		if(wlan_virtual_interface[0]){
			token=NULL;
			savestr1=NULL;
			sprintf(tmpBuff, "%s", wlan_virtual_interface);
			token = strtok_r(tmpBuff," ", &savestr1);
			do{
				if (token == NULL){
					break;
				}else{
					RunSystemCmd(NULL_FILE, "ifconfig", token, "down", NULL_STR);
					RunSystemCmd(NULL_FILE, "flash", "set_mib", token, NULL_STR);/*set virtual wlan iface*/
				}
				token = strtok_r(NULL, " ", &savestr1);
			}while(token !=NULL);
		}
	}	
	
	if(gateway==1){
		if(enable_br==1){
			/*init bridge interface*/
			//hyking:sure hw initialization first..
			
			set_br_interface(tmpBuff);
			setbridge(tmpBuff);

			/* init log setting*/
			set_log();

			/* init lan dhcp setting*/
			if(lan_dhcp_mode==0){		/*DHCP disabled*/
				apmib_get( MIB_IP_ADDR,  (void *)tmpBuff);
				sprintf(Ip, "%s", inet_ntoa(*((struct in_addr *)tmpBuff)));
				apmib_get( MIB_SUBNET_MASK,  (void *)tmpBuff);
				sprintf(Mask, "%s", inet_ntoa(*((struct in_addr *)tmpBuff)));
				apmib_get(MIB_DEFAULT_GATEWAY,  (void *)tmpBuff);
				
				if (!memcmp(tmpBuff, "\x0\x0\x0\x0", 4))
					memset(Gateway, 0x00, sizeof(Gateway));
				else
					sprintf(Gateway, "%s", inet_ntoa(*((struct in_addr *)tmpBuff)));
					
				RunSystemCmd(NULL_FILE, "ifconfig", br_interface, Ip, "netmask", Mask, NULL_STR);
				
				if(Gateway[0]){
					RunSystemCmd(NULL_FILE, "route", "del", "default", br_interface, NULL_STR);
					RunSystemCmd(NULL_FILE, "route", "add", "-net", "default", "gw", Gateway, "dev", br_interface, NULL_STR);
				}	
				start_wlanapp(v_wlan_app_enabled);
			}else
#ifdef CONFIG_DOMAIN_NAME_QUERY_SUPPORT
	if(lan_dhcp_mode==2 || lan_dhcp_mode==15)//dhcp disabled or server mode or auto
#else			
	if(lan_dhcp_mode==2)
#endif
			
			{		/*DHCP server enabled*/
				intValue1=0;
				for(i=0;i<NUM_WLAN_INTERFACE;i++){
					sprintf(tmp_args, " wlan%d", i);
					if(SetWlan_idx(tmp_args)){
						apmib_get(MIB_WLAN_WDS_ENABLED, (void *)&intValue);
						if(intValue!=0)
							intValue1=intValue1+5;
						else
							intValue1=intValue1+1;
					}	
				}
				sleep(intValue1);/*wait wlan wds init */		
				/*start dhcp server*/
				set_lan_dhcpd(br_interface, 2);
				start_wlanapp(v_wlan_app_enabled);
			}
		}/*for init bridge interface and wlan app*/

		RunSystemCmd(NULL_FILE, "iptables", "-F", NULL_STR);
		RunSystemCmd(NULL_FILE, "iptables", "-F", "-t", "nat",  NULL_STR);
		RunSystemCmd(NULL_FILE, "iptables", "-A", "INPUT", "-j", "ACCEPT", NULL_STR);
		
#ifdef CONFIG_DOMAIN_NAME_QUERY_SUPPORT		
		/* start dnrd for check dns query with hostname */
		domain_query_start_dnrd(wlan_mode_root, 1);
#endif		

		
		RunSystemCmd(NULL_FILE, "rm", "-f", "/var/eth1_ip", NULL_STR);
		RunSystemCmd(NULL_FILE, "rm", "-f", "/var/ntp_run", NULL_STR);
		if(wan_interface[0])
		{
			RunSystemCmd(NULL_FILE, "ifconfig", wan_interface, "down", NULL_STR);
			RunSystemCmd(NULL_FILE, "ifconfig", wan_interface, "up", NULL_STR);
		}

		if(enable_wan==1 && (opmode == 0 || opmode==2)){/*for init internet wan setting*/ 
			if(opmode==2){
				if(SetWlan_idx("wlan0")){
					apmib_get(MIB_WLAN_ENCRYPT, (void *)&intValue);
					if(intValue != 0){
						for(i=0;i<NUM_WLAN_INTERFACE;i++){
							sprintf(tmp_args, " wlan%d", i);
							RunSystemCmd(NULL_FILE, "iwpriv", tmp_args, "set_mib", "keep_rsnie=1", NULL_STR);
						}
					}
				}
			}
			RunSystemCmd(PROC_FASTNAT_FILE, "echo", "1", NULL_STR);
			
			if(wan_dhcp_mode==PPTP){
				RunSystemCmd(PROC_FASTPPTP_FILE, "echo", "1", NULL_STR);
				apmib_get(MIB_PPTP_CONNECTION_TYPE, (void *)&intValue);
				if(intValue==1){
					RunSystemCmd(PROC_PPTP_CONN_FILE, "echo", "3", NULL_STR);
				}else{
					RunSystemCmd(PROC_PPTP_CONN_FILE, "echo", "0", NULL_STR);
				}
			}else{
				RunSystemCmd(PROC_FASTPPTP_FILE, "echo", "0", NULL_STR);
			}
				
			if(wan_dhcp_mode==L2TP){
				RunSystemCmd(PROC_FASTL2TP_FILE, "echo", "1", NULL_STR);
			}else{
				RunSystemCmd(PROC_FASTL2TP_FILE, "echo", "0", NULL_STR);
			}
	#ifdef HOME_GATEWAY		
			if((wan_dhcp_mode !=DHCP_SERVER && wan_dhcp_mode < 7) || (wan_dhcp_mode == USB3G)){ /* */
				start_wan(wan_dhcp_mode, opmode, wan_interface, br_interface, wisp_wan_id, 1);
			}else
				printf("Invalid wan type:wan_dhcp_mode=%d\n", wan_dhcp_mode);
	#endif			
		}
		else if(enable_wan==1 && opmode == 1 ){
			/*Bridge mode, eth1 mtu should be sync with eth0 mtu (assume that eth0 mtu is 1500 here!!!)
			Otherwise, ping large pkt failed when GW mode changed to Bridge mode
			if eth1 mtu not equal with eth0 mtu.*/
			if(wan_interface[0])
				RunSystemCmd(NULL_FILE, "ifconfig", wan_interface, "mtu", "1500", NULL_STR);
		}

		//set kthreadd high priority for performance
		RunSystemCmd(NULL_FILE, "renice -20 2", NULL_STR);
		//set ksoftirqd high priority for performance
		RunSystemCmd(NULL_FILE, "renice -20 3", NULL_STR);
		//set webs high priority
		if(isFileExist(WEBS_PID_FILE)){
			pid=getPid_fromFile(WEBS_PID_FILE);
			if(pid != 0){
				sprintf(strPID, "%d", pid);
				RunSystemCmd(NULL_FILE, "renice", "-20", strPID, NULL_STR);
			}
		}
	}
	else
	{ /*gateway is 0, it is ap mode*/
		set_br_interface(tmpBuff);
		setbridge(tmpBuff);

		//Not used at present in order to find the root cause!!!
		//Patch: wlan pc can't visit AP using wapi-psk or wapi-cert when AP boots up
		//RunSystemCmd(NULL_FILE, "ifconfig", wlan_interface, "down", NULL_STR);
		//RunSystemCmd(NULL_FILE, "ifconfig", wlan_interface, "up", NULL_STR);
			
		/* init log setting*/
			set_log();
		if(lan_dhcp_mode==2){	
			sleep(1);
			set_lan_dhcpd(br_interface, 1);
		}	
		if(lan_dhcp_mode==2 || lan_dhcp_mode==0){	
			start_wlanapp(v_wlan_app_enabled);
		}	
	}

#ifndef STAND_ALONE_MINIUPNP
	start_upnpd(gateway, opmode);
#endif
	if(gateway==1 && opmode != 1){
		if(isFileExist(LLTD_PROCESS_FILE)){
			RunSystemCmd(NULL_FILE, "lld2d", br_interface, NULL_STR);
		}
	}
	if(isFileExist(SNMPD_PROCESS_FILE)){
		RunSystemCmd(NULL_FILE, "snmpd.sh", "restart", NULL_STR);
		RunSystemCmd(NULL_FILE, "snmpd", "-c", SNMPD_CONF_FILE, "-p", SNMPD_PID_FILE,  NULL_STR);
	}
	if(isFileExist(NMSD_PROCESS_FILE)){
		RunSystemCmd(NULL_FILE, "nmsd", NULL_STR);
	}

	for(index=0; index<NUM_WLAN_INTERFACE; index++)
		start_wlan_by_schedule(index);

#if defined(CONFIG_IPV6)
	set_ipv6();
#endif

#ifdef HOME_GATEWAY // To enable/disable ipv6 passthru no matter wan is connected or not
	if(opmode == 0)	// Gateway mode
		apmib_get(MIB_CUSTOM_PASSTHRU_ENABLED, (void *)&intValue);
	else
		intValue=0;

	RunSystemCmd("/proc/custom_Passthru", "echo", (intValue & 0x1)?"1":"0", NULL_STR);
	if (intValue == 0)
	{
		RunSystemCmd(NULL_FILE, "brctl", "delif", "br0", "peth0", NULL_STR);
		RunSystemCmd(NULL_FILE, "ifconfig", "peth0", "down", NULL_STR);
	}
	else
	{
		RunSystemCmd(NULL_FILE, "brctl", "addif", "br0", "peth0", NULL_STR);
		RunSystemCmd(NULL_FILE, "ifconfig", "peth0", "up", NULL_STR);
	}
#if defined(CONFIG_RTL_92D_SUPPORT)
	apmib_get(MIB_WISP_WAN_ID, (void *)&wispWanId);
	if(wispWanId==0)
	{
		if((opmode == 2) && (wlan_root_disabled == 0) && (wlan_mode_root == CLIENT_MODE))	//WISP mode, wireless enabled  and wireless client mode enabled
		{		
			apmib_get(MIB_CUSTOM_PASSTHRU_ENABLED, (void *)&intValue);
		}
		else
		{
			intValue=0;
		}
	}
	else if(wispWanId==1)
	{
		if((opmode == 2) && (wlan_root1_disabled == 0) && (wlan_mode_root1 == CLIENT_MODE))	//WISP mode, wireless enabled  and wireless client mode enabled
		{		
			apmib_get(MIB_CUSTOM_PASSTHRU_ENABLED, (void *)&intValue);
		}
		else
		{
			intValue=0;
		}
	}
	else
	{
		intValue=0;
	}
	
	if(intValue!=0)
	{
		char tmpStr[16];
		/*should also config wisp wlan index for dual band wireless interface*/
		intValue=((wispWanId&0xF)<<4)|intValue;
		memset(tmpStr,0,sizeof(tmpStr));
		sprintf(tmpStr,"%d",intValue);
		RunSystemCmd("/proc/custom_Passthru_wlan", "echo", tmpStr, NULL_STR);
	}
	else
	{
		RunSystemCmd("/proc/custom_Passthru_wlan", "echo", (intValue & 0x1)?"1":"0", NULL_STR);
	}
#else
	if((opmode == 2) && (wlan_root_disabled == 0) && (wlan_mode_root == CLIENT_MODE))	//WISP mode, wireless enabled  and wireless client mode enabled
	{		
		apmib_get(MIB_CUSTOM_PASSTHRU_ENABLED, (void *)&intValue);
	}
	else
		intValue=0;
	RunSystemCmd("/proc/custom_Passthru_wlan", "echo", (intValue & 0x1)?"1":"0", NULL_STR);
#endif
	
	if (intValue == 0)
	{

		RunSystemCmd(NULL_FILE, "brctl", "delif", "br0", "pwlan0", NULL_STR);
		RunSystemCmd(NULL_FILE, "ifconfig", "pwlan0", "down", NULL_STR);
	}
	else
	{
		RunSystemCmd(NULL_FILE, "brctl", "addif", "br0", "pwlan0", NULL_STR);
		RunSystemCmd(NULL_FILE, "ifconfig", "pwlan0", "up", NULL_STR);
	}
#endif

	/*enable igmp snooping*/
	/*igmp snooping is independent with igmp proxy*/
	RunSystemCmd(PROC_BR_IGMPSNOOP, "echo", "1", NULL_STR);
	RunSystemCmd(PROC_BR_IGMPQUERY, "echo", "1", NULL_STR);
#if defined (CONFIG_RTL_MLD_SNOOPING)	
	RunSystemCmd(PROC_BR_MLDSNOOP, "echo", "1", NULL_STR);
	RunSystemCmd(PROC_BR_MLDQUERY, "echo", "1", NULL_STR);
#endif

#if defined(CONFIG_APP_USBMOUNT)
	start_mount();
#if defined (CONFIG_APP_SAMBA)
	apmib_get(MIB_SAMBA_ENABLED, (void*)&intValue);
	if(intValue==1) {
printf("%s, %d\n", __FUNCTION__, __LINE__);
		start_samba();
	}
#endif	
#endif

#ifdef RTK_USB3G
    apmib_get(MIB_WAN_DHCP, (void*)&intValue);
    if(opmode == 0 && intValue == USB3G) {
        system("echo \"/sbin/hotplug\" > /proc/sys/kernel/hotplug");
        system("mount -t sysfs none /sys           >/dev/null 2>&1");
        system("mount -t usbfs none /proc/bus/usb  >/dev/null 2>&1");
        system("mount -t tmpfs none /dev           >/dev/null 2>&1");
        system("mdev -s                            >/dev/null 2>&1");
        system("echo \"remove\" > /var/usb3g.stat");
        system("mnet -d &");
    }
#endif /* #ifdef RTK_USB3G */

#if defined(HTTP_FILE_SERVER_SUPPORTED)
		RunSystemCmd("/proc/http_file/getLanIp", "echo", "1", NULL_STR);
#endif

	#if defined(CONFIG_DOMAIN_NAME_QUERY_SUPPORT)
		system("rm -f  /var/system/start_init 2> /dev/null");
	#endif

	//reply only if the target IP address is local address configured on the incoming interface
	RunSystemCmd("/proc/sys/net/ipv4/conf/eth1/arp_ignore", "echo", "1", NULL_STR);
	
	/* Edison 2011.4.7 */
	system("echo > /tmp/fwready");

	/* Emily 2011.5.6 set default timezone*/
	unsigned char t1[4]="", t2[4]="";
	unsigned char initTimezone[8]="";
	unsigned char Deftimezone[8]="";
	unsigned char puttzenv[10]="";
	apmib_get(MIB_NTP_TIMEZONE, (void *)initTimezone);
	sscanf(initTimezone, "%s%s", t1, t2);
	strcpy(Deftimezone,"GMT");
	strcat(Deftimezone,  t1);;
	RunSystemCmd("/var/TZ", "echo", Deftimezone, NULL_STR);
	strcpy(puttzenv, "TZ=");
	strcat(puttzenv, Deftimezone);
	putenv(puttzenv);
	printf("System TZ ENV = %s\n", getenv("TZ"));
	
	return 0;
}

void Init_Internet(int argc, char** argv)
{
#ifdef   HOME_GATEWAY	
	int wisp_id=0, wan_mode=0, opmode=0;
	char br_interface[16]={0};
	char wan_interface[16]={0};
	char tmp_args[16]={0};
	
	
	if(argc < 4)
		return;
		
	apmib_get(MIB_OP_MODE,(void *)&opmode);
	if(opmode == 1)
		return;
	
	apmib_get(MIB_WISP_WAN_ID,(void *)&wisp_id);
	
	sprintf(tmp_args, "%s",argv[1]);
	if(!strcmp(tmp_args, "pppoe"))
		wan_mode=3;
	else if(!strcmp(tmp_args, "pptp"))
		wan_mode=4;	
	else if(!strcmp(tmp_args, "l2tp"))
		wan_mode=6;
	else{
		printf("Un-support wan type for init\n");
		return;
	}
	sprintf(br_interface, "%s", "br0");
	sprintf(wan_interface, "%s",argv[3]);
	start_wan(wan_mode, opmode, wan_interface, br_interface, wisp_id, 0);		
#endif	
}
 
void Init_QoS(int argc, char** argv)
{
#ifdef   HOME_GATEWAY	
	int wisp_id=0, wan_mode=0, opmode=0;
	
	
	apmib_get(MIB_OP_MODE,(void *)&opmode);
	if(opmode == 1)
		return;
		
	apmib_get(MIB_WISP_WAN_ID,(void *)&wisp_id);
	apmib_get(MIB_WAN_DHCP,(void *)&wan_mode);		
	set_QoS(opmode, wan_mode, wisp_id);
#endif	
	
}

//2011.05.24 Jerry {
void restart_upnp_igd(int wantype, int sys_opmode, int wisp_id, char *lan_interface)
{
	int intValue=0;
	char tmp1[16]={0};
	char tmp2[16]={0};
	apmib_get(MIB_UPNP_ENABLED, (void *)&intValue);
	RunSystemCmd(NULL_FILE, "killall", "-15", "miniigd", NULL_STR); 
	if(intValue==1){
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
//2011.05.24 Jerry }

//2011.04.16 Jerry {
int restart_lan()
{
	int i, opmode=-1, intValue=0;
	char cmdBuffer[100], tmpBuff[512];
	int lan_dhcp_mode=0;
	char Ip[32], Mask[32], Gateway[32];
	char strPID[32];
	int pid = 0;
	char tmp_args[16];
	//2011.05.24 Jerry {
	int wan_dhcp_mode = 0;
	int sys_mode = -1;
	char lan_interface[16] = {0};
	int wisp_wan_id=0;
	//2011.05.24 Jerry }

	printf("Restart LAN...\n");

	//2011.05.24 Jerry {
	apmib_get(MIB_WAN_DHCP,(void *)&wan_dhcp_mode);
	apmib_get(MIB_OP_MODE,(void *)&sys_mode);
	sprintf(lan_interface, "%s", "br0");
	apmib_get(MIB_WISP_WAN_ID,(void *)&wisp_wan_id);
	//2011.05.24 Jerry }

	apmib_get(MIB_OP_MODE,(void *)&opmode);
	apmib_get(MIB_DHCP,(void *)&lan_dhcp_mode);

	/* set interface name  start*/		
	memset(br_lan2_interface, 0x00, sizeof(br_lan2_interface));
	sprintf(br_interface, "%s", "br0");
	sprintf(br_lan1_interface, "%s" , "eth0");
	if(opmode == 1) {	//ap
		gateway=0;
		sprintf(br_lan2_interface, "%s", "eth1");
	}
	else if (opmode == 0) {	//gw
		if(opmode==2)
			sprintf(wan_interface, "wlan%d", wisp_wan_id);
		else
			sprintf(wan_interface, "%s", "eth1");
		gateway = 1;
	}
	RunSystemCmd(PROC_BR_IGMPPROXY, "echo", "0", NULL_STR);	//2011.06.02 Jerry

	memset(wlan_interface, 0x00, sizeof(wlan_interface));
	for(i=0;i<NUM_WLAN_INTERFACE;i++){
		if(wlan_interface[0]==0x00)
			sprintf(wlan_interface, "wlan%d", i);
		else{
			sprintf(tmp_args, " wlan%d", i);
			strcat(wlan_interface, tmp_args); 
		}
	}
	/* set interface name  end*/

	//Clean process
	RunSystemCmd(NULL_FILE, "killall", "-9", "ntp_inet", NULL_STR);
	RunSystemCmd(NULL_FILE, "killall", "-9", "ntpclient", NULL_STR);	
	if(isFileExist(DHCPD_PID_FILE)){	//2011.03.16 Jerry
		pid=getPid_fromFile(DHCPD_PID_FILE);
		if(pid != 0){
			sprintf(strPID, "%d", pid);
			RunSystemCmd(NULL_FILE, "kill", "-16", strPID, NULL_STR);/*inform dhcp server write lease table to file*/
			sleep(1);
			RunSystemCmd(NULL_FILE, "kill", "-9", strPID, NULL_STR);
		}
		unlink(DHCPD_PID_FILE);
	}
	//2011.06.02 Jerry {
	if(isFileExist(IGMPPROXY_PID_FILE)){
		pid=getPid_fromFile(IGMPPROXY_PID_FILE);
		if(pid != 0){
			sprintf(strPID, "%d", pid);
			RunSystemCmd(NULL_FILE, "kill", "-9", strPID, NULL_STR);
		}
		unlink(IGMPPROXY_PID_FILE);
		RunSystemCmd(PROC_BR_MCASTFASTFWD, "echo", "1,0", NULL_STR);
	}
	//2011.06.02 Jerry }

	sprintf(tmpBuff, "/etc/udhcpc/udhcpc-%s.pid", br_interface);
	if(isFileExist(tmpBuff)){
		pid=getPid_fromFile(tmpBuff);
		if(pid != 0){
			sprintf(strPID, "%d", pid);
			RunSystemCmd(NULL_FILE, "kill", "-9", strPID, NULL_STR);
		}
		unlink(tmpBuff);
	}
	sprintf(tmpBuff, "/etc/udhcpc/udhcpc-%s.pid", br_lan2_interface);
	if(isFileExist(tmpBuff)){
		pid=getPid_fromFile(tmpBuff);
		if(pid !=0){
			sprintf(strPID, "%d", pid);
			RunSystemCmd(NULL_FILE, "kill", "-9", strPID, NULL_STR);
		}
		unlink(tmpBuff);
	}

	if(isFileExist(DETECTWAN_PID_FILE)){
		pid=getPid_fromFile(DETECTWAN_PID_FILE);
		if(pid != 0){
			sprintf(strPID, "%d", pid);
			RunSystemCmd(NULL_FILE, "kill", "-9", strPID, NULL_STR);
		}
		unlink(DETECTWAN_PID_FILE);
		unlink("/tmp/dhcp_renew");
	}


	RunSystemCmd(NULL_FILE, "ifconfig", "eth0", "down", NULL_STR);
	RunSystemCmd(NULL_FILE, "ifconfig", "peth0", "down", NULL_STR);

	apmib_get(MIB_ELAN_MAC_ADDR,  (void *)tmpBuff);
	if(!memcmp(tmpBuff, "\x00\x00\x00\x00\x00\x00", 6))
		apmib_get(MIB_HW_NIC0_ADDR,  (void *)tmpBuff);
	sprintf(cmdBuffer, "%02x%02x%02x%02x%02x%02x", (unsigned char)tmpBuff[0], (unsigned char)tmpBuff[1], 
		(unsigned char)tmpBuff[2], (unsigned char)tmpBuff[3], (unsigned char)tmpBuff[4], (unsigned char)tmpBuff[5]);
	
	if(br_lan1_interface[0])
		RunSystemCmd(NULL_FILE, "ifconfig", br_lan1_interface, "hw", "ether", cmdBuffer, NULL_STR);/*set eth0 mac address*/

	if(gateway==1){
		/*init bridge interface*/
		set_br_interface(tmpBuff);
		printf("bridge interface: %s\n", tmpBuff);
		setbridge(tmpBuff);

		/* init lan dhcp setting*/
		if(lan_dhcp_mode==0){		/*DHCP disabled*/
			apmib_get( MIB_IP_ADDR,  (void *)tmpBuff);
			sprintf(Ip, "%s", inet_ntoa(*((struct in_addr *)tmpBuff)));
			apmib_get( MIB_SUBNET_MASK,  (void *)tmpBuff);
			sprintf(Mask, "%s", inet_ntoa(*((struct in_addr *)tmpBuff)));
			apmib_get(MIB_DEFAULT_GATEWAY,  (void *)tmpBuff);
			
			if (!memcmp(tmpBuff, "\x0\x0\x0\x0", 4))
				memset(Gateway, 0x00, sizeof(Gateway));
			else
				sprintf(Gateway, "%s", inet_ntoa(*((struct in_addr *)tmpBuff)));
				
			RunSystemCmd(NULL_FILE, "ifconfig", br_interface, Ip, "netmask", Mask, NULL_STR);
			
			if(Gateway[0]){
				RunSystemCmd(NULL_FILE, "route", "del", "default", br_interface, NULL_STR);
				RunSystemCmd(NULL_FILE, "route", "add", "-net", "default", "gw", Gateway, "dev", br_interface, NULL_STR);
			}	
			//start_wlanapp(v_wlan_app_enabled);
		}else if(lan_dhcp_mode==2)
		{		/*DHCP server enabled*/
			set_lan_dhcpd(br_interface, 2);
			//start_wlanapp(v_wlan_app_enabled);
		}
	}
	else
	{ /*gateway is 0, it is ap mode*/
		set_br_interface(tmpBuff);
		setbridge(tmpBuff);

		//Not used at present in order to find the root cause!!!
		//Patch: wlan pc can't visit AP using wapi-psk or wapi-cert when AP boots up			
		if(lan_dhcp_mode==2){	
			sleep(1);
			set_lan_dhcpd(br_interface, 1);
		}	
	}

#ifndef STAND_ALONE_MINIUPNP
	start_upnpd(gateway, opmode);
#endif

	if(gateway==1 && opmode != 1){
		if(isFileExist(LLTD_PROCESS_FILE))
			RunSystemCmd(NULL_FILE, "lld2d", br_interface, NULL_STR);
	}

#ifdef HOME_GATEWAY // To enable/disable ipv6 passthru no matter wan is connected or not
	if(opmode == 0)	// Gateway mode
		apmib_get(MIB_CUSTOM_PASSTHRU_ENABLED, (void *)&intValue);
	else
		intValue=0;

	RunSystemCmd("/proc/custom_Passthru", "echo", (intValue & 0x1)?"1":"0", NULL_STR);
	if (intValue == 0)
	{
		RunSystemCmd(NULL_FILE, "brctl", "delif", "br0", "peth0", NULL_STR);
		RunSystemCmd(NULL_FILE, "ifconfig", "peth0", "down", NULL_STR);
	}
	else
	{
		RunSystemCmd(NULL_FILE, "brctl", "addif", "br0", "peth0", NULL_STR);
		RunSystemCmd(NULL_FILE, "ifconfig", "peth0", "up", NULL_STR);
	}
#endif

	/*enable igmp snooping*/
	/*igmp snooping is independent with igmp proxy*/
	RunSystemCmd(PROC_BR_IGMPSNOOP, "echo", "1", NULL_STR);	//2011.06.02 Jerry
	RunSystemCmd(PROC_BR_IGMPQUERY, "echo", "1", NULL_STR);	//2011.06.02 Jerry
	restart_upnp_igd(wan_dhcp_mode, sys_mode, wisp_wan_id, lan_interface);	//2011.05.24 Jerry
	return 0;
}
//2011.04.16 Jerry {

//2011.04.16 Jerry {
int restart_wan(int reinit_if)
{
	int i, opmode=-1, intValue=0;
	char cmdBuffer[100], tmpBuff[512];
	int wisp_wan_id=0;
	int wan_dhcp_mode=0;
	char strPID[32];
	int pid = 0;
	char tmp_args[16];
	int wanduckproc = 0;

	if(isFileExist(SET_TIME)==0){
		RunSystemCmd(NULL_FILE, "flash", "settime", NULL_STR);
	}

	printf("Restart WAN...\n");
	apmib_get(MIB_OP_MODE,(void *)&opmode);
	apmib_get(MIB_WISP_WAN_ID,(void *)&wisp_wan_id);
#ifdef   HOME_GATEWAY	
	apmib_get(MIB_WAN_DHCP,(void *)&wan_dhcp_mode);
#endif	

	/* set interface name  start*/		
	memset(br_lan2_interface, 0x00, sizeof(br_lan2_interface));
	sprintf(br_interface, "%s", "br0");
	sprintf(br_lan1_interface, "%s" , "eth0");
	if(opmode == 1) {	//ap
		gateway=0;
		sprintf(br_lan2_interface, "%s", "eth1");
	}
	else if (opmode == 0) {	//gw
		if(opmode==2)
			sprintf(wan_interface, "wlan%d", wisp_wan_id);
		else
			sprintf(wan_interface, "%s", "eth1");
		gateway = 1;
		//sprintf(br_lan2_interface, "%s", "eth1");
	}

	RunSystemCmd(PROC_BR_IGMPPROXY, "echo", "0", NULL_STR);

	memset(wlan_interface, 0x00, sizeof(wlan_interface));
	for(i=0;i<NUM_WLAN_INTERFACE;i++){
		if(wlan_interface[0]==0x00)
			sprintf(wlan_interface, "wlan%d", i);
		else{
			sprintf(tmp_args, " wlan%d", i);
			strcat(wlan_interface, tmp_args); 
		}
	}
	/* set interface name  end*/

	RunSystemCmd(NULL_FILE, "rm", "-f", "/etc/ppp/first", NULL_STR);
	RunSystemCmd(NULL_FILE, "rm", "-f", "/etc/ppp/firstpptp", NULL_STR);
	RunSystemCmd(NULL_FILE, "rm", "-f", "/etc/ppp/firstl2tp", NULL_STR);
	RunSystemCmd(NULL_FILE, "rm", "-f", "/etc/ppp/firstdemand", NULL_STR);
#ifdef   HOME_GATEWAY		
	wan_disconnect("all");
#endif

	//Clean process
	if(isFileExist(L2TPD_PID_FILE)){
		pid=getPid_fromFile(L2TPD_PID_FILE);
		if(pid != 0){
			sprintf(strPID, "%d", pid);
			RunSystemCmd(NULL_FILE, "kill", "-9", strPID, NULL_STR);
		}
		unlink(L2TPD_PID_FILE);
	}

	sprintf(tmpBuff, "/etc/udhcpc/udhcpc-%s.pid", wan_interface);
	if(isFileExist(tmpBuff)){
		pid=getPid_fromFile(tmpBuff);
		if(pid !=0){
			sprintf(strPID, "%d", pid);
			RunSystemCmd(NULL_FILE, "kill", "-9", strPID, NULL_STR);
		}
		unlink(tmpBuff);
	}

	if(isFileExist(DNRD_PID_FILE)){
		pid=getPid_fromFile(DNRD_PID_FILE);
		if(pid != 0){
			sprintf(strPID, "%d", pid);
			RunSystemCmd(NULL_FILE, "kill", "-9", strPID, NULL_STR);
		}
		unlink(DNRD_PID_FILE);
	}

	if(isFileExist(IGMPPROXY_PID_FILE)){
		pid=getPid_fromFile(IGMPPROXY_PID_FILE);
		if(pid != 0){
			sprintf(strPID, "%d", pid);
			RunSystemCmd(NULL_FILE, "kill", "-9", strPID, NULL_STR);
		}
		unlink(IGMPPROXY_PID_FILE);
		RunSystemCmd(PROC_BR_MCASTFASTFWD, "echo", "1,0", NULL_STR);
	}

	if(isFileExist(LLTD_PID_FILE)){
		pid=getPid_fromFile(LLTD_PID_FILE);
		if(pid != 0){
			sprintf(strPID, "%d", pid);
			RunSystemCmd(NULL_FILE, "kill", "-9", strPID, NULL_STR);
		}
		unlink(LLTD_PID_FILE);
	}

	if(isFileExist(DETECTWAN_PID_FILE)){
		pid=getPid_fromFile(DETECTWAN_PID_FILE);
		if(pid != 0){
			sprintf(strPID, "%d", pid);
			RunSystemCmd(NULL_FILE, "kill", "-9", strPID, NULL_STR);
		}
		unlink(DETECTWAN_PID_FILE);
		unlink("/tmp/dhcp_renew");
	}
	//Clearn process

	/*save the last wan type*/ /*no this operate in shell script*/
	sprintf(tmp_args, "%d", wan_dhcp_mode);
	RunSystemCmd("/var/system/last_wan", "echo", tmp_args, NULL_STR);
	if(reinit_if)
		RunSystemCmd(NULL_FILE, "ifconfig", "eth1", "down", NULL_STR);
	RunSystemCmd(NULL_FILE, "rm", "-f", "/tmp/wanstatus.log", NULL_STR);	//2011.05.26 Jerry: Delete ppp log

	if(reinit_if) 
	{	
		if(opmode == 1 || opmode == 2){
			apmib_get(MIB_ELAN_MAC_ADDR,  (void *)tmpBuff);
			if(!memcmp(tmpBuff, "\x00\x00\x00\x00\x00\x00", 6))
				apmib_get(MIB_HW_NIC1_ADDR,  (void *)tmpBuff);
			sprintf(cmdBuffer, "%02x%02x%02x%02x%02x%02x", (unsigned char)tmpBuff[0], (unsigned char)tmpBuff[1], 
				(unsigned char)tmpBuff[2], (unsigned char)tmpBuff[3], (unsigned char)tmpBuff[4], (unsigned char)tmpBuff[5]);
			if(br_lan2_interface[0])	
				RunSystemCmd(NULL_FILE, "ifconfig", br_lan2_interface, "hw", "ether", cmdBuffer, NULL_STR);/*set eth1 mac address when bridge mode*/
		}
	
#ifdef   HOME_GATEWAY	
		if(gateway ==1 && opmode != 1){
			apmib_get(MIB_WAN_MAC_ADDR,  (void *)tmpBuff);
			if(!memcmp(tmpBuff, "\x00\x00\x00\x00\x00\x00", 6)){
				if(opmode == 2)
					apmib_get(MIB_HW_WLAN_ADDR,  (void *)tmpBuff);
				else
					apmib_get(MIB_HW_NIC1_ADDR,  (void *)tmpBuff);
			}
			sprintf(cmdBuffer, "%02x%02x%02x%02x%02x%02x", (unsigned char)tmpBuff[0], (unsigned char)tmpBuff[1], 
				(unsigned char)tmpBuff[2], (unsigned char)tmpBuff[3], (unsigned char)tmpBuff[4], (unsigned char)tmpBuff[5]);
			if(wan_interface[0])
				RunSystemCmd(NULL_FILE, "ifconfig", wan_interface, "hw", "ether", cmdBuffer, NULL_STR);/*set wan mac address when it not bridge mode*/
		}
#endif
	}

	if(gateway==1){
		RunSystemCmd(NULL_FILE, "iptables", "-F", NULL_STR);
		RunSystemCmd(NULL_FILE, "iptables", "-F", "-t", "nat",  NULL_STR);
		RunSystemCmd(NULL_FILE, "iptables", "-A", "INPUT", "-j", "ACCEPT", NULL_STR);
		
		if(wan_interface[0])
		{
			if(reinit_if)
			{
				RunSystemCmd(NULL_FILE, "ifconfig", wan_interface, "down", NULL_STR);
				RunSystemCmd(NULL_FILE, "ifconfig", wan_interface, "up", NULL_STR);
			}
		}

		if(opmode == 0){/*for init internet wan setting*/ 
			RunSystemCmd(PROC_FASTNAT_FILE, "echo", "1", NULL_STR);
			
			if(wan_dhcp_mode==PPTP){
				RunSystemCmd(PROC_FASTPPTP_FILE, "echo", "1", NULL_STR);
				apmib_get(MIB_PPTP_CONNECTION_TYPE, (void *)&intValue);
				if(intValue==1){
					RunSystemCmd(PROC_PPTP_CONN_FILE, "echo", "3", NULL_STR);
				}else{
					RunSystemCmd(PROC_PPTP_CONN_FILE, "echo", "0", NULL_STR);
				}
			}else{
				RunSystemCmd(PROC_FASTPPTP_FILE, "echo", "0", NULL_STR);
			}
				
			if(wan_dhcp_mode==L2TP){
				RunSystemCmd(PROC_FASTL2TP_FILE, "echo", "1", NULL_STR);
			}else{
				RunSystemCmd(PROC_FASTL2TP_FILE, "echo", "0", NULL_STR);
			}
	#ifdef HOME_GATEWAY		
			if((wan_dhcp_mode !=DHCP_SERVER && wan_dhcp_mode < 7) || (wan_dhcp_mode == USB3G)){ /* */
				wanduckproc = find_pid_by_name("wanduck");
				if(wanduckproc > 0)
					kill(wanduckproc, SIGUSR2);
				if(wan_dhcp_mode == DHCP_CLIENT)
					system("echo 1 > /tmp/dhcp_renew");
				start_wan(wan_dhcp_mode, opmode, wan_interface, br_interface, wisp_wan_id, 1);
			}else
				printf("Invalid wan type:wan_dhcp_mode=%d\n", wan_dhcp_mode);
	#endif			
		}
		else if( opmode == 1 ){
			/*Bridge mode, eth1 mtu should be sync with eth0 mtu (assume that eth0 mtu is 1500 here!!!)
			Otherwise, ping large pkt failed when GW mode changed to Bridge mode
			if eth1 mtu not equal with eth0 mtu.*/
			if(wan_interface[0])
				RunSystemCmd(NULL_FILE, "ifconfig", wan_interface, "mtu", "1500", NULL_STR);
		}

		//set kthreadd high priority for performance
		RunSystemCmd(NULL_FILE, "renice -20 2", NULL_STR);
		//set ksoftirqd high priority for performance
		RunSystemCmd(NULL_FILE, "renice -20 3", NULL_STR);
	}

	if(gateway==1 && opmode != 1){
		if(isFileExist(LLTD_PROCESS_FILE))
			RunSystemCmd(NULL_FILE, "lld2d", br_interface, NULL_STR);
	}

	//reply only if the target IP address is local address configured on the incoming interface
	RunSystemCmd("/proc/sys/net/ipv4/conf/eth1/arp_ignore", "echo", "1", NULL_STR);

	wanduckproc = find_pid_by_name("wanduck");
	if(wanduckproc > 0)
		kill(wanduckproc, SIGUSR1);

	return 0;
}

int restart_wlan()
{
	int i, cmdRet=-1;
	int opmode=-1, v_wlan_app_enabled=1, intValue=0;
	char tmpBuff[512];
	int repeater_enabled1=0, repeater_enabled2=0;
	char *token=NULL, *savestr1=NULL;
	int wisp_wan_id=0;
	int wlan_mode_root=0, wlan_root_disabled=0;
	int wlan_support = 0;
	int index;
	char tmp_args[16];

	printf("Restart WLAN...\n");
	RunSystemCmd(NULL_FILE, "killall", "reload", NULL_STR);
	apmib_get(MIB_OP_MODE,(void *)&opmode);
	apmib_get(MIB_WISP_WAN_ID,(void *)&wisp_wan_id);

	/* set interface name  start*/		
	memset(br_lan2_interface, 0x00, sizeof(br_lan2_interface));
	sprintf(br_interface, "%s", "br0");
	sprintf(br_lan1_interface, "%s" , "eth0");
	if(opmode == 1) {	//ap
		gateway=0;
		sprintf(br_lan2_interface, "%s", "eth1");
	}
	else if (opmode == 0) {	//gw
		if(opmode==2)
			sprintf(wan_interface, "wlan%d", wisp_wan_id);
		else
			sprintf(wan_interface, "%s", "eth1");
		gateway = 1;
	}

	memset(wlan_interface, 0x00, sizeof(wlan_interface));
	memset(wlan_valid_interface, 0x00, sizeof(wlan_valid_interface));
	for(i=0;i<NUM_WLAN_INTERFACE;i++){
		if(wlan_interface[0]==0x00)
			sprintf(wlan_interface, "wlan%d", i);
		else{
			sprintf(tmp_args, " wlan%d", i);
			strcat(wlan_interface, tmp_args); 
		}
	}
	wlan_support = if_readlist_proc(wlan_valid_interface, "wlan", 0);
	if(wlan_support==0)
		memset(wlan_interface, 0x00, sizeof(wlan_interface));
	/* set interface name  end*/

	/*init wlan interface*/
	if (wlan_support != 0)
	{
		memset(wlan_interface, 0x00, sizeof(wlan_interface));
		for(i=0;i<NUM_WLAN_INTERFACE;i++)
		{
			int wlan_disable = 1;			
			unsigned char wlan_name[10];
			memset(wlan_name,0x00,sizeof(wlan_name));
			sprintf(wlan_name, "wlan%d",i);
			if(SetWlan_idx(wlan_name))
			{			
				apmib_get( MIB_WLAN_WLAN_DISABLED, (void *)&wlan_disable);	  

				if(wlan_disable == 1)
				{
					RunSystemCmd(NULL_FILE, "iwpriv", wlan_name, "radio_off", NULL_STR);					
				}
				else
				{
					if(wlan_interface[0]==0x00)
						sprintf(wlan_interface, "%s", wlan_name);
					else
					{
						sprintf(tmp_args, " %s", wlan_name);
						strcat(wlan_interface, tmp_args); 
					}							
				}
			}
		}				
	}

	apmib_get(MIB_REPEATER_ENABLED1,(void *)&repeater_enabled1);
	apmib_get(MIB_REPEATER_ENABLED2,(void *)&repeater_enabled2);

	if(SetWlan_idx("wlan0")){
		apmib_get( MIB_WLAN_MODE, (void *)&wlan_mode_root); 
		apmib_get( MIB_WLAN_WLAN_DISABLED, (void *)&wlan_root_disabled);	  
	}

	if(wlan_mode_root != AP_MODE && wlan_mode_root != AP_WDS_MODE && repeater_enabled1 == 0 && repeater_enabled2 == 0)
		v_wlan_app_enabled=0; // no virtual and repeat

	if((repeater_enabled1 == 0 && repeater_enabled2 == 0) ||(wlan_mode_root >= 4 && wlan_mode_root <=7) ||(wlan_mode_root == 2)) 
		memset(wlan_vxd_interface, 0x00, sizeof(wlan_vxd_interface));

	/*init wlan interface*/
	if (wlan_support != 0)
	{
		int br_wlan_block=0;
		memset(wlan_interface, 0x00, sizeof(wlan_interface));
		for(i=0;i<NUM_WLAN_INTERFACE;i++)
		{
			int wlan_disable = 1;
			int wlan_blockrelay=0;
			unsigned char wlan_name[10];
			memset(wlan_name,0x00,sizeof(wlan_name));
			sprintf(wlan_name, "wlan%d",i);
			if(SetWlan_idx(wlan_name))
			{
				apmib_get( MIB_WLAN_WLAN_DISABLED, (void *)&wlan_disable);	  
				if(wlan_disable == 1)
				{
					RunSystemCmd(NULL_FILE, "iwpriv", wlan_name, "radio_off", NULL_STR);					
				}
				else
				{
	                		if(wlan_interface[0]==0x00)
        	            			sprintf(wlan_interface, "%s", wlan_name);
                			else
	                		{
						sprintf(tmp_args, " %s", wlan_name);
	        	        		strcat(wlan_interface, tmp_args); 
        	        		}	
						
					RunSystemCmd(NULL_FILE, "ifconfig", wlan_name, "down", NULL_STR);
					cmdRet=RunSystemCmd(NULL_FILE, "flash", "set_mib", wlan_name, NULL_STR);
			
					if(cmdRet != 0)
					{
						printf("init %s failed!\n", wlan_name);
						continue;
					}

				}
				
				apmib_get( MIB_WLAN_BLOCK_RELAY,(void *)&wlan_blockrelay);
				/*if all wlan interface block then enable br_wlan_block*/
				if(wlan_blockrelay)
				{
					if(!br_wlan_block)
						br_wlan_block=1;
				}
				else
					br_wlan_block=0;
			}
		}
		
		if(br_wlan_block)
			RunSystemCmd("/proc/br_wlanblock", "echo","1",NULL_STR);
		else
			RunSystemCmd("/proc/br_wlanblock", "echo","0",NULL_STR);
	}

	if(wlan_interface[0])			
	{				
		if(wlan_vxd_interface[0]) {
			RunSystemCmd(NULL_FILE, "ifconfig", wlan_vxd_interface, "down", NULL_STR);
			RunSystemCmd(NULL_FILE, "flash", "set_mib", wlan_vxd_interface, NULL_STR);/*set vxd wlan iface*/
		}
		if(wlan_virtual_interface[0]){
			token=NULL;
			savestr1=NULL;
			sprintf(tmpBuff, "%s", wlan_virtual_interface);
			token = strtok_r(tmpBuff," ", &savestr1);
			do{
				if (token == NULL){
					break;
				}else{
					RunSystemCmd(NULL_FILE, "ifconfig", token, "down", NULL_STR);
					RunSystemCmd(NULL_FILE, "flash", "set_mib", token, NULL_STR);/*set virtual wlan iface*/
				}
				token = strtok_r(NULL, " ", &savestr1);
			}while(token !=NULL);
		}
	}

	printf("Sleep 5 seconds!!\n");
	sleep(5);
	set_br_interface(tmpBuff);
	setbridge(tmpBuff);
	start_wlanapp(v_wlan_app_enabled);

	for(index=0; index<NUM_WLAN_INTERFACE; index++)
		start_wlan_by_schedule(index);

	if((opmode == 2) && (wlan_root_disabled == 0) && (wlan_mode_root == CLIENT_MODE))	//WISP mode, wireless enabled  and wireless client mode enabled
		apmib_get(MIB_CUSTOM_PASSTHRU_ENABLED, (void *)&intValue);
	else
		intValue=0;
	RunSystemCmd("/proc/custom_Passthru_wlan", "echo", (intValue & 0x1)?"1":"0", NULL_STR);
	
	if (intValue == 0)
	{
		RunSystemCmd(NULL_FILE, "brctl", "delif", "br0", "pwlan0", NULL_STR);
		RunSystemCmd(NULL_FILE, "ifconfig", "pwlan0", "down", NULL_STR);
	}
	else
	{
		RunSystemCmd(NULL_FILE, "brctl", "addif", "br0", "pwlan0", NULL_STR);
		RunSystemCmd(NULL_FILE, "ifconfig", "pwlan0", "up", NULL_STR);
	}

	return 0;
}
//2011.04.18 Jerry {


