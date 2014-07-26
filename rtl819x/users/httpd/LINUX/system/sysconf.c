/*
 *
 *
 */

/* System include files */
#include <string.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <netdb.h>
#include <stdarg.h>
#include <errno.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/wait.h>
/* Local include files */
#include "../apmib.h"
#include "../mibtbl.h"

#include "sysconf.h"
#include "sys_utility.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <net/if.h>
#include <stddef.h>		/* offsetof */
#include <net/if_arp.h>
#include <linux/if_ether.h>
#include <dirent.h>	//2011.03.29 Jerry
int apmib_initialized = 0;
extern int setinit(int argc, char** argv);
extern int Init_Internet(int argc, char** argv);
extern int setbridge(char *argv);
extern int setFirewallIptablesRules(int argc, char** argv);
extern int setWlan_Applications(char *action, char *argv);
extern void wan_disconnect(char *option);
extern void wan_connect(char *interface, char *option);

extern int Init_QoS(int argc, char** argv);
extern void start_lan_dhcpd(char *interface);
//extern int save_cs_to_file();

extern int restart_lan();	//2011.04.16 Jerry
int restart_lan_flag = 0;	//2011.04.16 Jerry
extern int restart_wan(int reinit_if);	//2011.04.18 Jerry
extern int restart_wlan();	//2011.04.18 Jerry
int restart_wlan_flag = 0;	//2011.04.18 Jerry
extern void start_dnrd();	//2011.07.05 Jerry
extern void start_pppoe_relay(); //2011.07.13 Emily

#ifdef CONFIG_DOMAIN_NAME_QUERY_SUPPORT
extern void wan_connect_pocket(char *interface, char *option);
extern int Check_setting_default(int opmode, int wlan_mode);
extern int Check_setting(int type);
extern void start_upnpd(int isgateway, int sys_op);
#endif
//////////////////////////////////////////////////////////////////////

#ifdef CONFIG_POCKET_ROUTER_SUPPORT
#define POCKETAP_HW_SET_FLAG "/proc/pocketAP_hw_set_flag"
#define AP_CLIENT_ROU_FILE "/proc/ap_client_rou"
#define DC_PWR_FILE "/proc/dc_pwr"

static void set_wlan_low_power()
{
//fprintf(stderr,"\r\n __[%s_%u]\r\n",__FILE__,__LINE__);
	system("iwpriv wlan0 set_mib txPowerPlus_cck_1=0");
	system("iwpriv wlan0 set_mib txPowerPlus_cck_2=0");	
	system("iwpriv wlan0 set_mib txPowerPlus_cck_5=0");		
	system("iwpriv wlan0 set_mib txPowerPlus_cck_11=0");
	system("iwpriv wlan0 set_mib txPowerPlus_ofdm_6=0");	
	system("iwpriv wlan0 set_mib txPowerPlus_ofdm_9=0");
	system("iwpriv wlan0 set_mib txPowerPlus_ofdm_12=0");
	system("iwpriv wlan0 set_mib txPowerPlus_ofdm_18=0");	
	system("iwpriv wlan0 set_mib txPowerPlus_ofdm_24=0");		
	system("iwpriv wlan0 set_mib txPowerPlus_ofdm_36=0");
	system("iwpriv wlan0 set_mib txPowerPlus_ofdm_48=0");	
	system("iwpriv wlan0 set_mib txPowerPlus_ofdm_54=0");
	system("iwpriv wlan0 set_mib txPowerPlus_mcs_0=0");
	system("iwpriv wlan0 set_mib txPowerPlus_mcs_1=0");
	system("iwpriv wlan0 set_mib txPowerPlus_mcs_2=0");
	system("iwpriv wlan0 set_mib txPowerPlus_mcs_3=0");
	system("iwpriv wlan0 set_mib txPowerPlus_mcs_4=0");
	system("iwpriv wlan0 set_mib txPowerPlus_mcs_5=0");
	system("iwpriv wlan0 set_mib txPowerPlus_mcs_6=0");
	system("iwpriv wlan0 set_mib txPowerPlus_mcs_7=0");
	system("iwpriv wlan0 set_mib txPowerPlus_mcs_8=0");
	system("iwpriv wlan0 set_mib txPowerPlus_mcs_9=0");
	system("iwpriv wlan0 set_mib txPowerPlus_mcs_10=0");
	system("iwpriv wlan0 set_mib txPowerPlus_mcs_11=0");
	system("iwpriv wlan0 set_mib txPowerPlus_mcs_12=0");
	system("iwpriv wlan0 set_mib txPowerPlus_mcs_13=0");
	system("iwpriv wlan0 set_mib txPowerPlus_mcs_14=0");
	system("iwpriv wlan0 set_mib txPowerPlus_mcs_15=0");	
//fprintf(stderr,"\r\n __[%s-%u]\r\n",__FILE__,__LINE__);
}


/* Fix whan device is change wlan mode from client to AP or Router. *
  * The CIPHER_SUITE of wpa or wpa2 can't be tkip                           */
static int check_wpa_cipher_suite()
{
	int wlan_band, wlan_onoff_tkip, wlan_encrypt, wpaCipher, wpa2Cipher, wdsEncrypt;

	apmib_get( MIB_WLAN_BAND, (void *)&wlan_band) ;
	apmib_get( MIB_WLAN_11N_ONOFF_TKIP, (void *)&wlan_onoff_tkip) ;					
	apmib_get( MIB_WLAN_ENCRYPT, (void *)&wlan_encrypt);
	apmib_get( MIB_WLAN_WDS_ENCRYPT, (void *)&wdsEncrypt);
	if(wlan_onoff_tkip == 0) //Wifi request
	{
		if(wlan_band == 8 || wlan_band == 10 || wlan_band == 11)//8:n; 10:gn; 11:bgn
		{
			if(wlan_encrypt ==ENCRYPT_WPA || wlan_encrypt ==ENCRYPT_WPA2){
				wpaCipher =  WPA_CIPHER_AES;
				apmib_set(MIB_WLAN_WPA_CIPHER_SUITE, (void *)&wpaCipher);

				wpa2Cipher =  WPA_CIPHER_AES;				
				apmib_set(MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&wpa2Cipher);
			}
			if(wdsEncrypt == WDS_ENCRYPT_TKIP)
			{
				wdsEncrypt = WDS_ENCRYPT_DISABLED;
				apmib_set( MIB_WLAN_WDS_ENCRYPT, (void *)&wdsEncrypt);
			}

		}

	}


}
#if defined(FOR_DUAL_BAND)	
short whichWlanIfIs(PHYBAND_TYPE_T phyBand)
{
	int i;
	int ori_wlan_idx=wlan_idx;
	int ret=-1;
	
	for(i=0 ; i<NUM_WLAN_INTERFACE ; i++)
	{
		unsigned char wlanif[10];
		memset(wlanif,0x00,sizeof(wlanif));
		sprintf(wlanif, "wlan%d",i);
		if(SetWlan_idx(wlanif))
		{
			int phyBandSelect;
			apmib_get(MIB_WLAN_PHY_BAND_SELECT, (void *)&phyBandSelect);
			if(phyBandSelect == phyBand)
			{
				ret = i;
				break;			
			}
		}						
	}
	
	wlan_idx=ori_wlan_idx;
	return ret;		
}
#if defined(CONFIG_RTL_92D_SUPPORT)
void swapWlanMibSetting(unsigned char wlanifNumA, unsigned char wlanifNumB)
{
	unsigned char *wlanMibBuf=NULL;
	unsigned int totalSize = sizeof(CONFIG_WLAN_SETTING_T)*(NUM_VWLAN_INTERFACE+1); // 4vap+1rpt+1root
	wlanMibBuf = malloc(totalSize); 
	if(wlanMibBuf != NULL)
	{
		memcpy(wlanMibBuf, pMib->wlan[wlanifNumA], totalSize);
		memcpy(pMib->wlan[wlanifNumA], pMib->wlan[wlanifNumB], totalSize);
		memcpy(pMib->wlan[wlanifNumB], wlanMibBuf, totalSize);
	
		free(wlanMibBuf);
	}
	
#ifdef UNIVERSAL_REPEATER

	int rptEnable1, rptEnable2;
	char rptSsid1[MAX_SSID_LEN], rptSsid2[MAX_SSID_LEN];
	
	memset(rptSsid1, 0x00, MAX_SSID_LEN);
	memset(rptSsid2, 0x00, MAX_SSID_LEN);
	
	apmib_get(MIB_REPEATER_ENABLED1, (void *)&rptEnable1);
	apmib_get(MIB_REPEATER_ENABLED2, (void *)&rptEnable2);
	apmib_get(MIB_REPEATER_SSID1, (void *)rptSsid1);
	apmib_get(MIB_REPEATER_SSID2, (void *)rptSsid2);
	
	apmib_set(MIB_REPEATER_ENABLED1, (void *)&rptEnable2);
	apmib_set(MIB_REPEATER_ENABLED2, (void *)&rptEnable1);
	apmib_set(MIB_REPEATER_SSID1, (void *)rptSsid2);
	apmib_set(MIB_REPEATER_SSID2, (void *)rptSsid1);
#endif
}
#endif
int switchToClientMode(void)
{
	int intVal=0;
	int i;
	for(i=0 ; i<NUM_WLAN_INTERFACE ; i++)
	{
		unsigned char wlanif[10];
		memset(wlanif,0x00,sizeof(wlanif));
		sprintf(wlanif, "wlan%d",i);
		if(SetWlan_idx(wlanif))
		{
			int intVal;
			intVal = SMACSPHY;
			apmib_set(MIB_WLAN_MAC_PHY_MODE, (void *)&intVal);
		}
	}

	SetWlan_idx("wlan0");
	intVal = 0;
	apmib_set(MIB_WLAN_WLAN_DISABLED, (void *)&intVal);

	SetWlan_idx("wlan1");
	intVal = 1;
	apmib_set(MIB_WLAN_WLAN_DISABLED, (void *)&intVal);
	return 0;
}
int switchFromClientMode(void)
{
	short wlanif;
	int i;

	for(i=0 ; i<NUM_WLAN_INTERFACE ; i++)
	{
		unsigned char wlanif[10];
		memset(wlanif,0x00,sizeof(wlanif));
		sprintf(wlanif, "wlan%d",i);
		if(SetWlan_idx(wlanif))
		{
			int intVal;
			intVal = DMACDPHY;
			apmib_set(MIB_WLAN_MAC_PHY_MODE, (void *)&intVal);
			intVal = 0;
			apmib_set(MIB_WLAN_WLAN_DISABLED, (void *)&intVal);
		}
	}

	unsigned char wlanIfStr[10];	
	wlanif = whichWlanIfIs(PHYBAND_5G);

	/* 92d rule, 5g must up in wlan0 */
	/* phybandcheck */
	if(wlanif != 0)
	{
		swapWlanMibSetting(0,1);	
	}
	return 0;
}
#endif

static int pocketAP_bootup()
{
	char	pocketAP_hw_set_flag = 0;
	int op_mode=1;
	int lan_dhcp;
	int cur_op_mode;
	int wlan0_mode;
#if defined(FOR_DUAL_BAND)	
	int wlan_dual_band_mode;
#endif
	int ret = 0;

	apmib_get( MIB_OP_MODE, (void *)&cur_op_mode);
	apmib_get( MIB_WLAN_MODE, (void *)&wlan0_mode);
	if(isFileExist(DC_PWR_FILE))
	{
		FILE *fp=NULL;	
		unsigned char dcPwr_str[100];
		memset(dcPwr_str,0x00,sizeof(dcPwr_str));
			
		fp=fopen(DC_PWR_FILE, "r");
		if(fp!=NULL)
		{
			fgets(dcPwr_str,sizeof(dcPwr_str),fp);
			fclose(fp);

			if(strlen(dcPwr_str) != 0)
			{
				dcPwr_str[1]='\0';
				if(strcmp(dcPwr_str,"2") == 0)
				{
					set_wlan_low_power();
				}
			}
		}
	}


	if(isFileExist(POCKETAP_HW_SET_FLAG))
	{
		FILE *fp=NULL;	
		unsigned char pocketAP_hw_set_flag_str[10];
		memset(pocketAP_hw_set_flag_str,0x00,sizeof(pocketAP_hw_set_flag_str));
			
		fp=fopen(POCKETAP_HW_SET_FLAG, "r");
		if(fp!=NULL)
		{
			fgets(pocketAP_hw_set_flag_str,sizeof(pocketAP_hw_set_flag_str),fp);
			fclose(fp);

			if(strlen(pocketAP_hw_set_flag_str) != 0)
			{
				pocketAP_hw_set_flag_str[1]='\0';
				if(strcmp(pocketAP_hw_set_flag_str,"1") == 0)
				{
					pocketAP_hw_set_flag = 1;
				}
				else
				{
					pocketAP_hw_set_flag = 0;
					system("echo 1 > proc/pocketAP_hw_set_flag");					
				}
			}
		}
		
	}

	if(pocketAP_hw_set_flag == 0 && isFileExist(AP_CLIENT_ROU_FILE))
	{
		FILE *fp=NULL;	
		unsigned char ap_cli_rou_str[10];
		unsigned char kill_webs_flag = 0;
		memset(ap_cli_rou_str,0x00,sizeof(ap_cli_rou_str));		
		
		fp=fopen(AP_CLIENT_ROU_FILE, "r");
		if(fp!=NULL)
		{
			fgets(ap_cli_rou_str,sizeof(ap_cli_rou_str),fp);
			fclose(fp);

			if(strlen(ap_cli_rou_str) != 0)
			{
				ap_cli_rou_str[1]='\0';
												
				if((cur_op_mode != 1 || wlan0_mode == CLIENT_MODE) && strcmp(ap_cli_rou_str,"2") == 0) //AP
				{
					cur_op_mode = 1;
					wlan0_mode = 0;
					lan_dhcp = 15;
					#if defined(FOR_DUAL_BAND)
					wlan_dual_band_mode=BANDMODEBOTH;
					#endif
					
					apmib_set( MIB_OP_MODE, (void *)&cur_op_mode);
					apmib_set( MIB_WLAN_MODE, (void *)&wlan0_mode);
				#if defined(FOR_DUAL_BAND)
					apmib_set( MIB_WLAN_BAND2G5G_SELECT, (void *)&wlan_dual_band_mode);
					switchFromClientMode();	
				#endif
					check_wpa_cipher_suite();
				#if defined(CONFIG_DOMAIN_NAME_QUERY_SUPPORT)
					apmib_set( MIB_DHCP, (void *)&lan_dhcp);
					Check_setting(2);//ap
				#endif				
					if(apmib_update(CURRENT_SETTING) == 1)
						save_cs_to_file();

					reinit_webs();
					//RunSystemCmd(NULL_FILE, "webs&", NULL_STR);
				}
				else if((cur_op_mode != 1 || wlan0_mode != CLIENT_MODE) && strcmp(ap_cli_rou_str,"1") == 0) //CLIENT
				{
					cur_op_mode = 1;
					wlan0_mode = 1;
					lan_dhcp = 15;
					#if defined(FOR_DUAL_BAND)
					wlan_dual_band_mode=BANDMODESINGLE;
					#endif
					
					apmib_set( MIB_OP_MODE, (void *)&cur_op_mode);
					apmib_set( MIB_WLAN_MODE, (void *)&wlan0_mode);		
				#if defined(FOR_DUAL_BAND)
					apmib_set( MIB_WLAN_BAND2G5G_SELECT, (void *)&wlan_dual_band_mode);
					switchToClientMode();
				#endif
				#if defined(CONFIG_DOMAIN_NAME_QUERY_SUPPORT)
					apmib_set( MIB_DHCP, (void *)&lan_dhcp);
					Check_setting(1);//client
				#endif
					if(apmib_update(CURRENT_SETTING) == 1)
						save_cs_to_file();
					reinit_webs();
					
				}
				else if(cur_op_mode != 0 && strcmp(ap_cli_rou_str,"3") == 0) //router
				{
					cur_op_mode = 0;
					wlan0_mode = 0;
					lan_dhcp = 2;
					#if defined(FOR_DUAL_BAND)
					wlan_dual_band_mode=BANDMODEBOTH;
					#endif

					apmib_set( MIB_OP_MODE, (void *)&cur_op_mode);
					apmib_set( MIB_WLAN_MODE, (void *)&wlan0_mode);
				#if defined(FOR_DUAL_BAND)
					apmib_set( MIB_WLAN_BAND2G5G_SELECT, (void *)&wlan_dual_band_mode);
					switchFromClientMode();					
				#endif
					check_wpa_cipher_suite();
				#if defined(CONFIG_DOMAIN_NAME_QUERY_SUPPORT)
					apmib_set( MIB_DHCP, (void *)&lan_dhcp);
					Check_setting(3);//router
				#endif
					if(apmib_update(CURRENT_SETTING) == 1)
						save_cs_to_file();
					reinit_webs();
					//RunSystemCmd(NULL_FILE, "webs&", NULL_STR);				
				}
				else
				{
					#if defined(CONFIG_DOMAIN_NAME_QUERY_SUPPORT)
					apmib_get(MIB_OP_MODE, (void *)&op_mode);
					if(op_mode == 0)
					{
						lan_dhcp = 2;
						apmib_set(MIB_DHCP, (void *)&lan_dhcp);
					}
					else
					{
						lan_dhcp = 15;
						apmib_set(MIB_DHCP, (void *)&lan_dhcp);
					}
					ret=Check_setting_default(cur_op_mode, wlan0_mode);
				#if defined(FOR_DUAL_BAND)	
					apmib_get( MIB_WLAN_MODE, (void *)&wlan0_mode);
					apmib_get( MIB_WLAN_BAND2G5G_SELECT, (void *)&wlan_dual_band_mode);
					if((wlan0_mode == 1) && (wlan_dual_band_mode == 3))
					{
						switchToClientMode();
					}					
				#endif
				
					if(ret==1){
						if(apmib_update(CURRENT_SETTING) == 1)
							save_cs_to_file();

						reinit_webs();	
					}	
					#endif
				}
			}
		}
	}
	else
	{

		#if defined(CONFIG_DOMAIN_NAME_QUERY_SUPPORT)
		apmib_get(MIB_OP_MODE, (void *)&op_mode);
		if(op_mode == 0)
		{
			lan_dhcp = 2;
			apmib_set(MIB_DHCP, (void *)&lan_dhcp);
		}
		else
		{
			lan_dhcp = 15;
			apmib_set(MIB_DHCP, (void *)&lan_dhcp);
		}

		ret=Check_setting_default(cur_op_mode, wlan0_mode);
		if(ret==1){
			if(apmib_update(CURRENT_SETTING) == 1)
				save_cs_to_file();

			reinit_webs();	
		}	
		#endif
	}

}
#endif

int main(int argc, char** argv)
{
	char	line[300];
	char action[16];
	int i;
	//printf("start.......:%s\n",argv[1]);
	
	
	if ( !apmib_init()) {
		printf("Initialize AP MIB failed !\n");
		return -1;
	}
	apmib_initialized = 1;
	memset(line,0x00,300);
	
	if(argv[1] && (strcmp(argv[1], "init")==0)){
#ifdef CONFIG_POCKET_ROUTER_SUPPORT
	pocketAP_bootup();
#endif	
		int wan_ready = 0;
		int wanduck_pid;
		apmib_set(MIB_WAN_READY, (void *)&wan_ready);
		apmib_update(CURRENT_SETTING);
		wanduck_pid = find_pid_by_name("wanduck");
		if(wanduck_pid > 0)
			kill(wanduck_pid ,SIGUSR1);
		//system("flash set WAN_READY 0");	//2011.03.15 Jerry
		
		setinit(argc,argv);
		return 0;
	} else if(argv[1] && (strcmp(argv[1], "br")==0)){
		for(i=0;i<argc;i++){
			if( i>2 )
				string_casecade(line, argv[i]);
		}
		setbridge(line);
	}
#ifdef   HOME_GATEWAY	
	else if(argv[1] && (strcmp(argv[1], "firewall")==0)){
		setFirewallIptablesRules(argc,argv);
	}
	else if(argv[1] && (strcmp(argv[1], "wlanapp")==0)){
		for(i=0;i<argc;i++){
			if( i>2 )
				string_casecade(line, argv[i]);
			if(i==2)
				sprintf(action, "%s",argv[i]); 
		}
		setWlan_Applications(action, line);
	}else if(argv[1] && (strcmp(argv[1], "disc")==0)){
		sprintf(line, "%s", argv[2]);
		wan_disconnect(line);
	}else if(argv[1] && (strcmp(argv[1], "conn")==0)){
		if(argc < 4){
			printf("sysconf conn Invalid agrments!\n");
			return 0;
		}
		sprintf(action, "%s",argv[3]);
		for(i=0;i<argc;i++){
				if( i>2 )
					string_casecade(line, argv[i]);
			}

		if((!strcmp(argv[2], "dhcp"))&&(isFileExist(TEMP_WAN_CHECK))){
			RunSystemCmd(TEMP_WAN_DHCP_INFO, "echo", line, NULL_STR);
		}

#if defined(CONFIG_DOMAIN_NAME_QUERY_SUPPORT)
		if(!strcmp(action, "br0"))
			wan_connect_pocket(action, line);
		else
		wan_connect(action, line);
#else
		wan_connect(action, line);
#endif
	}else if(argv[1] && (strcmp(argv[1], "pppoe")==0)){
		Init_Internet(argc,argv);
	}else if(argv[1] && (strcmp(argv[1], "pptp")==0)){
		Init_Internet(argc,argv);
	}else if(argv[1] && (strcmp(argv[1], "l2tp")==0)){
		Init_Internet(argc,argv);
	}else if(argv[1] && (strcmp(argv[1], "setQos")==0)){
		Init_QoS(argc,argv);
	}else if(argv[1] && (strcmp(argv[1], "dhcpd")==0)){
		sprintf(action, "%s",argv[2]);
		start_lan_dhcpd(action);
	}
	//2011.04.16 Jerry {
	else if(argv[1] && (strcmp(argv[1], "restart_lan")==0)){
		restart_lan_flag = 1;
		restart_lan();
	}
	//2011.04.16 Jerry }
	//2011.04.18 Jerry {
	else if(argv[1] && (strcmp(argv[1], "restart_wan")==0))
		restart_wan(1);
	else if(argv[1] && (strcmp(argv[1], "wan_up")==0))
		restart_wan(0);
	else if(argv[1] && (strcmp(argv[1], "restart_wlan")==0)) {
		restart_wlan_flag = 1;
		restart_wlan();
	}else if(argv[1] && (strcmp(argv[1], "restart_dhcpd")==0)) {
		DHCP_T curDhcp = DHCP_DISABLED;	
		system("killall -16 udhcpd 2> /dev/null");
		system("killall -9 udhcpd 2> /dev/null");
		unlink(DHCPD_PID_FILE);
		apmib_get( MIB_DHCP, (void *)&curDhcp);
		if(curDhcp == DHCP_SERVER)
			set_lan_dhcpd("br0", 2);
	}
	//2011.04.18 Jerry }
	//2011.06.24 Jerry {
	else if(argv[1] && (strcmp(argv[1], "restart_syslog")==0))
	{
		system("killall syslogd");
		system("killall klogd");
		set_log();
	}
	else if(argv[1] && (strcmp(argv[1], "restart_ntpc")==0))
	{
		system("killall ntp_inet");
		system("killall ntpclient");
		start_ntp();
	}
	else if(argv[1] && (strcmp(argv[1], "restart_detectWAN")==0))
	{
		system("detectWAN &");
	}
	else if(argv[1] && (strcmp(argv[1], "restart_dnrd")==0))
	{
		start_dnrd();
	}
	else if(argv[1] && (strcmp(argv[1], "pppoeRelay")==0))
	{
		start_pppoe_relay();
	}
	//2011.06.24 Jerry }
#if defined(CONFIG_DOMAIN_NAME_QUERY_SUPPORT)	
	else if(argv[1] && (strcmp(argv[1], "upnpd")==0)){
		if(argc < 4){
			printf("sysconf upnpd Invalid agrments!\n");
			return 0;
	}
		start_upnpd(atoi(argv[2]),atoi(argv[3]));
	} 
#endif	
	
#endif	
	
//#ifdef CONFIG_POCKET_ROUTER_SUPPORT
//	system("webs &");
//#endif		
	return 0;
}
////////////////////////////////////////////////////////////////////////

