/*
 *      Utiltiy function for setting wlan application 
 *
 */

/*-- System inlcude files --*/
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <arpa/inet.h>
#include <unistd.h>
    
#include "../apmib.h"
#include "sysconf.h"
#include "sys_utility.h"
extern int SetWlan_idx(char * wlan_iface_name);  
extern int apmib_initialized;

#define IWCONTROL_PID_FILE "/var/run/iwcontrol.pid"
#define PATHSEL_PID_FILE "/var/run/pathsel.pid"
#define IAPP_PID_FILE "/var/run/iapp.pid"
#define MESH_PATHSEL "/bin/pathsel" 



int setWlan_Applications(char *action, char *argv)
{
	int pid=-1;
	char strPID[10];
	char iface_name[16];
	char tmpBuff[100], tmpBuff1[100], arg_buff[200],wlan_wapi_asipaddr[100];
	int _enable_1x=0, _use_rs=0;
	int wlan_mode_root=0,wlan_disabled_root=0, wlan_wpa_auth_root=0;
	int wlan_iapp_disabled_root=0,wlan_wsc_disabled_root=0, wlan_network_type_root=0;
	int wlan_1x_enabled_root=0, wlan_encrypt_root=0, wlan_mac_auth_enabled_root=0,wlan_wapi_auth=0;
	int wlan_disabled=0, wlan_mode=0, wlan_wds_enabled=0, wlan_wds_num=0;
	int wlan_encrypt=0, wlan_wds_encrypt=0;
	int wlan_wpa_auth=0, wlan_mesh_encrypt=0;
	int wlan_1x_enabled=0,wlan_mac_auth_enabled=0;
	int wlan_root_auth_enable=0, wlan_vap_auth_enable=0;
	int wlan_network_type=0, wlan_wsc_disabled=0, wlan_iapp_disabled=0;
	char tmp_iface[30]={0}, wlan_role[30]={0}, wlan_vap[30]={0}, wlan_vxd[30]={0};
	char valid_wlan_interface[200]={0}, all_wlan_interface[200]={0};
	int vap_not_in_pure_ap_mode=0, deamon_created=0;
	int isWLANEnabled=0, isAP=0, isIAPPEnabled=0, intValue=0;
	char bridge_iface[30]={0};
	char *token=NULL, *savestr1=NULL;
	int wps_debug=0, use_iwcontrol=1;
	int WSC=1, WSC_UPNP_Enabled=0;
	FILE *fp;
	char wsc_pin_local[16]={0},wsc_pin_peer[16]={0};
	int wait_fifo=0;
	char *cmd_opt[16]={0};
	int cmd_cnt = 0;
	//Added for virtual wlan interface
	int i=0, wlan_encrypt_virtual=0, asIPSet=0;
	char wlan_vname[16];

	int wlan_wsc1_disabled = 0 ;

	token=NULL;
	savestr1=NULL;	     
	sprintf(arg_buff, "%s", argv);
	
	token = strtok_r(arg_buff," ", &savestr1);
	do{
		if (token == NULL){/*check if the first arg is NULL*/
			break;
		}else{        
			sprintf(iface_name, "%s", token);                                           		
			if(strncmp(iface_name, "wlan", 4)==0){//wlan iface   
				if(all_wlan_interface[0]==0x0){
					sprintf(all_wlan_interface, "%s",iface_name); 
				}else{
					sprintf(tmp_iface, " %s", iface_name);
					strcat(all_wlan_interface, tmp_iface);
				}
			}else{
				sprintf(bridge_iface, "%s", iface_name);
			}
		}
		token = strtok_r(NULL, " ", &savestr1);
	}while(token !=NULL);
			
	if(isFileExist(IWCONTROL_PID_FILE)){
		pid=getPid_fromFile(IWCONTROL_PID_FILE);
		if(pid != -1){
			sprintf(strPID, "%d", pid);
			RunSystemCmd(NULL_FILE, "kill", "-9", strPID, NULL_STR);
		}
		unlink(IWCONTROL_PID_FILE);
	}
	if(isFileExist(PATHSEL_PID_FILE)){
		pid=getPid_fromFile(PATHSEL_PID_FILE);
		if(pid != -1){
			sprintf(strPID, "%d", pid);
			RunSystemCmd(NULL_FILE, "kill", "-9", strPID,NULL_STR);
		}
		unlink(PATHSEL_PID_FILE);
		RunSystemCmd(NULL_FILE, "brctl", "meshsignaloff",NULL_STR);
		
	}
	token=NULL;
	savestr1=NULL;	     
	sprintf(arg_buff, "%s", all_wlan_interface);
	token = strtok_r(arg_buff," ", &savestr1);
	do{
		if (token == NULL){/*check if the first arg is NULL*/
			break;
		}else{                
			sprintf(iface_name, "%s", token);    	
			if(strncmp(iface_name, "wlan", 4)==0){//wlan iface   
				sprintf(tmpBuff, "/var/run/auth-%s.pid",iface_name);
				if(isFileExist(tmpBuff)){
					pid=getPid_fromFile(tmpBuff);
						if(pid != -1){
							sprintf(strPID, "%d", pid);
							RunSystemCmd(NULL_FILE, "kill", "-9", strPID, NULL_STR);
						}
					unlink(tmpBuff);
					sprintf(tmpBuff1, "/var/run/auth-%s-vxd.pid",iface_name);
					if(isFileExist(tmpBuff1)){
					pid=getPid_fromFile(tmpBuff1);
						if(pid != -1){
							sprintf(strPID, "%d", pid);
							RunSystemCmd(NULL_FILE, "kill", "-9", strPID, NULL_STR);
						}
					unlink(tmpBuff1);
					}
				}
#if	1	//def FOR_DUAL_BAND
				sprintf(tmpBuff1, "/var/run/wscd-wlan0-wlan1.pid");
#else
				sprintf(tmpBuff1, "/var/run/wscd-%s.pid",iface_name);
#endif
				if(isFileExist(tmpBuff1)){
					pid=getPid_fromFile(tmpBuff1);
					if(pid != -1){
						sprintf(strPID, "%d", pid);
						RunSystemCmd(NULL_FILE, "kill", "-9", strPID, NULL_STR);
					}
					unlink(tmpBuff1);
				}
#if defined(UNIVERSAL_REPEATER) && defined(CONFIG_REPEATER_WPS_SUPPORT)

				do{
					sprintf(tmpBuff1, "/var/run/wscd-%s-vxd.pid",iface_name);
					if(isFileExist(tmpBuff1)){
						pid=getPid_fromFile(tmpBuff1);
						if(pid != -1){
							sprintf(strPID, "%d", pid);
							RunSystemCmd(NULL_FILE, "kill", "-9", strPID, NULL_STR);
						}
						else
							break;
						unlink(tmpBuff1);
					}
					else
						break;
					
					fprintf(stderr,"\r\n kill wscd.__[%s-%u]",__FILE__,__LINE__);
					sleep(1);					
				}while(find_pid_by_name("wscd") > 0);
				
#endif

				RunSystemCmd("/proc/gpio", "echo", "0", NULL_STR);///is it need to do this for other interface??????except wps
			}
		}	
		token = strtok_r(NULL, " ", &savestr1);
	}while(token !=NULL);
	
	if(isFileExist(IAPP_PID_FILE)){
		pid=getPid_fromFile(IAPP_PID_FILE);
		if(pid != -1){
			sprintf(strPID, "%d", pid);
			RunSystemCmd(NULL_FILE, "kill", "-9", strPID, NULL_STR);
		}
		unlink(IAPP_PID_FILE);
	}
	system("rm -f /var/*.fifo");
	if(!strcmp(action, "kill"))
		return 0;
	printf("Init Wlan application...\n");	
	//get root setting first//no this operate in script
	if(SetWlan_idx("wlan0")){
		apmib_get( MIB_WLAN_WLAN_DISABLED, (void *)&wlan_disabled_root);
		apmib_get( MIB_WLAN_MODE, (void *)&wlan_mode_root); 
		apmib_get( MIB_WLAN_IAPP_DISABLED, (void *)&wlan_iapp_disabled_root);
		apmib_get( MIB_WLAN_WSC_DISABLE, (void *)&wlan_wsc_disabled_root);
		apmib_get( MIB_WLAN_ENABLE_1X, (void *)&wlan_1x_enabled_root);
		apmib_get( MIB_WLAN_ENCRYPT, (void *)&wlan_encrypt_root);
		apmib_get( MIB_WLAN_MAC_AUTH_ENABLED, (void *)&wlan_mac_auth_enabled_root);
		apmib_get( MIB_WLAN_NETWORK_TYPE, (void *)&wlan_network_type_root);
		apmib_get( MIB_WLAN_WPA_AUTH, (void *)&wlan_wpa_auth_root);
		apmib_get( MIB_WLAN_WSC_UPNP_ENABLED, (void *)&WSC_UPNP_Enabled);
	}

#if defined(FOR_DUAL_BAND)
	if(SetWlan_idx("wlan1")){
		apmib_get( MIB_WLAN_WSC_DISABLE, (void *)&wlan_wsc1_disabled);		
	}
#endif
	
	token=NULL;
	savestr1=NULL;	     
	sprintf(arg_buff, "%s", all_wlan_interface);
	token = strtok_r(arg_buff," ", &savestr1);
	do{
		_enable_1x=0;
		_use_rs=0;

		if (token == NULL){/*check if the first arg is NULL*/
			break;
		}else{                
			sprintf(iface_name, "%s", token); 
			if(strncmp(iface_name, "wlan", 4)==0){//wlan iface   
					
				if(strlen(iface_name)>=9){
					wlan_vap[0]=iface_name[6];
					wlan_vap[1]=iface_name[7];	
				}else{
					wlan_vap[0]=0;
				}
				
				if(SetWlan_idx( iface_name)){
					
					apmib_get( MIB_WLAN_WLAN_DISABLED, (void *)&wlan_disabled);
					apmib_get( MIB_WLAN_MODE, (void *)&wlan_mode); 
					apmib_get( MIB_WLAN_WDS_ENABLED, (void *)&wlan_wds_enabled);
					apmib_get( MIB_WLAN_WDS_NUM, (void *)&wlan_wds_num);
					apmib_get( MIB_WLAN_ENCRYPT, (void *)&wlan_encrypt);
					apmib_get( MIB_WLAN_WPA_AUTH, (void *)&wlan_wpa_auth);
					
					if(wlan_disabled==0 && wlan_mode >3){
						apmib_get( MIB_MESH_ENCRYPT, (void *)&wlan_mesh_encrypt);
					}
					if(wlan_disabled==0 && (wlan_mode ==2 || wlan_mode ==3) && (wlan_wds_enabled !=0) &&(wlan_wds_num!=0)){
						apmib_get( MIB_WLAN_WDS_ENCRYPT, (void *)&wlan_wds_encrypt);
						if(wlan_wds_encrypt==3 || wlan_wds_encrypt==4){
							sprintf(tmpBuff, "/var/wpa-wds-%s.conf",iface_name);//encrytp conf file
							RunSystemCmd(NULL_FILE, "flash", "wpa", iface_name, tmpBuff, "wds", NULL_STR); 
							RunSystemCmd(NULL_FILE, "auth", iface_name, bridge_iface, "wds", tmpBuff, NULL_STR); 
							sprintf(tmpBuff1, "/var/run/auth-%s.pid",iface_name);//auth pid file
							do{
								if(isFileExist(tmpBuff1)){//check pid file is exist or not
									break;
								}else{
									sleep(1);
								}
							}while(1);
						}
						
					}
					
					if(wlan_encrypt < 2){
						apmib_get( MIB_WLAN_ENABLE_1X, (void *)&wlan_1x_enabled);
						apmib_get( MIB_WLAN_MAC_AUTH_ENABLED, (void *)&wlan_mac_auth_enabled);
						if(wlan_1x_enabled != 0 || wlan_mac_auth_enabled != 0){
							_enable_1x=1;
							_use_rs=1;
						}
					}else{
						_enable_1x=1;
						if(wlan_wpa_auth ==1){
							_use_rs=1;
						}
					}
					
					////////for mesh start
					if(wlan_disabled==0 && wlan_mode >3){
						if(wlan_mesh_encrypt != 0){
							
							sprintf(tmpBuff, "/var/wpa-%s-msh0.conf",iface_name);//encrytp conf file
							RunSystemCmd(NULL_FILE, "flash", "wpa", iface_name, tmpBuff, "msh", NULL_STR); 
							sprintf(tmp_iface, "%s-msh0", iface_name);
							RunSystemCmd(NULL_FILE, "auth", tmp_iface, bridge_iface,"wds", tmpBuff, NULL_STR); 
							sprintf(tmpBuff1, "/var/run/auth-%s-msh0.pid",iface_name);//auth pid file
							do{
								if(isFileExist(tmpBuff1)){//check pid file is exist or not
									break;
								}else{
									sleep(1);
								}
							}while(1);
							
							
						}
					}
					
					///////for mesh end
					if(_enable_1x !=0 && wlan_disabled==0){
						
						sprintf(tmpBuff, "/var/wpa-%s.conf",iface_name);//encrytp conf file
						
						RunSystemCmd(NULL_FILE, "flash", "wpa", iface_name, tmpBuff, NULL_STR); 
						if(wlan_mode==1){//client mode
							apmib_get( MIB_WLAN_NETWORK_TYPE, (void *)&wlan_network_type);
							if(wlan_network_type==0){
								sprintf(wlan_role, "%s", "client-infra");
							}else{
								sprintf(wlan_role, "%s", "client-adhoc");
							}
						}else{
							sprintf(wlan_role, "%s", "auth");
						}
						
						if(wlan_vap[0]=='v' && wlan_vap[1]=='a'){
							if(wlan_mode_root != 0 && wlan_mode_root != 3){
								vap_not_in_pure_ap_mode=1;
							}
						}
						if(wlan_mode != 2 && vap_not_in_pure_ap_mode==0){
							
							if(wlan_wpa_auth != 2 || _use_rs !=0 ){
								deamon_created=1;
								RunSystemCmd(NULL_FILE, "auth", iface_name, bridge_iface, wlan_role, tmpBuff, NULL_STR); 
								
								if(wlan_vap[0]=='v' && wlan_vap[1]=='a')
									wlan_vap_auth_enable=1;
								else
									wlan_root_auth_enable=1;
							}
						} 
					}
					
					if(wlan_vap[0]=='v' && wlan_vap[1]=='x' && wlan_disabled==0){
						if(strcmp(wlan_role, "auth") || (!strcmp(wlan_role, "auth") && (_use_rs !=0))) 
									sprintf(wlan_vxd, "%s",iface_name); 
					}
					if(wlan_vap[0]=='v' && wlan_vap[1]=='a'){
						if(wlan_disabled==0){
							if(wlan_iapp_disabled_root==0 || wlan_vap_auth_enable==1){
								if(valid_wlan_interface[0]==0){
									sprintf(valid_wlan_interface, "%s",iface_name); 
								}else{
									sprintf(tmp_iface, " %s", iface_name);
									strcat(valid_wlan_interface, tmp_iface);
								}
							}
						}
					}else{
						if(wlan_vap[0] !='v' && wlan_vap[1] !='x'){
							apmib_get( MIB_WLAN_IAPP_DISABLED, (void *)&wlan_iapp_disabled);
							apmib_get( MIB_WLAN_WSC_DISABLE, (void *)&wlan_wsc_disabled); 
							if(wlan_root_auth_enable==1 || wlan_iapp_disabled==0 || wlan_wsc_disabled==0){
								if(valid_wlan_interface[0]==0){
									sprintf(valid_wlan_interface, "%s",iface_name); 
								}else{
									sprintf(tmp_iface, " %s", iface_name);
									strcat(valid_wlan_interface, tmp_iface);
								}
							}
						}
					}
						
						if((wlan_vap[0] !='v' && wlan_vap[1] !='a') && (wlan_vap[0] !='v' && wlan_vap[1] !='x')){
							 if(wlan_disabled==0)
							 	isWLANEnabled=1;
							 if(wlan_mode ==0 || wlan_mode ==3 || wlan_mode ==4 || wlan_mode ==6)
							 	isAP=1;
							 if(wlan_iapp_disabled==0)
							 	isIAPPEnabled=1;
						}
				}	
			}
		}
		token = strtok_r(NULL, " ", &savestr1);
	}while(token !=NULL);
		
	if(isWLANEnabled==1 && isAP==1 && isIAPPEnabled==1){

		sprintf(tmpBuff, "iapp %s %s",bridge_iface, valid_wlan_interface);
		system(tmpBuff);
		
		deamon_created=1;
	}
	
//for mesh========================================================
	if(wlan_mode_root ==4 || wlan_mode_root ==5 || wlan_mode_root ==6 || wlan_mode_root ==7 ){
		apmib_get( MIB_MESH_ENABLE, (void *)&intValue); 
		if(intValue==1){
			system("pathsel br0 wlan0 &");
		}
	}


//========================================================
//for WPS
	if (isFileExist("/bin/wscd")) {
		memset(tmpBuff, 0x00, 100);
		memset(tmpBuff1, 0x00, 100);
		token=NULL;
		savestr1=NULL;	     
		sprintf(arg_buff, "%s", valid_wlan_interface);
		
#if defined(UNIVERSAL_REPEATER) && defined(CONFIG_REPEATER_WPS_SUPPORT)		
		int isRptEnabled1=0;
		apmib_get(MIB_REPEATER_ENABLED1, (void *)&isRptEnabled1);

		if(isRptEnabled1 == 1 && wlan_wsc_disabled_root == 0
#if defined(CONFIG_ONLY_SUPPORT_CLIENT_REPEATER_WPS)
			&& wlan_mode_root == CLIENT_MODE
#endif			
		)
		{
			sprintf(wlan_vxd, "%s", "wlan0-vxd");
				sprintf(tmpBuff," %s",wlan_vxd);
				strcat(arg_buff, tmpBuff);
			}

#endif		

		token = strtok_r(arg_buff," ", &savestr1);
			
		do{
			if (token == NULL){
				break;
			}else{
#if defined(UNIVERSAL_REPEATER) && defined(CONFIG_REPEATER_WPS_SUPPORT)
				unsigned char wscConfFile[40];
				unsigned char wscFifoFile[40];
				memset(wscConfFile, 0x00, sizeof(wscConfFile));
				memset(wscFifoFile, 0x00, sizeof(wscFifoFile));
#endif				
				_enable_1x=0;
				wps_debug=0;
				WSC=1;
				use_iwcontrol=1;
				if(!strcmp(token, "wlan0") //root if
#if defined(UNIVERSAL_REPEATER) && defined(CONFIG_REPEATER_WPS_SUPPORT)
					|| !strcmp(token, "wlan0-vxd")
#endif					
				)
				{
#if defined(UNIVERSAL_REPEATER) && defined(CONFIG_REPEATER_WPS_SUPPORT)
					if(strcmp(token, "wlan0-vxd") == 0) // here we ONLY get vxd mib value 
					{
						SetWlan_idx(token);
						apmib_get( MIB_WLAN_MODE, (void *)&wlan_mode_root); 
						apmib_get( MIB_WLAN_ENABLE_1X, (void *)&wlan_1x_enabled_root);
						apmib_get( MIB_WLAN_ENCRYPT, (void *)&wlan_encrypt_root);
						apmib_get( MIB_WLAN_MAC_AUTH_ENABLED, (void *)&wlan_mac_auth_enabled_root);
						apmib_get( MIB_WLAN_WPA_AUTH, (void *)&wlan_wpa_auth_root);
						apmib_get( MIB_WLAN_WSC_UPNP_ENABLED, (void *)&WSC_UPNP_Enabled);					
						wlan_disabled_root = 0;
						wlan_network_type_root = 0;
					}
#endif					
					if(wlan_encrypt_root < 2){ //ENCRYPT_DISABLED=0, ENCRYPT_WEP=1, ENCRYPT_WPA=2, ENCRYPT_WPA2=4, ENCRYPT_WPA2_MIXED=6 ,ENCRYPT_WAPI=7
						
						if(wlan_1x_enabled_root != 0 || wlan_mac_auth_enabled_root !=0)
							_enable_1x=1;
					}else
						_enable_1x=1;
						
					if(wlan_wsc_disabled_root != 0 && wlan_wsc1_disabled!=0){
						WSC=0;
					}else{
							
						if(wlan_disabled_root != 0 || wlan_mode_root==2){
							WSC=0;
						}else{
								if(wlan_mode_root ==1){
									if(wlan_network_type_root != 0)
										WSC=0;
								}
								if(wlan_mode_root ==0){
									if(wlan_encrypt_root < 2 && _enable_1x !=0 )
										WSC=0;		
									if(wlan_encrypt_root >= 2 && wlan_wpa_auth_root ==1 )
										WSC=0;							
								}
						
							}
					}
						
					if(WSC==1){ //start wscd 
						memset(cmd_opt, 0x00, 16);
						cmd_cnt=0;
						cmd_opt[cmd_cnt++] = "wscd";
						if(isFileExist("/var/wps/simplecfgservice.xml")==0){ //file is not exist
							if(isFileExist("/var/wps"))
								RunSystemCmd(NULL_FILE, "rm", "/var/wps", "-rf", NULL_STR);
							RunSystemCmd(NULL_FILE, "mkdir", "/var/wps", NULL_STR); 
							system("cp /etc/simplecfg*.xml /var/wps");
						}
						if(wlan_mode_root ==1){
							WSC_UPNP_Enabled=0;
							cmd_opt[cmd_cnt++] = "-mode";
							cmd_opt[cmd_cnt++] = "2";
						}else{
							cmd_opt[cmd_cnt++] = "-start";
						}
						if(WSC_UPNP_Enabled==1){
							RunSystemCmd(NULL_FILE, "route", "del", "-net", "239.255.255.250", "netmask", "255.255.255.255", bridge_iface, NULL_STR); 
							RunSystemCmd(NULL_FILE, "route", "add", "-net", "239.255.255.250", "netmask", "255.255.255.255", bridge_iface, NULL_STR); 
						}
						
#if defined(UNIVERSAL_REPEATER) && defined(CONFIG_REPEATER_WPS_SUPPORT)					
						sprintf(wscConfFile,"/var/wsc-%s.conf",token);
						RunSystemCmd(NULL_FILE, "flash", "upd-wsc-conf", "/etc/wscd.conf", wscConfFile, token, NULL_STR); 
#else						
						RunSystemCmd(NULL_FILE, "flash", "upd-wsc-conf", "/etc/wscd.conf", "/var/wsc.conf", NULL_STR); 
#endif //#if defined(UNIVERSAL_REPEATER) && defined(CONFIG_REPEATER_WPS_SUPPORT)

						cmd_opt[cmd_cnt++] = "-c";
						#ifdef CONFIG_RTL_COMAPI_CFGFILE
						  #if !defined(CONFIG_RTL_819X)
						    #define WSC_CFG "/var/RTL8190N.dat"
						  #else
						    #define WSC_CFG "/var/RTL8192CD.dat"
						  #endif
						#else
						  #define WSC_CFG "/var/wsc.conf"
						#endif
#if defined(UNIVERSAL_REPEATER) && defined(CONFIG_REPEATER_WPS_SUPPORT)											
						cmd_opt[cmd_cnt++] = wscConfFile;
#else												
						cmd_opt[cmd_cnt++] = WSC_CFG;
#endif						
						cmd_opt[cmd_cnt++] = "-w";
#if defined(UNIVERSAL_REPEATER) && defined(CONFIG_REPEATER_WPS_SUPPORT)					
						cmd_opt[cmd_cnt++] = token;
#else						
						cmd_opt[cmd_cnt++] = "wlan0";
#endif						
						if(wps_debug==1){
							/* when you would like to open debug, you should add define in wsc.h for debug mode enable*/
							cmd_opt[cmd_cnt++] = "-debug";
						}
						if(use_iwcontrol==1){
							cmd_opt[cmd_cnt++] = "-fi";
#if defined(UNIVERSAL_REPEATER) && defined(CONFIG_REPEATER_WPS_SUPPORT)					
							sprintf(wscFifoFile,"/var/wscd-%s.fifo",token);
							cmd_opt[cmd_cnt++] = wscFifoFile;
#else													
							cmd_opt[cmd_cnt++] = "/var/wscd-wlan0.fifo";
#endif							
							deamon_created=1;
						}
						if(isFileExist("/var/wps_start_pbc")){
							cmd_opt[cmd_cnt++] = "-start_pbc";
							unlink("/var/wps_start_pbc");
						}
						if(isFileExist("/var/wps_start_pin")){
							cmd_opt[cmd_cnt++] = "-start";
							unlink("/var/wps_start_pin");
						}
						if(isFileExist("/var/wps_local_pin")){
							fp=fopen("/var/wps_local_pin", "r");
							if(fp != NULL){
								fscanf(fp, "%s", tmpBuff1);
								fclose(fp);
							}
							sprintf(wsc_pin_local, "%s", tmpBuff1);
							cmd_opt[cmd_cnt++] = "-local_pin";
							cmd_opt[cmd_cnt++] = wsc_pin_local;
							unlink("/var/wps_local_pin");
						}
						if(isFileExist("/var/wps_peer_pin")){
							fp=fopen("/var/wps_peer_pin", "r");
							if(fp != NULL){
								fscanf(fp, "%s", tmpBuff1);
								fclose(fp);
							}
							sprintf(wsc_pin_peer, "%s", tmpBuff1);
							cmd_opt[cmd_cnt++] = "-peer_pin";
							cmd_opt[cmd_cnt++] = wsc_pin_peer;
							unlink("/var/wps_peer_pin");
						}
						cmd_opt[cmd_cnt++] = "-daemon";						
						cmd_opt[cmd_cnt++] = 0;
						DoCmd(cmd_opt, NULL_FILE);
					}
					
					wait_fifo=5;
					do{
#if defined(UNIVERSAL_REPEATER) && defined(CONFIG_REPEATER_WPS_SUPPORT)											
						if(isFileExist(wscFifoFile))
#else								
						if(isFileExist("/var/wscd-wlan0.fifo"))
#endif							
						{
							wait_fifo=0;
						}else{
							wait_fifo--;
							sleep(1);
						}
						
					}while(use_iwcontrol !=0 && wait_fifo !=0);		
				}
			}   
			token = strtok_r(NULL, " ", &savestr1);
		}while(token !=NULL);
	}
		
	if(deamon_created==1){
		if(wlan_vxd[0]){
				sprintf(tmpBuff, "iwcontrol %s %s",valid_wlan_interface, wlan_vxd);
		}else{
				sprintf(tmpBuff, "iwcontrol %s",valid_wlan_interface);
		}
			system(tmpBuff);						

	}
	
/*for WAPI*/
	//first, to kill daemon related wapi-cert
	//in order to avoid multiple daemon existing
#ifdef CONFIG_RTL_WAPI_SUPPORT
#ifdef CONFIG_RTL_WAPI_LOCAL_AS_SUPPORT
	RunSystemCmd(NULL_FILE, "killall", "aseUdpServer", NULL_STR); 
#endif
	RunSystemCmd(NULL_FILE, "killall", "aeUdpClient", NULL_STR);

	///////////////////////////////
	//no these operations in script
	//should sync with WLAN_INTERFACE_LIST: "wlan0,wlan0-va0,wlan0-va1,wlan0-va2,wlan0-va3"
	//At first, check virtual wlan interface
	asIPSet=0;//Initial, note: as IP only need to be set once because all wlan interfaces use the same as IP setting
	for(i=0;i<4;i++)
	{
		memset(wlan_vname,0,sizeof(wlan_vname));
		sprintf(wlan_vname, "wlan0-va%d",i);
		if(SetWlan_idx(wlan_vname)){
			apmib_get( MIB_WLAN_ENCRYPT, (void *)&wlan_encrypt_virtual);
			apmib_get(MIB_WLAN_WAPI_AUTH, (void *)&wlan_wapi_auth);
			memset(wlan_wapi_asipaddr,0x00,sizeof(wlan_wapi_asipaddr));
			apmib_get(MIB_WLAN_WAPI_ASIPADDR,  (void*)wlan_wapi_asipaddr);
		}
		if(wlan_encrypt_virtual ==7){
			if((wlan_wapi_auth==1)&&(asIPSet==0)){
#ifdef CONFIG_RTL_WAPI_LOCAL_AS_SUPPORT
				apmib_get(MIB_IP_ADDR,  (void*)tmpBuff1);
				if(!memcmp(wlan_wapi_asipaddr, tmpBuff1, 4)){
					system("aseUdpServer &");
				}
#endif
				sprintf(arg_buff,"aeUdpClient -d %s -i %s &", inet_ntoa(*((struct in_addr *)wlan_wapi_asipaddr)), WLAN_INTERFACE_LIST);
				system(arg_buff);
				asIPSet=1;
				break;
			}
		}
	}
	////////////////////////////////////

	//At last, check root wlan interface
	if(SetWlan_idx("wlan0")){
		apmib_get(MIB_WLAN_WAPI_AUTH, (void *)&wlan_wapi_auth);
		memset(wlan_wapi_asipaddr,0x00,sizeof(wlan_wapi_asipaddr));
		apmib_get(MIB_WLAN_WAPI_ASIPADDR,  (void*)wlan_wapi_asipaddr);
	}
	if(wlan_encrypt_root ==7){
		if((wlan_wapi_auth==1)&&(asIPSet==0)){
#ifdef CONFIG_RTL_WAPI_LOCAL_AS_SUPPORT
			apmib_get(MIB_IP_ADDR,  (void*)tmpBuff1);
			if(!memcmp(wlan_wapi_asipaddr, tmpBuff1, 4)){
				system("aseUdpServer &");
			}
#endif
			sprintf(arg_buff,"aeUdpClient -d %s -i %s &", inet_ntoa(*((struct in_addr *)wlan_wapi_asipaddr)), WLAN_INTERFACE_LIST);
			system(arg_buff);

			asIPSet=1;
		}
	}
#endif

return 0;	
	
		
}

 
 
 
 
 
 
 
 
 
 
 
