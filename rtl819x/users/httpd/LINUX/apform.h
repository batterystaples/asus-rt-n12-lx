/*
 *      Include file of form handler
 *
 *      Authors: David Hsu	<davidhsu@realtek.com.tw>
 *
 *      $Id: apform.h,v 1.4 2011/05/16 01:56:07 jerry_jian Exp $
 *
 */

#ifndef _INCLUDE_APFORM_H
#define _INCLUDE_APFORM_H

#if HAVE_STDBOOL_H
# include <stdbool.h>
#else
typedef enum {false = 0, true = 1} bool;
#endif

#include "apmib.h"
#ifndef ASP_SECURITY_PATCH
#define ASP_SECURITY_PATCH
#endif
#ifdef __i386__
  #define _CONFIG_SCRIPT_PATH	T(".")
  #define _LITTLE_ENDIAN_
#else
  #define _CONFIG_SCRIPT_PATH	T("/bin")
#endif

#define _CONFIG_SCRIPT_PROG	T("init.sh")
#define _WLAN_SCRIPT_PROG	T("wlan.sh")
#define _PPPOE_SCRIPT_PROG	T("pppoe.sh")
#define _PPTP_SCRIPT_PROG	T("pptp.sh")
#define _L2TP_SCRIPT_PROG	T("l2tp.sh")
#define _FIREWALL_SCRIPT_PROG	T("firewall.sh")
#define _ROUTE_SCRIPT_PROG	T("route.sh")
#define _PPPOE_DC_SCRIPT_PROG	T("disconnect.sh")
#define _IAPPAUTH_SCRIPT_PROG	T("iappauth.sh")
#define _NTP_SCRIPT_PROG	T("ntp.sh")
#ifdef HOME_GATEWAY
#ifdef VPN_SUPPORT
#define _VPN_SCRIPT_PROG	T("vpn.sh")
#endif

#ifdef GW_QOS_ENGINE
#define _QOS_SCRIPT_PROG	    T("qos.sh")
#endif

#ifdef QOS_BY_BANDWIDTH
#define _QOS_SCRIPT_PROG	    T("ip_qos.sh")
#endif

#ifdef CONFIG_IPV6
#define _IPV6_RADVD_SCRIPT_PROG T("radvd.sh")
#define _IPV6_DNSMASQ_SCRIPT_PROG T("dnsv6.sh")
#define _IPV6_DHCPV6S_SCRIPT_PROG T("dhcp6s")
#define _IPV6_LAN_INTERFACE T("br0")
#define _IPV6_WAN_INTERFACE T("eth1")
#endif

#ifdef CONFIG_RTL_BT_CLIENT
#define _BT_SCRIPT_PROG T("bt.sh")
#endif
#endif
#define _WLAN_APP_SCRIPT_PROG	T("wlanapp.sh")
#define _DHCPD_PROG_NAME	T("udhcpd")
#define _DHCPD_PID_PATH		T("/var/run")

#ifdef WLAN_EASY_CONFIG
#define _AUTO_CONFIG_DAEMON_PROG T("autoconf")
#endif

#ifdef WIFI_SIMPLE_CONFIG
#define _WSC_DAEMON_PROG 	T("wscd")
#endif

#define REBOOT_CHECK


#ifdef REBOOT_CHECK
#define APPLY_COUNTDOWN_TIME 20 
#define APPLY_OK_MSG T("<h4>Change setting successfully!<BR>")
#define COUNTDOWN_PAGE "/countDownPage.asp"
extern int needReboot;
extern char okMsg[];
extern char lastUrl[];
extern int countDownTime;
extern int run_init_script_flag;
#endif

///////////////////////////////////////////////////////////////////////////
static bool _is_hex(char c)
{
    return (((c >= '0') && (c <= '9')) ||
            ((c >= 'A') && (c <= 'F')) ||
            ((c >= 'a') && (c <= 'f')));
}

// Validate digit
static bool _isdigit(char c)
{
    return ((c >= '0') && (c <= '9'));
}

static int __inline__ string_to_hex(char_t *string, unsigned char *key, int len)
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

static int __inline__ string_to_dec(char_t *string, int *val)
{
	int idx;
	int len = strlen(string);

	for (idx=0; idx<len; idx++) {
		if ( !_isdigit(string[idx]))
			return 0;
	}

	*val = strtol(string, (char**)NULL, 10);
	return 1;
}

static int __inline__ apmib_update_web(int type)
{    
	int ret;

	ret = apmib_update(type);
		
	if (ret == 0)
		return 0;
//2011.03.30 Jerry {
#if 0
	if (type & CURRENT_SETTING) {
		save_cs_to_file();
	}
#endif
//2011.03.30 Jerry }
	return ret;
}
 
static __inline__ void update_form_hander_name(webs_t wp)
{
	char_t			*last, *nextp;

#ifdef ASP_SECURITY_PATCH	
	extern	void log_goform(char *form);
#endif	
	//last = wp->url;
	while (1) {		
		nextp = gstrstr(last, T("/goform/"));
		if (nextp) {
			last = nextp + 8;
			nextp = last;
			//while (*nextp && !gisspace(*nextp))
			//	nextp++;			
			*nextp = '\0';
#ifdef ASP_SECURITY_PATCH	
			//log_goform(last);			
#endif
		}
		break;
	}
}
#define ERR_MSG(msg) { \
	update_form_hander_name(wp); \
	websHeader(wp); \
   	websWrite(wp, T("<body><blockquote><h4>%s</h4>\n"), msg); \
	websWrite(wp, T("<form><input type=\"button\" onclick=\"history.go (-1)\" value=\"&nbsp;&nbsp;OK&nbsp;&nbsp\" name=\"OK\"></form></blockquote></body>")); \
   	websFooter(wp); \
	websDone(wp, 200); \
}


#ifdef REBOOT_CHECK
#define REBOOT_WAIT(url) { \
		sprintf(lastUrl,"%s",url); \
		sprintf(okMsg,"%s",APPLY_OK_MSG); \
		countDownTime = APPLY_COUNTDOWN_TIME; \
		websRedirect(wp, COUNTDOWN_PAGE); \
}

#define OK_MSG(url) { \
	needReboot = 1; \
	if(strlen(url) == 0) \
		strcpy(url,"/wizard.asp"); \		
	websHeader(wp); \
 	websWrite(wp, T("<body><blockquote><h4>Change setting successfully!</h4>Your changes have been saved. The router must be rebooted for the changes to take effect.<br> You can reboot now, or you can continue to make other changes and reboot later.\n")); \
	websWrite(wp, T("<form action=/goform/formRebootCheck method=POST name='rebootForm'>")); \
	websWrite(wp, T("<input type='hidden' value='%s' name='submit-url'>"),url); \
	websWrite(wp, T("<input id='restartNow' type='submit' value='Reboot Now' onclick=\"return true\" />&nbsp;&nbsp;")); \
	websWrite(wp, T("<input id='restartLater' type='button' value='Reboot Later' OnClick=window.location.replace(\"%s\")>"), url); \
	websWrite(wp, T("</form></blockquote></body>"));\
 	websFooter(wp); \
	websDone(wp, 200); \
}
#else
#define OK_MSG(url) { \
	websHeader(wp); \
   	websWrite(wp, T("<body><blockquote><h4>Change setting successfully!</h4>\n")); \
	if (url[0]) websWrite(wp, T("<form><input type=button value=\"  OK  \" OnClick=window.location.replace(\"%s\")></form></blockquote></body>"), url);\
	else websWrite(wp, T("<form><input type=button value=\"  OK  \" OnClick=window.close()></form></blockquote></body>"));\
   	websFooter(wp); \
	websDone(wp, 200); \
}
#endif

#define OK_MSG1(msg, url) { \
	websHeader(wp); \
   	websWrite(wp, T("<body><blockquote><h4>%s</h4>\n"), msg); \
	if (url) websWrite(wp, T("<form><input type=button value=\"  OK  \" OnClick=window.location.replace(\"%s\")></form></blockquote></body>"), url);\
	else websWrite(wp, T("<form><input type=button value=\"  OK  \" OnClick=window.close()></form></blockquote></body>"));\
   	websFooter(wp); \
	websDone(wp, 200); \
}
//Brad for firmware upgrade
#define OK_MSG_FW(msg, url, c, ip) { \
	websHeader(wp); \
	websWrite(wp, T("<head><script language=JavaScript><!--\n"));\
	websWrite(wp, T("var count = %d;function get_by_id(id){with(document){return getElementById(id);}}\n"), c);\
   	websWrite(wp, T("function do_count_down(){get_by_id(\"show_sec\").innerHTML = count\n"));\
	websWrite(wp, T("if(count == 0) {parent.location.href='http://%s/home.asp?t='+new Date().getTime(); return false;}\n"), ip);\
       websWrite(wp, T("if (count > 0) {count--;setTimeout('do_count_down()',1000);}}"));\
	websWrite(wp, T("//-->\n"));\
	websWrite(wp,T("</script></head>"));\
	websWrite(wp, T("<body onload=\"do_count_down();\"><blockquote><h4>%s</h4>\n"), msg);\
	websWrite(wp, T("<P align=left><h4>Please wait <B><SPAN id=show_sec></SPAN></B>&nbsp;seconds ...</h4></P>"));\
	websWrite(wp, T("</blockquote></body>"));\
	websFooter(wp); \
	websDone(wp, 200); \
}
//Brad add end
#define OK_MSG2(msg, msg1, url) { \
	char tmp[200]; \
	sprintf(tmp, msg, msg1); \
	OK_MSG1(tmp, url); \
}

#ifdef WIFI_SIMPLE_CONFIG
#define START_PBC_MSG \
	"Start PBC successfully!<br><br>" \
	"You have to run Wi-Fi Protected Setup in %s within 2 minutes."
#define START_PIN_MSG \
	"Start PIN successfully!<br><br>" \
	"You have to run Wi-Fi Protected Setup in %s within 2 minutes."
#define SET_PIN_MSG \
	"Applied WPS PIN successfully!<br><br>" \
	"You have to run Wi-Fi Protected Setup within 2 minutes."
#endif


//////////////////////////////////////////////////////////////////////////
#if defined(HTTP_FILE_SERVER_SUPPORTED)
int dump_directory_index(int eid, webs_t wp, int argc, char_t **argv);
void formusbdisk_uploadfile(webs_t wp, char_t * path, char_t * query);
int Check_directory_status(int eid, webs_t wp, int argc, char_t **argv);
#endif

/* Routines exported in fmmgmt.c */
#ifndef HOME_GATEWAY
extern void formSetTime(webs_t wp, char_t *path, char_t *query);
#endif
extern int sysLogList(int eid, webs_t wp, int argc, char_t **argv);
extern void formPasswordSetup(webs_t wp, char_t *path, char_t *query);
extern void formUpload(webs_t wp, char_t * path, char_t * query);
#ifdef CONFIG_RTL_WAPI_SUPPORT
extern void formWapiReKey(webs_t wp, char_t * path, char_t * query);
extern void formUploadWapiCert(webs_t wp, char_t * path, char_t * query);
extern void formWapiCertManagement(webs_t wp, char_t * path, char_t * query);
extern void formWapiCertDistribute(webs_t wp, char_t * path, char_t * query);
#endif

#ifdef CONFIG_RTL_802_1X_CLIENT_SUPPORT
extern void formUpload8021xUserCert(webs_t wp, char_t * path, char_t * query);
#endif

#ifdef TLS_CLIENT
extern void formCertUpload(webs_t wp, char_t * path, char_t * query);
#endif
extern void formSaveConfig(webs_t wp, char_t *path, char_t *query);
extern void formSchedule(webs_t wp, char_t *path, char_t *query);
extern int updateConfigIntoFlash(unsigned char *data, int total_len, int *pType, int *pStatus);	//2011.03.30 Jerry
#if defined(NEW_SCHEDULE_SUPPORT)
extern void formNewSchedule(webs_t wp, char_t *path, char_t *query);
extern int wlSchList(int eid, webs_t wp, int argc, char_t **argv);
#endif // #if defined(NEW_SCHEDULE_SUPPORT)
extern int getScheduleInfo(int eid, webs_t wp, int argc, char_t **argv);
extern void set_user_profile();
extern void formStats(webs_t wp, char_t *path, char_t *query);

//=========add for MESH=========
#ifdef CONFIG_RTK_MESH
extern void formMeshStatus(webs_t wp, char_t *path, char_t *query);
#endif
//=========add for MESH=========

extern void formLogout(webs_t wp, char_t *path, char_t *query);
extern void formSysCmd(webs_t wp, char_t *path, char_t *query);
extern int sysCmdLog(int eid, webs_t wp, int argc, char_t **argv);
extern void formSysLog(webs_t wp, char_t *path, char_t *query);
#ifdef HOME_GATEWAY
#ifdef DOS_SUPPORT
extern void formDosCfg(webs_t wp, char_t *path, char_t *query);
#endif
// by sc_yang
extern void formNtp(webs_t wp, char_t *path, char_t *query);
extern void formOpMode(webs_t wp, char_t *path, char_t *query);

#if defined(CONFIG_RTL_92D_SUPPORT)
extern void formWlanBand2G5G(webs_t wp, char_t *path, char_t *query);
#endif

#if defined(CONFIG_RTL_FLASH_DUAL_IMAGE_ENABLE)
extern void formDualFirmware(webs_t wp, char_t *path, char_t *query);
#endif

#endif
extern void formWizard(webs_t wp, char_t *path, char_t *query);
extern void formPocketWizard(webs_t wp, char_t *path, char_t *query);
extern void formPocketWizardGW(webs_t wp, char_t *path, char_t *query);

#ifdef REBOOT_CHECK
extern void formRebootCheck(webs_t wp, char_t *path, char_t *query);
#endif
#ifdef LOGIN_URL
extern void formLogin(webs_t wp, char_t *path, char_t *query);
extern int is_valid_user(webs_t wp);
#endif


/* Routines exported in fmget.c */
extern int getIndex(int eid, webs_t wp, int argc, char_t **argv);
extern int getInfo(int eid, webs_t wp, int argc, char_t **argv);
extern int isConnectPPP();
extern int FirmwareUpgrade(char *upload_data, int upload_len, int is_root, char *buffer);

//add for MESH
//necessarily, no matter MESH is enable or not ,for  add MESH webpage compatible
extern int getModeCombobox(int eid, webs_t wp, int argc, char_t **argv);
extern int getDHCPModeCombobox(int eid, webs_t wp, int argc, char_t **argv);

//=========add for MESH=========
#ifdef CONFIG_RTK_MESH
extern void formMeshSetup(webs_t wp, char_t *path, char_t *query);
extern void formMeshProxy(webs_t wp, char_t *path, char_t *query);
extern int formMeshProxyTbl(webs_t wp, char_t *path, char_t *query);
extern int wlMeshNeighborTable(int eid, webs_t wp, int argc, char_t **argv);
extern int wlMeshRoutingTable(int eid, webs_t wp, int argc, char_t **argv);
extern int wlMeshProxyTable(int eid, webs_t wp, int argc, char_t **argv);
extern int wlMeshRootInfo(int eid, webs_t wp, int argc, char_t **argv);
extern int wlMeshPortalTable(int eid, webs_t wp, int argc, char_t **argv);
#ifdef 	_11s_TEST_MODE_
extern void formEngineeringMode(webs_t wp, char_t *path, char_t *query);
extern void formEngineeringMode2(webs_t wp, char_t *path, char_t *query);
extern int wlRxStatics(int eid, webs_t wp, int argc, char_t **argv);
#endif
#ifdef _MESH_ACL_ENABLE_
extern void formMeshACLSetup(webs_t wp, char_t *path, char_t *query);
extern int wlMeshAcList(int eid, webs_t wp, int argc, char_t **argv);
#endif
#endif
//========add for MESH=========

extern void formWlanSetup(webs_t wp, char_t *path, char_t *query);
extern int wlAcList(int eid, webs_t wp, int argc, char_t **argv);
extern void formWlAc(webs_t wp, char_t *path, char_t *query);
extern void formAdvanceSetup(webs_t wp, char_t *path, char_t *query);
extern int wirelessClientList(int eid, webs_t wp, int argc, char_t **argv);
extern void formWirelessTbl(webs_t wp, char_t *path, char_t *query);
extern void formWep(webs_t wp, char_t *path, char_t *query);
extern void formWlSiteSurvey(webs_t wp, char_t *path, char_t *query);
extern int wepHandler(webs_t wp, char *tmpBuf, int wlan_id);
extern int wlanHandler(webs_t wp, char *tmpBuf, int *mode, int wlan_id); 
extern int wpaHandler(webs_t wp, char *tmpBuf, int wlan_id);
extern void formWlanRedirect(webs_t wp, char_t *path, char_t *query);
#ifdef TLS_CLIENT
extern int certRootList(int eid, webs_t wp, int argc, char_t **argv);
extern int certUserList(int eid, webs_t wp, int argc, char_t **argv);
#endif
extern void update_wps_configuration();	//2011.05.05 Jerry

int wlSiteSurveyTbl(int eid, webs_t wp, int argc, char_t **argv);
extern void formWlEncrypt(webs_t wp, char_t *path, char_t *query);

extern void formWlWds(webs_t wp, char_t *path, char_t *query);
extern int wlWdsList(int eid, webs_t wp, int argc, char_t **argv);
extern void formWdsEncrypt(webs_t wp, char_t *path, char_t *query);
extern int wdsList(int eid, webs_t wp, int argc, char_t **argv);
#ifdef WLAN_EASY_CONFIG
extern void sigHandler_autoconf(int signo);
extern void formAutoCfg(webs_t wp, char_t *path, char_t *query);
#endif

#ifdef WIFI_SIMPLE_CONFIG
#ifndef WLAN_EASY_CONFIG
extern void sigHandler_autoconf(int signo);
#endif
extern void formWsc(webs_t wp, char_t *path, char_t *query);
extern void call_wps_update();	//2011.05.05 Jerry
#endif

#ifdef MBSSID
extern int getVirtualIndex(int eid, webs_t wp, int argc, char_t **argv);
extern int getVirtualInfo(int eid, webs_t wp, int argc, char_t **argv);
extern void formWlanMultipleAP(webs_t wp, char_t *path, char_t *query);
#endif

#ifdef CONFIG_RTL_BT_CLIENT
extern void formBTBasicSetting(webs_t wp, char_t * path, char_t * query);
extern void formBTClientSetting(webs_t wp, char_t * path, char_t * query);
extern void formBTFileSetting(webs_t wp, char_t * path, char_t * query);
extern void formBTNewTorrent(webs_t wp, char_t * path, char_t * query);
#endif

#ifndef NO_ACTION
extern void run_init_script(char *arg);
#ifdef REBOOT_CHECK
extern void run_init_script_rebootCheck(char *arg);
#endif
#endif

/* Routines exported in fmtcpip.c */
extern void formTcpipSetup(webs_t wp, char_t *path, char_t *query);
extern int isDhcpClientExist(char *name);
extern void formReflashClientTbl(webs_t wp, char_t *path, char_t *query);
extern int dhcpClientList(int eid, webs_t wp, int argc, char_t **argv);
extern int tcpipLanHandler(webs_t wp, char *tmpBuf);
extern int dhcpRsvdIp_List(int eid, webs_t wp, int argc, char_t **argv);
extern int getPid(char *filename);
#if defined(POWER_CONSUMPTION_SUPPORT)
extern int getPowerConsumption(int eid, webs_t wp, int argc, char_t **argv);
#endif 

#if defined(CONFIG_RTL_8198_AP_ROOT) && defined(VLAN_CONFIG_SUPPORTED)
extern int vlanList(int eid, webs_t wp, int argc, char_t **argv);
extern void formVlan(webs_t wp, char_t *path, char_t *query);

#if defined(CONFIG_RTL_92D_SUPPORT)
extern void formWlanBand2G5G(webs_t wp, char_t *path, char_t *query);
#endif
#endif

#ifdef HOME_GATEWAY
extern void formWanTcpipSetup(webs_t wp, char_t *path, char_t *query);

/* Routines exported in fmfwall.c */
extern void formPortFw(webs_t wp, char_t *path, char_t *query);
extern void formFilter(webs_t wp, char_t *path, char_t *query);
extern int portFwList(int eid, webs_t wp, int argc, char_t **argv);
extern int portFilterList(int eid, webs_t wp, int argc, char_t **argv);
extern int ipFilterList(int eid, webs_t wp, int argc, char_t **argv);
extern int macFilterList(int eid, webs_t wp, int argc, char_t **argv);
extern int urlFilterList(int eid, webs_t wp, int argc, char_t **argv);
extern void formDMZ(webs_t wp, char_t *path, char_t *query);
#if defined(VLAN_CONFIG_SUPPORTED)
extern int vlanList(int eid, webs_t wp, int argc, char_t **argv);
extern void formVlan(webs_t wp, char_t *path, char_t *query);
#endif
extern void formTriggerPort(webs_t wp, char_t *path, char_t *query);
//extern int triggerPortList(int eid, webs_t wp, int argc, char_t **argv);
extern int tcpipWanHandler(webs_t wp, char * tmpBuf, int *dns_changed);
/* Routines exported in fmroute.c */
#ifdef ROUTE_SUPPORT
extern void formRoute(webs_t wp, char_t *path, char_t *query);
extern int staticRouteList(int eid, webs_t wp, int argc, char_t **argv);
extern int kernelRouteList(int eid, webs_t wp, int argc, char_t **argv);
#endif

#ifdef GW_QOS_ENGINE
extern int qosList(int eid, webs_t wp, int argc, char_t **argv);
extern void formQoS(webs_t wp, char_t *path, char_t *query);
#endif

#ifdef QOS_BY_BANDWIDTH
extern int ipQosList(int eid, webs_t wp, int argc, char_t **argv);
extern void formIpQoS(webs_t wp, char_t *path, char_t *query);
#endif

#endif

#ifdef HOME_GATEWAY
/* Routine exported in fmddns.c */
extern void formDdns(webs_t wp, char_t *path, char_t *query);
#endif

#ifdef HOME_GATEWAY
#ifdef VPN_SUPPORT
/* Routines exported in fmvpn.c */
extern void formVpnSetup(webs_t wp, char_t *path, char_t *query);
extern void formVpnConn(webs_t wp, char_t *path, char_t *query);
//extern int vpnStatList(int eid, webs_t wp, int argc, char_t **argv);
extern int vpnConnList(int eid, webs_t wp, int argc, char_t **argv);
extern int vpnRsaList(int eid, webs_t wp, int argc, char_t **argv);
extern int vpnShowLog(int eid, webs_t wp, int argc, char_t **argv);
extern void formVpnLog(webs_t wp, char_t *path, char_t *query);
extern int getVpnTblIdx(void);
extern void len2Mask(int len, char * mask );
extern int mask2Len(char *buf);
extern int getVpnKeyMode(void);
extern int  getConnStat(char *in_connName);
#endif
#ifdef CONFIG_IPV6
extern void formRadvd(webs_t wp, char_t *path, char_t *query);
extern void formDnsv6(webs_t wp, char_t * path, char_t * query);
extern void formDhcpv6s(webs_t wp, char_t * path, char_t * query);
extern void formIPv6Addr(webs_t wp, char_t * path, char_t * query);
extern void formTunnel6(webs_t wp, char_t * path, char_t * query);
extern int getIPv6Info(int eid, webs_t wp, int argc, char_t **argv);
extern int getIPv6BasicInfo(int eid, webs_t wp, int argc, char_t **argv);
#endif
#endif
extern void formStaticDHCP(webs_t wp, char_t *path, char_t *query);

/*+++++added by Jack for Tr-069 configuration+++++
Routines exported in fmtr069.c */
#ifdef CONFIG_CWMP_TR069
extern void formTR069Config(webs_t wp, char_t *path, char_t *query);
extern int saveTR069Config(webs_t wp, char_t *path, char_t *query);
extern int TR069ConPageShow(int eid, webs_t wp, int argc, char_t **argv);
#ifdef CONFIG_USER_CWMP_WITH_MATRIXSSL
extern int ShowMNGCertTable(webs_t wp);
extern void formTR069CertUpload(webs_t wp, char_t *path, char_t *query);
#endif /*CONFIG_USER_CWMP_WITH_MATRIXSSL*/
#endif /*CONFIG_CWMP_TR069*/
/*-----end-----*/

/* variables exported in main.c */
#if defined(CONFIG_RTL_8198_AP_ROOT)
extern char *BRIDGE_IF;
extern char *ELAN_IF;
extern char *ELAN2_IF;
extern char *ELAN3_IF;
extern char *ELAN4_IF;
extern char *ELAN5_IF;
extern char *ELAN6_IF;
#elif defined(HOME_GATEWAY)
extern char *WAN_IF;
extern char *BRIDGE_IF;
extern char *ELAN_IF;
extern char *ELAN2_IF;
extern char *ELAN3_IF;
extern char *ELAN4_IF;
extern char *PPPOE_IF;

#else
extern char *BRIDGE_IF;
extern char *ELAN_IF;
#endif
extern char WLAN_IF[];
extern int wlan_num;
#ifdef MBSSID
	extern int vwlan_num; 
	extern int mssid_idx;
#endif	
#endif // _INCLUDE_APFORM_H
