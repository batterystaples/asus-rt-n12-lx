/*
 * main.c -- Main program for the GoAhead WebServer (LINUX version)
 *
 * Copyright (c) GoAhead Software Inc., 1995-2000. All Rights Reserved.
 *
 * See the file "license.txt" for usage and redistribution license requirements
 */

/******************************** Description *********************************/

/*
 *	Main program for for the GoAhead WebServer. This is a demonstration
 *	main program to initialize and configure the web server.
 */

/********************************* Includes ***********************************/

#include	"../uemf.h"
#include	"../wsIntrn.h"
#include	<signal.h>
#include	<unistd.h>
#include	<sys/types.h>
#include	<sys/wait.h>

#ifdef WEBS_SSL_SUPPORT
#include	"../websSSL.h"
#endif

#ifdef USER_MANAGEMENT_SUPPORT
#include	"../um.h"
void	formDefineUserMgmt(void);
#endif

// added by david /////////////////////////////////////////
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "apmib.h"
#include "apform.h"
#include "utility.h"

#if defined( HTTP_FILE_SERVER_SUPPORTED)	 
extern void web_http_file_server_init(void);
extern void web_http_file_server_default_init(void);
#endif

// added by rock /////////////////////////////////////////
#ifdef VOIP_SUPPORT
#include "web_voip.h"
#endif

/*********************************** Global ***********************************/
#if defined(CONFIG_RTL_8198_AP_ROOT)
char *BRIDGE_IF;
char *ELAN_IF;
char *ELAN2_IF;
char *ELAN3_IF;
char *ELAN4_IF;
char *ELAN5_IF;
#elif defined(HOME_GATEWAY)
char *WAN_IF;
char *BRIDGE_IF;
char *ELAN_IF;
char *ELAN2_IF;
char *ELAN3_IF;
char *ELAN4_IF;
char *PPPOE_IF;

#else
char *BRIDGE_IF;
char *ELAN_IF;
#endif

char WLAN_IF[20];
int wlan_num;
#ifdef MBSSID
	int vwlan_num=0;
	int mssid_idx=0;
#endif

////////////////////////////////////////////////////////////

/*********************************** Locals ***********************************/
/*
 *	Change configuration here
 */

static char_t		*rootWeb = T("web");			/* Root web directory */
static char_t		*password = T("");				/* Security password */

static char_t	*pidfile=T("/var/run/webs.pid"); // david

#ifndef __mips__	// For Mesh test
static int                      port = 8000;                                            /* Server port */
#else
static int			port = 80;						/* Server port */
#endif
static int			retries = 5;					/* Server port retries */
static int			finished=0;						/* Finished flag */

/****************************** Forward Declarations **************************/

static int 	initWebs();
// marked by david
//static int	aspTest(int eid, webs_t wp, int argc, char_t **argv);
//static void formTest(webs_t wp, char_t *path, char_t *query);
static int  websHomePageHandler(webs_t wp, char_t *urlPrefix, char_t *webDir,
				int arg, char_t *url, char_t *path, char_t *query);
extern void defaultErrorHandler(int etype, char_t *msg);
extern void defaultTraceHandler(int level, char_t *buf);
#ifdef B_STATS
static void printMemStats(int handle, char_t *fmt, ...);
static void memLeaks();
#endif
//sc_yang to wait child process to terminate
#if defined(CONFIG_DOMAIN_NAME_QUERY_SUPPORT)
extern void Confirm_Chld_termniated(void);
#endif
void sig_chld(int signo)
{
	pid_t pid;
	int stat;
	while( (pid = waitpid(-1, &stat, WNOHANG)) > 0)
		printf("goahead child %d termniated\n", pid);
		
#if defined(CONFIG_DOMAIN_NAME_QUERY_SUPPORT)
		Confirm_Chld_termniated();
#endif
	return ;

}
/*********************************** Code *************************************/
/*
 *	Main -- entry point from LINUX
 */

//Brad add for firmware upgrade
int confirm_last_req=0;
extern int isFWUpgrade;
extern int FW_Data_Size;
extern char *FW_Data;
//Brad add end
int main(int argc, char** argv)
{
/*
 *	Initialize the memory allocator. Allow use of malloc and start
 *	with a 60K heap.  For each page request approx 8KB is allocated.
 *	60KB allows for several concurrent page requests.  If more space
 *	is required, malloc will be used for the overflow.
 */
 sigset_t sigset;
 char buff_msg[200];
#ifndef __mips__
 	printf(" current size = 0x%x\n", sizeof(APMIB_T));
 	printf(" hw size = 0x%x\n", sizeof(HW_SETTING_T));
#endif
 	bopen(NULL, (60 * 1024), B_USE_MALLOC);

	signal(SIGPIPE, SIG_IGN);
	signal(SIGCHLD, sig_chld); //sc_yang
	
	sigemptyset(&sigset);
	sigaddset(&sigset,SIGUSR1);
	sigprocmask(SIG_UNBLOCK,&sigset,NULL);
#ifdef WLAN_EASY_CONFIG
	signal(SIGUSR1, sigHandler_autoconf);
#else
#ifdef WIFI_SIMPLE_CONFIG
	signal(SIGUSR1, sigHandler_autoconf);
#endif
#endif

// david, destroy old process and create a PID file -------
{	FILE *fp;
	char_t line[20];
	pid_t pid;
	if ((fp = fopen(pidfile, "r")) != NULL) {
		fgets(line, sizeof(line), fp);
		if ( sscanf(line, "%d", &pid) ) {
			if (pid > 1)
				kill(pid, SIGTERM);
		}
		fclose(fp);
	}
	sprintf(line, "%d\n", getpid());
	if ((fp = fopen(pidfile, "w")) == NULL) {
		error(E_L, E_LOG, T("Can't create PID file!"));
		return -1;
	}
	fwrite(line, strlen(line), 1, fp);
	fclose(fp);
}
//-----------------------------------------------------------


// david ----- remove user management file, only get from MIB
	{	struct stat status;
       		if ( stat(UM_TXT_FILENAME, &status) == 0) // file existed
                	unlink(UM_TXT_FILENAME);
	}
//-----------




// david ---- queury number of wlan interface ----------------
{	int i, num;
	char interface[10];
	wlan_num = 0;
	for (i=0; i<NUM_WLAN_INTERFACE; i++) {
		sprintf(interface, "wlan%d", i);
		if (getWlStaNum(interface, &num) < 0)
			break;
		wlan_num++;
	}
	
#if defined(VOIP_SUPPORT) && defined(ATA867x)
	// no wlan interface in ATA867x
#else
	if (wlan_num==0)
		wlan_num = 1;	// set 1 as default
#endif

#ifdef MBSSID
	vwlan_num = NUM_VWLAN_INTERFACE; 
#endif
}
//---------------------------------------------------------

/*
 *	Initialize the web server
 */
	if (initWebs() < 0) {
		return -1;
	}

#ifdef WEBS_SSL_SUPPORT
	websSSLOpen("/etc",0);
#endif

/*
 *	Basic event loop. SocketReady returns true when a socket is ready for
 *	service. SocketSelect will block until an event occurs. SocketProcess
 *	will actually do the servicing.
 */
	while (!finished) {
		if (socketReady(-1) || socketSelect(-1, 1000)) {
			socketProcess(-1);
			
		}
		//Brad add for firmware upgrade 20080711
		if(isFWUpgrade == 1){
			confirm_last_req++;
			if(confirm_last_req > 18){ //Keith. 2->18. Allow more request before FirmwareUpgrade().
				 if(FirmwareUpgrade(FW_Data, FW_Data_Size, 0, buff_msg)){
					confirm_last_req=0;
					isFWUpgrade=0;
				 }
			}
		}
		//Brad add end
		websCgiCleanup();
		emfSchedProcess();
#ifdef CONFIG_POCKET_ROUTER_SUPPORT
		pocketAPProcess();
//printf("\r\n  ,__[%s-%u]\r\n",__FILE__,__LINE__);
#endif

#if defined(CONFIG_REPEATER_WPS_SUPPORT)
		{
			int wlan_mode_root, wlan_wsc_disabled_root, isRptEnabled1, isRptEnabled2;
			apmib_get( MIB_WLAN_MODE, (void *)&wlan_mode_root); 
			apmib_get( MIB_WLAN_WSC_DISABLE, (void *)&wlan_wsc_disabled_root);
			apmib_get(MIB_REPEATER_ENABLED1, (void *)&isRptEnabled1);
			apmib_get(MIB_REPEATER_ENABLED2, (void *)&isRptEnabled2);
			if(wlan_wsc_disabled_root == 0 && (isRptEnabled1 == 1 || isRptEnabled2 == 1) 
#if defined(CONFIG_ONLY_SUPPORT_CLIENT_REPEATER_WPS)
				&& wlan_mode_root == CLIENT_MODE
#endif
			)
			{
		updateWlanifState("wlan0");
	}
		}
#endif		
	}

#ifdef WEBS_SSL_SUPPORT
	websSSLClose();
#endif

#ifdef USER_MANAGEMENT_SUPPORT
	umClose();
#endif

/*
 *	Close the socket module, report memory leaks and close the memory allocator
 */
	websCloseServer();
	socketClose();
#ifdef B_STATS
	memLeaks();
#endif
	bclose();
	return 0;
}

/******************************************************************************/
/*
 *	Initialize the web server.
 */

static int initWebs()
{
// david
//	struct hostent	*hp;
//	struct in_addr	intaddr;
	char	host[128], dir[128], webdir[128];
	char	*cp;
// david	
//	char_t	wbuf[128];
	int noIp = FALSE;	// david
	extern int save_cs_to_file();	

/*
 *	Initialize the socket subsystem
 */
	socketOpen();

#ifdef USER_MANAGEMENT_SUPPORT
/*
 *	Initialize the User Management database
 */
	umOpen();
	umRestore(UM_TXT_FILENAME);
#endif

/*
 *	Define the local Ip address, host name, default home page and the
 *	root web directory.
 */
	if (gethostname(host, sizeof(host)) < 0) {
		error(E_L, E_LOG, T("Can't get hostname"));
		return -1;
	}

// david /////////////////////////////////////////
#if 0
	if ((hp = gethostbyname(host)) == NULL) {
		error(E_L, E_LOG, T("Can't get host address"));
		return -1;
	}
#endif
#if 0
	if ( !getInAddr(BRIDGE_IF, IP_ADDR, (void *)&intaddr) ) {
//		error(E_L, E_LOG, T("Can't get bridge address!"));
		noIp = TRUE;
	}
#endif
	noIp = TRUE;

//////////////////////////////////////////////////

/*
 *	Set ../web as the root web. Modify this to suit your needs
 */
	getcwd(dir, sizeof(dir));
	if ((cp = strrchr(dir, '/'))) {
		*cp = '\0';
	}

	sprintf(webdir, "%s/%s", dir, rootWeb);

/*
 *	Configure the web server options before opening the web server
 */
	websSetDefaultDir(webdir);
#if 0
	if ( !noIp ) { // david
		cp = inet_ntoa(intaddr);
		ascToUni(wbuf, cp, min(strlen(cp) + 1, sizeof(wbuf)));
		websSetIpaddr(wbuf);
		ascToUni(wbuf, host, min(strlen(host) + 1, sizeof(wbuf)));
		websSetHost(wbuf);
	}
#endif	

/*
 *	Configure the web server options before opening the web server
 */
	websSetDefaultPage(T("default.asp"));
	websSetPassword(password);

/*
 *	Open the web server on the given port. If that port is taken, try
 *	the next sequential port for up to "retries" attempts.
 */
	websOpenServer(port, retries);

/*
 * 	First create the URL handlers. Note: handlers are called in sorted order
 *	with the longest path handler examined first. Here we define the security
 *	handler, forms handler and the default web page handler.
 */
	websUrlHandlerDefine(T(""), NULL, 0, websSecurityHandler,
		WEBS_HANDLER_FIRST);
	websUrlHandlerDefine(T("/goform"), NULL, 0, websFormHandler, 0);
	websUrlHandlerDefine(T("/cgi-bin"), NULL, 0, websCgiHandler, 0);
#if defined( HTTP_FILE_SERVER_SUPPORTED)
	web_http_file_server_default_init();
#endif
	websUrlHandlerDefine(T(""), NULL, 0, websDefaultHandler,
		WEBS_HANDLER_LAST);

// david -------------------
	if ( apmib_init() == 0 ) {
		error(E_L, E_LOG, T("Initialize AP MIB failed!\n"));
		return -1;
	}
	save_cs_to_file(); //michael

	set_user_profile();

#ifdef CONFIG_RTK_MESH
	websFormDefine(T("formMeshSetup"), formMeshSetup);
	websFormDefine(T("formMeshProxy"), formMeshProxy);
	//websFormDefine(T("formMeshProxyTbl"), formMeshProxyTbl);
#ifdef 	_11s_TEST_MODE_
	websFormDefine(T("asdfgh"), formEngineeringMode);
	websFormDefine(T("zxcvbnm"), formEngineeringMode2);
	websAspDefine(T("wlRxStatics"), wlRxStatics);
	
#endif
#ifdef _MESH_ACL_ENABLE_
	websFormDefine(T("formMeshACLSetup"), formMeshACLSetup);
	websAspDefine(T("wlMeshAcList"), wlMeshAcList);
#endif
#endif

	websFormDefine(T("formWlanSetup"), formWlanSetup);
	websFormDefine(T("formWlanRedirect"), formWlanRedirect);
#if 0
	websFormDefine(T("formWep64"), formWep64);
	websFormDefine(T("formWep128"), formWep128);
#endif
	websFormDefine(T("formWep"), formWep);

	websFormDefine(T("formTcpipSetup"), formTcpipSetup);
	websAspDefine(T("getInfo"), getInfo);
	websAspDefine(T("getIndex"), getIndex);
#if defined(NEW_SCHEDULE_SUPPORT)	
	websAspDefine(T("wlSchList"), wlSchList);
#endif	
	websAspDefine(T("getScheduleInfo"), getScheduleInfo);
	websAspDefine(T("wlAcList"), wlAcList);
//modify by nctu
	websAspDefine(T("getModeCombobox"), getModeCombobox);
	websAspDefine(T("getDHCPModeCombobox"), getDHCPModeCombobox);
#ifdef CONFIG_RTK_MESH
	websAspDefine(T("wlMeshNeighborTable"), wlMeshNeighborTable);
	websAspDefine(T("wlMeshRoutingTable"), wlMeshRoutingTable);
	websAspDefine(T("wlMeshProxyTable"), wlMeshProxyTable);
	websAspDefine(T("wlMeshRootInfo"), wlMeshRootInfo);
	websAspDefine(T("wlMeshPortalTable"), wlMeshPortalTable);
#endif
	websFormDefine(T("formPasswordSetup"), formPasswordSetup);
	websFormDefine(T("formLogout"), formLogout);

	websFormDefine(T("formUpload"), formUpload);
#ifdef CONFIG_RTL_WAPI_SUPPORT
	websFormDefine(T("formWapiReKey"), formWapiReKey);
	websFormDefine(T("formUploadWapiCert"), formUploadWapiCert);
	websFormDefine(T("formWapiCertManagement"), formWapiCertManagement);
	websFormDefine(T("formWapiCertDistribute"), formWapiCertDistribute);
#endif

#ifdef CONFIG_RTL_802_1X_CLIENT_SUPPORT
websFormDefine(T("formUpload8021xUserCert"), formUpload8021xUserCert);
#endif

#ifdef TLS_CLIENT	
	websFormDefine(T("formCertUpload"), formCertUpload);
	websAspDefine(T("certRootList"), certRootList);	
	websAspDefine(T("certUserList"), certUserList);
#endif	
	websFormDefine(T("formWlAc"), formWlAc);
	websFormDefine(T("formAdvanceSetup"), formAdvanceSetup);
	websAspDefine(T("dhcpClientList"), dhcpClientList);
	websAspDefine(T("dhcpRsvdIp_List"), dhcpRsvdIp_List);
	websFormDefine(T("formReflashClientTbl"), formReflashClientTbl);
	websFormDefine(T("formWlEncrypt"), formWlEncrypt);
	websFormDefine(T("formStaticDHCP"), formStaticDHCP);
#ifndef HOME_GATEWAY
	websFormDefine(T("formSetTime"), formSetTime);
#endif

#if defined(POWER_CONSUMPTION_SUPPORT)
	websAspDefine(T("getPowerConsumption"), getPowerConsumption);
#endif

#if defined(CONFIG_RTL_8198_AP_ROOT) && defined(VLAN_CONFIG_SUPPORTED)
	websAspDefine(T("vlanList"), vlanList);
	websFormDefine(T("formVlan"), formVlan);
#if defined(CONFIG_RTL_92D_SUPPORT)
        websFormDefine(T("formWlanBand2G5G"), formWlanBand2G5G);
#endif
#endif
	
#ifdef HOME_GATEWAY
#if 0  //sc_yang
	websAspDefine(T("showWanPage"), showWanPage);
#endif
	websFormDefine(T("formWanTcpipSetup"), formWanTcpipSetup);

	websAspDefine(T("portFwList"), portFwList);
	websAspDefine(T("ipFilterList"), ipFilterList);
	websAspDefine(T("portFilterList"), portFilterList);
	websAspDefine(T("macFilterList"), macFilterList);
	websAspDefine(T("urlFilterList"), urlFilterList);

//	websAspDefine(T("triggerPortList"), triggerPortList);
#ifdef ROUTE_SUPPORT
	websAspDefine(T("staticRouteList"), staticRouteList);
	websAspDefine(T("kernelRouteList"), kernelRouteList);
	websFormDefine(T("formRoute"), formRoute);
#endif

	websFormDefine(T("formPortFw"), formPortFw);
	websFormDefine(T("formFilter"), formFilter);
//	websFormDefine(T("formTriggerPort"), formTriggerPort);
	websFormDefine(T("formDMZ"), formDMZ);
#if defined(VLAN_CONFIG_SUPPORTED)
	websAspDefine(T("vlanList"), vlanList);
	websFormDefine(T("formVlan"), formVlan);
#endif	
	websFormDefine(T("formDdns"), formDdns);
	// by sc_yang
	websFormDefine(T("formNtp"), formNtp);
	websFormDefine(T("formOpMode"), formOpMode);
#if defined(CONFIG_RTL_92D_SUPPORT)
	websFormDefine(T("formWlanBand2G5G"), formWlanBand2G5G);
#endif

#if defined(CONFIG_RTL_FLASH_DUAL_IMAGE_ENABLE)	
	websFormDefine(T("formDualFirmware"), formDualFirmware);
#endif
	
#if defined(GW_QOS_ENGINE)
	websAspDefine(T("qosList"), qosList);
	websFormDefine(T("formQoS"), formQoS);
#elif defined(QOS_BY_BANDWIDTH)	
	websAspDefine(T("ipQosList"), ipQosList);
	websFormDefine(T("formIpQoS"), formIpQoS);
#endif
#endif
	websFormDefine(T("formWizard"), formWizard);
	websFormDefine(T("formPocketWizard"), formPocketWizard);
	websFormDefine(T("formPocketWizardGW"), formPocketWizardGW);
	
#ifdef REBOOT_CHECK	
	websFormDefine(T("formRebootCheck"), formRebootCheck);
#endif	
	websFormDefine(T("formSysCmd"),  formSysCmd);
	websFormDefine(T("formSysLog"), formSysLog);
	websAspDefine(T("sysLogList"), sysLogList);
	websAspDefine(T("sysCmdLog"), sysCmdLog);

#ifdef HOME_GATEWAY
#ifdef DOS_SUPPORT
	websFormDefine(T("formDosCfg"), formDosCfg);
#endif
#ifdef VPN_SUPPORT
	websFormDefine(T("formVpnSetup"), formVpnSetup);
	websFormDefine(T("formVpnConn"), formVpnConn);
	//websFormDefine(T("formVpnLog"), formVpnLog);
	//websAspDefine(T("vpnStatList"), vpnStatList);
	websAspDefine(T("vpnConnList"), vpnConnList);
	websAspDefine(T("vpnRsaList"), vpnRsaList);
	//websAspDefine(T("vpnShowLog"), vpnShowLog);
#endif

#ifdef CONFIG_IPV6
	websFormDefine(T("formRadvd"), formRadvd);
	websFormDefine(T("formDnsv6"), formDnsv6);
	websFormDefine(T("formDhcpv6s"), formDhcpv6s);
	websFormDefine(T("formIPv6Addr"), formIPv6Addr);
	websFormDefine(T("formTunnel6"), formTunnel6);	
	websAspDefine(T("getIPv6Info"), getIPv6Info);
	websAspDefine(T("getIPv6BasicInfo"), getIPv6BasicInfo);	
#endif
#endif

	websFormDefine(T("formSaveConfig"), formSaveConfig);
	websFormDefine(T("formSchedule"), formSchedule);
#if defined(NEW_SCHEDULE_SUPPORT)	
	websFormDefine(T("formNewSchedule"), formNewSchedule);	
#endif 	
	websAspDefine(T("wirelessClientList"), wirelessClientList);
	websFormDefine(T("formWirelessTbl"), formWirelessTbl);
	websFormDefine(T("formStats"), formStats);
#ifdef CONFIG_RTK_MESH
	websFormDefine(T("formMeshStatus"), formMeshStatus);
#endif
	websFormDefine(T("formWlSiteSurvey"), formWlSiteSurvey);
	websAspDefine(T("wlSiteSurveyTbl"), wlSiteSurveyTbl);
	websAspDefine(T("wlWdsList"), wlWdsList);
	websFormDefine(T("formWlWds"), formWlWds);
	websFormDefine(T("formWdsEncrypt"), formWdsEncrypt);
	websAspDefine(T("wdsList"), wdsList);

#ifdef WLAN_EASY_CONFIG
	websFormDefine(T("formAutoCfg"), formAutoCfg);
#endif

#ifdef WIFI_SIMPLE_CONFIG
	websFormDefine(T("formWsc"), formWsc);
#endif

#ifdef LOGIN_URL
	websFormDefine(T("formLogin"), formLogin);
#endif

#ifdef MBSSID
	websFormDefine(T("formWlanMultipleAP"), formWlanMultipleAP);
	websAspDefine(T("getVirtualIndex"), getVirtualIndex);
	websAspDefine(T("getVirtualInfo"), getVirtualInfo);
#endif

#ifdef HOME_GATEWAY
#ifdef CONFIG_RTL_BT_CLIENT
	websFormDefine(T("formBTBasicSetting"),formBTBasicSetting);
	websFormDefine(T("formBTClientSetting"),formBTClientSetting);
	websFormDefine(T("formBTFileSetting"),formBTFileSetting);
	websFormDefine(T("formBTNewTorrent"),formBTNewTorrent);
#endif
#endif
#if defined( HTTP_FILE_SERVER_SUPPORTED)
	web_http_file_server_init();
#endif
// added by rock /////////////////////////////////////////
#ifdef VOIP_SUPPORT
	web_voip_init();
#endif 

/*+++++added by Jack for Tr-069 configuration+++++*/
#ifdef CONFIG_CWMP_TR069
	websFormDefine(T("formTR069Config"), formTR069Config);
	websAspDefine(T("TR069ConPageShow"), TR069ConPageShow);
#ifdef CONFIG_USER_CWMP_WITH_MATRIXSSL
	websFormDefine(T("formTR069CertUpload"), formTR069CertUpload);
#endif
#endif /*CONFIG_CWMP_TR069*/
/*-----end-----*/

	/* determine interface name by mib value */
#ifdef HOME_GATEWAY
#if 0
// Old code and no longer used
	if (pHwSetting->boardVer & USE_ETH0_WAN) {
		WAN_IF = T("eth0");
		BRIDGE_IF = T("wlan0");
		ELAN_IF = T("wlan0");
	}
	else {
		WAN_IF = T("eth1");
		BRIDGE_IF = T("br0");
		ELAN_IF = T("eth0");
	}
#endif
	WAN_IF = T("eth1");
	BRIDGE_IF = T("br0");
	ELAN_IF = T("eth0");
	ELAN2_IF = T("eth2");
	ELAN3_IF = T("eth3");
	ELAN4_IF = T("eth4");

	PPPOE_IF = T("ppp0");
#elif defined(VOIP_SUPPORT) && defined(ATA867x)
	BRIDGE_IF = T("eth0");
	ELAN_IF = T("eth0");
#else
	BRIDGE_IF = T("br0");
	ELAN_IF = T("eth0");
#endif
	strcpy(WLAN_IF,"wlan0");
//---------------------------

/*
 *	Now define two test procedures. Replace these with your application
 *	relevant ASP script procedures and form functions.
 */
// marked by david
//	websAspDefine(T("aspTest"), aspTest);
//	websFormDefine(T("formTest"), formTest);

/*
 *	Create the Form handlers for the User Management pages
 */
#ifdef USER_MANAGEMENT_SUPPORT
// marked by david
//	formDefineUserMgmt();
#endif

/*
 *	Create a handler for the default home page
 */
	websUrlHandlerDefine(T("/"), NULL, 0, websHomePageHandler, 0);
	return 0;
}
// marked by david
#if 0
/******************************************************************************/
/*
 *	Test Javascript binding for ASP. This will be invoked when "aspTest" is
 *	embedded in an ASP page. See web/asp.asp for usage. Set browser to
 *	"localhost/asp.asp" to test.
 */

static int aspTest(int eid, webs_t wp, int argc, char_t **argv)
{
	char_t	*name, *address;

	if (ejArgs(argc, argv, T("%s %s"), &name, &address) < 2) {
		websError(wp, 400, T("Insufficient args\n"));
		return -1;
	}
	return websWrite(wp, T("Name: %s, Address %s"), name, address);
}

/******************************************************************************/
/*
 *	Test form for posted data (in-memory CGI). This will be called when the
 *	form in web/asp.asp is invoked. Set browser to "localhost/asp.asp" to test.
 */

static void formTest(webs_t wp, char_t *path, char_t *query)
{
	char_t	*name, *address;

	name = websGetVar(wp, T("name"), T("Joe Smith")); 
	address = websGetVar(wp, T("address"), T("1212 Milky Way Ave.")); 

	websHeader(wp);
	websWrite(wp, T("<body><h2>Name: %s, Address: %s</h2>\n"), name, address);
	websFooter(wp);
	websDone(wp, 200);
}
#endif

/******************************************************************************/
/*
 *	Home page handler
 */

static int websHomePageHandler(webs_t wp, char_t *urlPrefix, char_t *webDir,
	int arg, char_t *url, char_t *path, char_t *query)
{
/*
 *	If the empty or "/" URL is invoked, redirect default URLs to the home page
 */
	if (*url == '\0' || gstrcmp(url, T("/")) == 0) {
#ifdef LOGIN_URL
		char tmpbuf[100];
		apmib_get(MIB_USER_NAME, tmpbuf);
		if (tmpbuf[0])
			websRedirect(wp, T("login.asp"));
		else
#endif
#if defined(HTTP_FILE_SERVER_SUPPORTED)
		websRedirect(wp, T("http_files.asp"));
		return 1;
#else
		websRedirect(wp, T("home.asp"));
		return 1;
#endif
	}
	return 0;
}

/******************************************************************************/
/*
 *	Default error handler.  The developer should insert code to handle
 *	error messages in the desired manner.
 */

void defaultErrorHandler(int etype, char_t *msg)
{
// david
#if 1
	write(1, msg, gstrlen(msg));
#endif
}

/******************************************************************************/
/*
 *	Trace log. Customize this function to log trace output
 */

void defaultTraceHandler(int level, char_t *buf)
{
/*
 *	The following code would write all trace regardless of level
 *	to stdout.
 */
// david
#if 0
	if (buf) {
		write(1, buf, gstrlen(buf));
	}
#endif
}

/******************************************************************************/
/*
 *	Returns a pointer to an allocated qualified unique temporary file name.
 *	This filename must eventually be deleted with bfree();
 */

char_t *websGetCgiCommName()
{
	char_t	*pname1, *pname2;

// david, remove warning ---------
//	pname1 = tempnam(NULL, T("cgi"));
pname1=malloc(40);
sprintf(pname1, "%sXXXXXX",  T("cgi"));
mkstemp(pname1);
//--------------------------------

	pname2 = bstrdup(B_L, pname1);
	free(pname1);
	return pname2;
}

/******************************************************************************/
/*
 *	Launch the CGI process and return a handle to it.
 */

int websLaunchCgiProc(char_t *cgiPath, char_t **argp, char_t **envp,
					  char_t *stdIn, char_t *stdOut)
{
	int	pid, fdin, fdout, hstdin, hstdout, rc;

	fdin = fdout = hstdin = hstdout = rc = -1;
	if ((fdin = open(stdIn, O_RDWR | O_CREAT, 0666)) < 0 ||
		(fdout = open(stdOut, O_RDWR | O_CREAT, 0666)) < 0 ||
		(hstdin = dup(0)) == -1 ||
		(hstdout = dup(1)) == -1 ||
		dup2(fdin, 0) == -1 ||
		dup2(fdout, 1) == -1) {
		goto DONE;
	}

 	rc = pid = fork();
 	if (pid == 0) {
/*
 *		if pid == 0, then we are in the child process
 */
		if (execve(cgiPath, argp, envp) == -1) {
			printf("content-type: text/html\n\n"
				"Execution of cgi process failed\n");
		}
		exit (0);
	} 

DONE:
	if (hstdout >= 0) {
		dup2(hstdout, 1);
	}
	if (hstdin >= 0) {
		dup2(hstdin, 0);
	}
	if (fdout >= 0) {
		close(fdout);
	}
	if (fdin >= 0) {
		close(fdin);
	}
	return rc;
}

/******************************************************************************/
/*
 *	Check the CGI process.  Return 0 if it does not exist; non 0 if it does.
 */

int websCheckCgiProc(int handle)
{
/*
 *	Check to see if the CGI child process has terminated or not yet.
 */
	if (waitpid(handle, NULL, WNOHANG) == handle) {
		return 0;
	} else {
		return 1;
	}
}

/******************************************************************************/

#ifdef B_STATS
static void memLeaks() 
{
	int		fd;

	if ((fd = gopen(T("leak.txt"), O_CREAT | O_TRUNC | O_WRONLY)) >= 0) {
		bstats(fd, printMemStats);
		close(fd);
	}
}

/******************************************************************************/
/*
 *	Print memory usage / leaks
 */

static void printMemStats(int handle, char_t *fmt, ...)
{
	va_list		args;
	char_t		buf[256];

	va_start(args, fmt);
	vsprintf(buf, fmt, args);
	va_end(args);
	write(handle, buf, strlen(buf));
}
#endif

/******************************************************************************/

