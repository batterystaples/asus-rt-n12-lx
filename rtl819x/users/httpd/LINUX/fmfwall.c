/*
 *      Web server handler routines for firewall
 *
 *      Authors: David Hsu	<davidhsu@realtek.com.tw>
 *
 *      $Id: fmfwall.c,v 1.6 2011/06/20 10:46:11 edison_shih Exp $
 *
 */

/*-- System inlcude files --*/
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/wait.h>

//#include "../webs.h"	//Comment by Jerry
#include "../httpd.h"	//Added by Jerry
#include "apform.h"
#include "apmib.h"
#include "utility.h"

#if defined(CONFIG_RTL_8198_AP_ROOT) && defined(VLAN_CONFIG_SUPPORTED)
struct nameMapping
{
	char display[32];
	char ifname[16];
};
static struct nameMapping vlanNameMapping[10] = 
{
	{"Ethernet Port1","eth0"},
	{"Ethernet Port2","eth1"},
	{"Ethernet Port3","eth2"},
	{"Ethernet Port4","eth3"},
	{"Ethernet Port5","eth4"},
	{"Wireless Primary AP","wlan0"},
	{"Virtual AP1","wlan0-va0"},
	{"Virtual AP2","wlan0-va1"},
	{"Virtual AP3","wlan0-va2"},
	{"Virtual AP4","wlan0-va3"},	
};

static struct nameMapping* findNameMapping(const char *display)
{	
	int i;
	for(i = 0; i < MAX_IFACE_VLAN_CONFIG;i++)
	{
		if(strcmp(display,vlanNameMapping[i].display) == 0)
			return &vlanNameMapping[i];
	}
	return NULL;
}
int vlanList(int eid, webs_t wp, int argc, char_t **argv)
{
	VLAN_CONFIG_T entry;
	char *strToken;
	int cmpResult=0;
	//char *tmpStr0;
	int  index=0;
	char IfaceName[32];
	OPMODE_T opmode=-1;
	char wanLan[8];
	char bufStr[50];
	memset(IfaceName,0x00,sizeof(IfaceName));
	memset(wanLan,0x00,sizeof(wanLan));
	memset(bufStr,0x00,sizeof(bufStr));
	
	index = atoi(argv[--argc]);

	if( index <= MAX_IFACE_VLAN_CONFIG && index != 0) /* ignore item 0 */
	{
		*((char *)&entry) = (char)index;
		if ( !apmib_get(MIB_VLANCONFIG_TBL, (void *)&entry))
		{
			fprintf(stderr,"Get vlan entry fail\n");
			return -1;
		}
		
		apmib_get( MIB_OP_MODE, (void *)&opmode);
		
		switch(index)
		{
			case 1:
			case 2:
			case 3:
			case 4:
				sprintf(IfaceName,"%s%d","Ethernet Port",index);
				sprintf(wanLan,"%s","LAN");
				break;
			case 5:
				sprintf(IfaceName,"%s","Wireless 1 Primary AP");
				if(opmode == WISP_MODE)
				{
					sprintf(wanLan,"%s","WAN");
				}
				else
				{
					sprintf(wanLan,"%s","LAN");
				}
				break;
			case 6:
			case 7:
			case 8:
			case 9:
				sprintf(IfaceName,"%s%d","Virtual AP",index-5);
				sprintf(wanLan,"%s","LAN");
				break;
			case 10:
				sprintf(IfaceName,"%s","Wireless 2 Primary AP");
				sprintf(wanLan,"%s","LAN");
				break;
			case 11:
			case 12:
			case 13:
			case 14:
				sprintf(IfaceName,"%s%d","Virtual AP",index-10);
				sprintf(wanLan,"%s","LAN");
				break;

			case 15:
				sprintf(IfaceName,"%s","Ethernet Port5");
#ifdef RTK_USB3G_PORT5_LAN
				if(opmode == WISP_MODE || opmode == BRIDGE_MODE || wan_dhcp == USB3G)
#else
				if(opmode == WISP_MODE || opmode == BRIDGE_MODE)
#endif
				{
					sprintf(wanLan,"%s","LAN");
				}
				else
				{
					sprintf(wanLan,"%s","WAN");
				}
				break;
			case 16:
			sprintf(IfaceName,"%s","Local Host/WAN");
				sprintf(wanLan,"%s","LAN");
				break;
		}
		
		/* enabled/netIface/tagged/untagged/priority/cfi/groupId/vlanId/LanWan */
		//websWrite(wp, T("%d|%s|%d|%d|%d|%d|%d|%d|%s"), entry.enabled,IfaceName,entry.tagged,0,entry.priority,entry.cfi,0,entry.vlanId,wanLan);
		sprintf(bufStr, "%d|%s|%d|%d|%d|%d|%d|%d|%s", entry.enabled,IfaceName,entry.tagged,0,entry.priority,entry.cfi,0,entry.vlanId,wanLan);
		
	}
	else
	{
		sprintf(bufStr, "0|none|0|0|0|0|0|0|LAN");
	}
	
	//ejSetResult(eid, bufStr);	//Comment by Jerry
	websWrite(wp, bufStr);		//Added by Jerry
	return 0;
}

void formVlan(webs_t wp, char_t *path, char_t *query)
{
	VLAN_CONFIG_T entry;
	char_t *submitUrl,*strTmp;
	int	i, vlan_onoff;
	struct nameMapping *mapping;
	char tmpBuf[100];
	
	//displayPostDate(wp->postData);

	strTmp= websGetVar(wp, T("vlan_onoff"), T(""));
	if(strTmp[0])
	{
		vlan_onoff = atoi(strTmp);
	}
	
	if (!apmib_set(MIB_VLANCONFIG_ENABLED, (void *)&vlan_onoff)) 
	{
		strcpy(tmpBuf, T("set  MIB_VLANCONFIG_ENABLED error!"));
		goto setErr;
	}
	if(vlan_onoff == 1)
	{
		if ( !apmib_set(MIB_VLANCONFIG_DELALL, (void *)&entry)) 
		{
			strcpy(tmpBuf, T("Delete all table error!"));
			goto setErr;
		}

		for(i=1; i<=MAX_IFACE_VLAN_CONFIG ; i++)
		{
			memset(&entry, '\0', sizeof(entry));
			
			*((char *)&entry) = (char)i;
			apmib_get(MIB_VLANCONFIG_TBL, (void *)&entry);			

			memset(tmpBuf,0x00, sizeof(tmpBuf));			
			sprintf(tmpBuf,"vlan_iface_%d",i);
			strTmp = websGetVar(wp, T(tmpBuf), T(""));

			if(strTmp[0])
			{
				//strcpy(entry.netIface,strTmp);
				mapping = findNameMapping(strTmp);
				if(mapping)
				{
					strcpy(entry.netIface,mapping->ifname);
				}				
			}
			else
			{
				if ( apmib_set(MIB_VLANCONFIG_ADD, (void *)&entry) == 0) 
				{				
					strcpy(tmpBuf, T("Add table entry error!"));				
					goto setErr;
				}
				continue;
			}

			memset(tmpBuf,0x00, sizeof(tmpBuf));			
			sprintf(tmpBuf,"vlan_enable_%d",i);
			strTmp = websGetVar(wp, T(tmpBuf), T(""));
			if(strTmp[0])
			{
				entry.enabled = atoi(strTmp);
			}

			memset(tmpBuf,0x00, sizeof(tmpBuf));			
			sprintf(tmpBuf,"vlan_tag_%d",i);
			strTmp = websGetVar(wp, T(tmpBuf), T(""));
			if(strTmp[0])
			{
				entry.tagged = atoi(strTmp);
			}

			memset(tmpBuf,0x00, sizeof(tmpBuf));			
			sprintf(tmpBuf,"vlan_cfg_%d",i);
			strTmp = websGetVar(wp, T(tmpBuf), T(""));
			if(strTmp[0])
			{
				entry.cfi = atoi(strTmp);
			}

			memset(tmpBuf,0x00, sizeof(tmpBuf));			
			sprintf(tmpBuf,"vlan_id_%d",i);
			strTmp = websGetVar(wp, T(tmpBuf), T(""));
			if(strTmp[0])
			{
				entry.vlanId = atoi(strTmp);
			}

			memset(tmpBuf,0x00, sizeof(tmpBuf));			
			sprintf(tmpBuf,"vlan_priority_%d",i);
			strTmp = websGetVar(wp, T(tmpBuf), T(""));
			if(strTmp[0])
			{
				entry.priority = atoi(strTmp);
			}

			if ( apmib_set(MIB_VLANCONFIG_ADD, (void *)&entry) == 0) 
			{				
				strcpy(tmpBuf, T("Add table entry error!"));				
				goto setErr;
			}


			

		}
		
	}

	apmib_update_web(CURRENT_SETTING);

#ifndef NO_ACTION
	run_init_script("all");                
#endif

	submitUrl = websGetVar(wp, T("submit-url"), T(""));   // hidden page
	if (submitUrl[0])
	{
		OK_MSG(submitUrl);
	}
	else
		websDone(wp, 200);
  	return;

setErr:
	ERR_MSG(tmpBuf);
	return;

}
#endif

#ifdef HOME_GATEWAY

//Added by Jerry
void formBasicFwallSetup(webs_t wp, char_t *path, char_t *query)
{
	char_t  *strVal, *submitUrl;
	int intVal;
	long enabled = 0;

	submitUrl = websGetVar(wp, T("submit-url"), T(""));   // hidden page

	/* Set DoS to MIB */
	strVal = websGetVar(wp, T("dosEnabled"), T(""));
	if ( !gstrcmp(strVal, T("ON")))
	{
		enabled |= 1;	//Enable
		enabled |= 2;	//MIB_DOS_SYSSYN_FLOOD
		enabled |= 4;	//MIB_DOS_SYSFIN_FLOOD
		enabled |= 8;	//MIB_DOS_SYSUDP_FLOOD
		enabled |= 0x10;	//MIB_DOS_SYSICMP_FLOOD
		enabled |= 0x20;	//MIB_DOS_PIPSYN_FLOOD
		enabled |= 0x40;	//MIB_DOS_PIPFIN_FLOOD
		enabled |= 0x80;	//MIB_DOS_PIPUDP_FLOOD
		enabled |= 0x100;	//MIB_DOS_PIPICMP_FLOOD
		enabled |= 0x200;	//TCPUDPPortScan
		enabled |= 0x800000;	//portscanSensi
		enabled |= 0x400;	//ICMPSmurfEnabled
		enabled |= 0x800;	//IPLandEnabled
		enabled |= 0x1000;	//IPSpoofEnabled
		enabled |= 0x2000;	//IPTearDropEnabled
		enabled |= 0x4000;	//PingOfDeathEnabled
		enabled |= 0x8000;	//TCPScanEnabled
		enabled |= 0x10000;	//TCPSynWithDataEnabled
		enabled |= 0x20000;	//UDPBombEnabled
		enabled |= 0x40000;	//UDPEchoChargenEnabled
		enabled |= 0x400000;	//sourceIPblock
	}
	else
		enabled = 0;
	if ( !apmib_set(MIB_DOS_ENABLED, (void *)&enabled))
		printf("Set MIB_DOS_ENABLED error!\n");

	/* Set FIREWALL_ENABLED to MIB by Edison 2011.6.1*/
	strVal = websGetVar(wp, T("firewallEnabled"), T(""));
	if ( !gstrcmp(strVal, T("ON")))
		intVal = 1;
	else
		intVal = 0;
	if ( !apmib_set(MIB_FIREWALL_ENABLED, (void *)&intVal))
		printf("Set FIREWALL_ENABLED error!\n");

	/* Set web wan access to MIB */
	strVal = websGetVar(wp, T("webWanAccess"), T(""));
	if ( !gstrcmp(strVal, T("ON")))
		intVal = 1;
	else
		intVal = 0;
	if ( !apmib_set(MIB_WEB_WAN_ACCESS_ENABLED, (void *)&intVal))
		printf("Set WEB_WAN_ACCESS_ENABLED error!\n");

	/* Set web wan access port to MIB by Edison 2011.6.2*/
	strVal = websGetVar(wp, T("webWanAccessPort"), T(""));
	if ( strVal[0] ) {
		int WanAccessPort;
		WanAccessPort = strtol(strVal, (char**)NULL, 10);
		if ( !apmib_set(MIB_WEB_WAN_ACCESS_PORT, (void *)&WanAccessPort))
			printf("Set WEB_WAN_ACCESS_PORT error!\n");
	}
	

	/* Set ping wan access to MIB */
	strVal = websGetVar(wp, T("pingWanAccess"), T(""));
	if ( !gstrcmp(strVal, T("ON")))
		intVal = 1;
	else
		intVal = 0;
	if ( !apmib_set(MIB_PING_WAN_ACCESS_ENABLED, (void *)&intVal))
		printf("Set PING_WAN_ACCESS_ENABLED error!\n");

	apmib_update_web(CURRENT_SETTING);

	/*if (submitUrl[0])
		websRedirect(wp, submitUrl);	

	system("sysconf init gw all"); //mars add	*/
	return;
}


/////////////////////////////////////////////////////////////////////////////
void formPortFw(webs_t wp, char_t *path, char_t *query)
{
	char_t *submitUrl, *strAddPort, *strDelPort, *strVal, *strDelAllPort;
	char_t *strIp, *strFrom, *strTo, *strComment;
	char tmpBuf[100];
	int entryNum, intVal, i;
	PORTFW_T entry;
	struct in_addr curIpAddr, curSubnet;
	unsigned long v1, v2, v3;
#ifndef NO_ACTION
	int pid;
#endif

	strAddPort = websGetVar(wp, T("addPortFw"), T(""));
	strDelPort = websGetVar(wp, T("deleteSelPortFw"), T(""));
	strDelAllPort = websGetVar(wp, T("deleteAllPortFw"), T(""));

	memset(&entry, '\0', sizeof(entry));

	/* Add new port-forwarding table */
	if (strAddPort[0]) {
		strVal = websGetVar(wp, T("enabled"), T(""));
		if ( !gstrcmp(strVal, T("ON")))
			intVal = 1;
		else
			intVal = 0;
		if ( apmib_set( MIB_PORTFW_ENABLED, (void *)&intVal) == 0) {
			strcpy(tmpBuf, T("Set enabled flag error!"));
			goto setErr_portfw;
		}

		strIp = websGetVar(wp, T("ip"), T(""));
		strFrom = websGetVar(wp, T("fromPort"), T(""));
		strTo = websGetVar(wp, T("toPort"), T(""));
		strComment = websGetVar(wp, T("comment"), T(""));
		
		if (!strIp[0] && !strFrom[0] && !strTo[0] && !strComment[0])
			goto setOk_portfw;

		if (!strIp[0]) {
			strcpy(tmpBuf, T("Error! No ip address to set."));
			goto setErr_portfw;
		}

		inet_aton(strIp, (struct in_addr *)&entry.ipAddr);
		getInAddr(BRIDGE_IF, IP_ADDR, (void *)&curIpAddr);
		getInAddr(BRIDGE_IF, SUBNET_MASK, (void *)&curSubnet);

		v1 = *((unsigned long *)entry.ipAddr);
		v2 = *((unsigned long *)&curIpAddr);
		v3 = *((unsigned long *)&curSubnet);

		if ( (v1 & v3) != (v2 & v3) ) {
			strcpy(tmpBuf, T("Invalid IP address! It should be set within the current subnet."));
			goto setErr_portfw;
		}

		if ( !strFrom[0] ) { // if port-forwarding, from port must exist
			strcpy(tmpBuf, T("Error! No from-port value to be set."));
			goto setErr_portfw;
		}
		if ( !string_to_dec(strFrom, &intVal) || intVal<1 || intVal>65535) {
			strcpy(tmpBuf, T("Error! Invalid value of from-port."));
			goto setErr_portfw;
		}
		entry.fromPort = (unsigned short)intVal;

		if ( !strTo[0] )
			entry.toPort = entry.fromPort;
		else {
			if ( !string_to_dec(strTo, &intVal) || intVal<1 || intVal>65535) {
				strcpy(tmpBuf, T("Error! Invalid value of to-port."));
				goto setErr_portfw;
			}
		}
		entry.toPort = (unsigned short)intVal;

		if ( entry.fromPort  > entry.toPort ) {
			strcpy(tmpBuf, T("Error! Invalid port range."));
			goto setErr_portfw;
		}

		strVal = websGetVar(wp, T("protocol"), T(""));
		if (strVal[0]) {
			if ( strVal[0] == '0' )
				entry.protoType = PROTO_BOTH;
			else if ( strVal[0] == '1' )
				entry.protoType = PROTO_TCP;
			else if ( strVal[0] == '2' )
				entry.protoType = PROTO_UDP;
			else {
				strcpy(tmpBuf, T("Error! Invalid protocol type."));
				goto setErr_portfw;
			}
		}
		else {
			strcpy(tmpBuf, T("Error! Protocol type cannot be empty."));
			goto setErr_portfw;
		}

		if ( strComment[0] ) {
			if (strlen(strComment) > COMMENT_LEN-1) {
				strcpy(tmpBuf, T("Error! Comment length too long."));
				goto setErr_portfw;
			}
			strcpy(entry.comment, strComment);
		}
		if ( !apmib_get(MIB_PORTFW_TBL_NUM, (void *)&entryNum)) {
			strcpy(tmpBuf, T("Get entry number error!"));
			goto setErr_portfw;
		}

		if ( (entryNum + 1) > MAX_FILTER_NUM) {
			strcpy(tmpBuf, T("Cannot add new entry because table is full!"));
			goto setErr_portfw;
		}

		// Check if there is any port overlapped
		for (i=1; i<=entryNum; i++) {
			PORTFW_T checkEntry;
			*((char *)&checkEntry) = (char)i;
			if ( !apmib_get(MIB_PORTFW_TBL, (void *)&checkEntry)) {
				strcpy(tmpBuf, T("Get table entry error!"));
				goto setErr_portfw;
			}
			if ( ( (entry.fromPort <= checkEntry.fromPort &&
					entry.toPort >= checkEntry.fromPort) ||
			       (entry.fromPort >= checkEntry.fromPort &&
				entry.fromPort <= checkEntry.toPort)
			     )&&
			       (entry.protoType & checkEntry.protoType) ) {
				strcpy(tmpBuf, T("Setting port range has overlapped with used port numbers!"));
				goto setErr_portfw;
			}
		}

		// set to MIB. try to delete it first to avoid duplicate case
		apmib_set(MIB_PORTFW_DEL, (void *)&entry);
		if ( apmib_set(MIB_PORTFW_ADD, (void *)&entry) == 0) {
			strcpy(tmpBuf, T("Add table entry error!"));
			goto setErr_portfw;
		}
	}

	/* Delete entry */
	if (strDelPort[0]) {
		if ( !apmib_get(MIB_PORTFW_TBL_NUM, (void *)&entryNum)) {
			strcpy(tmpBuf, T("Get entry number error!"));
			goto setErr_portfw;
		}

		for (i=entryNum; i>0; i--) {
			snprintf(tmpBuf, 20, "select%d", i);

			strVal = websGetVar(wp, tmpBuf, T(""));
			if ( !gstrcmp(strVal, T("ON")) ) {
				*((char *)&entry) = (char)i;
				if ( !apmib_get(MIB_PORTFW_TBL, (void *)&entry)) {
					strcpy(tmpBuf, T("Get table entry error!"));
					goto setErr_portfw;
				}
				if ( !apmib_set(MIB_PORTFW_DEL, (void *)&entry)) {
					strcpy(tmpBuf, T("Delete table entry error!"));
					goto setErr_portfw;
				}
			}
		}
	}

	/* Delete all entry */
	if ( strDelAllPort[0]) {
		if ( !apmib_set(MIB_PORTFW_DELALL, (void *)&entry)) {
			strcpy(tmpBuf, T("Delete all table error!"));
			goto setErr_portfw;
		}
	}

setOk_portfw:
	apmib_update_web(CURRENT_SETTING);

//2011.03.28 Jerry {
#if 0
#ifndef NO_ACTION
	pid = fork();
        if (pid) {
	      	waitpid(pid, NULL, 0);
	}
        else if (pid == 0) {
		snprintf(tmpBuf, 100, "%s/%s", _CONFIG_SCRIPT_PATH, _FIREWALL_SCRIPT_PROG);
		execl( tmpBuf, _FIREWALL_SCRIPT_PROG, NULL);
               	exit(1);
        }
#endif

	submitUrl = websGetVar(wp, T("submit-url"), T(""));   // hidden page

#ifdef REBOOT_CHECK
	if(needReboot == 1)
	{
		OK_MSG(submitUrl);
		return;
	}
#endif
	
	if (submitUrl[0])
		websRedirect(wp, submitUrl);
	else
		websDone(wp, 200);
  	return;

setErr_portfw:
	ERR_MSG(tmpBuf);
#endif
//2011.03.28 Jerry }

setErr_portfw:
	return;
}


/////////////////////////////////////////////////////////////////////////////
void formFilter(webs_t wp, char_t *path, char_t *query)
{
	char_t *strAddIp, *strAddPort, *strAddMac, *strDelPort, *strDelIp, *strDelMac;
	char_t *strDelAllPort, *strDelAllIp, *strDelAllMac, *strVal, *submitUrl, *strComment;
	char_t *strFrom, *strTo;
	char tmpBuf[100];
	int entryNum, intVal, i;
	IPFILTER_T ipEntry;
	PORTFILTER_T portEntry;
	MACFILTER_T macEntry;
	struct in_addr curIpAddr, curSubnet;
	void *pEntry;
	unsigned long v1, v2, v3;
	int num_id, get_id, add_id, del_id, delall_id, enable_id;
	char_t *strAddUrl, *strDelUrl;
	char_t *strDelAllUrl;
	URLFILTER_T urlEntry;
#ifndef NO_ACTION
	int pid;
#endif

	strAddIp = websGetVar(wp, T("addFilterIp"), T(""));
	strDelIp = websGetVar(wp, T("deleteSelFilterIp"), T(""));
	strDelAllIp = websGetVar(wp, T("deleteAllFilterIp"), T(""));

	strAddPort = websGetVar(wp, T("addFilterPort"), T(""));
	strDelPort = websGetVar(wp, T("deleteSelFilterPort"), T(""));
	strDelAllPort = websGetVar(wp, T("deleteAllFilterPort"), T(""));

	strAddMac = websGetVar(wp, T("addFilterMac"), T(""));
	strDelMac = websGetVar(wp, T("deleteSelFilterMac"), T(""));
	strDelAllMac = websGetVar(wp, T("deleteAllFilterMac"), T(""));

	strAddUrl = websGetVar(wp, T("addFilterUrl"), T(""));
	strDelUrl = websGetVar(wp, T("deleteSelFilterUrl"), T(""));
	strDelAllUrl = websGetVar(wp, T("deleteAllFilterUrl"), T(""));

	if (strAddIp[0] || strDelIp[0] || strDelAllIp[0]) {
		num_id = MIB_IPFILTER_TBL_NUM;
		get_id = MIB_IPFILTER_TBL;
		add_id = MIB_IPFILTER_ADD;
		del_id = MIB_IPFILTER_DEL;
		delall_id = MIB_IPFILTER_DELALL;
		enable_id = MIB_IPFILTER_ENABLED;
		memset(&ipEntry, '\0', sizeof(ipEntry));
		pEntry = (void *)&ipEntry;
	}
	else if (strAddPort[0] || strDelPort[0] || strDelAllPort[0]) {
		num_id = MIB_PORTFILTER_TBL_NUM;
		get_id = MIB_PORTFILTER_TBL;
		add_id = MIB_PORTFILTER_ADD;
		del_id = MIB_PORTFILTER_DEL;
		delall_id = MIB_PORTFILTER_DELALL;
		enable_id = MIB_PORTFILTER_ENABLED;
		memset(&portEntry, '\0', sizeof(portEntry));
		pEntry = (void *)&portEntry;
	}
	else if (strAddMac[0] || strDelMac[0] || strDelAllMac[0]) {
		num_id = MIB_MACFILTER_TBL_NUM;
		get_id = MIB_MACFILTER_TBL;
		add_id = MIB_MACFILTER_ADD;
		del_id = MIB_MACFILTER_DEL;
		delall_id = MIB_MACFILTER_DELALL;
		enable_id = MIB_MACFILTER_ENABLED;
		memset(&macEntry, '\0', sizeof(macEntry));
		pEntry = (void *)&macEntry;
	}
	else {
		num_id = MIB_URLFILTER_TBL_NUM;
		get_id = MIB_URLFILTER_TBL;
		add_id = MIB_URLFILTER_ADD;
		del_id = MIB_URLFILTER_DEL;
		delall_id = MIB_URLFILTER_DELALL;
		enable_id = MIB_URLFILTER_ENABLED;
		memset(&urlEntry, '\0', sizeof(urlEntry));
		pEntry = (void *)&urlEntry;
	}
	// Set enable flag
	if ( strAddIp[0] || strAddPort[0] || strAddMac[0] || strAddUrl[0]) {
		strVal = websGetVar(wp, T("enabled"), T(""));
		if ( !gstrcmp(strVal, T("ON")))
			intVal = 1;
		else
			intVal = 0;

		if ( apmib_set(enable_id, (void *)&intVal) == 0) {
			strcpy(tmpBuf, T("Set enabled flag error!"));
			goto setErr_filter;
		}
	}

	strComment = websGetVar(wp, T("comment"), T(""));

	/* Add IP filter */
	if (strAddIp[0]) {
		strVal = websGetVar(wp, T("ip"), T(""));
		if (!strVal[0] && !strComment[0])
			goto setOk_filter;

		if (!strVal[0]) {
			strcpy(tmpBuf, T("Error! No ip address to set."));
			goto setErr_filter;
		}
		inet_aton(strVal, (struct in_addr *)&ipEntry.ipAddr);
		getInAddr(BRIDGE_IF, IP_ADDR, (void *)&curIpAddr);
		getInAddr(BRIDGE_IF, SUBNET_MASK, (void *)&curSubnet);

		v1 = *((unsigned long *)ipEntry.ipAddr);
		v2 = *((unsigned long *)&curIpAddr);
		v3 = *((unsigned long *)&curSubnet);

		if ( (v1 & v3) != (v2 & v3) ) {
			strcpy(tmpBuf, T("Invalid IP address! It should be set within the current subnet."));
			goto setErr_filter;
		}
	}

	/* Add port filter */
	if (strAddPort[0]) {
		strFrom = websGetVar(wp, T("fromPort"), T(""));
		strTo = websGetVar(wp, T("toPort"), T(""));
		if (!strFrom[0] && !strTo[0] && !strComment[0])
			goto setOk_filter;

		if (!strFrom[0]) { // if port-forwarding, from port must exist
			strcpy(tmpBuf, T("Error! No from-port value to be set."));
			goto setErr_filter;
		}
		if ( !string_to_dec(strFrom, &intVal) || intVal<1 || intVal>65535) {
			strcpy(tmpBuf, T("Error! Invalid value of from-port."));
			goto setErr_filter;
		}
		portEntry.fromPort = (unsigned short)intVal;

		if ( !strTo[0] )
			portEntry.toPort = portEntry.fromPort;
		else {
			if ( !string_to_dec(strTo, &intVal) || intVal<1 || intVal>65535) {
				strcpy(tmpBuf, T("Error! Invalid value of to-port."));
				goto setErr_filter;
			}
			portEntry.toPort = (unsigned short)intVal;
		}

		if ( portEntry.fromPort  > portEntry.toPort ) {
			strcpy(tmpBuf, T("Error! Invalid port range."));
			goto setErr_filter;
		}
	}

	if (strAddPort[0] || strAddIp[0]) {
		strVal = websGetVar(wp, T("protocol"), T(""));
		if (strVal[0]) {
			if ( strVal[0] == '0' ) {
				if (strAddPort[0])
					portEntry.protoType = PROTO_BOTH;
				else
					ipEntry.protoType = PROTO_BOTH;
			}
			else if ( strVal[0] == '1' ) {
				if (strAddPort[0])
					portEntry.protoType = PROTO_TCP;
				else
					ipEntry.protoType = PROTO_TCP;
			}
			else if ( strVal[0] == '2' ) {
				if (strAddPort[0])
					portEntry.protoType = PROTO_UDP;
				else
					ipEntry.protoType = PROTO_UDP;
			}
			else {
				strcpy(tmpBuf, T("Error! Invalid protocol type."));
				goto setErr_filter;
			}
		}
		else {
			strcpy(tmpBuf, T("Error! Protocol type cannot be empty."));
			goto setErr_filter;
		}
	}

	if (strAddMac[0]) {
		strVal = websGetVar(wp, T("mac"), T(""));
		if (!strVal[0] && !strComment[0])
			goto setOk_filter;

		if ( !strVal[0] ) {
			strcpy(tmpBuf, T("Error! No mac address to set."));
			goto setErr_filter;
		}
		if (strlen(strVal)!=12 || !string_to_hex(strVal, macEntry.macAddr, 12)) {
			strcpy(tmpBuf, T("Error! Invalid MAC address."));
			goto setErr_filter;
		}
	}

	if (strAddUrl[0]) {
		strVal = websGetVar(wp, T("url"), T(""));
		if (!strVal[0])// && !strComment[0])
			goto setOk_filter;

		if ( !strVal[0] ) {
			strcpy(tmpBuf, T("Error! No url keyword to set."));
			goto setErr_filter;
		}
		else
		{
			strcpy(urlEntry.urlAddr, strVal);
		}
	}

	if (strAddIp[0] || strAddPort[0] || strAddMac[0] || strAddUrl[0]) {
		if ( strComment[0] ) {
			if (strlen(strComment) > COMMENT_LEN-1) {
				strcpy(tmpBuf, T("Error! Comment length too long."));
				goto setErr_filter;
			}
			if (strAddIp[0])
				strcpy(ipEntry.comment, strComment);
			else if (strAddPort[0])
				strcpy(portEntry.comment, strComment);
			else if (strAddMac[0])
				strcpy(macEntry.comment, strComment);
		}

		if ( !apmib_get(num_id, (void *)&entryNum)) {
			strcpy(tmpBuf, T("Get entry number error!"));
			goto setErr_filter;
		}
		if (strAddUrl[0])
		{
			if ( (entryNum + 1) > MAX_URLFILTER_NUM) {
				strcpy(tmpBuf, T("Cannot add new URL entry because table is full!"));
				goto setErr_filter;
			}
		}
		else
		{
			if ( (entryNum + 1) > MAX_FILTER_NUM) {
				strcpy(tmpBuf, T("Cannot add new entry because table is full!"));
				goto setErr_filter;
			}
		}

		// set to MIB. try to delete it first to avoid duplicate case
		apmib_set(del_id, pEntry);
		if ( apmib_set(add_id, pEntry) == 0) {
			strcpy(tmpBuf, T("Add table entry error!"));
			goto setErr_filter;
		}
	}


	/* Delete entry */
	if (strDelPort[0] || strDelIp[0] || strDelMac[0] || strDelUrl[0]) {
		if ( !apmib_get(num_id, (void *)&entryNum)) {
			strcpy(tmpBuf, T("Get entry number error!"));
			goto setErr_filter;
		}
		for (i=entryNum; i>0; i--) {
			snprintf(tmpBuf, 20, "select%d", i);

			strVal = websGetVar(wp, tmpBuf, T(""));
			if ( !gstrcmp(strVal, T("ON")) ) {

				*((char *)pEntry) = (char)i;
				if ( !apmib_get(get_id, pEntry)) {
					strcpy(tmpBuf, T("Get table entry error!"));
					goto setErr_filter;
				}
				if ( !apmib_set(del_id, pEntry)) {
					strcpy(tmpBuf, T("Delete table entry error!"));
					goto setErr_filter;
				}
			}
		}
	}

	/* Delete all entry */
	if ( strDelAllPort[0] || strDelAllIp[0] || strDelAllMac[0] || strDelAllUrl[0]) {
		if ( !apmib_set(delall_id, pEntry)) {
			strcpy(tmpBuf, T("Delete all table error!"));
			goto setErr_filter;
		}
	}
setOk_filter:
	apmib_update_web(CURRENT_SETTING);
//2011.03.28 Jerry {
	/*pid = fork();
        if (pid) {
	      	waitpid(pid, NULL, 0);
	}
        else if (pid == 0) {
		apmib_update_web(CURRENT_SETTING);
               exit(1);
        }*/
//2011.03.28 Jerry }
	
//2011.03.28 Jerry {
#if 0
#ifndef NO_ACTION
	pid = fork();
        if (pid) {
	      	waitpid(pid, NULL, 0);
	}
        else if (pid == 0) {
		snprintf(tmpBuf, 100, "%s/%s", _CONFIG_SCRIPT_PATH, _FIREWALL_SCRIPT_PROG);
		execl( tmpBuf, _FIREWALL_SCRIPT_PROG, NULL);
               	exit(1);
        }
#endif

	submitUrl = websGetVar(wp, T("submit-url"), T(""));   // hidden page
	
#ifdef REBOOT_CHECK
	if(needReboot == 1)
	{
		OK_MSG(submitUrl);
		return;
	}
#endif

	if (submitUrl[0])
		websRedirect(wp, submitUrl);
	else
		websDone(wp, 200);
  	return;

setErr_filter:
	ERR_MSG(tmpBuf);

#endif
//2011.03.28 Jerry }

setErr_filter:
	return;
}

#if 0
/////////////////////////////////////////////////////////////////////////////
void formTriggerPort(webs_t wp, char_t *path, char_t *query)
{
	char_t *strAddPort, *strDelAllPort, *strDelPort, *strVal, *submitUrl;
	char_t *strTriFrom, *strTriTo, *strIncFrom, *strIncTo, *strComment;
	char tmpBuf[100];
	int entryNum, intVal, i;
	TRIGGERPORT_T entry;

	memset(&entry, '\0', sizeof(entry));

	/* Add port filter */
	strAddPort = websGetVar(wp, T("addPort"), T(""));
	if (strAddPort[0]) {
		strVal = websGetVar(wp, T("enabled"), T(""));
		if ( !gstrcmp(strVal, T("ON")))
			intVal = 1;
		else
			intVal = 0;


		if ( apmib_set(MIB_TRIGGERPORT_ENABLED, (void *)&intVal) == 0) {
			strcpy(tmpBuf, T("Set enabled flag error!"));
			goto setErr_triPort;
		}

		strTriFrom = websGetVar(wp, T("triFromPort"), T(""));
		strTriTo = websGetVar(wp, T("triToPort"), T(""));
		strIncFrom = websGetVar(wp, T("incFromPort"), T(""));
		strIncTo = websGetVar(wp, T("incToPort"), T(""));
		strComment = websGetVar(wp, T("comment"), T(""));

		if (!strTriFrom[0] && !strTriTo[0] && !strIncFrom[0] &&
					!strIncTo[0] && !strComment[0])
			goto setOk_triPort;

		// get trigger port range and protocol
		if (!strTriFrom[0]) { // from port must exist
			strcpy(tmpBuf, T("Error! No from-port value to be set."));
			goto setErr_triPort;
		}
		if ( !string_to_dec(strTriFrom, &intVal) || intVal<1 || intVal>65535) {
			strcpy(tmpBuf, T("Error! Invalid value of trigger from-port."));
			goto setErr_triPort;
		}
		entry.tri_fromPort = (unsigned short)intVal;

		if ( !strTriTo[0] )
			entry.tri_toPort = entry.tri_fromPort;
		else {
			if ( !string_to_dec(strTriTo, &intVal) || intVal<1 || intVal>65535) {
				strcpy(tmpBuf, T("Error! Invalid value of trigger to-port."));
				goto setErr_triPort;
			}
			entry.tri_toPort = (unsigned short)intVal;
		}

		if ( entry.tri_fromPort  > entry.tri_toPort ) {
			strcpy(tmpBuf, T("Error! Invalid trigger port range."));
			goto setErr_triPort;
		}

		strVal = websGetVar(wp, T("triProtocol"), T(""));
		if (strVal[0]) {
			if ( strVal[0] == '0' ) {
				if (strAddPort[0])
					entry.tri_protoType = PROTO_BOTH;
				else
					entry.tri_protoType = PROTO_BOTH;
			}
			else if ( strVal[0] == '1' ) {
				if (strAddPort[0])
					entry.tri_protoType = PROTO_TCP;
				else
					entry.tri_protoType = PROTO_TCP;
			}
			else if ( strVal[0] == '2' ) {
				if (strAddPort[0])
					entry.tri_protoType = PROTO_UDP;
				else
					entry.tri_protoType = PROTO_UDP;
			}
			else {
				strcpy(tmpBuf, T("Error! Invalid trigger-port protocol type."));
				goto setErr_triPort;
			}
		}
		else {
			strcpy(tmpBuf, T("Error! trigger-port protocol type cannot be empty."));
			goto setErr_triPort;
		}

		// get incoming port range and protocol
		if (!strIncFrom[0]) { // from port must exist
			strcpy(tmpBuf, T("Error! No from-port value to be set."));
			goto setErr_triPort;
		}
		if ( !string_to_dec(strIncFrom, &intVal) || intVal<1 || intVal>65535) {
			strcpy(tmpBuf, T("Error! Invalid value of incoming from-port."));
			goto setErr_triPort;
		}
		entry.inc_fromPort = (unsigned short)intVal;

		if ( !strIncTo[0] )
			entry.inc_toPort = entry.inc_fromPort;
		else {
			if ( !string_to_dec(strIncTo, &intVal) || intVal<1 || intVal>65535) {
				strcpy(tmpBuf, T("Error! Invalid value of incoming to-port."));
				goto setErr_triPort;
			}
			entry.inc_toPort = (unsigned short)intVal;
		}

		if ( entry.inc_fromPort  > entry.inc_toPort ) {
			strcpy(tmpBuf, T("Error! Invalid incoming port range."));
			goto setErr_triPort;
		}


		strVal = websGetVar(wp, T("incProtocol"), T(""));
		if (strVal[0]) {
			if ( strVal[0] == '0' ) {
				if (strAddPort[0])
					entry.inc_protoType = PROTO_BOTH;
				else
					entry.inc_protoType = PROTO_BOTH;
			}
			else if ( strVal[0] == '1' ) {
				if (strAddPort[0])
					entry.inc_protoType = PROTO_TCP;
				else
					entry.inc_protoType = PROTO_TCP;
			}
			else if ( strVal[0] == '2' ) {
				if (strAddPort[0])
					entry.inc_protoType = PROTO_UDP;
				else
					entry.inc_protoType = PROTO_UDP;
			}
			else {
				strcpy(tmpBuf, T("Error! Invalid incoming-port protocol type."));
				goto setErr_triPort;
			}
		}
		else {
			strcpy(tmpBuf, T("Error! incoming-port protocol type cannot be empty."));
			goto setErr_triPort;
		}

		// get comment
		if ( strComment[0] ) {
			if (strlen(strComment) > COMMENT_LEN-1) {
				strcpy(tmpBuf, T("Error! Comment length too long."));
				goto setErr_triPort;
			}
			strcpy(entry.comment, strComment);
		}

		// get entry number to see if it exceeds max
		if ( !apmib_get(MIB_TRIGGERPORT_TBL_NUM, (void *)&entryNum)) {
			strcpy(tmpBuf, T("Get entry number error!"));
			goto setErr_triPort;
		}
		if ( (entryNum + 1) > MAX_FILTER_NUM) {
			strcpy(tmpBuf, T("Cannot add new entry because table is full!"));
			goto setErr_triPort;
		}
		
		// Check if there is any port overlapped
		for (i=1; i<=entryNum; i++) {
			TRIGGERPORT_T checkEntry;
			*((char *)&checkEntry) = (char)i;
			if ( !apmib_get(MIB_TRIGGERPORT_TBL, (void *)&checkEntry)) {
				strcpy(tmpBuf, T("Get table entry error!"));
				goto setErr_triPort;
			}
			if ( ( (entry.tri_fromPort <= checkEntry.tri_fromPort &&
					entry.tri_toPort >= checkEntry.tri_fromPort) ||
			       (entry.tri_fromPort >= checkEntry.tri_fromPort &&
				entry.tri_fromPort <= checkEntry.tri_toPort)
			     )&&
			       (entry.tri_protoType & checkEntry.tri_protoType) ) {
				strcpy(tmpBuf, T("Trigger port range has overlapped with used port numbers!"));
				goto setErr_triPort;
			}
		}

		// set to MIB. try to delete it first to avoid duplicate case
		apmib_set(MIB_TRIGGERPORT_DEL, (void *)&entry);
		if ( apmib_set(MIB_TRIGGERPORT_ADD, (void *)&entry) == 0) {
			strcpy(tmpBuf, T("Add table entry error!"));
			goto setErr_triPort;
		}
	}

	/* Delete entry */
	strDelPort = websGetVar(wp, T("deleteSelPort"), T(""));
	if (strDelPort[0]) {
		if ( !apmib_get(MIB_TRIGGERPORT_TBL_NUM, (void *)&entryNum)) {
			strcpy(tmpBuf, T("Get entry number error!"));
			goto setErr_triPort;
		}
		for (i=entryNum; i>0; i--) {
			snprintf(tmpBuf, 20, "select%d", i);

			strVal = websGetVar(wp, tmpBuf, T(""));
			if ( !gstrcmp(strVal, T("ON")) ) {

				*((char *)&entry) = (char)i;
				if ( !apmib_get(MIB_TRIGGERPORT_TBL, (void *)&entry)) {
					strcpy(tmpBuf, T("Get table entry error!"));
					goto setErr_triPort;
				}
				if ( !apmib_set(MIB_TRIGGERPORT_DEL, (void *)&entry)) {
					strcpy(tmpBuf, T("Delete table entry error!"));
					goto setErr_triPort;
				}
			}
		}
	}

	/* Delete all entry */
	strDelAllPort = websGetVar(wp, T("deleteAllPort"), T(""));
	if ( strDelAllPort[0]) {
		if ( !apmib_set(MIB_TRIGGERPORT_DELALL, (void *)&entry)) {
			strcpy(tmpBuf, T("Delete all table error!"));
			goto setErr_triPort;
		}
	}

setOk_triPort:
	apmib_update_web(CURRENT_SETTING);

	submitUrl = websGetVar(wp, T("submit-url"), T(""));   // hidden page
	if (submitUrl[0])
		websRedirect(wp, submitUrl);
	else
		websDone(wp, 200);
  	return;

setErr_triPort:
	ERR_MSG(tmpBuf);
}
#endif

#if defined(VLAN_CONFIG_SUPPORTED)
struct nameMapping
{
	char display[32];
	char ifname[16];
};
static struct nameMapping vlanNameMapping[10] = 
{
	{"Ethernet Port1","eth0"},
	{"Ethernet Port2","eth2"},
	{"Ethernet Port3","eth3"},
	{"Ethernet Port4","eth4"},
	{"Ethernet Port5","eth1"},
	{"Wireless Primary AP","wlan0"},
	{"Virtual AP1","wlan0-va0"},
	{"Virtual AP2","wlan0-va1"},
	{"Virtual AP3","wlan0-va2"},
	{"Virtual AP4","wlan0-va3"},	
};

static struct nameMapping* findNameMapping(const char *display)
{	
	int i;
	for(i = 0; i < MAX_IFACE_VLAN_CONFIG;i++)
	{
		if(strcmp(display,vlanNameMapping[i].display) == 0)
			return &vlanNameMapping[i];
	}
	return NULL;
}
int vlanList(int eid, webs_t wp, int argc, char_t **argv)
{
	VLAN_CONFIG_T entry;
	char *strToken;
	int cmpResult=0;
	//char *tmpStr0;
	int  index=0;
	char IfaceName[32];
	OPMODE_T opmode=-1;
	char wanLan[8];
	char bufStr[50];
	memset(IfaceName,0x00,sizeof(IfaceName));
	memset(wanLan,0x00,sizeof(wanLan));
	memset(bufStr,0x00,sizeof(bufStr));
	
	index = atoi(argv[--argc]);

	if( index <= MAX_IFACE_VLAN_CONFIG && index != 0) /* ignore item 0 */
	{
			
    #ifdef RTK_USB3G_PORT5_LAN
        DHCP_T wan_dhcp = -1;
        apmib_get( MIB_DHCP, (void *)&wan_dhcp);
    #endif
		
		*((char *)&entry) = (char)index;
		if ( !apmib_get(MIB_VLANCONFIG_TBL, (void *)&entry))
		{
			fprintf(stderr,"Get vlan entry fail\n");
			return -1;
		}
		
		apmib_get( MIB_OP_MODE, (void *)&opmode);
		
		switch(index)
		{
			case 1:
			case 2:
			case 3:
			case 4:
				sprintf(IfaceName,"%s%d","Ethernet Port",index);
				sprintf(wanLan,"%s","LAN");
				break;
			case 5:
				sprintf(IfaceName,"%s","Wireless 1 Primary AP");
				if(opmode == WISP_MODE)
				{
					sprintf(wanLan,"%s","WAN");
				}
				else
				{
					sprintf(wanLan,"%s","LAN");
				}
				break;
			case 6:
			case 7:
			case 8:
			case 9:
				sprintf(IfaceName,"%s%d","Virtual AP",index-5);
				sprintf(wanLan,"%s","LAN");
				break;
			case 10:
				sprintf(IfaceName,"%s","Wireless 2 Primary AP");
				sprintf(wanLan,"%s","LAN");
				break;
			case 11:
			case 12:
			case 13:
			case 14:
				sprintf(IfaceName,"%s%d","Virtual AP",index-10);
				sprintf(wanLan,"%s","LAN");
				break;

			case 15:
				sprintf(IfaceName,"%s","Ethernet Port5");
#ifdef RTK_USB3G_PORT5_LAN
				if(opmode == WISP_MODE || opmode == BRIDGE_MODE || wan_dhcp == USB3G)
#else
				if(opmode == WISP_MODE || opmode == BRIDGE_MODE)
#endif
				{
					sprintf(wanLan,"%s","LAN");
				}
				else
				{
					sprintf(wanLan,"%s","WAN");
				}
				break;
			case 16:
			sprintf(IfaceName,"%s","Local Host/WAN");
				sprintf(wanLan,"%s","LAN");
				break;
		}
		
		/* enabled/netIface/tagged/untagged/priority/cfi/groupId/vlanId/LanWan */
		//websWrite(wp, T("%d|%s|%d|%d|%d|%d|%d|%d|%s"), entry.enabled,IfaceName,entry.tagged,0,entry.priority,entry.cfi,0,entry.vlanId,wanLan);
		sprintf(bufStr, "%d|%s|%d|%d|%d|%d|%d|%d|%s", entry.enabled,IfaceName,entry.tagged,0,entry.priority,entry.cfi,0,entry.vlanId,wanLan);
		
	}
	else
	{
		sprintf(bufStr, "0|none|0|0|0|0|0|0|LAN");
	}
	
	//ejSetResult(eid, bufStr);	//Comment by Jerry
	websWrite(wp, bufStr);		//Added by Jerry
	return 0;
}

void formVlan(webs_t wp, char_t *path, char_t *query)
{
	VLAN_CONFIG_T entry;
	char_t *submitUrl,*strTmp;
	int	i, vlan_onoff;
	struct nameMapping *mapping;
	char tmpBuf[100];
	
	//displayPostDate(wp->postData);

	strTmp= websGetVar(wp, T("vlan_onoff"), T(""));
	if(strTmp[0])
	{
		vlan_onoff = atoi(strTmp);
	}
	
	if (!apmib_set(MIB_VLANCONFIG_ENABLED, (void *)&vlan_onoff)) 
	{
		strcpy(tmpBuf, T("set  MIB_VLANCONFIG_ENABLED error!"));
		goto setErr;
	}
	if(vlan_onoff == 1)
	{
		if ( !apmib_set(MIB_VLANCONFIG_DELALL, (void *)&entry)) 
		{
			strcpy(tmpBuf, T("Delete all table error!"));
			goto setErr;
		}

		for(i=1; i<=MAX_IFACE_VLAN_CONFIG ; i++)
		{
			memset(&entry, '\0', sizeof(entry));
			
			*((char *)&entry) = (char)i;
			apmib_get(MIB_VLANCONFIG_TBL, (void *)&entry);			

			memset(tmpBuf,0x00, sizeof(tmpBuf));			
			sprintf(tmpBuf,"vlan_iface_%d",i);
			strTmp = websGetVar(wp, T(tmpBuf), T(""));

			if(strTmp[0])
			{
				//strcpy(entry.netIface,strTmp);
				mapping = findNameMapping(strTmp);
				if(mapping)
				{
					strcpy(entry.netIface,mapping->ifname);
				}				
			}
			else
			{
				if ( apmib_set(MIB_VLANCONFIG_ADD, (void *)&entry) == 0) 
				{				
					strcpy(tmpBuf, T("Add table entry error!"));				
					goto setErr;
				}
				continue;
			}

			memset(tmpBuf,0x00, sizeof(tmpBuf));			
			sprintf(tmpBuf,"vlan_enable_%d",i);
			strTmp = websGetVar(wp, T(tmpBuf), T(""));
			if(strTmp[0])
			{
				entry.enabled = atoi(strTmp);
			}

			memset(tmpBuf,0x00, sizeof(tmpBuf));			
			sprintf(tmpBuf,"vlan_tag_%d",i);
			strTmp = websGetVar(wp, T(tmpBuf), T(""));
			if(strTmp[0])
			{
				entry.tagged = atoi(strTmp);
			}

			memset(tmpBuf,0x00, sizeof(tmpBuf));			
			sprintf(tmpBuf,"vlan_cfg_%d",i);
			strTmp = websGetVar(wp, T(tmpBuf), T(""));
			if(strTmp[0])
			{
				entry.cfi = atoi(strTmp);
			}

			memset(tmpBuf,0x00, sizeof(tmpBuf));			
			sprintf(tmpBuf,"vlan_id_%d",i);
			strTmp = websGetVar(wp, T(tmpBuf), T(""));
			if(strTmp[0])
			{
				entry.vlanId = atoi(strTmp);
			}

			memset(tmpBuf,0x00, sizeof(tmpBuf));			
			sprintf(tmpBuf,"vlan_priority_%d",i);
			strTmp = websGetVar(wp, T(tmpBuf), T(""));
			if(strTmp[0])
			{
				entry.priority = atoi(strTmp);
			}

			if ( apmib_set(MIB_VLANCONFIG_ADD, (void *)&entry) == 0) 
			{				
				strcpy(tmpBuf, T("Add table entry error!"));				
				goto setErr;
			}


			

		}
		
	}

	apmib_update_web(CURRENT_SETTING);

#ifndef NO_ACTION
	run_init_script("all");                
#endif

	submitUrl = websGetVar(wp, T("submit-url"), T(""));   // hidden page
	if (submitUrl[0])
	{
		OK_MSG(submitUrl);
	}
	else
		websDone(wp, 200);
  	return;

setErr:
	ERR_MSG(tmpBuf);
	return;

}
#endif

/////////////////////////////////////////////////////////////////////////////
void formDMZ(webs_t wp, char_t *path, char_t *query)
{
	char_t *submitUrl, *strSave, *strVal;
	char tmpBuf[100];
	int intVal;
	struct in_addr ipAddr, curIpAddr, curSubnet;
	unsigned long v1, v2, v3;
#ifndef NO_ACTION
	int pid;
#endif

	strSave = websGetVar(wp, T("save"), T(""));

	if (strSave[0]) {
		strVal = websGetVar(wp, T("enabled"), T(""));
		if ( !gstrcmp(strVal, T("ON")))
			intVal = 1;
		else
			intVal = 0;

		if ( apmib_set(MIB_DMZ_ENABLED, (void *)&intVal) == 0) {
			strcpy(tmpBuf, T("Set enabled flag error!"));
			goto setErr_dmz;
		}

		strVal = websGetVar(wp, T("ip"), T(""));
		if (!strVal[0]) {
			goto setOk_dmz;
		}
		inet_aton(strVal, &ipAddr);
		getInAddr(BRIDGE_IF, IP_ADDR, (void *)&curIpAddr);
		getInAddr(BRIDGE_IF, SUBNET_MASK, (void *)&curSubnet);

		v1 = *((unsigned long *)&ipAddr);
		v2 = *((unsigned long *)&curIpAddr);
		v3 = *((unsigned long *)&curSubnet);
		if (v1) {
			if ( (v1 & v3) != (v2 & v3) ) {
				strcpy(tmpBuf, T("Invalid IP address! It should be set within the current subnet."));
				goto setErr_dmz;
			}
		}
		if ( apmib_set(MIB_DMZ_HOST, (void *)&ipAddr) == 0) {
			strcpy(tmpBuf, T("Set DMZ MIB error!"));
			goto setErr_dmz;
		}
	}

setOk_dmz:
	apmib_update_web(CURRENT_SETTING);

#if 0
#ifndef NO_ACTION
	pid = fork();
        if (pid) {
	      	waitpid(pid, NULL, 0);
	}
        else if (pid == 0) {
		snprintf(tmpBuf, 100, "%s/%s", _CONFIG_SCRIPT_PATH, _FIREWALL_SCRIPT_PROG);
		execl( tmpBuf, _FIREWALL_SCRIPT_PROG, NULL);
               	exit(1);
        }
#endif

	submitUrl = websGetVar(wp, T("submit-url"), T(""));   // hidden page
//	OK_MSG(submitUrl);
	if (submitUrl[0])
		websRedirect(wp, submitUrl);
	else
		websDone(wp, 200);

  	return;

setErr_dmz:
	ERR_MSG(tmpBuf);
#endif
setErr_dmz:
	return;
}


/////////////////////////////////////////////////////////////////////////////
int portFwList(int eid, webs_t wp, int argc, char_t **argv)
{
	int	nBytesSent=0, entryNum, i;
	PORTFW_T entry;
	char	*type, portRange[20], *ip;

	if ( !apmib_get(MIB_PORTFW_TBL_NUM, (void *)&entryNum)) {
  		websError(wp, 400, T("Get table entry error!\n"));
		return -1;
	}
/*
	nBytesSent += websWrite(wp, T("<tr>"
	"<td align=center width=\"20%%\" bgcolor=\"#808080\">Select</td>\n"
      	"<td align=center width=\"30%%\" bgcolor=\"#808080\">Local IP Address</td>\n"
      	"<td align=center width=\"25%%\" bgcolor=\"#808080\">Protocol</td>\n"
      	"<td align=center width=\"25%%\" bgcolor=\"#808080\">Port Range</td></tr>\n"
	//"<td align=center width=\"20%%\" bgcolor=\"#808080\">Comment</td>\n"
      	));
*/
	for (i=1; i<=entryNum; i++) {
		*((char *)&entry) = (char)i;
		if ( !apmib_get(MIB_PORTFW_TBL, (void *)&entry))
			return -1;

		ip = inet_ntoa(*((struct in_addr *)entry.ipAddr));
		if ( !strcmp(ip, "0.0.0.0"))
			ip = "----";

		if ( entry.protoType == PROTO_BOTH )
			type = "TCP+UDP";
		else if ( entry.protoType == PROTO_TCP )
			type = "TCP";
		else
			type = "UDP";

		if ( entry.fromPort == 0)
			strcpy(portRange, "----");
		else if ( entry.fromPort == entry.toPort )
			snprintf(portRange, 20, "%d", entry.fromPort);
		else
			snprintf(portRange, 20, "%d-%d", entry.fromPort, entry.toPort);

		nBytesSent += websWrite(wp, T("<tr>"
			"<td align=center width=\"20%%\" bgcolor=\"#C0C0C0\"><input type=\"checkbox\" name=\"select%d\" value=\"ON\"></td>\n"
			"<td align=center width=\"30%%\" bgcolor=\"#C0C0C0\">%s</td>\n"
      			"<td align=center width=\"25%%\" bgcolor=\"#C0C0C0\">%s</td>\n"
      			"<td align=center width=\"25%%\" bgcolor=\"#C0C0C0\">%s</td></tr>\n"
     			//"<td align=center width=\"20%%\" bgcolor=\"#C0C0C0\">%s</td>\n"
      			),
				i, ip, type, portRange);
				//ip, type, portRange, entry.comment, i);
	}
	return nBytesSent;
}


/////////////////////////////////////////////////////////////////////////////
int portFilterList(int eid, webs_t wp, int argc, char_t **argv)
{
	int	nBytesSent=0, entryNum, i;
	PORTFILTER_T entry;
	char	*type, portRange[20];

	if ( !apmib_get(MIB_PORTFILTER_TBL_NUM, (void *)&entryNum)) {
  		websError(wp, 400, T("Get table entry error!\n"));
		return -1;
	}
/*
	nBytesSent += websWrite(wp, T("<tr>"
	"<td align=center width=\"25%%\" bgcolor=\"#808080\">Select</td>\n"
      	"<td align=center width=\"40%%\" bgcolor=\"#808080\">Port Range</td>\n"
      	"<td align=center width=\"35%%\" bgcolor=\"#808080\">Protocol</td></tr>\n"
	//"<td align=center width=\"30%%\" bgcolor=\"#808080\">Comment</td>\n"
      	));
*/
	for (i=1; i<=entryNum; i++) {
		*((char *)&entry) = (char)i;
		if ( !apmib_get(MIB_PORTFILTER_TBL, (void *)&entry))
			return -1;

		if ( entry.protoType == PROTO_BOTH )
			type = "TCP+UDP";
		else if ( entry.protoType == PROTO_TCP )
			type = "TCP";
		else
			type = "UDP";

		if ( entry.fromPort == 0)
			strcpy(portRange, "----");
		else if ( entry.fromPort == entry.toPort )
			snprintf(portRange, 20, "%d", entry.fromPort);
		else
			snprintf(portRange, 20, "%d-%d", entry.fromPort, entry.toPort);

		nBytesSent += websWrite(wp, T("<tr>"
			"<td align=center width=\"25%%\" bgcolor=\"#C0C0C0\"><input type=\"checkbox\" name=\"select%d\" value=\"ON\"></td>\n"
			"<td align=center width=\"40%%\" bgcolor=\"#C0C0C0\">%s</td>\n"
   			"<td align=center width=\"35%%\" bgcolor=\"#C0C0C0\">%s</td></tr>\n"
     			//"<td align=center width=\"30%%\" bgcolor=\"#C0C0C0\">%s</td>\n"
      			),
				i, portRange, type);
				//portRange, type, entry.comment, i);
	}
	return nBytesSent;
}


/////////////////////////////////////////////////////////////////////////////
int ipFilterList(int eid, webs_t wp, int argc, char_t **argv)
{
	int	nBytesSent=0, entryNum, i;
	IPFILTER_T entry;
	char	*type, *ip;

	if ( !apmib_get(MIB_IPFILTER_TBL_NUM, (void *)&entryNum)) {
  		websError(wp, 400, T("Get table entry error!\n"));
		return -1;
	}
/*
	nBytesSent += websWrite(wp, T("<tr>"
	"<td align=center width=\"25%%\" bgcolor=\"#808080\">Select</td>\n"
      	"<td align=center width=\"40%%\" bgcolor=\"#808080\">Local IP Address</td>\n"
      	"<td align=center width=\"35%%\" bgcolor=\"#808080\">Protocol</td></tr>\n"
      	//"<td align=center width=\"25%%\" bgcolor=\"#808080\">Comment</td>\n"
      	));
*/
	for (i=1; i<=entryNum; i++) {
		*((char *)&entry) = (char)i;
		if ( !apmib_get(MIB_IPFILTER_TBL, (void *)&entry))
			return -1;

		ip = inet_ntoa(*((struct in_addr *)entry.ipAddr));
		if ( !strcmp(ip, "0.0.0.0"))
			ip = "----";

		if ( entry.protoType == PROTO_BOTH )
			type = "TCP+UDP";
		else if ( entry.protoType == PROTO_TCP )
			type = "TCP";
		else
			type = "UDP";

		nBytesSent += websWrite(wp, T("<tr>"
			"<td align=center width=\"25%%\" bgcolor=\"#C0C0C0\"><input type=\"checkbox\" name=\"select%d\" value=\"ON\"></td>\n"
			"<td align=center width=\"40%%\" bgcolor=\"#C0C0C0\">%s</td>\n"
      			"<td align=center width=\"35%%\" bgcolor=\"#C0C0C0\">%s</td></tr>\n"
      			//"<td align=center width=\"25%%\" bgcolor=\"#C0C0C0\">%s</td>\n"
      			),
				i, ip, type);
				//ip, type, entry.comment, i);
	}
	return nBytesSent;
}


/////////////////////////////////////////////////////////////////////////////
int macFilterList(int eid, webs_t wp, int argc, char_t **argv)
{
	int nBytesSent=0, entryNum, i;
	MACFILTER_T entry;
	char tmpBuf[100];

	if ( !apmib_get(MIB_MACFILTER_TBL_NUM, (void *)&entryNum)) {
  		websError(wp, 400, T("Get table entry error!\n"));
		return -1;
	}
/*
	nBytesSent += websWrite(wp, T("<tr>"
	"<td align=center width=\"30%%\" bgcolor=\"#808080\">Select</td>\n"
      	"<td align=center width=\"70%%\" bgcolor=\"#808080\">MAC Address</td></tr>\n"
      	//"<td align=center width=\"30%%\" bgcolor=\"#808080\">Comment</td>\n"
      	//"<td align=center width=\"20%%\" bgcolor=\"#808080\">Select</td></tr>\n"
	));
*/
	for (i=1; i<=entryNum; i++) {
		*((char *)&entry) = (char)i;
		if ( !apmib_get(MIB_MACFILTER_TBL, (void *)&entry))
			return -1;

		snprintf(tmpBuf, 100, T("%02x:%02x:%02x:%02x:%02x:%02x"),
			entry.macAddr[0], entry.macAddr[1], entry.macAddr[2],
			entry.macAddr[3], entry.macAddr[4], entry.macAddr[5]);

		nBytesSent += websWrite(wp, T("<tr>"
			"<td align=center width=\"30%%\" bgcolor=\"#C0C0C0\"><input type=\"checkbox\" name=\"select%d\" value=\"ON\"></td>\n"
			"<td align=center width=\"70%%\" bgcolor=\"#C0C0C0\">%s</td></tr>\n"
      			//"<td align=center width=\"30%%\" bgcolor=\"#C0C0C0\">%s</td>\n"
       			//"<td align=center width=\"20%%\" bgcolor=\"#C0C0C0\"><input type=\"checkbox\" name=\"select%d\" value=\"ON\"></td></tr>\n"
			),
			 i,tmpBuf); //Added by Mars
				//tmpBuf, entry.comment, i); //Comment by Mars
	}
	return nBytesSent;
}

/////////////////////////////////////////////////////////////////////////////
int urlFilterList(int eid, webs_t wp, int argc, char_t **argv)
{
	int nBytesSent=0, entryNum, i;
	URLFILTER_T entry;

	if ( !apmib_get(MIB_URLFILTER_TBL_NUM, (void *)&entryNum)) {
  		websError(wp, 400, T("Get table entry error!\n"));
		return -1;
	}
/*
	nBytesSent += websWrite(wp, T("<tr>"
	"<td align=center width=\"30%%\" bgcolor=\"#808080\">Select</td>\n"
      	"<td align=center width=\"70%%\" bgcolor=\"#808080\">URL Address</td></tr>\n"
      	));
*/
	for (i=1; i<=entryNum; i++) {
		*((char *)&entry) = (char)i;
		if ( !apmib_get(MIB_URLFILTER_TBL, (void *)&entry))
			return -1;

		nBytesSent += websWrite(wp, T("<tr>"
			"<td align=center width=\"30%%\" bgcolor=\"#C0C0C0\"><input type=\"checkbox\" name=\"select%d\" value=\"ON\"></td>\n"
			"<td align=center width=\"70%%\" bgcolor=\"#C0C0C0\">%s</td></tr>\n"
      			//"<td align=center width=\"30%%\" bgcolor=\"#C0C0C0\">%s</td>\n"
       			),
			i, entry.urlAddr); //tmpBuf
			//entry.urlAddr, entry.comment, i); //tmpBuf
	}
	return nBytesSent;

}

#if 0
/////////////////////////////////////////////////////////////////////////////
int triggerPortList(int eid, webs_t wp, int argc, char_t **argv)
{

	int	nBytesSent=0, entryNum, i;
	TRIGGERPORT_T entry;
	char	*triType, triPortRange[20], *incType, incPortRange[20];

	if ( !apmib_get(MIB_TRIGGERPORT_TBL_NUM, (void *)&entryNum)) {
  		websError(wp, 400, T("Get table entry error!\n"));
		return -1;
	}

	nBytesSent += websWrite(wp, T("<tr>"
      	"<td align=center width=\"20%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Trigger-port Range</b></font></td>\n"
      	"<td align=center width=\"20%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Trigger-port Protocol</b></font></td>\n"
     	"<td align=center width=\"20%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Incoming-port Range</b></font></td>\n"
      	"<td align=center width=\"20%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Incoming-port Protocol</b></font></td>\n"
	"<td align=center width=\"14%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Comment</b></font></td>\n"
      	"<td align=center width=\"6%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Select</b></font></td></tr>\n"));


#if 0
	nBytesSent += websWrite(wp, T("<tr>"
	"<td align=center width=\"25%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Trigger-port Range</b></font></td>\n"
      	"<td align=center width=\"15%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Trigger-port Protocol</b></font></td>\n")
	"<td align=center width=\"25%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Incoming-port Range</b></font></td>\n"
      	"<td align=center width=\"15%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Incoming-port Protocol</b></font></td>\n"	
	"<td align=center width=\"14%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Comment</b></font></td>\n"
      	"<td align=center width=\"6%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Select</b></font></td></tr>\n"));

#endif
	for (i=1; i<=entryNum; i++) {
		*((char *)&entry) = (char)i;
		if ( !apmib_get(MIB_TRIGGERPORT_TBL, (void *)&entry))
			return -1;

		if ( entry.tri_protoType == PROTO_BOTH )
			triType = "TCP+UDP";
		else if ( entry.tri_protoType == PROTO_TCP )
			triType = "TCP";
		else
			triType = "UDP";

		if ( entry.tri_fromPort == 0)
			strcpy(triPortRange, "----");
		else if ( entry.tri_fromPort == entry.tri_toPort )
			snprintf(triPortRange, 20, "%d", entry.tri_fromPort);
		else
			snprintf(triPortRange, 20, "%d-%d", entry.tri_fromPort, entry.tri_toPort);

		if ( entry.inc_protoType == PROTO_BOTH )
			incType = "TCP+UDP";
		else if ( entry.inc_protoType == PROTO_TCP )
			incType = "TCP";
		else
			incType = "UDP";

		if ( entry.inc_fromPort == 0)
			strcpy(incPortRange, "----");
		else if ( entry.inc_fromPort == entry.inc_toPort )
			snprintf(incPortRange, 20, "%d", entry.inc_fromPort);
		else
			snprintf(incPortRange, 20, "%d-%d", entry.inc_fromPort, entry.inc_toPort);


		nBytesSent += websWrite(wp, T("<tr>"
			"<td align=center width=\"20%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
   			"<td align=center width=\"20%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
			"<td align=center width=\"20%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
   			"<td align=center width=\"20%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
     			"<td align=center width=\"20%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
      			"<td align=center width=\"6%%\" bgcolor=\"#C0C0C0\"><input type=\"checkbox\" name=\"select%d\" value=\"ON\"></td></tr>\n"),
				triPortRange, triType, incPortRange, incType, entry.comment, i);
	}
	return nBytesSent;
}
#endif

#ifdef GW_QOS_ENGINE
/////////////////////////////////////////////////////////////////////////////
int qosList(int eid, webs_t wp, int argc, char_t **argv)
{
	int	entryNum;
	QOS_T entry;
	char buffer[120];
	char tmpBuf[80];
	int index;
    
	if ( !apmib_get(MIB_QOS_RULE_TBL_NUM, (void *)&entryNum)) {
		goto ret_empty;
	}
	index= atoi(argv[0]); // index shoud be 0 ~ 9
	index += 1;
	
	if( index <= entryNum)
	{
		*((char *)&entry) = (char)index;
		if ( !apmib_get(MIB_QOS_RULE_TBL, (void *)&entry))
		{
			goto ret_empty;
		}

              strcpy(tmpBuf, inet_ntoa(*((struct in_addr*)entry.local_ip_start)));
              strcpy(&tmpBuf[20], inet_ntoa(*((struct in_addr*)entry.local_ip_end)));
              strcpy(&tmpBuf[40], inet_ntoa(*((struct in_addr*)entry.remote_ip_start)));
              strcpy(&tmpBuf[60], inet_ntoa(*((struct in_addr*)entry.remote_ip_end)));
		 sprintf(buffer, "%d-%d-%d-%s-%s-%d-%d-%s-%s-%d-%d-%s", entry.enabled, entry.priority, entry.protocol,
                        tmpBuf, &tmpBuf[20],entry.local_port_start, entry.local_port_end,
                        &tmpBuf[40], &tmpBuf[60], entry.remote_port_start, entry.remote_port_end, entry.entry_name );        

		websWrite(wp, T("%s"), buffer);
	      return 0;
	}
    
ret_empty:	
	websWrite(wp, T("%s"), "");
	return 0;
}

/////////////////////////////////////////////////////////////////////////////
#define _PROTOCOL_TCP   6
#define _PROTOCOL_UDP   17
#define _PROTOCOL_BOTH   257
#define _PORT_MIN       0
#define _PORT_MAX       65535

static QOS_T entry_for_save[MAX_QOS_RULE_NUM];

void formQoS(webs_t wp, char_t *path, char_t *query)
{
#ifndef NO_ACTION
    int pid;
#endif

    char_t *submitUrl;
    char tmpBuf[100];

    char *strIp, *endIp, *tmpStr, *strEnabled;
    char varName[48];
    int index=1, protocol_others;
    int intVal, valid_num;
    QOS_T entry;
    struct in_addr curIpAddr, curSubnet;
    unsigned long v1, v2, v3, v4;   

    strEnabled = websGetVar(wp, T("config.qos_enabled"), T(""));
    if( !strcmp(strEnabled, "true"))
    {   
        intVal=1;
    }
    else
        intVal=0;
    if ( apmib_set( MIB_QOS_ENABLED, (void *)&intVal) == 0) {
        strcpy(tmpBuf, T("Set QoS enabled flag error!"));
        goto setErr_qos;
    }
    if (intVal==0)
         goto setOk_qos;
    strEnabled = websGetVar(wp, T("config.qos_auto_trans_rate"), T(""));
    if( !strcmp(strEnabled, "true"))
        intVal=1;
    else
        intVal=0;
    if ( apmib_set( MIB_QOS_AUTO_UPLINK_SPEED, (void *)&intVal) == 0) {
        strcpy(tmpBuf, T("Set QoS error!"));
        goto setErr_qos;
    }

    if( intVal == 0)
    {   
        tmpStr = websGetVar(wp, T("config.qos_max_trans_rate"), T(""));
          string_to_dec(tmpStr, &intVal);
        if ( apmib_set(MIB_QOS_MANUAL_UPLINK_SPEED, (void *)&intVal) == 0) {
            strcpy(tmpBuf, T("Set QoS error!"));
            goto setErr_qos;
        }
    }


/*    if ( !apmib_set(MIB_QOS_DELALL, (void *)&entry)) {
        strcpy(tmpBuf, T("Delete all table error!"));
        goto setErr_qos;
    } */
    
    for(index=0, valid_num=0; index<MAX_QOS_RULE_NUM; index++)
    {
        sprintf(varName, "config.qos_rules[%d].enabled", index);
        tmpStr = websGetVar(wp, varName, T(""));
        if( !strcmp(tmpStr, "true"))
            intVal=1;
        else
            intVal=0;
        entry.enabled = (unsigned char)intVal;
          
        sprintf(varName, "config.qos_rules[%d].entry_name", index);
        tmpStr = websGetVar(wp, varName, T(""));
        strcpy(entry.entry_name, tmpStr);

        if (intVal == 0 && tmpStr[0] == 0)
             continue;
           
        sprintf(varName, "config.qos_rules[%d].priority", index);
        tmpStr = websGetVar(wp, varName, T(""));
        string_to_dec(tmpStr, &intVal);
        entry.priority = (unsigned char)intVal;
        
        sprintf(varName, "config.qos_rules[%d].protocol_menu", index);
        tmpStr = websGetVar(wp, varName, T(""));
        if (!strcmp(tmpStr, "-1"))
            protocol_others = 1;
        else
            protocol_others = 0;
    
        sprintf(varName, "config.qos_rules[%d].protocol", index);
        tmpStr = websGetVar(wp, varName, T(""));
        string_to_dec(tmpStr, &intVal);
        entry.protocol = (unsigned short)intVal;
        
        sprintf(varName, "config.qos_rules[%d].local_ip_start", index);
        strIp = websGetVar(wp, varName, T(""));
        inet_aton(strIp, (struct in_addr *)&entry.local_ip_start);
        sprintf(varName, "config.qos_rules[%d].local_ip_end", index);
        endIp = websGetVar(wp, varName, T(""));
        inet_aton(endIp, (struct in_addr *)&entry.local_ip_end);
        getInAddr(BRIDGE_IF, IP_ADDR, (void *)&curIpAddr);
        getInAddr(BRIDGE_IF, SUBNET_MASK, (void *)&curSubnet);

        v1 = *((unsigned long *)entry.local_ip_start);
        v2 = *((unsigned long *)&curIpAddr);
        v3 = *((unsigned long *)&curSubnet);
        if ( (v1 & v3) != (v2 & v3) ) {
            sprintf(tmpBuf, "\'%s\': Local IP start \'%s\' is not in the LAN subnet", 
                        entry.entry_name, strIp);
            goto setErr_qos;
        }
        v4 = *((unsigned long *)entry.local_ip_end);
        if ( (v4 & v3) != (v2 & v3) ) {
            sprintf(tmpBuf, "\'%s\': Local IP end \'%s\' is not in the LAN subnet", 
                        entry.entry_name, endIp);
            goto setErr_qos;
        }
        if ( v1 > v4 ) {
            sprintf(tmpBuf, "\'%s\': Local IP start, \'%s\', must be less than or equal to local IP end, \'%s\'", 
                        entry.entry_name, strIp, endIp);
            goto setErr_qos;
        }

        
        sprintf(varName, "config.qos_rules[%d].remote_ip_start", index);
        strIp = websGetVar(wp, varName, T(""));
        inet_aton(strIp, (struct in_addr *)&entry.remote_ip_start);
        sprintf(varName, "config.qos_rules[%d].remote_ip_end", index);
        endIp = websGetVar(wp, varName, T(""));
        inet_aton(endIp, (struct in_addr *)&entry.remote_ip_end);
        v1 = *((unsigned long *)entry.remote_ip_start);
        v4 = *((unsigned long *)entry.remote_ip_end);
        if ( (v1 & v3) == (v2 & v3) ) {
            sprintf(tmpBuf, "\'%s\': Remote IP start \'%s\' is in the LAN subnet", 
                        entry.entry_name, strIp);
            goto setErr_qos;
        }
        if ( (v4 & v3) == (v2 & v3) ) {
            sprintf(tmpBuf, "\'%s\': Remote IP end \'%s\' is in the LAN subnet", 
                        entry.entry_name, endIp);
            goto setErr_qos;
        }
        if ( v1 > v4 ) {
            sprintf(tmpBuf, "\'%s\': Remote IP start, \'%s\', must be less than or equal to remote IP end, \'%s\'", 
                        entry.entry_name, strIp, endIp);
            goto setErr_qos;
        }

/*        if ((!protocol_others) &&
            ( entry.protocol  == _PROTOCOL_TCP || entry.protocol  == _PROTOCOL_UDP ||entry.protocol  == _PROTOCOL_BOTH)) */
        {
            sprintf(varName, "config.qos_rules[%d].local_port_start", index);
            tmpStr = websGetVar(wp, varName, T(""));
            string_to_dec(tmpStr, &intVal);
            entry.local_port_start = (unsigned short)intVal;
            sprintf(varName, "config.qos_rules[%d].local_port_end", index);
            tmpStr = websGetVar(wp, varName, T(""));
            string_to_dec(tmpStr, &intVal);
            entry.local_port_end = (unsigned short)intVal;

            sprintf(varName, "config.qos_rules[%d].remote_port_start", index);
            tmpStr = websGetVar(wp, varName, T(""));
            string_to_dec(tmpStr, &intVal);
            entry.remote_port_start = (unsigned short)intVal;
            sprintf(varName, "config.qos_rules[%d].remote_port_end", index);
            tmpStr = websGetVar(wp, varName, T(""));
            string_to_dec(tmpStr, &intVal);
            entry.remote_port_end = (unsigned short)intVal;
        
        }

/*        *((char *)&entry_existed) = (char)index;
        if ( !apmib_get(MIB_QOS_RULE_TBL, (void *)&entry_existed)) {
		strcpy(tmpBuf, T("Get table entry error!"));
		goto setErr_qos;
        }
        if ( !apmib_set(MIB_QOS_DEL, (void *)&entry_existed)) {
		strcpy(tmpBuf, T("Delete table entry error!"));
		goto setErr_qos;
        } */

/*        if ( apmib_set(MIB_QOS_ADD, (void *)&entry) == 0) {
            strcpy(tmpBuf, T("Add table entry error!"));
            goto setErr_qos;
        } */
        memcpy(&entry_for_save[valid_num], &entry, sizeof(QOS_T));
        valid_num++;
            
    }


    if ( !apmib_set(MIB_QOS_DELALL, (void *)&entry)) {
        strcpy(tmpBuf, T("Delete all table error!"));
        goto setErr_qos;
    }
    
    for(index=0; index<valid_num; index++)
    {
        if ( apmib_set(MIB_QOS_ADD, (void *)&entry_for_save[index]) == 0) {
            strcpy(tmpBuf, T("Add table entry error!"));
            goto setErr_qos;
        }
    }
    
setOk_qos:
    apmib_update_web(CURRENT_SETTING);

#ifndef NO_ACTION
    pid = fork();
    if (pid) {
        waitpid(pid, NULL, 0);
    }
    else if (pid == 0) {
        snprintf(tmpBuf, 100, "%s/%s", _CONFIG_SCRIPT_PATH, _QOS_SCRIPT_PROG);
        execl( tmpBuf, _QOS_SCRIPT_PROG, NULL);
        exit(1);
    }
#endif

    submitUrl = websGetVar(wp, T("submit-url"), T(""));   // hidden page
    if (submitUrl[0])
        websRedirect(wp, submitUrl);
    else
        websDone(wp, 200);
    return;

setErr_qos:
    ERR_MSG(tmpBuf);
}
#endif

#ifdef QOS_BY_BANDWIDTH
static const char _md1[] = "Guaranteed minimum bandwidth", _md2[] = "Restricted maximum bandwidth";
static const char s4dashes[] = "----";

/////////////////////////////////////////////////////////////////////////////
int ipQosList(int eid, webs_t wp, int argc, char_t **argv)
{
	int	nBytesSent=0, entryNum, i;
	IPQOS_T entry;
	char	*mode, bandwidth[10], bandwidth_downlink[10];
	char	mac[20], ip[40], *tmpStr;

	if ( !apmib_get(MIB_QOS_RULE_TBL_NUM, (void *)&entryNum)) {
  		websError(wp, 400, T("Get table entry error!\n"));
		return -1;
	}
/*
	nBytesSent += websWrite(wp, T("<tr>"
	"<td align=center width=\"15%%\" bgcolor=\"#808080\">Select</td>\n"
      	"<td align=center width=\"30%%\" bgcolor=\"#808080\">Local IP Address</td>\n"
      	"<td align=center width=\"25%%\" bgcolor=\"#808080\">MAC Address</td>\n"
      	"<td align=center width=\"25%%\" bgcolor=\"#808080\">Mode</td>\n"
      	"<td align=center width=\"25%%\" bgcolor=\"#808080\">Uplink Bandwidth</td>\n"
      	"<td align=center width=\"25%%\" bgcolor=\"#808080\">Downlink Bandwidth</td></tr>\n"
	//"<td align=center width=\"20%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Comment</b></font></td>\n"
      	));
*/
	for (i=1; i<=entryNum; i++) {
		*((char *)&entry) = (char)i;
		if ( !apmib_get(MIB_QOS_RULE_TBL, (void *)&entry))
			return -1;

		if ( (entry.mode & QOS_RESTRICT_IP)  != 0) {
			tmpStr = inet_ntoa(*((struct in_addr *)entry.local_ip_start));
			strcpy(mac, tmpStr);
			tmpStr = inet_ntoa(*((struct in_addr *)entry.local_ip_end));
			sprintf(ip, "%s - %s", mac, tmpStr);
			
			strcpy(mac, s4dashes);
		}
		else {
			sprintf(mac, "%02x%02x%02x%02x%02x%02x", 
				entry.mac[0],entry.mac[1],entry.mac[2],entry.mac[3],entry.mac[4],entry.mac[5]);
			strcpy(ip, s4dashes);
		}
		
		if ( (entry.mode & QOS_RESTRICT_MIN)  != 0)
			mode = (char *)_md1;
		else
			mode = (char *)_md2;
    
    if(entry.bandwidth == 0)
    	sprintf(bandwidth, "%s", "-");
		else
			snprintf(bandwidth, 10, "%ld", entry.bandwidth);
			
		if(entry.bandwidth_downlink == 0)
    	sprintf(bandwidth_downlink, "%s", "-");
		else
			snprintf(bandwidth_downlink, 10, "%ld", entry.bandwidth_downlink);

		nBytesSent += websWrite(wp, T("<tr>"
			"<td align=center width=\"15%%\" bgcolor=\"#C0C0C0\"><input type=\"checkbox\" name=\"select%d\" value=\"ON\"></td>\n"
			"<td align=center width=\"30%%\" bgcolor=\"#C0C0C0\">%s</td>\n"
      			"<td align=center width=\"25%%\" bgcolor=\"#C0C0C0\">%s</td>\n"
      			"<td align=center width=\"25%%\" bgcolor=\"#C0C0C0\">%s</td>\n"
      			"<td align=center width=\"25%%\" bgcolor=\"#C0C0C0\">%s</td>\n"
      			"<td align=center width=\"25%%\" bgcolor=\"#C0C0C0\">%s</td></tr>\n"
     			//"<td align=center width=\"20%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
      			),
				//ip, mac, mode, bandwidth, bandwidth_downlink, entry.entry_name, i);
				//ip, mac, mode, bandwidth, bandwidth_downlink, i);	//Modified by Jerry
				i, ip, mac, mode, bandwidth, bandwidth_downlink);
	}
	return nBytesSent;
}

/////////////////////////////////////////////////////////////////////////////
void formIpQoS(webs_t wp, char_t *path, char_t *query)
{
	char_t *submitUrl, *strAdd, *strDel, *strVal, *strDelAll;
	char_t *strIpStart, *strIpEnd, *strMac, *strBandwidth, *strBandwidth_downlink, *strComment;
	char tmpBuf[100];
	int entryNum, intVal, i;
	IPQOS_T entry;
#ifndef NO_ACTION
	int pid;
#endif

//displayPostDate(wp->postData);

	strAdd = websGetVar(wp, T("addQos"), T(""));
	strDel = websGetVar(wp, T("deleteSel"), T(""));
	strDelAll = websGetVar(wp, T("deleteAll"), T(""));

	memset(&entry, '\0', sizeof(entry));

	if (strAdd[0]) {
		strVal = websGetVar(wp, T("enabled"), T(""));
		if ( !gstrcmp(strVal, T("ON")))
			intVal = 1;
		else
			intVal = 0;
		if ( apmib_set( MIB_QOS_ENABLED, (void *)&intVal) == 0) {
			strcpy(tmpBuf, T("Set enabled flag error!"));
			goto setErr;
		}

		if (intVal == 0)
			goto setOk;
		
		strVal = websGetVar(wp, T("automaticUplinkSpeed"), T(""));
		if ( !gstrcmp(strVal, T("ON")))
			intVal = 1;
		else
			intVal = 0;
		if ( apmib_set( MIB_QOS_AUTO_UPLINK_SPEED, (void *)&intVal) == 0) {
			strcpy(tmpBuf, T("Set mib error!"));
			goto setErr;
		}

		if (intVal == 0) {
			strVal = websGetVar(wp, T("manualUplinkSpeed"), T(""));
			string_to_dec(strVal, &intVal);
			if ( apmib_set( MIB_QOS_MANUAL_UPLINK_SPEED, (void *)&intVal) == 0) {
				strcpy(tmpBuf, T("Set mib error!"));
				goto setErr;
			}
		}
		
		strVal = websGetVar(wp, T("automaticDownlinkSpeed"), T(""));
		if ( !gstrcmp(strVal, T("ON")))
			intVal = 1;
		else
			intVal = 0;
			
		if ( apmib_set( MIB_QOS_AUTO_DOWNLINK_SPEED, (void *)&intVal) == 0) {
			strcpy(tmpBuf, T("Set mib error!"));
			goto setErr;
		}

		if (intVal == 0) {
			strVal = websGetVar(wp, T("manualDownlinkSpeed"), T(""));
			string_to_dec(strVal, &intVal);
			if ( apmib_set( MIB_QOS_MANUAL_DOWNLINK_SPEED, (void *)&intVal) == 0) {
				strcpy(tmpBuf, T("Set mib error!"));
				goto setErr;
			}
		}

		strIpStart = websGetVar(wp, T("ipStart"), T(""));
		strIpEnd = websGetVar(wp, T("ipEnd"), T(""));
		strMac = websGetVar(wp, T("mac"), T(""));
		strBandwidth = websGetVar(wp, T("bandwidth"), T(""));
		strBandwidth_downlink = websGetVar(wp, T("bandwidth_downlink"), T(""));
		strComment = websGetVar(wp, T("comment"), T(""));
		
		if (!strIpStart[0] && !strIpEnd[0] && !strMac[0] && !strBandwidth[0] && !strBandwidth_downlink[0] && !strComment[0])
			goto setOk;

		strVal = websGetVar(wp, T("addressType"), T(""));
		string_to_dec(strVal, &intVal);
		if (intVal == 0) { // IP
			inet_aton(strIpStart, (struct in_addr *)&entry.local_ip_start);
			inet_aton(strIpEnd, (struct in_addr *)&entry.local_ip_end);
			entry.mode |= QOS_RESTRICT_IP;
		}
		else { //MAC
			if (!string_to_hex(strMac, entry.mac, 12)) 
				goto setErr;
			entry.mode |= QOS_RESTRICT_MAC;
		}

		strVal = websGetVar(wp, T("mode"), T(""));
		if (strVal[0] == '1')
			entry.mode |= QOS_RESTRICT_MIN;
		else
			entry.mode |= QOS_RESTRICT_MAX;
			
		string_to_dec(strBandwidth, &intVal);
		entry.bandwidth = (unsigned long)intVal;
		
		string_to_dec(strBandwidth_downlink, &intVal);
		entry.bandwidth_downlink = (unsigned long)intVal;

		if ( strComment[0] ) {
			strcpy(entry.entry_name, strComment);
		}
		entry.enabled = 1;
		if ( !apmib_get(MIB_QOS_RULE_TBL_NUM, (void *)&entryNum)) {
			strcpy(tmpBuf, T("Get entry number error!"));
			goto setErr;
		}

		if ( (entryNum + 1) > MAX_QOS_RULE_NUM) {
			strcpy(tmpBuf, T("Cannot add new entry because table is full!"));
			goto setErr;
		}

		// set to MIB. try to delete it first to avoid duplicate case
		apmib_set(MIB_QOS_DEL, (void *)&entry);
		if ( apmib_set(MIB_QOS_ADD, (void *)&entry) == 0) {
			strcpy(tmpBuf, T("Add table entry error!"));
			goto setErr;
		}
	}

	/* Delete entry */
	if (strDel[0]) {
		if ( !apmib_get(MIB_QOS_RULE_TBL_NUM, (void *)&entryNum)) {
			strcpy(tmpBuf, T("Get entry number error!"));
			goto setErr;
		}

		for (i=entryNum; i>0; i--) {
			snprintf(tmpBuf, 20, "select%d", i);

			strVal = websGetVar(wp, tmpBuf, T(""));
			if ( !gstrcmp(strVal, T("ON")) ) {
				*((char *)&entry) = (char)i;
				if ( !apmib_get(MIB_QOS_RULE_TBL, (void *)&entry)) {
					strcpy(tmpBuf, T("Get table entry error!"));
					goto setErr;
				}
				if ( !apmib_set(MIB_QOS_DEL, (void *)&entry)) {
					strcpy(tmpBuf, T("Delete table entry error!"));
					goto setErr;
				}
			}
		}
	}

	/* Delete all entry */
	if ( strDelAll[0]) {
		if ( !apmib_set(MIB_QOS_DELALL, (void *)&entry)) {
			strcpy(tmpBuf, T("Delete all table error!"));
			goto setErr;
		}
	}

setOk:
	apmib_update(CURRENT_SETTING);

#if 0
#ifndef NO_ACTION
	pid = fork();
        if (pid) {
	      	waitpid(pid, NULL, 0);
	}
        else if (pid == 0) {
		snprintf(tmpBuf, 100, "%s/%s", _CONFIG_SCRIPT_PATH, _QOS_SCRIPT_PROG);
		execl( tmpBuf, _QOS_SCRIPT_PROG, NULL);
             exit(1);
        }
#endif

	submitUrl = websGetVar(wp, T("submit-url"), T(""));   // hidden page

#ifdef REBOOT_CHECK
	if(needReboot == 1)
	{
		OK_MSG(submitUrl);
		return;
	}
#endif
	
	if (submitUrl[0])
		websRedirect(wp, submitUrl);
	else
		websDone(wp, 200);
  	return;

setErr:
	ERR_MSG(tmpBuf);
#endif

setErr:
	return;


}
#endif
#endif // HOME_GATEWAY

