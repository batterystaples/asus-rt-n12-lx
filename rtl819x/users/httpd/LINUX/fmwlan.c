/*
 *      Web server handler routines for wlan stuffs
 *
 *      Authors: David Hsu	<davidhsu@realtek.com.tw>
 *
 *      $Id: fmwlan.c,v 1.14 2011/05/24 11:29:05 jerry_jian Exp $
 *
 */

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#ifdef WIFI_SIMPLE_CONFIG
#include <sys/time.h>
#endif

#include <stdio.h>	//Added by Jerry
#include <errno.h>	//Added by Jerry
#include <sys/socket.h>	//Added by Jerry
#include <netinet/in.h>	//Added by Jerry
#include <sys/stat.h>	//Added by Jerry

//#include "../webs.h"	//Comment by Jerry
#include "../httpd.h"	//Added by Jerry
#include "apmib.h"
#include "apform.h"
#include "utility.h"

#ifdef WLAN_EASY_CONFIG
#include "../md5.h"
#endif

// added by rock /////////////////////////////////////////
#ifdef VOIP_SUPPORT 
#include "web_voip.h"
#endif

#if defined(CONFIG_DOMAIN_NAME_QUERY_SUPPORT)
extern void Stop_Domain_Query_Process(void);
extern void Reset_Domain_Query_Setting(void);
extern int Start_Domain_Query_Process;
#endif

#ifdef WLAN_EASY_CONFIG
#define DO_CONFIG_WAIT_TIME	60
#define CONFIG_SUCCESS		0
#define AUTOCONF_PID_FILENAME	("/var/run/autoconf.pid")

static int wait_config = CONFIG_SUCCESS;
#endif

static SS_STATUS_Tp pStatus=NULL;

#ifdef CONFIG_RTK_MESH
#ifndef __mips__
        #define _FILE_MESH_ASSOC "mesh_assoc_mpinfo"
        #define _FILE_MESH_ROUTE "mesh_pathsel_routetable"
		#define _FILE_MESH_ROOT  "mesh_root_info"
		#define _FILE_MESH_PROXY "mesh_proxy_table"
		#define _FILE_MESH_PORTAL "mesh_portal_table"		
		#define _FILE_MESHSTATS  "mesh_stats"
#else
        #define _FILE_MESH_ASSOC "/proc/wlan0/mesh_assoc_mpinfo"
        #define _FILE_MESH_ROUTE "/proc/wlan0/mesh_pathsel_routetable"
		#define _FILE_MESH_ROOT  "/proc/wlan0/mesh_root_info"
		#define _FILE_MESH_PROXY "/proc/wlan0/mesh_proxy_table"	
		#define _FILE_MESH_PORTAL "/proc/wlan0/mesh_portal_table"
		#define _FILE_MESHSTATS  "/proc/wlan0/mesh_stats"
#endif
#endif // CONFIG_RTK_MESH

#ifdef WIFI_SIMPLE_CONFIG
//enum {	CALLED_FROM_WLANHANDLER=1, CALLED_FROM_WEPHANDLER=2, CALLED_FROM_WPAHANDLER=3, CALLED_FROM_ADVANCEHANDLER=4};
enum {	CALLED_FROM_WLANHANDLER=1, CALLED_FROM_WEPHANDLER=2, CALLED_FROM_WPAHANDLER=3, CALLED_FROM_ADVANCEHANDLER=4, CALLED_FROM_HTTPD=5};	//2011.05.05 Jerry
struct wps_config_info_struct {
	int caller_id;
	int wlan_mode;
	int auth;
	int shared_type;
	int wep_enc;
	int wpa_enc;
	int wpa2_enc;
	unsigned char ssid[MAX_SSID_LEN];
	int KeyId;
	unsigned char wep64Key1[WEP64_KEY_LEN];
	unsigned char wep64Key2[WEP64_KEY_LEN];
	unsigned char wep64Key3[WEP64_KEY_LEN];
	unsigned char wep64Key4[WEP64_KEY_LEN];
	unsigned char wep128Key1[WEP128_KEY_LEN];
	unsigned char wep128Key2[WEP128_KEY_LEN];
	unsigned char wep128Key3[WEP128_KEY_LEN];
	unsigned char wep128Key4[WEP128_KEY_LEN];
	unsigned char wpaPSK[MAX_PSK_LEN+1];
};
static struct wps_config_info_struct wps_config_info;
static void update_wps_configured(int reset_flag);
void call_wps_update();	//2011.05.05 Jerry
#endif


//changes in following table should be synced to MCS_DATA_RATEStr[] in 8190n_proc.c
WLAN_RATE_T rate_11n_table_20M_LONG[]={
	{MCS0, 	"6.5"},
	{MCS1, 	"13"},
	{MCS2, 	"19.5"},
	{MCS3, 	"26"},
	{MCS4, 	"39"},
	{MCS5, 	"52"},
	{MCS6, 	"58.5"},
	{MCS7, 	"65"},
	{MCS8, 	"13"},
	{MCS9, 	"26"},
	{MCS10, 	"39"},
	{MCS11, 	"52"},
	{MCS12, 	"78"},
	{MCS13, 	"104"},
	{MCS14, 	"117"},
	{MCS15, 	"130"},
	{0}
};
WLAN_RATE_T rate_11n_table_20M_SHORT[]={
	{MCS0, 	"7.2"},
	{MCS1, 	"14.4"},
	{MCS2, 	"21.7"},
	{MCS3, 	"28.9"},
	{MCS4, 	"43.3"},
	{MCS5, 	"57.8"},
	{MCS6, 	"65"},
	{MCS7, 	"72.2"},
	{MCS8, 	"14.4"},
	{MCS9, 	"28.9"},
	{MCS10, 	"43.3"},
	{MCS11, 	"57.8"},
	{MCS12, 	"86.7"},
	{MCS13, 	"115.6"},
	{MCS14, 	"130"},
	{MCS15, 	"144.5"},
	{0}
};
WLAN_RATE_T rate_11n_table_40M_LONG[]={
	{MCS0, 	"13.5"},
	{MCS1, 	"27"},
	{MCS2, 	"40.5"},
	{MCS3, 	"54"},
	{MCS4, 	"81"},
	{MCS5, 	"108"},
	{MCS6, 	"121.5"},
	{MCS7, 	"135"},
	{MCS8, 	"27"},
	{MCS9, 	"54"},
	{MCS10, 	"81"},
	{MCS11, 	"108"},
	{MCS12, 	"162"},
	{MCS13, 	"216"},
	{MCS14, 	"243"},
	{MCS15, 	"270"},
	{0}
};
WLAN_RATE_T rate_11n_table_40M_SHORT[]={
	{MCS0, 	"15"},
	{MCS1, 	"30"},
	{MCS2, 	"45"},
	{MCS3, 	"60"},
	{MCS4, 	"90"},
	{MCS5, 	"120"},
	{MCS6, 	"135"},
	{MCS7, 	"150"},
	{MCS8, 	"30"},
	{MCS9, 	"60"},
	{MCS10, 	"90"},
	{MCS11, 	"120"},
	{MCS12, 	"180"},
	{MCS13, 	"240"},
	{MCS14, 	"270"},
	{MCS15, 	"300"},
	{0}
};

WLAN_RATE_T tx_fixed_rate[]={
	{1, "1"},
	{(1<<1), 	"2"},
	{(1<<2), 	"5.5"},
	{(1<<3), 	"11"},
	{(1<<4), 	"6"},
	{(1<<5), 	"9"},
	{(1<<6), 	"12"},
	{(1<<7), 	"18"},
	{(1<<8), 	"24"},
	{(1<<9), 	"36"},
	{(1<<10), 	"48"},
	{(1<<11), 	"54"},
	{(1<<12), 	"MCS0"},
	{(1<<13), 	"MCS1"},
	{(1<<14), 	"MCS2"},
	{(1<<15), 	"MCS3"},
	{(1<<16), 	"MCS4"},
	{(1<<17), 	"MCS5"},
	{(1<<18), 	"MCS6"},
	{(1<<19), 	"MCS7"},
	{(1<<20), 	"MCS8"},
	{(1<<21), 	"MCS9"},
	{(1<<22), 	"MCS10"},
	{(1<<23), 	"MCS11"},
	{(1<<24), 	"MCS12"},
	{(1<<25), 	"MCS13"},
	{(1<<26), 	"MCS14"},
	{(1<<27), 	"MCS15"},
	{0}
};

/////////////////////////////////////////////////////////////////////////////
#ifndef NO_ACTION
//Patch: kill some daemons to free some RAM in order to call "init.sh gw al"l more quickly
//which need more tests
void killSomeDaemon(void)
{
	system("killall -9 sleep 2> /dev/null");
       system("killall -9 routed 2> /dev/null");
//	system("killall -9 pppoe 2> /dev/null");
//	system("killall -9 pppd 2> /dev/null");
//	system("killall -9 pptp 2> /dev/null");
	system("killall -9 dnrd 2> /dev/null");
	system("killall -9 ntpclient 2> /dev/null");
//	system("killall -9 miniigd 2> /dev/null");	//comment for miniigd iptables rule recovery
	system("killall -9 lld2d 2> /dev/null");
//	system("killall -9 l2tpd 2> /dev/null");	
//	system("killall -9 udhcpc 2> /dev/null");	
//	system("killall -9 udhcpd 2> /dev/null");	
	system("killall -9 reload 2> /dev/null");		
	system("killall -9 iapp 2> /dev/null");	
	system("killall -9 wscd 2> /dev/null");
	system("killall -9 mini_upnpd 2> /dev/null");
	system("killall -9 iwcontrol 2> /dev/null");
	system("killall -9 auth 2> /dev/null");
	system("killall -9 disc_server 2> /dev/null");
	system("killall -9 igmpproxy 2> /dev/null");
	system("echo 1,0 > /proc/br_mCastFastFwd");
	system("killall -9 syslogd 2> /dev/null");
	system("killall -9 klogd 2> /dev/null");
	
	system("killall -9 ppp_inet 2> /dev/null");
	
#ifdef VOIP_SUPPORT
	system("killall -9 snmpd 2> /dev/null");
	system("killall -9 solar_monitor 2> /dev/null");
	system("killall -9 solar 2> /dev/null");
	system("killall -9 dns_task 2> /dev/null");
	system("killall -9 ivrserver 2> /dev/null");
#endif

#ifdef CONFIG_SNMP
	system("killall -9 snmpd 2> /dev/null");
#endif
}

void run_init_script(char *arg)
{
	int pid=0;
	int i;
	char tmpBuf[100];
	
#ifdef REBOOT_CHECK
	if(run_init_script_flag == 1){
#endif

#ifdef RTK_USB3G
	system("killall -9 mnet 2> /dev/null");
	system("killall -9 hub-ctrl 2> /dev/null");
	system("killall -9 usb_modeswitch 2> /dev/null");
    system("killall -9 ppp_inet 2> /dev/null");
    system("killall -9 pppd 2> /dev/null");
    system("rm /etc/ppp/connectfile >/dev/null 2>&1");
#endif /* #ifdef RTK_USB3G */

#if defined(CONFIG_DOMAIN_NAME_QUERY_SUPPORT)
	Stop_Domain_Query_Process();
	Reset_Domain_Query_Setting();
#endif

	snprintf(tmpBuf, 100, "%s/%s.pid", _DHCPD_PID_PATH, _DHCPD_PROG_NAME);
	pid = getPid(tmpBuf);
	if ( pid > 0)
		kill(pid, SIGUSR1);
		
	usleep(1000);
	
	if ( pid > 0){
		system("killall -9 udhcpd 2> /dev/null");
		system("rm -f /var/run/udhcpd.pid 2> /dev/null");
	}

	//Patch: kill some daemons to free some RAM in order to call "init.sh gw all" more quickly
	//which need more tests especially for 8196c 2m/16m
	killSomeDaemon();
	
	system("killsh.sh");	// kill all running script	

#ifdef REBOOT_CHECK
	run_init_script_flag = 0;
	needReboot = 0;
#endif
// added by rock /////////////////////////////////////////
#ifdef VOIP_SUPPORT
	web_restart_solar();
#endif

	pid = fork();
/*	
       	if (pid)
               	waitpid(pid, NULL, 0);
   	else 
*/ 
	if (pid == 0) {
#ifdef HOME_GATEWAY
		sprintf(tmpBuf, "%s gw %s", _CONFIG_SCRIPT_PROG, arg);
#elif defined(VOIP_SUPPORT) && defined(ATA867x)
		sprintf(tmpBuf, "%s ATA867x %s", _CONFIG_SCRIPT_PROG, arg);
#else
		sprintf(tmpBuf, "%s ap %s", _CONFIG_SCRIPT_PROG, arg);
#endif
		for(i=3; i<sysconf(_SC_OPEN_MAX); i++)
                	close(i);
		sleep(1);
		system(tmpBuf);
		exit(1);
	}
#ifdef REBOOT_CHECK
}
	else
	{
	}
#endif
}

#endif //#ifndef NO_ACTION

/////////////////////////////////////////////////////////////////////////////
static inline int isAllStar(char *data)
{
	int i;
	for (i=0; i<strlen(data); i++) {
		if (data[i] != '*')
			return 0;
	}
	return 1;
}
//////////////////////
#ifndef HOME_GATEWAY
void formSetTime(webs_t wp, char_t *path, char_t *query)
{
	char_t *submitUrl,*strVal;
	char tmpBuf[100];
	int time_value=0;
	int cur_year=0;

	submitUrl = websGetVar(wp, T("submit-url"), T(""));   
	strVal = websGetVar(wp, T("save"), T(""));   

	if(strVal[0]){		
		struct tm tm_time;
		time_t tm;
		memcpy(&tm_time, localtime(&tm), sizeof(tm_time));
		tm_time.tm_sec = 0;
		tm_time.tm_min = 0;
		tm_time.tm_hour = 0;
		tm_time.tm_isdst = -1;  /* Be sure to recheck dst. */
		strVal = websGetVar(wp, T("year"), T(""));	
		cur_year= atoi(strVal);
		tm_time.tm_year = atoi(strVal) - 1900;
		strVal = websGetVar(wp, T("month"), T(""));	
		tm_time.tm_mon = atoi(strVal)-1;
		strVal = websGetVar(wp, T("day"), T(""));	
		tm_time.tm_mday = atoi(strVal);
		strVal = websGetVar(wp, T("hour"), T(""));	
		tm_time.tm_hour = atoi(strVal);
		strVal = websGetVar(wp, T("minute"), T(""));	
		tm_time.tm_min = atoi(strVal);
		strVal = websGetVar(wp, T("second"), T(""));	
		tm_time.tm_sec = atoi(strVal);
		tm = mktime(&tm_time);
		if(tm < 0){
			sprintf(tmpBuf, "set Time Error\n");
			goto setErr_end;
		}
		if(stime(&tm) < 0){
			sprintf(tmpBuf, "set Time Error\n");
			goto setErr_end;
		}
		
		apmib_set( MIB_SYSTIME_YEAR, (void *)&cur_year);
		time_value = tm_time.tm_mon;
		apmib_set( MIB_SYSTIME_MON, (void *)&time_value);
		time_value = tm_time.tm_mday;
		apmib_set( MIB_SYSTIME_DAY, (void *)&time_value);
		time_value = tm_time.tm_hour;
		apmib_set( MIB_SYSTIME_HOUR, (void *)&time_value);
		time_value = tm_time.tm_min;
		apmib_set( MIB_SYSTIME_MIN, (void *)&time_value);
		time_value = tm_time.tm_sec;
		apmib_set( MIB_SYSTIME_SEC, (void *)&time_value);
	}
	
	apmib_update_web(CURRENT_SETTING);
	OK_MSG(submitUrl);
	return;
setErr_end:
	ERR_MSG(tmpBuf);	
}

#endif

#if defined(NEW_SCHEDULE_SUPPORT)
int wlSchList(int eid, webs_t wp, int argc, char_t **argv)
{
	SCHEDULE_T entry;
	char *strToken;
	int cmpResult=0;
	int  index=0;
	
	cmpResult= strncmp(argv[0], "wlSchList_", strlen("wlSchList_"));
	strToken=strstr(argv[0], "_");
	index= atoi(strToken+1);

	index++;
	if(index <= MAX_SCHEDULE_NUM)
	{
		*((char *)&entry) = (char)index;
		if ( !apmib_get(MIB_WLAN_SCHEDULE_TBL, (void *)&entry))
		{
			fprintf(stderr,"Get schedule entry fail\n");
			return -1;
		}												
		
		
		/* eco/day/fTime/tTime/week */
		websWrite(wp, T("%d|%d|%d|%d"), entry.eco, entry.day, entry.fTime, entry.tTime);
	}
	else
	{
		websWrite(wp, T("0|0|0|0") );
	}
	return 0;
}
#endif //#if defined(NEW_SCHEDULE_SUPPORT)

void formSchedule(webs_t wp, char_t *path, char_t *query)
{
	char	tmpBuf[100];
	char *strHours, *strEnabled, *strWeekdays, *strStime, *strEtime;
	SCHEDULE_T entry;
	int entryNum=0;
	char_t *submitUrl;
	int isEnabled=0;
	submitUrl = websGetVar(wp, T("webpage"), T(""));   // hidden page
	
	
	if ( !apmib_set(MIB_WLAN_SCHEDULE_DELALL, (void *)&entry)) {
			strcpy(tmpBuf, T("Delete table entry error!"));
			goto setErr_schedule;
	}
	memset(&entry, '\0', sizeof(entry));
	
	strEnabled = websGetVar(wp, T("enabled_sch"), T(""));
	if(strcmp(strEnabled,"true") == 0) // the entry is enabled
	{
			entry.eco |= ECO_LEDDIM_MASK;
			isEnabled = 1;
	}else{
			entry.eco &= ~ECO_LEDDIM_MASK;
			isEnabled = 0;
	}
	apmib_set(MIB_WLAN_SCHEDULE_ENABLED,(void *)&isEnabled);
	sprintf(entry.text, "%s", "wlanSchedule");	
	
	strWeekdays = websGetVar(wp, T("weekdays"), T(""));
	entry.day = atoi(strWeekdays);

	

	if(strcmp(strWeekdays, "127") ==0)
	{
		entry.eco |= ECO_EVERYDAY_MASK;
	}else
		entry.eco &= ~ECO_EVERYDAY_MASK;
		  
	strHours = websGetVar(wp, T("all_day"), T(""));	

	if(strcmp(strHours,"on") == 0) // the entry is enabled 24 hours
	{
		entry.eco |= ECO_24HOURS_MASK;
		
	}else
		entry.eco &= ~ECO_24HOURS_MASK;

	strStime = websGetVar(wp, T("start_time"), T(""));
	if(strStime[0])
		entry.fTime = atoi(strStime);

	strEtime = websGetVar(wp, T("end_time"), T(""));
	if(strEtime[0])
		entry.tTime = atoi(strEtime);
	
	if(entry.eco & ECO_24HOURS_MASK){
			entry.fTime = 0;
			entry.tTime = 1440;
	}
	
	if ( !apmib_get(MIB_WLAN_SCHEDULE_TBL_NUM, (void *)&entryNum)) 
	{
			strcpy(tmpBuf, T("\"Get entry number error!\""));
			goto setErr_schedule;
	}
	if ( !apmib_set(MIB_WLAN_SCHEDULE_ADD,(void *)&entry)) {
			strcpy(tmpBuf, T("Add table entry error!"));
			goto setErr_schedule;
	}
	
	
	
	
	apmib_update_web(CURRENT_SETTING);
	run_init_script("bridge");
OK_MSG(submitUrl);
	return;

setErr_schedule:
	ERR_MSG(tmpBuf);
	
}

#if defined(NEW_SCHEDULE_SUPPORT)
void formNewSchedule(webs_t wp, char_t *path, char_t *query)
{
	SCHEDULE_T entry;
	char_t *submitUrl,*strTmp;
	int	i, wlsch_onoff;
	char tmpBuf[100];
	
//displayPostDate(wp->postData);
	
	strTmp= websGetVar(wp, T("wlsch_onoff"), T(""));
	if(strTmp[0])
	{
		wlsch_onoff = atoi(strTmp);
	
		if (!apmib_set(MIB_WLAN_SCHEDULE_ENABLED, (void *)&wlsch_onoff)) 
		{
			strcpy(tmpBuf, T("set  MIB_WLAN_SCHEDULE_ENABLED error!"));
			goto setErr_schedule;
		}
	}
	
	if ( !apmib_set(MIB_WLAN_SCHEDULE_DELALL, (void *)&entry)) {
			strcpy(tmpBuf, T("MIB_WLAN_SCHEDULE_DELALL error!"));
			goto setErr_schedule;
	}
	
	for(i=1; i<=MAX_SCHEDULE_NUM ; i++)
	{
		int index;
		memset(&entry, '\0', sizeof(entry));
		
		*((char *)&entry) = (char)i;
		apmib_get(MIB_WLAN_SCHEDULE_TBL, (void *)&entry);			

		index = i-1;
			
		memset(tmpBuf,0x00, sizeof(tmpBuf));			
		sprintf(tmpBuf,"wlsch_enable_%d",index);
		strTmp = websGetVar(wp, T(tmpBuf), T(""));
		if(strTmp[0])
		{
			entry.eco = atoi(strTmp);
		}
		
		memset(tmpBuf,0x00, sizeof(tmpBuf));			
		sprintf(tmpBuf,"wlsch_day_%d",index);
		strTmp = websGetVar(wp, T(tmpBuf), T(""));
		if(strTmp[0])
		{
			entry.day = atoi(strTmp);
		}
		
		memset(tmpBuf,0x00, sizeof(tmpBuf));			
		sprintf(tmpBuf,"wlsch_from_%d",index);
		strTmp = websGetVar(wp, T(tmpBuf), T(""));
		if(strTmp[0])
		{
			entry.fTime = atoi(strTmp);
		}
		
		
		memset(tmpBuf,0x00, sizeof(tmpBuf));			
		sprintf(tmpBuf,"wlsch_to_%d",index);
		strTmp = websGetVar(wp, T(tmpBuf), T(""));
		if(strTmp[0])
		{
			entry.tTime = atoi(strTmp);
		}
		
		if ( apmib_set(MIB_WLAN_SCHEDULE_ADD, (void *)&entry) == 0) 
		{				
			strcpy(tmpBuf, T("MIB_WLAN_SCHEDULE_ADD error!"));				
			goto setErr_schedule;
		}

		
	}

	submitUrl = websGetVar(wp, T("submit-url"), T(""));   // hidden page
	
	apmib_update_web(CURRENT_SETTING);
	run_init_script("all");
	OK_MSG(submitUrl);
	return;

setErr_schedule:
	ERR_MSG(tmpBuf);
	
}
#endif // #if defined(NEW_SCHEDULE_SUPPORT)

int getScheduleInfo(int eid, webs_t wp, int argc, char_t **argv)
{
	int	entryNum=0, i;
	SCHEDULE_T entry;
	int everyday=0, hours24=0;
	int dayWeek=0;
	char tmpBuf[200];
	unsigned char buffer[200];
	int isEnabled=0;
	char *strToken;
	int cmpResult=0;
	int index=0;
	char_t	*name_arg;
	if (ejArgs(argc, argv, T("%s"), &name_arg) < 1) {
   		websError(wp, 400, T("Insufficient args\n"));
   		return -1;
   	}

	if ( !strcmp(name_arg, T("wlan_state")) ) {
		bss_info bss;
		getWlBssInfo(WLAN_IF, &bss);
		if (bss.state == STATE_DISABLED) 
			strcpy(buffer, "Disabled");
		else
			strcpy(buffer, "Enabled");	
		websWrite(wp, T("%s"), buffer);
		return 0;
	}else if(!strcmp(name_arg, T("system_time"))){
		#ifdef HOME_GATEWAY
					return 0;
		#else
		
		return websWrite(wp,T("%s"),"menu.addItem(\"System Time\", \"time.asp\", \"\", \"Setup System Time\");");
		#endif
	} 		
	cmpResult= strncmp(name_arg, "getentry_", 9);
	strToken=strstr(name_arg, "_");
	
	index= atoi(strToken+1);
	
	if ( !apmib_get(MIB_WLAN_SCHEDULE_TBL_NUM, (void *)&entryNum)) {
  		strcpy(tmpBuf, "Get table entry error!");
		return -1;
	}
	apmib_get(MIB_WLAN_SCHEDULE_ENABLED,(void *)&isEnabled);
	if(isEnabled==0){
		websWrite(wp,"%s", "wlanSchedule-0-0-0-0-0-0");
		return 0;
	}
		
		for (i=1; i<=entryNum; i++) {
				*((char *)&entry) = (char)i;
				if ( !apmib_get(MIB_WLAN_SCHEDULE_TBL, (void *)&entry)){
					fprintf(stderr,"Get SCHEDULE entry fail\n");
					return -1;
				}
				if(entry.eco & ECO_EVERYDAY_MASK)
					everyday = 1;
				else
					everyday = 0;
				
				if(entry.eco & ECO_24HOURS_MASK)
					hours24 = 1;
				else
					hours24 = 0;
					
				if(everyday == 1)
				{
					dayWeek = 127; /* 01111111 */
				}
				else
				{
					dayWeek=entry.day;					
				}
				
				if(hours24 == 1)
				{
					entry.fTime=0;
					entry.tTime=1435;
				}
				
				if(index==i){
					websWrite(wp,"%s-%d-%d-%d-%d-%d-%d",entry.text, isEnabled, everyday, dayWeek, hours24, entry.fTime, entry.tTime);   
				}
		}

	
	return 0;
	
	
	
}

#ifdef UNIVERSAL_REPEATER
void setRepeaterSsid(int wlanid, int rptid, char *str_ssid)
{
	char wlanifStr[10];
	char tmpStr[MAX_SSID_LEN];		
	
	sprintf(wlanifStr,"wlan%d-vxd",wlanid);
	SetWlan_idx(wlanifStr);	
	
	apmib_get(MIB_WLAN_SSID, (void *)tmpStr);
	if(strcmp(tmpStr, str_ssid) != 0)
	{
		int is_configured = 1;
		
		apmib_set(MIB_WLAN_WSC_CONFIGURED, (void *)&is_configured);
		
		sprintf(tmpStr,"%s",str_ssid);
		apmib_set(MIB_WLAN_SSID, (void *)tmpStr);
		apmib_set(MIB_WLAN_WSC_SSID, (void *)tmpStr);	
		apmib_set(rptid, (void *)tmpStr);
	}
	
	sprintf(wlanifStr,"wlan%d",wlanid);
	SetWlan_idx(wlanifStr);
}
#endif

////////////////////
int wlanHandler(webs_t wp, char *tmpBuf, int *mode, int wlan_id)
{
  char_t *strSSID, *strChan, *strDisabled, *strVal, strtmp[20];
	int chan, disabled ;
	NETWORK_TYPE_T net;
	char_t *strRate;
	int val;
	char varName[20];
	int band_no=0;
	int cur_band=0;
	
//displayPostDate(wp->postData);
	
	/*sprintf(varName, "wlanDisabled%d", wlan_id);
	strDisabled = websGetVar(wp, varName, T(""));
	if ( !gstrcmp(strDisabled, T("ON")))
		disabled = 1;
	else
		disabled = 0;
	if ( apmib_set( MIB_WLAN_WLAN_DISABLED, (void *)&disabled) == 0) {
  		strcpy(tmpBuf, T("Set disabled flag error!"));
		goto setErr_wlan;
	}

	if ( disabled )
		return 0;*/

#ifdef WIFI_SIMPLE_CONFIG
	memset(&wps_config_info, 0, sizeof(struct wps_config_info_struct));
	wps_config_info.caller_id = CALLED_FROM_WLANHANDLER;
	apmib_get(MIB_WLAN_SSID, (void *)wps_config_info.ssid);	
	apmib_get(MIB_WLAN_MODE, (void *)&wps_config_info.wlan_mode);
#endif

	sprintf(varName, "mode%d", wlan_id);
	strVal = websGetVar(wp, varName, T(""));

	if(strVal[0] == NULL)
	{
		int val;

		apmib_get( MIB_WLAN_MODE, (void *)&val);
		sprintf(strtmp,"%d",val);
		strVal = strtmp;		
	}


	if ( strVal[0] ) {
#ifndef CONFIG_RTK_MESH
		if (strVal[0]!= '0' && strVal[0]!= '1' && strVal[0]!= '2' &&  strVal[0]!= '3') {
#else
#ifdef CONFIG_NEW_MESH_UI
		if (strVal[0]!= '0' && strVal[0]!= '1' && strVal[0]!= '2' &&  strVal[0]!= '3' &&  strVal[0]!= '4' &&  strVal[0]!= '5' ) {
#else
		if (strVal[0]!= '0' && strVal[0]!= '1' && strVal[0]!= '2' &&  strVal[0]!= '3' &&  strVal[0]!= '4' &&  strVal[0]!= '5' &&  strVal[0]!= '6'&&  strVal[0]!= '7') {
#endif
#endif // CONFIG_RTK_MESH
  			strcpy(tmpBuf, T("Invalid mode value!"));
			goto setErr_wlan;
		}
		*mode = strVal[0] - '0';

		if (*mode == CLIENT_MODE) {
			ENCRYPT_T encrypt;
      		apmib_get( MIB_WLAN_ENCRYPT,  (void *)&encrypt);
			if (encrypt &  ENCRYPT_WPA2_MIXED) {
				int format;
				apmib_get( MIB_WLAN_WPA_AUTH, (void *)&format);
				if (format & 1) { // radius
#ifdef CONFIG_RTL_802_1X_CLIENT_SUPPORT
					//Support wlan client mode with Enterprise (RADIUS)
#else
					strcpy(tmpBuf, T("You cannot set client mode with Enterprise (RADIUS) !<br><br>Please change the encryption method in security page first."));
					goto setErr_wlan;
#endif
				}
			}
			else if (encrypt == ENCRYPT_WEP || encrypt == 0) {
				int use1x;
				apmib_get( MIB_WLAN_ENABLE_1X, (void *)&use1x);
				if (use1x & 1) {
#ifdef CONFIG_RTL_802_1X_CLIENT_SUPPORT
					//Support wlan client mode with Enterprise (RADIUS)
#else
					strcpy(tmpBuf, T("You cannot set client mode with 802.1x enabled!<br><br>Please change the encryption method in security page first."));
					goto setErr_wlan;
#endif
				}
			}
			sprintf(varName, "wlanMacClone%d", wlan_id);
			strVal = websGetVar(wp, varName, T(""));
			if ( !gstrcmp(strVal, T("ON")))
				val = 1 ;
			else
				val = 0 ;
			if ( apmib_set( MIB_WLAN_MACCLONE_ENABLED, (void *)&val) == 0) {
				strcpy(tmpBuf, T("Set wlan Mac clone error!"));
				goto setErr_wlan;
			}
		}

		if ( apmib_set( MIB_WLAN_MODE, (void *)mode) == 0) {
   			strcpy(tmpBuf, T("Set MIB_WLAN_MODE error!"));
			goto setErr_wlan;
		}

#ifdef WLAN_EASY_CONFIG
		apmib_set( MIB_WLAN_EASYCFG_WLAN_MODE, (void *)mode);
#endif

	}

	sprintf(varName, "ssid%d", wlan_id);
   	strSSID = websGetVar(wp, varName, T(""));
	if ( strSSID[0] ) {
		if ( apmib_set(MIB_WLAN_SSID, (void *)strSSID) == 0) {
   	 			strcpy(tmpBuf, T("Set SSID error!"));
				goto setErr_wlan;
		}
	}
	else if ( *mode == 1 && !strSSID[0] ) { // client and NULL SSID
		if ( apmib_set(MIB_WLAN_SSID, (void *)strSSID) == 0) {
   	 			strcpy(tmpBuf, T("Set SSID error!"));
				goto setErr_wlan;
		}
	}

	sprintf(varName, "chan%d", wlan_id);
	strChan = websGetVar(wp, varName, T(""));
	if ( strChan[0] ) {
		errno=0;
		chan = strtol( strChan, (char **)NULL, 10);
		if (errno) {
   			strcpy(tmpBuf, T("Invalid channel number!"));
			goto setErr_wlan;
		}
		if ( apmib_set( MIB_WLAN_CHANNEL, (void *)&chan) == 0) {
   			strcpy(tmpBuf, T("Set channel number error!"));
			goto setErr_wlan;
		}
	}

	sprintf(varName, "type%d", wlan_id);
	strVal = websGetVar(wp, varName, T(""));
	if (strVal[0]) {
		if (strVal[0]!= '0' && strVal[0]!= '1') {
  			strcpy(tmpBuf, T("Invalid network type value!"));
			goto setErr_wlan;
		}
		if (strVal[0] == '0')
			net = INFRASTRUCTURE;
		else
			net = ADHOC;
		if ( apmib_set(MIB_WLAN_NETWORK_TYPE, (void *)&net) == 0) {
			strcpy(tmpBuf, T("Set MIB_WLAN_NETWORK_TYPE failed!"));
			goto setErr_wlan;
		}
	}

	sprintf(varName, "band%d", wlan_id);
	strVal = websGetVar(wp, varName, T(""));
	if ( strVal[0] ) 
	{
		int wlan_onoff_tkip;
		
		apmib_get( MIB_WLAN_11N_ONOFF_TKIP, (void *)&wlan_onoff_tkip);
				
		band_no = strtol( strVal, (char **)NULL, 10);
		if (band_no < 0 || band_no > 19) {
  			strcpy(tmpBuf, T("Invalid band value!"));
			goto setErr_wlan;
		}
		//val = (strVal[0] - '0' + 1);
		if(wlan_onoff_tkip == 0) //Wifi request
		{
			int wpaCipher;
			int wpa2Cipher;
			int wdsEncrypt;
			int wlan_encrypt=0;
			
			apmib_get( MIB_WLAN_ENCRYPT, (void *)&wlan_encrypt);
			apmib_get(MIB_WLAN_WPA_CIPHER_SUITE, (void *)&wpaCipher);
			apmib_get(MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&wpa2Cipher);
			apmib_get( MIB_WLAN_WDS_ENCRYPT, (void *)&wdsEncrypt);
			
			if(*mode != CLIENT_MODE && (band_no == 7 || band_no == 9 || band_no == 10 || band_no == 11)) //7:n; 9:gn; 10:bgn 11:5g_an
			{
				
				if(wlan_encrypt ==ENCRYPT_WPA || wlan_encrypt ==ENCRYPT_WPA2){
				wpaCipher &= ~WPA_CIPHER_TKIP;
					if(wpaCipher== 0)
						wpaCipher =  WPA_CIPHER_AES;
				apmib_set(MIB_WLAN_WPA_CIPHER_SUITE, (void *)&wpaCipher);
				
				wpa2Cipher &= ~WPA_CIPHER_TKIP;
					if(wpa2Cipher== 0)
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
		val = (band_no + 1);
		if ( apmib_set( MIB_WLAN_BAND, (void *)&val) == 0) {
   			strcpy(tmpBuf, T("Set band error!"));
			goto setErr_wlan;
		}		
	}

	// set tx rate
	sprintf(varName, "txRate%d", wlan_id);
	strRate = websGetVar(wp, varName, T(""));
	if ( strRate[0] ) {
		if ( strRate[0] == '0' ) { // auto
			val = 1;
			if ( apmib_set(MIB_WLAN_RATE_ADAPTIVE_ENABLED, (void *)&val) == 0) {
				strcpy(tmpBuf, T("Set rate adaptive failed!"));
				goto setErr_wlan;
			}
		}
		else  {
			val = 0;
			if ( apmib_set(MIB_WLAN_RATE_ADAPTIVE_ENABLED, (void *)&val) == 0) {
				strcpy(tmpBuf, T("Set rate adaptive failed!"));
				goto setErr_wlan;
			}  
			val = atoi(strRate);
			val = 1 << (val-1);
			if ( apmib_set(MIB_WLAN_FIX_RATE, (void *)&val) == 0) {
				strcpy(tmpBuf, T("Set fix rate failed!"));
				goto setErr_wlan;
			}
		}			
	}

	sprintf(varName, "basicrates%d", wlan_id);
	strRate = websGetVar(wp, varName, T(""));	
	if ( strRate[0] ) {
		val = atoi(strRate);		
		if ( apmib_set(MIB_WLAN_BASIC_RATES, (void *)&val) == 0) {
			strcpy(tmpBuf, T("Set Tx basic rate failed!"));
			goto setErr_wlan;
		}
	}

	sprintf(varName, "operrates%d", wlan_id);
	strRate = websGetVar(wp, varName, T(""));	
	if ( strRate[0] ) {
		val = atoi(strRate);
		if ( apmib_set(MIB_WLAN_SUPPORTED_RATES, (void *)&val) == 0) {
			strcpy(tmpBuf, T("Set Tx operation rate failed!"));
			goto setErr_wlan;
		}
	}

	// set hidden SSID
	sprintf(varName, "hiddenSSID%d", wlan_id);
	strVal = websGetVar(wp, varName, T(""));
	if (strVal[0]) {
		if ( strVal[0] == '0')
			val = 0;
		else if (strVal[0] == '1')
			val = 1;
		else {
			strcpy(tmpBuf, T("Error! Invalid Channel Bonding."));
			goto setErr_wlan;
		}
		if ( apmib_set(MIB_WLAN_HIDDEN_SSID, (void *)&val) == 0) {
			strcpy(tmpBuf, T("Set hidden ssid failed!"));
			goto setErr_wlan;
		}
	}
	sprintf(varName, "wlanwmm%d", wlan_id);
	strVal= websGetVar(wp, varName, T(""));
	if (strVal[0]) {
		if ( strVal[0] == '0')
			val = 0;
		else if (strVal[0] == '1')
			val = 1;
		else {
			strcpy(tmpBuf, T("Error! Invalid WMM value."));
			goto setErr_wlan;
		}
		if ( apmib_set(MIB_WLAN_WMM_ENABLED, (void *)&val) == 0) {
			strcpy(tmpBuf, T("Set MIB_WLAN_WMM_ENABLED failed!"));
			goto setErr_wlan;
		}
	}else{
		//enable wmm in 11N mode always
			apmib_get( MIB_WLAN_BAND, (void *)&cur_band);
			if(cur_band == 10 || cur_band ==11){
				val = 1;
				if ( apmib_set(MIB_WLAN_WMM_ENABLED, (void *)&val) == 0) {
					strcpy(tmpBuf, T("Set MIB_WLAN_WMM_ENABLED failed!"));
					goto setErr_wlan;
				}
			}
	}
// for 11N
	sprintf(varName, "channelbound%d", wlan_id);
	strVal = websGetVar(wp, varName, T(""));
	if (strVal[0]) {
		if ( strVal[0] == '0')
			val = 0;
		else if (strVal[0] == '1')
			val = 1;
		else {
			strcpy(tmpBuf, T("Error! Invalid Channel Bonding."));
			goto setErr_wlan;
		}
		if ( apmib_set(MIB_WLAN_CHANNEL_BONDING, (void *)&val) == 0) {
			strcpy(tmpBuf, T("Set MIB_WLAN_CHANNEL_BONDING failed!"));
			goto setErr_wlan;
		}
		if ( apmib_set(MIB_WLAN_COEXIST_ENABLED, (void *)&val) == 0) {	//Edison 2011.5.17
			strcpy(tmpBuf, T("Set MIB_WLAN_COEXIST_ENABLED failed!"));
			goto setErr_wlan;
		}
	}

	sprintf(varName, "controlsideband%d", wlan_id);
	strVal= websGetVar(wp, varName, T(""));
	if (strVal[0]) {
		if ( strVal[0] == '0')
			val = 0;
		else if ( strVal[0] == '1')
			val = 1;
		else {
			strcpy(tmpBuf, T("Error! Invalid Control SideBand."));
			goto setErr_wlan;
		}
		if ( apmib_set(MIB_WLAN_CONTROL_SIDEBAND, (void *)&val) == 0) {
			strcpy(tmpBuf, T("Set MIB_WLAN_CONTROL_SIDEBAND failed!"));
			goto setErr_wlan;
		}
	}

//

	sprintf(varName, "basicrates%d", wlan_id);
	strRate = websGetVar(wp, varName, T(""));
	if ( strRate[0] ) {
		val = atoi(strRate);

		if ( val && apmib_set(MIB_WLAN_BASIC_RATES, (void *)&val) == 0) {
			strcpy(tmpBuf, T("Set Tx basic rate failed!"));
			goto setErr_wlan;
		}
	}

	sprintf(varName, "operrates%d", wlan_id);
	strRate = websGetVar(wp, varName, T(""));
	if ( strRate[0] ) {
		val = atoi(strRate);
		if ( val && apmib_set(MIB_WLAN_SUPPORTED_RATES, (void *)&val) == 0) {
			strcpy(tmpBuf, T("Set Tx operation rate failed!"));
			goto setErr_wlan;
		}
	}	//do twice ??

#ifdef UNIVERSAL_REPEATER
#ifdef CONFIG_RTK_MESH
	if( *mode >= 4 && *mode <=7)
	{
		val=0;
		apmib_set(MIB_REPEATER_ENABLED1, (void *)&val);
		apmib_set(MIB_REPEATER_ENABLED2, (void *)&val);
	}
	else
#endif
{	int id;
	sprintf(varName, "repeaterEnabled%d", wlan_id);
	strVal = websGetVar(wp, T("lan_ip"), T(""));
	
	if ((strVal==NULL || strVal[0]==0) &&  // not called from wizard	
				(*mode != WDS_MODE) &&
			!(*mode == CLIENT_MODE && net == ADHOC)) {
		strVal = websGetVar(wp, varName, "");
		if ( !gstrcmp(strVal, T("ON")))
			val = 1 ;
		else
			val = 0 ;
		if (wlan_id == 0)
			id = MIB_REPEATER_ENABLED1;
		else
			id = MIB_REPEATER_ENABLED2;
		apmib_set(id, (void *)&val);

		if (val == 1) {
			sprintf(varName, "repeaterSSID%d", wlan_id);
			strVal = websGetVar(wp, varName, NULL);
			if (strVal){
				if (wlan_id == 0)
					id = MIB_REPEATER_SSID1;
				else
					id = MIB_REPEATER_SSID2;
					
				setRepeaterSsid(wlan_id, id, strVal);
			}
		}

#ifdef MBSSID
		int old_idx = vwlan_idx;
		vwlan_idx = NUM_VWLAN_INTERFACE; // repeater interface
		int disable;
		if (val)
			disable = 0;
		else
			disable = 1;		
		apmib_set(MIB_WLAN_WLAN_DISABLED, (void *)&disable);

		if (!disable) {
			if (*mode == CLIENT_MODE)
				val = AP_MODE;
			else
				val = CLIENT_MODE;
			apmib_set(MIB_WLAN_MODE, (void *)&val);			
			apmib_set(MIB_WLAN_SSID, (void *)strVal);			
		}

		if (val == CLIENT_MODE) {
			// if client mode, check if Radius or mixed mode encryption is used
			apmib_get(MIB_WLAN_ENCRYPT, (void *)&val);

			if (val <= ENCRYPT_WEP) {				
				apmib_get( MIB_WLAN_ENABLE_1X, (void *)&val);
				if (val != 0) {
					val = 0;
					apmib_set( MIB_WLAN_ENABLE_1X, (void *)&val);				
				}
			}	
			else if (val == ENCRYPT_WPA2_MIXED) {				
				val = ENCRYPT_DISABLED;
				apmib_set(MIB_WLAN_ENCRYPT, (void *)&val);
			}
			else if (val == ENCRYPT_WPA) {	
				apmib_get(MIB_WLAN_WPA_AUTH, (void *)&val);
				if ((val == 0) || (val & 1)) { // if no or radius, force to psk
					val = 2;
					apmib_set(MIB_WLAN_WPA_AUTH, (void *)&val);
				}				
				apmib_get(MIB_WLAN_WPA_CIPHER_SUITE, (void *)&val);
				if ((val == 0) || (val == WPA_CIPHER_MIXED)) {
					val = WPA_CIPHER_AES;
					apmib_set(MIB_WLAN_WPA_CIPHER_SUITE, (void *)&val);					
				}
			}
			else if (val == ENCRYPT_WPA2) {	
				apmib_get(MIB_WLAN_WPA_AUTH, (void *)&val);
				if ((val == 0) || (val & 1)) { // if no or radius, force to psk
					val = 2;
					apmib_set(MIB_WLAN_WPA_AUTH, (void *)&val);
				}				
				apmib_get(MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&val);
				if ((val == 0) || (val == WPA_CIPHER_MIXED)) {
					val = WPA_CIPHER_AES;
					apmib_set(MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&val);					
				}
			}	
		}

		vwlan_idx = old_idx;
#endif	
	}
}
#endif

#ifdef WIFI_SIMPLE_CONFIG
	sprintf(varName, "wps_clear_configure_by_reg%d", wlan_id);
	strVal = websGetVar(wp, varName, NULL);
	val = 0;
	if (strVal[0])
		val = atoi(strVal);
	update_wps_configured(val);
#endif

	return  0;
setErr_wlan:
	return -1 ;
}

#ifdef CONFIG_RTK_MESH
/////////////////////////////////////////////////////////////////////////////

int meshWpaHandler(webs_t wp, char *tmpBuf, int wlan_id)
{
  	char_t *strEncrypt, *strVal;
	ENCRYPT_T encrypt;
	int	intVal, getPSK=1, len;	

	char varName[20];

	sprintf(varName, "method%d", wlan_id);
   	strEncrypt = websGetVar(wp, varName, T(""));
	if (!strEncrypt[0]) {
 		strcpy(tmpBuf, T("Error! no encryption method."));
		goto setErr_mEncrypt;
	}
	encrypt = (ENCRYPT_T) strEncrypt[0] - '0';
	if (encrypt!=ENCRYPT_DISABLED &&  encrypt != ENCRYPT_WPA2 ) {
		strcpy(tmpBuf, T("Invalid encryption method!"));
		goto setErr_mEncrypt;
	}

	if (apmib_set( MIB_MESH_ENCRYPT, (void *)&encrypt) == 0) {
  		strcpy(tmpBuf, T("Set MIB_MESH_ENCRYPT mib error!"));
		goto setErr_mEncrypt;
	}

	if(encrypt == ENCRYPT_WPA2)
	{
		// WPA authentication  ( RADIU / Pre-Shared Key )
		intVal = WPA_AUTH_PSK;		
		if ( apmib_set(MIB_MESH_WPA_AUTH, (void *)&intVal) == 0) {
				strcpy(tmpBuf, T("Set MIB_MESH_AUTH_TYPE failed!"));
				goto setErr_mEncrypt;
		}

		// cipher suite	 (TKIP / AES)
		intVal =   WPA_CIPHER_AES ;		
		if ( apmib_set(MIB_MESH_WPA2_CIPHER_SUITE, (void *)&intVal) == 0) {
				strcpy(tmpBuf, T("Set MIB_MESH_WPA2_UNICIPHER failed!"));
				goto setErr_mEncrypt;
		}

		// pre-shared key
		if ( getPSK ) {
			int oldFormat, oldPskLen, i;

			sprintf(varName, "pskFormat%d", wlan_id);
   			strVal = websGetVar(wp, varName, T(""));
			if (!strVal[0]) {
	 			strcpy(tmpBuf, T("Error! no psk format."));
				goto setErr_mEncrypt;
			}
			intVal = strVal[0] - '0';
			if (intVal != 0 && intVal != 1) {
	 			strcpy(tmpBuf, T("Error! invalid psk format."));
				goto setErr_mEncrypt;
			}

			// remember current psk format and length to compare to default case "****"
			apmib_get(MIB_MESH_PSK_FORMAT, (void *)&oldFormat);
			apmib_get(MIB_MESH_WPA_PSK, (void *)tmpBuf);
			oldPskLen = strlen(tmpBuf);

			sprintf(varName, "pskValue%d", wlan_id);
			strVal = websGetVar(wp, varName, T(""));
			len = strlen(strVal);

			if (oldFormat == intVal && len == oldPskLen ) {
				for (i=0; i<len; i++) {
					if ( strVal[i] != '*' )
						break;
				}
				if (i == len)
					goto mRekey_time;
			}

			if ( apmib_set(MIB_MESH_PSK_FORMAT, (void *)&intVal) == 0) {
				strcpy(tmpBuf, T("Set MIB_MESH_PSK_FORMAT failed!"));
				goto setErr_mEncrypt;
			}

			if (intVal==1) { // hex
				if (len!=MAX_PSK_LEN || !string_to_hex(strVal, tmpBuf, MAX_PSK_LEN)) {
	 				strcpy(tmpBuf, T("Error! invalid psk value."));
					goto setErr_mEncrypt;
				}
			}
			else { // passphras
				if (len==0 || len > (MAX_PSK_LEN-1) ) {
	 				strcpy(tmpBuf, T("Error! invalid psk value."));
					goto setErr_mEncrypt;
				}
			}
			if ( !apmib_set(MIB_MESH_WPA_PSK, (void *)strVal)) {
				strcpy(tmpBuf, T("Set MIB_MESH_WPA_PSK error!"));
				goto setErr_mEncrypt;
			}
		}	
	}
mRekey_time:
		// group key rekey time			
	return 0 ;
setErr_mEncrypt:
	return -1 ;		
}	

#ifdef 	_11s_TEST_MODE_
void formEngineeringMode(webs_t wp, char_t *path, char_t *query)
{
	char_t *submitUrl;
	char tmpBuf[100];
	char_t *param;
	int val;
	//
	param = websGetVar(wp, "param1", T(""));
	string_to_dec(param , &val);
	if ( apmib_set(MIB_MESH_TEST_PARAM1, (void *)&val)==0 )
		goto setErr_meshTest;
	sprintf(tmpBuf, "iwpriv wlan0 set_mib mesh_reserved1=%d", val);
	system(tmpBuf);
	
	param = websGetVar(wp, "param2", T(""));
	string_to_dec(param , &val);
	if ( apmib_set(MIB_MESH_TEST_PARAM2, (void *)&val)==0 )
		goto setErr_meshTest;
	sprintf(tmpBuf, "iwpriv wlan0 set_mib mesh_reserved2=%d", val);
	system(tmpBuf);

	param = websGetVar(wp, "param3", T(""));
	string_to_dec(param , &val);
	if ( apmib_set(MIB_MESH_TEST_PARAM3, (void *)&val)==0 )	
		goto setErr_meshTest;
	sprintf(tmpBuf, "iwpriv wlan0 set_mib mesh_reserved3=%d", val);
	system(tmpBuf);

	param = websGetVar(wp, "param4", T(""));
	string_to_dec(param , &val);
	if ( apmib_set(MIB_MESH_TEST_PARAM4, (void *)&val)==0 )
		goto setErr_meshTest;
	sprintf(tmpBuf, "iwpriv wlan0 set_mib mesh_reserved4=%d", val);
	system(tmpBuf);

	param = websGetVar(wp, "param5", T(""));
	string_to_dec(param , &val);
	if ( apmib_set(MIB_MESH_TEST_PARAM5, (void *)&val)==0 )
		goto setErr_meshTest;
	sprintf(tmpBuf, "iwpriv wlan0 set_mib mesh_reserved5=%d", val);
	system(tmpBuf);
	
	param = websGetVar(wp, "param6", T(""));
	string_to_dec(param , &val);
	if ( apmib_set(MIB_MESH_TEST_PARAM6, (void *)&val)==0 )
		goto setErr_meshTest;
	sprintf(tmpBuf, "iwpriv wlan0 set_mib mesh_reserved6=%d", val);
	system(tmpBuf);

	param = websGetVar(wp, "param7", T(""));
	string_to_dec(param , &val);
	if ( apmib_set(MIB_MESH_TEST_PARAM7, (void *)&val)==0 )	
		goto setErr_meshTest;
	sprintf(tmpBuf, "iwpriv wlan0 set_mib mesh_reserved7=%d", val);
	system(tmpBuf);

	param = websGetVar(wp, "param8", T(""));
	string_to_dec(param , &val);
	if ( apmib_set(MIB_MESH_TEST_PARAM8, (void *)&val)==0 )
		goto setErr_meshTest;
	sprintf(tmpBuf, "iwpriv wlan0 set_mib mesh_reserved8=%d", val);
	system(tmpBuf);

	param = websGetVar(wp, "param9", T(""));
	string_to_dec(param , &val);
	if ( apmib_set(MIB_MESH_TEST_PARAM9, (void *)&val)==0 )
		goto setErr_meshTest;
	sprintf(tmpBuf, "iwpriv wlan0 set_mib mesh_reserved9=%d", val);
	system(tmpBuf);
	
	param = websGetVar(wp, "parama", T(""));
	string_to_dec(param , &val);
	if ( apmib_set(MIB_MESH_TEST_PARAMA, (void *)&val)==0 )
		goto setErr_meshTest;
	sprintf(tmpBuf, "iwpriv wlan0 set_mib mesh_reserveda=%d", val);
	system(tmpBuf);

	param = websGetVar(wp, "paramb", T(""));
	string_to_dec(param , &val);
	if ( apmib_set(MIB_MESH_TEST_PARAMB, (void *)&val)==0 )	
		goto setErr_meshTest;
	sprintf(tmpBuf, "iwpriv wlan0 set_mib mesh_reservedb=%d", val);
	system(tmpBuf);

	param = websGetVar(wp, "paramc", T(""));
	string_to_dec(param , &val);
	if ( apmib_set(MIB_MESH_TEST_PARAMC, (void *)&val)==0 )
		goto setErr_meshTest;
	sprintf(tmpBuf, "iwpriv wlan0 set_mib mesh_reservedc=%d", val);
	system(tmpBuf);

	param = websGetVar(wp, "paramd", T(""));
	string_to_dec(param , &val);
	if ( apmib_set(MIB_MESH_TEST_PARAMD, (void *)&val)==0 )
		goto setErr_meshTest;
	sprintf(tmpBuf, "iwpriv wlan0 set_mib mesh_reservedd=%d", val);
	system(tmpBuf);
	
	param = websGetVar(wp, "parame", T(""));
	string_to_dec(param , &val);
	if ( apmib_set(MIB_MESH_TEST_PARAME, (void *)&val)==0 )
		goto setErr_meshTest;
	sprintf(tmpBuf, "iwpriv wlan0 set_mib mesh_reservede=%d", val);
	system(tmpBuf);

	param = websGetVar(wp, "paramf", T(""));
	string_to_dec(param , &val);
	if ( apmib_set(MIB_MESH_TEST_PARAMF, (void *)&val)==0 )	
		goto setErr_meshTest;
	sprintf(tmpBuf, "iwpriv wlan0 set_mib mesh_reservedf=%d", val);
	system(tmpBuf);
	
	param = websGetVar(wp, "paramstr1", T(""));
    if (param[0])
    {
            if (strlen(param)>16) 
                  goto setErr_meshTest;

            if ( apmib_set(MIB_MESH_TEST_PARAMSTR1, (void *)param) == 0)
                    goto setErr_meshTest;
			sprintf(tmpBuf, "iwpriv wlan0 set_mib mesh_reservedstr1='%s'", param);
			system(tmpBuf);			
    }
    apmib_update(CURRENT_SETTING);
/*
#ifndef NO_ACTION
        run_init_script("bridge");
#endif
*/
	submitUrl = websGetVar(wp, T("meshtest-url"), T(""));   // hidden page
	OK_MSG(submitUrl);
	return;

setErr_meshTest:
		strcpy(tmpBuf, T("Error! set Mesh Test Param Error!!! "));
        ERR_MSG(tmpBuf);	 
}

void formEngineeringMode2(webs_t wp, char_t *path, char_t *query)
{
	char_t *submitUrl;
	char_t	*strCMD;
	char tmpBuf[200];
	strCMD = websGetVar(wp, T("cmd"), T(""));
	system(strCMD);
	submitUrl = websGetVar(wp, T("meshtest-url"), T(""));   // hidden page
	OK_MSG1(tmpBuf, submitUrl);
}

#endif



#ifdef _MESH_ACL_ENABLE_
int wlMeshAcList(int eid, webs_t wp, int argc, char_t **argv)
{
	int nBytesSent=0, entryNum, i;
	MACFILTER_T entry;
	char tmpBuf[100];

	if ( !apmib_get(MIB_MESH_ACL_NUM, (void *)&entryNum)) {
  		websError(wp, 400, T("Get MIB_MESH_ACL_NUM table entry error!\n"));
		return -1;
	}

	nBytesSent += websWrite(wp, T("<tr>"
      	"<td align=center width=\"45%%\" bgcolor=\"#808080\"><font size=\"2\"><b>MAC Address</b></font></td>\n"
      	"<td align=center width=\"35%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Comment</b></font></td>\n"
      	"<td align=center width=\"20%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Select</b></font></td></tr>\n"));

	for (i=1; i<=entryNum; i++) {
		*((char *)&entry) = (char)i;
		if ( !apmib_get(MIB_MESH_ACL_ADDR, (void *)&entry))
			return -1;

		snprintf(tmpBuf, 100, T("%02x:%02x:%02x:%02x:%02x:%02x"),
			entry.macAddr[0], entry.macAddr[1], entry.macAddr[2],
			entry.macAddr[3], entry.macAddr[4], entry.macAddr[5]);

		nBytesSent += websWrite(wp, T("<tr>"
			"<td align=center width=\"45%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
      			"<td align=center width=\"35%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
       			"<td align=center width=\"20%%\" bgcolor=\"#C0C0C0\"><input type=\"checkbox\" name=\"select%d\" value=\"ON\"></td></tr>\n"),
				tmpBuf, entry.comment, i);
	}
	return nBytesSent;
}

void formMeshACLSetup(webs_t wp, char_t *path, char_t *query)
{
	char_t *submitUrl;
	char_t *strAddMac, *strDelMac, *strDelAllMac, *strVal, *strEnabled;
	int entryNum, i, enabled;
	MACFILTER_T macEntry;
	char tmpBuf[100];

	strAddMac = websGetVar(wp, T("addMeshAclMac"), T(""));
	strDelMac = websGetVar(wp, T("deleteSelMeshAclMac"), T(""));
	strDelAllMac = websGetVar(wp, T("deleteAllMeshAclMac"), T(""));
	strEnabled = websGetVar(wp, T("meshAclEnabled"), T(""));
	submitUrl = websGetVar(wp, T("mesh-url"), T(""));   // hidden page

	if (strAddMac[0]) {
		/*if ( !gstrcmp(strEnabled, T("ON")))
			enabled = 1;
		else
			enabled = 0; */ //by sc_yang
		 enabled = strEnabled[0] - '0';
		if ( apmib_set( MIB_MESH_ACL_ENABLED, (void *)&enabled) == 0) {
  			strcpy(tmpBuf, T("Set enabled flag error!"));
			goto setErr_meshACL;
		}

		strVal = websGetVar(wp, T("aclmac"), T(""));
		if ( !strVal[0] ) {		// For Disable/Allow/Deny mode setting.
//			strcpy(tmpBuf, T("Error! No mac address to set."));
			goto meshAclExit;
		}
		if (strlen(strVal)!=12 || !string_to_hex(strVal, macEntry.macAddr, 12)) {
			strcpy(tmpBuf, T("Error! Invalid MAC address."));
			goto setErr_meshACL;
		}

		strVal = websGetVar(wp, T("aclcomment"), T(""));
		if ( strVal[0] ) {
			if (strlen(strVal) > COMMENT_LEN-1) {
				strcpy(tmpBuf, T("Error! Comment length too long."));
				goto setErr_meshACL;
			}
			strcpy(macEntry.comment, strVal);
		}
		else
			macEntry.comment[0] = '\0';

		if ( !apmib_get(MIB_MESH_ACL_NUM, (void *)&entryNum)) {
			strcpy(tmpBuf, T("Get entry number error!"));
			goto setErr_meshACL;
		}
		if ( (entryNum + 1) > MAX_MESH_ACL_NUM) {
			strcpy(tmpBuf, T("Cannot add new entry, Because table is full!"));
			goto setErr_meshACL;
		}

		// set to MIB. try to delete it first to avoid duplicate case
		apmib_set(MIB_MESH_ACL_ADDR_DEL, (void *)&macEntry);
		if ( apmib_set(MIB_MESH_ACL_ADDR_ADD, (void *)&macEntry) == 0) {
			strcpy(tmpBuf, T("Add table entry error!"));
			goto setErr_meshACL;
		}
		goto meshAclExit;
	}

	/* Delete entry */
	if (strDelMac[0]) {
		if ( !apmib_get(MIB_MESH_ACL_NUM, (void *)&entryNum)) {
			strcpy(tmpBuf, T("Get entry number error!"));
			goto setErr_meshACL;
		}
		for (i=entryNum; i>0; i--) {
			snprintf(tmpBuf, 20, "select%d", i);

			strVal = websGetVar(wp, tmpBuf, T(""));
			if ( !gstrcmp(strVal, T("ON")) ) {

				*((char *)&macEntry) = (char)i;
				if ( !apmib_get(MIB_MESH_ACL_ADDR, (void *)&macEntry)) {
					strcpy(tmpBuf, T("Get table entry error!"));
					goto setErr_meshACL;
				}
				if ( !apmib_set(MIB_MESH_ACL_ADDR_DEL, (void *)&macEntry)) {
					strcpy(tmpBuf, T("Delete table entry error!"));
					goto setErr_meshACL;
				}
			}
		}
		goto meshAclExit;
	}

	/* Delete all entry */
	if ( strDelAllMac[0]) {
		if ( !apmib_set(MIB_MESH_ACL_ADDR_DELALL, (void *)&macEntry)) {
			strcpy(tmpBuf, T("Delete all table error!"));
			goto setErr_meshACL;
		}
		goto meshAclExit;
	}

meshAclExit:
#ifndef NO_ACTION
        run_init_script("bridge");
#endif
        apmib_update(CURRENT_SETTING);

        submitUrl = websGetVar(wp, T("mesh-url"), T(""));   // hidden page
#ifdef REBOOT_CHECK
        OK_MSG(submitUrl);
#else
	RECONNECT_MSG(submitUrl);       // display reconnect msg to remote
#endif

        return;

setErr_meshACL:
        ERR_MSG(tmpBuf);
}
#endif	// _MESH_ACL_ENABLE_

int formMeshProxyTbl(webs_t wp, char_t *path, char_t *query)
{
        char_t *submitUrl,*refresh;

        submitUrl = websGetVar(wp, T("mesh-url"), T(""));   // hidden page
        refresh = websGetVar(wp, T("refresh"), T(""));

        if ( refresh[0] )
        {
                websRedirect(wp, submitUrl);
                return;
        }
}
char * _get_token( FILE * fPtr,char * token,char * data )
{
        char buf[512];
        char * pch;

        strcpy( data,"");

        if( fgets(buf, sizeof buf, fPtr) == NULL ) // get a new line
                return NULL;

        pch = strstr( buf, token ); //parse the tag

        if( pch == NULL )
                return NULL;

        pch += strlen( token );

        sprintf( data,"%s",pch );                  // set data

        return pch;
}


void strtolower(char *str, int len)
{
	int i;
	for (i = 0; i<len; i++) {
		str[i] = tolower(str[i]);
	}
}


void formMeshProxy(webs_t wp, char_t *path, char_t *query)
{
	char_t *strPrxyOwnr;
	int nRecordCount=0;
	FILE *fh;
	char buf[512];
	char sta[20],owner[20], macstr[20];
	
	strPrxyOwnr = websGetVar(wp, T("owner"), T(""));
	strtolower(strPrxyOwnr, 12);
	
	// show proxy
	if ( strPrxyOwnr[0] )
	{
		sprintf(macstr, "%c%c:%c%c:%c%c:%c%c:%c%c:%c%c", strPrxyOwnr[0],strPrxyOwnr[1],strPrxyOwnr[2]
			,strPrxyOwnr[3],strPrxyOwnr[4],strPrxyOwnr[5],strPrxyOwnr[6],strPrxyOwnr[7],strPrxyOwnr[8]
			,strPrxyOwnr[9],strPrxyOwnr[10],strPrxyOwnr[11]);
		websHeader(wp); 
		websWrite(wp, T("<! Copyright (c) Realtek Semiconductor Corp., 2003~2005. All Rights Reserved. ->\n"));
		websWrite(wp, T("<head><meta http-equiv=\"Content-Type\" content=\"text/html\">\n"));
		//websWrite(wp, T("<script type=\"text/javascript\" src=\"util_gw.js\"></script>\n"));
		websWrite(wp, T("<title>Proxy Table</title></head>\n"));
		websWrite(wp, T("<blockquote><h2><font color=\"#0000FF\">Active Client Table - %s</font></h2>\n"), macstr);
		websWrite(wp, T("<body><form action=/goform/formMeshProxy method=POST name=\"formMeshProxy\">\n"));
		websWrite(wp, T("<table border=0 width=550 cellspacing=4 cellpadding=0>\n"));
		websWrite(wp, T("<tr><font size=2>\n"));
		websWrite(wp, T("This table shows the MAC address for each proxied wired or wireless client\n"));
		websWrite(wp, T("</font></tr>\n"));
		websWrite(wp, T("<tr><hr size=1 noshade align=top></tr></table>\n"));
		
		
		websWrite(wp, T("<table border=1 width=200>\n"));
		//websWrite(wp, T("<tr><font size=4><b>Proxy Table </b></font></tr>\n"));
		
				
		websWrite(wp, T("<tr bgcolor=\"#7F7F7F\">"
		//"<td align=center width=\"50%%\"><font size=\"2\"><b>MP MAC Address</b></font></td>\n"
		"<td align=center><font size=\"2\"><b>Client MAC Address</b></font></td></tr>\n"));
		
		fh = fopen(_FILE_MESH_PROXY , "r");
		if (!fh)
		{
				printf("Warning: cannot open %s\n",_FILE_MESH_PROXY );
				return -1;
		}
		
		while( fgets(buf, sizeof buf, fh) != NULL )
		{
			if( strstr(buf,"table info...") != NULL )
			{
				_get_token( fh,"STA_MAC: ",sta );
				_get_token( fh,"OWNER_MAC: ",owner );
				strtolower(owner, 12);
				if (!strncmp(strPrxyOwnr,owner,12)){
					websWrite(wp,T("<tr bgcolor=\"#b7b7b7\">"
							"<td align=center width=\"50%%\"><font size=\"2\">%s</td>\n"),sta);
					nRecordCount++;
				}
			}
		}
		
		fclose(fh);
		
		if(nRecordCount == 0)
		{
			websWrite(wp,T("<tr bgcolor=\"#b7b7b7\">"
					"<td align=center width=\"17%%\"><font size=\"2\">None</td>\n"));
		}
				
		websWrite(wp,T("</tr></table>\n"));
		websWrite(wp,T("<input type=\"hidden\" value=\"%s\" name=\"owner\">\n"), strPrxyOwnr);
		websWrite(wp,T("<p><input type=\"submit\" value=\"Refresh\" name=\"refresh\">&nbsp;&nbsp;\n"));
		websWrite(wp,T("<input type=\"button\" value=\" Close \" name=\"close\" onClick=\"javascript: window.close();\"><p>\n"));
		websWrite(wp,T("</form>\n"));
		
		
		websWrite(wp, T("</blockquote></body>"));
		websFooter(wp); 
		websDone(wp, 200); 
		
	}
		
		
}



void formMeshSetup(webs_t wp, char_t *path, char_t *query)
{
        char_t *submitUrl,*meshRootEnabled,*refresh, *strMeshID, *strEnabled;
        int enabled,meshenable=0;
        char tmpBuf[100];
        int warn=0;
		
#ifdef CONFIG_NEW_MESH_UI
		#if 1
		meshRootEnabled = websGetVar(wp, T("meshRootEnabled"), T(""));
		#else
		meshRootEnabled = "ON";
		#endif
#else
        meshRootEnabled = websGetVar(wp, T("meshRootEnabled"), T(""));
#endif
        strMeshID = websGetVar(wp, T("meshID"), T(""));
        submitUrl = websGetVar(wp, T("mesh-url"), T(""));   // hidden page
        refresh = websGetVar(wp, T("refresh"), T(""));
		//new feature:Mesh enable/disable
		strEnabled = websGetVar(wp, T("wlanMeshEnable"), T(""));

		// refresh button response
        if ( refresh[0] )
        {
        		websRedirect(wp, submitUrl);
                return;
        }
		
		if ( !gstrcmp(strEnabled, T("ON")))
			meshenable = 1;
		else
			meshenable = 0;

		if ( apmib_set(MIB_MESH_ENABLE, (void *)&meshenable) == 0)
        {
                strcpy( tmpBuf, T("Set mesh enable error!"));
                goto setErr_mesh;
        }

		if( !meshenable )
			goto setupEnd;

		// backbone privacy settings
		
		if(meshWpaHandler(wp, tmpBuf, wlan_idx) < 0)
			goto setErr_mesh;
		
#ifdef CONFIG_NEW_MESH_UI
	if(!strcmp(meshRootEnabled, "ON"))
            enabled = 1 ;
    else
            enabled = 0 ;
#else
        if(!strcmp(meshRootEnabled, "ON"))
                enabled = 1 ;
        else
                enabled = 0 ;
#endif
        if ( apmib_set(MIB_MESH_ROOT_ENABLE, (void *)&enabled) == 0)
        {
                strcpy( tmpBuf, T("Set mesh Root enable error!"));
                goto setErr_mesh;
        }

        if (strMeshID[0])
        {
//              if (strlen(strMeshID)!=12 || !string_to_hex(strMeshID, tmpBuf, 12)) {
                if (strlen(strMeshID)>32) {
                        strcpy(tmpBuf, T("Error! Invalid Mesh ID."));
                        goto setErr_mesh;
                }
                if ( apmib_set(MIB_MESH_ID, (void *)strMeshID) == 0)
                {
                        strcpy(tmpBuf, T("Set MIB_MESH_ID error!"));
                        goto setErr_mesh;
                }
        }
setupEnd:
        apmib_update(CURRENT_SETTING);

#ifndef NO_ACTION
        run_init_script("bridge");
#endif

        submitUrl = websGetVar(wp, T("mesh-url"), T(""));   // hidden page
        if (warn) {
                OK_MSG1(tmpBuf, submitUrl);
        }
        else {
#ifdef REBOOT_CHECK
		OK_MSG(submitUrl);
#else
		RECONNECT_MSG(submitUrl);       // display reconnect msg to remote
#endif
        }
        return;

setErr_mesh:
        ERR_MSG(tmpBuf);
}

#endif // CONFIG_RTK_MESH

/////////////////////////////////////////////////////////////////////////////
#if defined(CONFIG_RTL_92D_SUPPORT)
void swapWlanMibSetting(unsigned char wlanifNumA, unsigned char wlanifNumB)
{
	unsigned char *wlanMibBuf=NULL;
	unsigned int totalSize = sizeof(CONFIG_WLAN_SETTING_T)*(NUM_VWLAN_INTERFACE+1); // 4vap+1rpt+1root
	wlanMibBuf = malloc(totalSize); 
#if 0	
	printf("\r\n wlanifNumA=[%u],__[%s-%u]\r\n",wlanifNumA,__FILE__,__LINE__);
	printf("\r\n wlanifNumB=[%u],__[%s-%u]\r\n",wlanifNumB,__FILE__,__LINE__);
	
	printf("\r\n pMib->wlan[wlanifNumA]=[0x%x],__[%s-%u]\r\n",pMib->wlan[wlanifNumA],__FILE__,__LINE__);
	printf("\r\n pMib->wlan[wlanifNumB]=[0x%x],__[%s-%u]\r\n",pMib->wlan[wlanifNumB],__FILE__,__LINE__);
	
	printf("\r\n pMib->wlan[0][0].wlanDisabled=[%u],__[%s-%u]\r\n",pMib->wlan[0][0].wlanDisabled,__FILE__,__LINE__);
	printf("\r\n pMib->wlan[0][0].phyBandSelect=[%u],__[%s-%u]\r\n",pMib->wlan[0][0].phyBandSelect,__FILE__,__LINE__);
	printf("\r\n pMib->wlan[0][0].channel=[%u],__[%s-%u]\r\n",pMib->wlan[0][0].channel,__FILE__,__LINE__);
	
	printf("\r\n pMib->wlan[1][0].wlanDisabled=[%u],__[%s-%u]\r\n",pMib->wlan[1][0].wlanDisabled,__FILE__,__LINE__);
	printf("\r\n pMib->wlan[1][0].phyBandSelect=[%u],__[%s-%u]\r\n",pMib->wlan[1][0].phyBandSelect,__FILE__,__LINE__);
	printf("\r\n pMib->wlan[1][0].channel=[%u],__[%s-%u]\r\n",pMib->wlan[1][0].channel,__FILE__,__LINE__);
#endif			
	if(wlanMibBuf != NULL)
	{
		memcpy(wlanMibBuf, pMib->wlan[wlanifNumA], totalSize);
		memcpy(pMib->wlan[wlanifNumA], pMib->wlan[wlanifNumB], totalSize);
		memcpy(pMib->wlan[wlanifNumB], wlanMibBuf, totalSize);
	
		free(wlanMibBuf);
	}
	
#if 0	
	printf("\r\n pMib->wlan[0][0].wlanDisabled=[%u],__[%s-%u]\r\n",pMib->wlan[0][0].wlanDisabled,__FILE__,__LINE__);
	printf("\r\n pMib->wlan[0][0].phyBandSelect=[%u],__[%s-%u]\r\n",pMib->wlan[0][0].phyBandSelect,__FILE__,__LINE__);
	printf("\r\n pMib->wlan[0][0].channel=[%u],__[%s-%u]\r\n",pMib->wlan[0][0].channel,__FILE__,__LINE__);
	
	printf("\r\n pMib->wlan[1][0].wlanDisabled=[%u],__[%s-%u]\r\n",pMib->wlan[1][0].wlanDisabled,__FILE__,__LINE__);
	printf("\r\n pMib->wlan[1][0].phyBandSelect=[%u],__[%s-%u]\r\n",pMib->wlan[1][0].phyBandSelect,__FILE__,__LINE__);
	printf("\r\n pMib->wlan[1][0].channel=[%u],__[%s-%u]\r\n",pMib->wlan[1][0].channel,__FILE__,__LINE__);
#endif	
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
#if VLAN_CONFIG_SUPPORTED 
	unsigned char *vlanMibBuf=NULL;
	totalSize = sizeof(VLAN_CONFIG_T)*5; // 4vap+1root
	vlanMibBuf = malloc(totalSize);
	if(vlanMibBuf != NULL)
	{
		memcpy(vlanMibBuf, pMib->VlanConfigArray+4, totalSize);
		memcpy(pMib->VlanConfigArray+4, pMib->VlanConfigArray+9, totalSize);
		memcpy(pMib->VlanConfigArray+9, vlanMibBuf, totalSize);
	
		free(vlanMibBuf);
	}
	
#endif
}

void formWlanBand2G5G(webs_t wp, char_t *path, char_t *query)
{
	char_t *submitUrl;
	char tmpBuf[100];
	char_t *tmpStr;
	int wlanBand2G5GSelect;
	char lan_ip_buf[30], lan_ip[30];
	int i;
	
//displayPostDate(wp->postData);
	
	submitUrl = websGetVar(wp, T("submit-url"), T(""));   // hidden page

	tmpStr = websGetVar(wp, T("wlBandMode"), T(""));  
	if(tmpStr[0]){
		wlanBand2G5GSelect = atoi(tmpStr);
	}
	if(wlanBand2G5GSelect<BANDMODE2G || wlanBand2G5GSelect>BANDMODESINGLE)
	{
		goto setErr;
	}
	else
	{	
		apmib_set(MIB_WLAN_BAND2G5G_SELECT,(void *)&wlanBand2G5GSelect);
	}
	
	/* init all wireless interface is set radio off and DMACDPHY */
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
			intVal = 1;
			apmib_set(MIB_WLAN_WLAN_DISABLED, (void *)&intVal);
		}						
	}
	
	/* Set expect wireless interface is radio on and SMACSPHY */
	if(wlanBand2G5GSelect == BANDMODE2G)
	{
		short wlanif;
		unsigned char wlanIfStr[10];
				
		wlanif = whichWlanIfIs(PHYBAND_2G);
		
		memset(wlanIfStr,0x00,sizeof(wlanIfStr));		
		sprintf(wlanIfStr, "wlan%d",wlanif);
		
		if(SetWlan_idx(wlanIfStr))
		{
			int val;
			val = 0;
			apmib_set(MIB_WLAN_WLAN_DISABLED, (void *)&val);
			val = SMACSPHY;
			apmib_set(MIB_WLAN_MAC_PHY_MODE, (void *)&val);
		}
		
		/* we can't up wlan1 alone, so we swap wlan0 and wlan1 settings */
		if(wlanif != 0)
		{
			swapWlanMibSetting(0,wlanif);			
		}		
	}
	else if(wlanBand2G5GSelect == BANDMODE5G)
	{
		short wlanif;
		unsigned char wlanIfStr[10];
				
		wlanif = whichWlanIfIs(PHYBAND_5G);
		
		memset(wlanIfStr,0x00,sizeof(wlanIfStr));		
		sprintf(wlanIfStr, "wlan%d",wlanif);
		
		if(SetWlan_idx(wlanIfStr))
		{
			int val;
			val = 0;
			apmib_set(MIB_WLAN_WLAN_DISABLED, (void *)&val);
			val = SMACSPHY;
			apmib_set(MIB_WLAN_MAC_PHY_MODE, (void *)&val);
		}
		
		/* we can't up wlan1 alone, so we swap wlan0 and wlan1 settings */
		if(wlanif != 0)
		{
			swapWlanMibSetting(0,wlanif);			
		}	
	}
	/* Set both wireless interface is radio on and DMACDPHY */
	else if(wlanBand2G5GSelect == BANDMODEBOTH)
	{
		short wlanif;
		
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
	}							
	if(wlanBand2G5GSelect == BANDMODESINGLE)
	{
		int intVal=0;
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
		
	}							
	/* set wlan index to 0 to avoid get wrong index when singleband*/
	wlan_idx = 0;
	apmib_update_web(CURRENT_SETTING);
	
#ifdef REBOOT_CHECK
	run_init_script_flag = 1;
#endif		


#ifndef NO_ACTION
	run_init_script("all");
#endif
	apmib_get( MIB_IP_ADDR,  (void *)lan_ip_buf) ;
  sprintf(lan_ip,"%s",inet_ntoa(*((struct in_addr *)lan_ip_buf)) );
  	
  sprintf(tmpBuf,"%s","<h4>Change setting successfully!<BR><BR>Do not turn off or reboot the Device during this time.</h4>");
	OK_MSG_FW(tmpBuf, submitUrl,APPLY_COUNTDOWN_TIME,lan_ip);
return;

setErr:
	ERR_MSG(tmpBuf);
}
#endif //#if defined(CONFIG_RTL_92D_SUPPORT)

void formWlanSetup(webs_t wp, char_t *path, char_t *query)
{
	char_t *submitUrl;
	char tmpBuf[100];
	int mode=-1;
	int warn=0;
	
#if defined(CONFIG_RTL_92D_SUPPORT)
	int wlanif=0;
	
	PHYBAND_TYPE_T phyBandSelect = PHYBAND_OFF; 
	int wlanBand2G5GSelect=PHYBAND_OFF;
#endif
//displayPostDate(wp->postData);	

#if defined(CONFIG_RTL_92D_SUPPORT)		
	apmib_get(MIB_WLAN_BAND2G5G_SELECT,(void *)&wlanBand2G5GSelect);
	
	if(wlanBand2G5GSelect == BANDMODESINGLE)
	{
		char_t *strVal=NULL;
		
		strVal=websGetVar(wp,T("Band2G5GSupport"),T(""));
		if(strVal[0])
		{
			
			phyBandSelect= atoi(strVal);		
			wlanif = whichWlanIfIs(phyBandSelect);			
				

			if(wlanif != 0)
			{
				int val;
				val = 1;
				apmib_set(MIB_WLAN_WLAN_DISABLED, (void *)&val); //close original interface
				
				swapWlanMibSetting(0,wlanif);
				
				val = 0;
				apmib_set(MIB_WLAN_WLAN_DISABLED, (void *)&val); //enable after interface
				//apmib_update_web(CURRENT_SETTING);
			}
		}
	}
#endif //#if defined(CONFIG_RTL_92D_SUPPORT)

	if(wlanHandler(wp, tmpBuf, &mode, wlan_idx) < 0)
		goto setErr_wlan ;
	if (mode == 1) { // not AP mode
		//set cipher suit to AES and encryption to wpa2 only if wpa2 mixed mode is set
		ENCRYPT_T encrypt;
		int intVal;
		apmib_get( MIB_WLAN_ENCRYPT, (void *)&encrypt);
		if(encrypt == ENCRYPT_WPA2_MIXED){
			intVal =   WPA_CIPHER_AES ;
			if ( apmib_set(MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&intVal) == 0) {
				strcpy(tmpBuf, T("Set MIB_WLAN_WPA2_UNICIPHER failed!"));
				goto setErr_wlan;
			}
			encrypt = ENCRYPT_WPA2;
			if ( apmib_set(MIB_WLAN_ENCRYPT, (void *)&encrypt) == 0) {
				strcpy(tmpBuf, T("Set MIB_WLAN_WPA2_UNICIPHER failed!"));
				goto setErr_wlan;
			}

			intVal =   0;
			if ( apmib_set(MIB_WLAN_WPA_CIPHER_SUITE, (void *)&intVal) == 0) {
				strcpy(tmpBuf, T("Set MIB_WLAN_WPA_CIPHER_SUITE failed!"));
				goto setErr_wlan;
			}
			strcpy(tmpBuf, T("Warning! WPA2 Mixed encryption is not supported in client Mode. <BR> Change to WPA2 Encryption."));
			warn = 1;
		}
	}
	apmib_update_web(CURRENT_SETTING);

#ifndef NO_ACTION
	run_init_script("bridge");
#endif

	submitUrl = websGetVar(wp, T("wlan-url"), T(""));   // hidden page
	if (warn) {
		OK_MSG1(tmpBuf, submitUrl);
	}
	else {
		OK_MSG(submitUrl);
	}
	return;

setErr_wlan:
	ERR_MSG(tmpBuf);
}

int wepHandler(webs_t wp, char *tmpBuf, int wlan_id)
{
   	char_t  *wepKey,*strKeyId,*strASUS;
   	char_t *strKeyLen, *strFormat, /* *strKeyId, */ *strEnabled;
	char key[30];
	int enabled, keyLen, ret, i;
	WEP_T wep;
	ENCRYPT_T encrypt=ENCRYPT_WEP;
	char varName[20];

#ifdef WIFI_SIMPLE_CONFIG
#ifdef MBSSID
	if (vwlan_idx == 0)
#endif
	{
		memset(&wps_config_info, 0, sizeof(struct wps_config_info_struct));
		wps_config_info.caller_id = CALLED_FROM_WEPHANDLER;
		apmib_get(MIB_WLAN_ENCRYPT, (void *)&wps_config_info.auth);
		apmib_get(MIB_WLAN_WEP, (void *)&wps_config_info.wep_enc);
		apmib_get(MIB_WLAN_WEP_DEFAULT_KEY, (void *)&wps_config_info.KeyId);
		apmib_get(MIB_WLAN_WEP64_KEY1, (void *)wps_config_info.wep64Key1);
		apmib_get(MIB_WLAN_WEP64_KEY2, (void *)wps_config_info.wep64Key2);
		apmib_get(MIB_WLAN_WEP64_KEY3, (void *)wps_config_info.wep64Key3);
		apmib_get(MIB_WLAN_WEP64_KEY4, (void *)wps_config_info.wep64Key4);
		apmib_get(MIB_WLAN_WEP128_KEY1, (void *)wps_config_info.wep128Key1);
		apmib_get(MIB_WLAN_WEP128_KEY2, (void *)wps_config_info.wep128Key2);
		apmib_get(MIB_WLAN_WEP128_KEY3, (void *)wps_config_info.wep128Key3);
		apmib_get(MIB_WLAN_WEP128_KEY4, (void *)wps_config_info.wep128Key4);
	}
#endif

	sprintf(varName, "wepEnabled%d", wlan_id);
	strEnabled = websGetVar(wp, varName, T(""));
	if ( !gstrcmp(strEnabled, T("ON")))
		enabled = 1;
	else
		enabled = 0;

	if ( enabled ) {
		sprintf(varName, "length%d", wlan_id);
		strKeyLen = websGetVar(wp, varName, T(""));
		if (!strKeyLen[0]) {
			printf("Key length must exist!\n");	//Added by Jerry
 			strcpy(tmpBuf, T("Key length must exist!"));
			goto setErr_wep;
		}
		//if (strKeyLen[0]!='1' && strKeyLen[0]!='2') {
		if (strKeyLen[0]!='0' && strKeyLen[0]!='1' && strKeyLen[0]!='2') {	//2011.05.04 Jerry
			printf("Invalid key length value!\n");	//Added by Jerry
 			strcpy(tmpBuf, T("Invalid key length value!"));
			goto setErr_wep;
		}
		/*if (strKeyLen[0] == '1')
			wep = WEP64;
		else
			wep = WEP128;*/
		//2011.05.04 Jerry {	
		if (strKeyLen[0] == '1')
			wep = WEP64;
		else if (strKeyLen[0] == '2')
			wep = WEP128;
		else
			wep = WEP_DISABLED;
		//2011.05.04 Jerry }
	}
	else
		wep = WEP_DISABLED;

	if ( apmib_set( MIB_WLAN_WEP, (void *)&wep) == 0) {
		printf("Set WEP MIB error!\n");	//Added by Jerry
  		strcpy(tmpBuf, T("Set WEP MIB error!"));
		goto setErr_wep;
	}

	if (wep == WEP_DISABLED)
		encrypt = ENCRYPT_DISABLED;

	if (apmib_set( MIB_WLAN_ENCRYPT, (void *)&encrypt) == 0) {
		printf("Set MIB_WLAN_ENCRYPT mib error!\n");	//Added by Jerry
		strcpy(tmpBuf, T("Set MIB_WLAN_ENCRYPT mib error!"));
		goto setErr_wep;
	}

	if (wep == WEP_DISABLED)
		return 0 ;

	sprintf(varName, "format%d", wlan_id);
	strFormat = websGetVar(wp, varName, T(""));
	if (!strFormat[0]) {
		printf("Key type must exist!\n");	//Added by Jerry
 		strcpy(tmpBuf, T("Key type must exist!"));
		goto setErr_wep;
	}

	if (strFormat[0]!='1' && strFormat[0]!='2') {
		printf("Invalid key type value!\n");	//Added by Jerry
		strcpy(tmpBuf, T("Invalid key type value!"));
		goto setErr_wep;
	}

	i = strFormat[0] - '0' - 1;
	if ( apmib_set( MIB_WLAN_WEP_KEY_TYPE, (void *)&i) == 0) {
		printf("Set WEP key type error!\n");	//Added by Jerry
  		strcpy(tmpBuf, T("Set WEP key type error!"));
		goto setErr_wep;
	}

	if (wep == WEP64) {
		if (strFormat[0]=='1')
			keyLen = WEP64_KEY_LEN;
		else
			keyLen = WEP64_KEY_LEN*2;
	}
	else {
		if (strFormat[0]=='1')
			keyLen = WEP128_KEY_LEN;
		else
			keyLen = WEP128_KEY_LEN*2;
	}
//Lucifer add
#if 0
		sprintf(varName, "key%d", wlan_id);
	wepKey = websGetVar(wp, varName, T(""));
	if  (wepKey[0]) {
		if (strlen(wepKey) != keyLen) {
			printf("Invalid key length!\n");	//Added by Jerry
			strcpy(tmpBuf, T("Invalid key length!"));
			goto setErr_wep;
		}
		if ( !isAllStar(wepKey) ) {
			if (strFormat[0] == '1') // ascii
				strcpy(key, wepKey);
			else { // hex
				if ( !string_to_hex(wepKey, key, keyLen)) {
					printf("Invalid wep-key value!\n");	//Added by Jerry
	   				strcpy(tmpBuf, T("Invalid wep-key value!"));
					goto setErr_wep;
				}
			}
			if (wep == WEP64){
				ret=apmib_set(MIB_WLAN_WEP64_KEY1, (void *)key);
				ret=apmib_set(MIB_WLAN_WEP64_KEY2, (void *)key);
				ret=apmib_set(MIB_WLAN_WEP64_KEY3, (void *)key);
				ret=apmib_set(MIB_WLAN_WEP64_KEY4, (void *)key);
			}else{
				ret=apmib_set(MIB_WLAN_WEP128_KEY1, (void *)key);
				ret=apmib_set(MIB_WLAN_WEP128_KEY2, (void *)key);
				ret=apmib_set(MIB_WLAN_WEP128_KEY3, (void *)key);
				ret=apmib_set(MIB_WLAN_WEP128_KEY4, (void *)key);
			}
			if (!ret) {
				printf("Set wep-key error!\n");	//Added by Jerry
	 			strcpy(tmpBuf, T("Set wep-key error!"));
				goto setErr_wep;
			}
		}
	}
#endif
	
	
#if 1
	sprintf(varName, "defaultTxKeyId%d", wlan_id);
	strKeyId = websGetVar(wp, varName, T(""));
	if ( strKeyId[0] ) {
		if ( strKeyId[0]!='1' && strKeyId[0]!='2' && strKeyId[0]!='3' && strKeyId[0]!='4' ) {
	 		strcpy(tmpBuf, T("Invalid default tx key id!"));
   			goto setErr_wep;
		}
		i = strKeyId[0] - '0' - 1;
		if ( !apmib_set( MIB_WLAN_WEP_DEFAULT_KEY, (void *)&i ) ) {
	 		strcpy(tmpBuf, T("Set default tx key id error!"));
   			goto setErr_wep;
		}
	}

	sprintf(varName, "key1%d", wlan_id);
	wepKey = websGetVar(wp, varName, T(""));
	if  (wepKey[0]) {
		if (strlen(wepKey) != keyLen) {
			strcpy(tmpBuf, T("Invalid key 1 length!"));
			goto setErr_wep;
		}
		if ( !isAllStar(wepKey) ) {
			if (strFormat[0] == '1') // ascii
				strcpy(key, wepKey);
			else { // hex
				if ( !string_to_hex(wepKey, key, keyLen)) {
	   				strcpy(tmpBuf, T("Invalid wep-key1 value!"));
					goto setErr_wep;
				}
			}
			if (wep == WEP64)
				ret=apmib_set(MIB_WLAN_WEP64_KEY1, (void *)key);
			else
				ret=apmib_set(MIB_WLAN_WEP128_KEY1, (void *)key);
			if (!ret) {
	 			strcpy(tmpBuf, T("Set wep-key1 error!"));
				goto setErr_wep;
			}
		}
	}
	else
	{
		sprintf(key, "NULL");
		if (wep == WEP64)
			ret=apmib_set(MIB_WLAN_WEP64_KEY1, (void *)key);
		else
			ret=apmib_set(MIB_WLAN_WEP128_KEY1, (void *)key);
		if (!ret) {
	 		strcpy(tmpBuf, T("Set NULL wep-key1 error!"));
			goto setErr_wep;
		}	
	}

	sprintf(varName, "key2%d", wlan_id);
	wepKey = websGetVar(wp, varName, T(""));
	if  (wepKey[0]) {
		if (strlen(wepKey) != keyLen) {
			strcpy(tmpBuf, T("Invalid key 2 length!"));
			goto setErr_wep;
		}
		if ( !isAllStar(wepKey) ) {
			if (strFormat[0] == '1') // ascii
				strcpy(key, wepKey);
			else { // hex
				if ( !string_to_hex(wepKey, key, keyLen)) {
	   				strcpy(tmpBuf, T("Invalid wep-key2 value!"));
   					goto setErr_wep;
				}
			}
			if (wep == WEP64)
				ret=apmib_set(MIB_WLAN_WEP64_KEY2, (void *)key);
			else
				ret=apmib_set(MIB_WLAN_WEP128_KEY2, (void *)key);
			if (!ret) {
	 			strcpy(tmpBuf, T("Set wep-key2 error!"));
				goto setErr_wep;
			}
		}
	}
	else
	{
		sprintf(key, "NULL");
		if (wep == WEP64)
			ret=apmib_set(MIB_WLAN_WEP64_KEY2, (void *)key);
		else
			ret=apmib_set(MIB_WLAN_WEP128_KEY2, (void *)key);
		if (!ret) {
	 		strcpy(tmpBuf, T("Set NULL wep-key2 error!"));
			goto setErr_wep;
		}	
	}

	sprintf(varName, "key3%d", wlan_id);
	wepKey = websGetVar(wp, varName, T(""));
	if  (wepKey[0]) {
		if (strlen(wepKey) != keyLen) {
			strcpy(tmpBuf, T("Invalid key 3 length!"));
			goto setErr_wep;
		}
		if ( !isAllStar(wepKey) ) {
			if (strFormat[0] == '1') // ascii
				strcpy(key, wepKey);
			else { // hex
				if ( !string_to_hex(wepKey, key, keyLen)) {
	   				strcpy(tmpBuf, T("Invalid wep-key3 value!"));
   					goto setErr_wep;
				}
			}
			if (wep == WEP64)
				ret=apmib_set(MIB_WLAN_WEP64_KEY3, (void *)key);
			else
				ret=apmib_set(MIB_WLAN_WEP128_KEY3, (void *)key);
			if (!ret) {
	 			strcpy(tmpBuf, T("Set wep-key3 error!"));
				goto setErr_wep;
			}
		}
	}
	else
	{
		sprintf(key, "NULL");
		if (wep == WEP64)
			ret=apmib_set(MIB_WLAN_WEP64_KEY3, (void *)key);
		else
			ret=apmib_set(MIB_WLAN_WEP128_KEY3, (void *)key);
		if (!ret) {
	 		strcpy(tmpBuf, T("Set NULL wep-key3 error!"));
			goto setErr_wep;
		}
	}

	sprintf(varName, "key4%d", wlan_id);
	wepKey = websGetVar(wp, varName, T(""));
	if  (wepKey[0]) {
		if (strlen(wepKey) != keyLen) {
			strcpy(tmpBuf, T("Invalid key 1 length!"));
			goto setErr_wep;
		}
		if ( !isAllStar(wepKey) ) {
			if (strFormat[0] == '1') // ascii
				strcpy(key, wepKey);
			else { // hex
				if ( !string_to_hex(wepKey, key, keyLen)) {
	   				strcpy(tmpBuf, T("Invalid wep-key4 value!"));
   					goto setErr_wep;
				}
			}
			if (wep == WEP64)
				ret=apmib_set(MIB_WLAN_WEP64_KEY4, (void *)key);
			else
				ret=apmib_set(MIB_WLAN_WEP128_KEY4, (void *)key);
			if (!ret) {
	 			strcpy(tmpBuf, T("Set wep-key4 error!"));
				goto setErr_wep;
			}
		}
	}
	else
	{
		sprintf(key, "NULL");
		if (wep == WEP64)
			ret=apmib_set(MIB_WLAN_WEP64_KEY4, (void *)key);
		else
			ret=apmib_set(MIB_WLAN_WEP128_KEY4, (void *)key);
		if (!ret) {
	 		strcpy(tmpBuf, T("Set NULL wep-key4 error!"));
			goto setErr_wep;
		}	
	}

	sprintf(varName, "asus_phrase%d", wlan_id);
   	strASUS = websGetVar(wp, varName, T(""));
	if(strASUS[0])
	{
	ret=apmib_set(MIB_WLAN_ASUS_PHRASE, (void *)strASUS);
	if (!ret) 
	{
		strcpy(tmpBuf, T("Set asus_phrase error!"));
		goto setErr_wep;
	}
	}
	else
	{
	ret=apmib_set(MIB_WLAN_ASUS_PHRASE, "");
	if (!ret) 
	{
		strcpy(tmpBuf, T("Set asus_phrase error!"));
		goto setErr_wep;
	}
	}
#endif
//Lucifer add
#ifdef WIFI_SIMPLE_CONFIG
	#ifdef MBSSID
	if (vwlan_idx == 0)
#endif
	{
		sprintf(varName, "wps_clear_configure_by_reg%d", wlan_id);
		wepKey = websGetVar(wp, varName, NULL);
		ret = 0;
		if (wepKey[0])
			ret = atoi(wepKey);
		update_wps_configured(ret);
	}
#endif

#if defined(UNIVERSAL_REPEATER) && defined(CONFIG_REPEATER_WPS_SUPPORT)
	if (vwlan_idx == NUM_VWLAN_INTERFACE)
	{
		sprintf(varName, "wps_clear_configure_by_reg%d", wlan_id);
		wepKey = websGetVar(wp, varName, NULL);
		ret = 0;
		if (wepKey[0])
			ret = atoi(wepKey);
		update_wps_configured(ret);
	}
#endif

	return 0 ;
setErr_wep:
	return -1 ;	
}	
/////////////////////////////////////////////////////////////////////////////
void formWep(webs_t wp, char_t *path, char_t *query)
{
	char_t *submitUrl;
	char tmpBuf[100];


	if(wepHandler(wp, tmpBuf, wlan_idx) < 0 )
		goto setErr_end ;

	apmib_update_web(CURRENT_SETTING);
//2011.04.28 Jerry {
#if 0
#ifndef NO_ACTION
	run_init_script("bridge");
#endif

	submitUrl = websGetVar(wp, T("submit-url"), T(""));   // hidden page
	//OK_MSG(submitUrl);
	system("sysconf init gw all"); //mars add
#endif
//2011.04.28 Jerry }
	return;

setErr_end:
	//ERR_MSG(tmpBuf);
	printf("goto setErr_end in formWep\n");
}


int wpaHandler(webs_t wp, char *tmpBuf, int wlan_id)
{
   	char_t *strEncrypt, *strVal;
	ENCRYPT_T encrypt;
	int enableRS=0, intVal, getPSK=0, len, val;
	unsigned long reKeyTime;
	SUPP_NONWAP_T suppNonWPA;
	struct in_addr inIp;
	char varName[20];
#ifdef CONFIG_RTL_WAPI_SUPPORT
	int enableAS=0;
#endif

#ifdef CONFIG_RTL_802_1X_CLIENT_SUPPORT
	int wlan_mode;
	int intVal2;
#endif

	sprintf(varName, "method%d", wlan_id);
   	strEncrypt = websGetVar(wp, varName, T(""));
	if (!strEncrypt[0]) {
		printf("Error! no encryption method\n");	//Added by Jerry
 		strcpy(tmpBuf, T("Error! no encryption method."));
		goto setErr_encrypt;
	}
	encrypt = (ENCRYPT_T) strEncrypt[0] - '0';
	if (encrypt!=ENCRYPT_DISABLED && encrypt!=ENCRYPT_WEP && encrypt!=ENCRYPT_WPA
		&& encrypt != ENCRYPT_WPA2 && encrypt != ENCRYPT_WPA2_MIXED
#ifdef CONFIG_RTL_WAPI_SUPPORT		
		&& encrypt != ENCRYPT_WAPI
#endif
) {
		printf("Invalid encryption method\n");	//Added by Jerry
		strcpy(tmpBuf, T("Invalid encryption method!"));
		goto setErr_encrypt;
	}

#ifdef WIFI_SIMPLE_CONFIG
#ifdef MBSSID
	if (vwlan_idx == 0)
#endif
	{
		memset(&wps_config_info, 0, sizeof(struct wps_config_info_struct));
		wps_config_info.caller_id = CALLED_FROM_WPAHANDLER;
		apmib_get(MIB_WLAN_ENCRYPT, (void *)&wps_config_info.auth);
		apmib_get(MIB_WLAN_WPA_CIPHER_SUITE, (void *)&wps_config_info.wpa_enc);
		apmib_get(MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&wps_config_info.wpa2_enc);
		apmib_get(MIB_WLAN_WPA_PSK, (void *)wps_config_info.wpaPSK);
	}
#endif

	if (apmib_set( MIB_WLAN_ENCRYPT, (void *)&encrypt) == 0) {
		printf("Set MIB_WLAN_ENCRYPT mib error!\n");	//Added by Jerry
  		strcpy(tmpBuf, T("Set MIB_WLAN_ENCRYPT mib error!"));
		goto setErr_encrypt;
	}

	if (encrypt == ENCRYPT_DISABLED || encrypt == ENCRYPT_WEP) {
		sprintf(varName, "use1x%d", wlan_id);
		strVal = websGetVar(wp, varName, T(""));
		if ( !gstrcmp(strVal, T("ON"))) {
			apmib_get( MIB_WLAN_MODE, (void *)&intVal);
			if (intVal !=AP_MODE && intVal != AP_WDS_MODE) { // not AP mode
#ifdef CONFIG_RTL_802_1X_CLIENT_SUPPORT
				if(intVal == CLIENT_MODE){//client mode
//					printf("%s(%d): WPA-RADIUS can be used when device is set to client mode\n",__FUNCTION__,__LINE__);//Added for test 
					intVal = 1;
					enableRS = 1;
				}
				else{
					printf("Error! 802.1x authentication cannot be used when device is set to wds or mesh mode.\n");	//Added by Jerry
					strcpy(tmpBuf, T("Error! 802.1x authentication cannot be used when device is set to wds or mesh mode."));
					goto setErr_encrypt;
					intVal = 0;
				}
#else
				printf("Error! 802.1x authentication cannot be used when device is set to client mode.\n");	//Added by Jerry
				strcpy(tmpBuf, T("Error! 802.1x authentication cannot be used when device is set to client mode."));
				goto setErr_encrypt;
				intVal = 0;				
#endif
			}
			else {
				intVal = 1;
				enableRS = 1;
			}
		}
		else
			intVal = 0;

		if ( apmib_set( MIB_WLAN_ENABLE_1X, (void *)&intVal) == 0) {
			printf("Set 1x enable flag error\n");	//Added by Jerry
  			strcpy(tmpBuf, T("Set 1x enable flag error!"));
			goto setErr_encrypt;
		}

		if (encrypt == ENCRYPT_WEP) {
	 		WEP_T wep;
			if ( !apmib_get( MIB_WLAN_WEP,  (void *)&wep) ) {
				printf("Get MIB_WLAN_WEP MIB error\n");	//Added by Jerry
				strcpy(tmpBuf, T("Get MIB_WLAN_WEP MIB error!"));
				goto setErr_encrypt;
			}
			if (wep == WEP_DISABLED) {
				wep = WEP64;
				if ( apmib_set( MIB_WLAN_WEP, (void *)&wep) == 0) {
					printf("Set WEP MIB error!\n");	//Added by Jerry
		  			strcpy(tmpBuf, T("Set WEP MIB error!"));
					goto setErr_encrypt;
				}
			}
		}
		else {
			sprintf(varName, "useMacAuth%d", wlan_id);
			strVal = websGetVar(wp, varName, T(""));
			if ( !gstrcmp(strVal, T("ON"))) {
				intVal = 1;
				enableRS = 1;
			}
			else
				intVal = 0;
			if ( apmib_set( MIB_WLAN_MAC_AUTH_ENABLED, (void *)&intVal) == 0) {
				printf("Set MIB_WLAN_MAC_AUTH_ENABLED MIB error!\n");	//Added by Jerry
  				strcpy(tmpBuf, T("Set MIB_WLAN_MAC_AUTH_ENABLED MIB error!"));
				goto setErr_encrypt;
			}
		}
	}
#ifdef CONFIG_RTL_WAPI_SUPPORT	
	else if(ENCRYPT_WAPI==encrypt)
	{
		/*WAPI handle*/
		sprintf(varName, "wapiAuth%d", wlan_id);
		strVal = websGetVar(wp, varName, T(""));
		if (strVal[0]) 
		{
			if ( !gstrcmp(strVal, T("eap")))
			{
				apmib_get( MIB_WLAN_MODE, (void *)&intVal);
				if (intVal!=AP_MODE && intVal!=AP_WDS_MODE) { // not AP mode
					printf("Error! WAPI AS cannot be used when device is set to client mode.\n");	//Added by Jerry
					strcpy(tmpBuf, T("Error! WAPI AS cannot be used when device is set to client mode."));
					goto setErr_encrypt;
				}
				intVal = WAPI_AUTH_AUTO;
				enableAS = 1;
			}
			else if ( !gstrcmp(strVal, T("psk"))) 
			{
				intVal = WAPI_AUTH_PSK;
				getPSK = 1;
			}
			else 
			{
				printf("Error! Invalid wapi authentication value.\n");	//Added by Jerry
				strcpy(tmpBuf, T("Error! Invalid wapi authentication value."));
				goto setErr_encrypt;
			}

			if ( apmib_set(MIB_WLAN_WAPI_AUTH, (void *)&intVal) == 0) 
			{
				printf("Set MIB_WLAN_AUTH_TYPE failed!\n");	//Added by Jerry
				strcpy(tmpBuf, T("Set MIB_WLAN_AUTH_TYPE failed!"));
				goto setErr_encrypt;
			}
		}
		// pre-shared key
		if ( getPSK ) {
			int oldFormat, oldPskLen, i;

			sprintf(varName, "wapiPskFormat%d", wlan_id);
   			strVal = websGetVar(wp, varName, T(""));
			if (!strVal[0]) {
				printf("Error! no psk format.\n");	//Added by Jerry
	 			strcpy(tmpBuf, T("Error! no psk format."));
				goto setErr_encrypt;
			}
			intVal = strVal[0] - '0';
			if (intVal != 0 && intVal != 1) {
				printf("Error! invalid psk format.\n");	//Added by Jerry
	 			strcpy(tmpBuf, T("Error! invalid psk format."));
				goto setErr_encrypt;
			}

			// remember current psk format and length to compare to default case "****"
			apmib_get(MIB_WLAN_WAPI_PSK_FORMAT, (void *)&oldFormat);
			apmib_get(MIB_WLAN_WPA_PSK, (void *)tmpBuf);
			oldPskLen = strlen(tmpBuf);

			sprintf(varName, "wapiPskValue%d", wlan_id);
			strVal = websGetVar(wp, varName, T(""));
			len = strlen(strVal);

			if (oldFormat == intVal && len == oldPskLen ) {
				for (i=0; i<len; i++) {
					if ( strVal[i] != '*' )
						break;
				}
				if (i == len)
					goto wapi_end;
			}

			if ( apmib_set(MIB_WLAN_WAPI_PSK_FORMAT, (void *)&intVal) == 0) {
				printf("Set MIB_WLAN_PSK_FORMAT failed!\n");	//Added by Jerry
				strcpy(tmpBuf, T("Set MIB_WLAN_PSK_FORMAT failed!"));
				goto setErr_encrypt;
			}

			if (intVal==1) { // hex
				if (/*len!=MAX_PSK_LEN ||*/!string_to_hex(strVal, tmpBuf, MAX_PSK_LEN)) {
					printf("Error! invalid psk value.\n");	//Added by Jerry
	 				strcpy(tmpBuf, T("Error! invalid psk value."));
					goto setErr_encrypt;
				}
				if(0 ==(len % 2))
				{
					len = len/2;
				}
				else
				{
					/*wapi hex key len should be even*/
					printf("Error! invalid psk len.\n");	//Added by Jerry
					strcpy(tmpBuf, T("Error! invalid psk len."));
					goto setErr_encrypt;
				}					
				if(!apmib_set(MIB_WLAN_WAPI_PSKLEN,(void*)&len))
				{
					printf("Error! Set wapi key len fault\n");	//Added by Jerry
					strcpy(tmpBuf,T("Error! Set wapi key len fault"));
				}
			}
			else { // passphras
				if (len==0 || len > (MAX_PSK_LEN-1) ) {
					printf("Error! invalid psk value.\n");	//Added by Jerry
	 				strcpy(tmpBuf, T("Error! invalid psk value."));
					goto setErr_encrypt;
				}
				if(!apmib_set(MIB_WLAN_WAPI_PSKLEN,(void*)&len))
				{
					printf("Error! Set wapi key len fault\n");	//Added by Jerry
					strcpy(tmpBuf,T("Error! Set wapi key len fault"));
				}
			}
			if ( !apmib_set(MIB_WLAN_WAPI_PSK, (void *)strVal)) {
				printf("Set MIB_WLAN_WPA_PSK error!\n");	//Added by Jerry
				strcpy(tmpBuf, T("Set MIB_WLAN_WPA_PSK error!"));
				goto setErr_encrypt;
			}
		}
	wapi_end:
		/*save AS IP*/
		if(1==enableAS)
		{ 
			int old_vwlan_idx,i;
			sprintf(varName, "wapiASIP%d", wlan_id);
			strVal = websGetVar(wp, varName, T(""));
			if (!strVal[0]) {
				printf("No WAPI AS address!\n");	//Added by Jerry
				strcpy(tmpBuf, T("No WAPI AS address!"));
				goto setErr_encrypt;
			}
			if ( !inet_aton(strVal, &inIp) ) {
				printf("Invalid AS IP-address value!\n");	//Added by Jerry
				strcpy(tmpBuf, T("Invalid AS IP-address value!"));
				goto setErr_encrypt;
			}

			// To record old vwlan_idx
			old_vwlan_idx=vwlan_idx;
			// Set current MIB_WLAN_WAPI_ASIPADDR to all wlan interfaces
			// root wlan interface and virtual wlan interface
			for(i=0;i<NUM_VWLAN_INTERFACE+1;i++)
			{
				vwlan_idx=i;
				if ( !apmib_set(MIB_WLAN_WAPI_ASIPADDR, (void *)&inIp)) {
					printf("Set RS IP-address error!\n");	//Added by Jerry
					strcpy(tmpBuf, T("Set RS IP-address error!"));
					goto setErr_encrypt;
				}	
			}
			// Back to old vwlan_idx
			vwlan_idx=old_vwlan_idx;
		}
	}
#endif
	else {
		// support nonWPA client

		sprintf(varName, "nonWpaSupp%d", wlan_id);
 		strVal = websGetVar(wp, varName, T(""));
		apmib_get( MIB_WLAN_ENABLE_SUPP_NONWPA, (void *)&intVal);
		if(strVal[0])
		{
		if ( !gstrcmp(strVal, T("ON")))
			intVal = 1;
		else
			intVal = 0;
		}
		if ( apmib_set( MIB_WLAN_ENABLE_SUPP_NONWPA, (void *)&intVal) == 0) {
			printf("Set MIB_WLAN_ENABLE_SUPP_NONWPA mib error!\n");	//Added by Jerry
  			strcpy(tmpBuf, T("Set MIB_WLAN_ENABLE_SUPP_NONWPA mib error!"));
			goto setErr_encrypt;
		}
		if ( intVal ) {
			suppNonWPA = SUPP_NONWPA_NONE;
			sprintf(varName, "nonWpaWep%d", wlan_id);
			strVal = websGetVar(wp, varName, T(""));
			if ( !gstrcmp(strVal, T("ON")))
				suppNonWPA |= SUPP_NONWPA_WEP;

			sprintf(varName, "nonWpa1x%d", wlan_id);
			strVal = websGetVar(wp, varName, T(""));
			if ( !gstrcmp(strVal, T("ON"))) {
				suppNonWPA |= SUPP_NONWPA_1X;
				enableRS = 1;
			}

			if ( apmib_set( MIB_WLAN_SUPP_NONWPA, (void *)&suppNonWPA) == 0) {
				printf("Set MIB_WLAN_SUPP_NONWPA mib error!\n");	//Added by Jerry
  				strcpy(tmpBuf, T("Set MIB_WLAN_SUPP_NONWPA mib error!"));
				goto setErr_encrypt;
			}
		}

		// WPA authentication
		sprintf(varName, "wpaAuth%d", wlan_id);
		strVal = websGetVar(wp, varName, T(""));
		if (strVal[0]) {
			if ( !gstrcmp(strVal, T("eap"))) {
				apmib_get( MIB_WLAN_MODE, (void *)&intVal);
#ifndef TLS_CLIENT
				if (intVal!=AP_MODE && intVal!=AP_WDS_MODE) { // not AP mode
#ifdef CONFIG_RTL_802_1X_CLIENT_SUPPORT
					if(intVal == CLIENT_MODE){//client mode
//						printf("%s(%d): WPA-RADIUS can be used when device is set to client mode\n",__FUNCTION__,__LINE__);//Added for test 
					}
					else{
						printf("Error! WPA-RADIUS cannot be used when device is set to wds or mesh mode.\n");	//Added by Jerry
						strcpy(tmpBuf, T("Error! WPA-RADIUS cannot be used when device is set to wds or mesh mode."));
						goto setErr_encrypt;
					}
						
#else
					printf("Error! WPA-RADIUS cannot be used when device is set to client mode.\n");	//Added by Jerry
					strcpy(tmpBuf, T("Error! WPA-RADIUS cannot be used when device is set to client mode."));
					goto setErr_encrypt;
#endif
				}
#endif
				intVal = WPA_AUTH_AUTO;
				enableRS = 1;
			}
			else if ( !gstrcmp(strVal, T("psk"))) {
				intVal = WPA_AUTH_PSK;
				getPSK = 1;

			}
			else {
				printf("Error! Invalid wpa authentication value.\n");	//Added by Jerry
				strcpy(tmpBuf, T("Error! Invalid wpa authentication value."));
				goto setErr_encrypt;
			}
			if ( apmib_set(MIB_WLAN_WPA_AUTH, (void *)&intVal) == 0) {
				printf("Set MIB_WLAN_AUTH_TYPE failed!\n");	//Added by Jerry
				strcpy(tmpBuf, T("Set MIB_WLAN_AUTH_TYPE failed!"));
				goto setErr_encrypt;
			}
		}

		// cipher suite		
		// sc_yang write the ciphersuite according to  encrypt for wpa
		// wpa mixed mode is not implemented yet.
		
// get cipher suite from user setting, for wpa-aes -------------------		
#if 0				
		intVal = 0 ;
		if( (encrypt ==  ENCRYPT_WPA) || (encrypt == ENCRYPT_WPA2_MIXED) )
			intVal =   WPA_CIPHER_TKIP ;
		if ( apmib_set(MIB_WLAN_WPA_CIPHER_SUITE, (void *)&intVal) == 0) {
				strcpy(tmpBuf, T("Set MIB_WLAN_WPA_CIPHER_SUITE failed!"));
				goto setErr_encrypt;
		}
		//set wpa2UniCipher  for wpa2
		// wpa2 mixed mode is not implemented yet.
		intVal = 0 ;
		if( (encrypt ==  ENCRYPT_WPA2) || (encrypt == ENCRYPT_WPA2_MIXED) )
			intVal =   WPA_CIPHER_AES ;
		if ( apmib_set(MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&intVal) == 0) {
				strcpy(tmpBuf, T("Set MIB_WLAN_WPA2_UNICIPHER failed!"));
				goto setErr_encrypt;
		}
#endif	
		if ((encrypt == ENCRYPT_WPA) || (encrypt == ENCRYPT_WPA2_MIXED)) {
			sprintf(varName, "ciphersuite%d", wlan_id);
			strVal = websGetVar(wp, varName, T(""));	 	
			if (strVal[0]) {
				intVal = 0;				
				if ( gstrstr(strVal, T("tkip"))) 
					intVal |= WPA_CIPHER_TKIP;
				if ( gstrstr(strVal, T("aes"))) 
					intVal |= WPA_CIPHER_AES;
				if (intVal == 0) {
					printf("Invalid value of cipher suite!\n");	//Added by Jerry
					strcpy(tmpBuf, T("Invalid value of cipher suite!"));
					goto setErr_encrypt;
				}
			}
			else{
				int band_value=0;
				 apmib_get( MIB_WLAN_BAND, (void *)&band_value);
				 if(band_value == 10 || band_value ==11)
				 	intVal = WPA_CIPHER_AES;	
				 else
					intVal = WPA_CIPHER_TKIP;	
			}

			// check if both TKIP and AES cipher are selected in client mode
			apmib_get(MIB_WLAN_MODE, (void *)&val);
			if (val == CLIENT_MODE) {
				apmib_get(MIB_WLAN_NETWORK_TYPE, &val);
				if (val == INFRASTRUCTURE && intVal == WPA_CIPHER_MIXED) {
					printf("Error! Can't set cipher to TKIP + AES when device is set to client mode.\n");	//Added by Jerry
					strcpy(tmpBuf, T("Error! Can't set cipher to TKIP + AES when device is set to client mode."));
					goto setErr_encrypt;							
				}
			}	// david+2006-1-11
					
			if ( apmib_set(MIB_WLAN_WPA_CIPHER_SUITE, (void *)&intVal) == 0) {
				printf("Set MIB_WLAN_WPA_CIPHER_SUITE failed!\n");	//Added by Jerry
				strcpy(tmpBuf, T("Set MIB_WLAN_WPA_CIPHER_SUITE failed!"));
				goto setErr_encrypt;							
			}				
		}		
		if ((encrypt == ENCRYPT_WPA2) || (encrypt == ENCRYPT_WPA2_MIXED)) {
			sprintf(varName, "wpa2ciphersuite%d", wlan_id);
			strVal = websGetVar(wp, varName, T(""));	 	
			if (strVal[0]) {
				intVal = 0;				
				if ( gstrstr(strVal, T("tkip"))) 
					intVal |= WPA_CIPHER_TKIP;
				if ( gstrstr(strVal, T("aes"))) 
					intVal |= WPA_CIPHER_AES;
				if (intVal == 0) {
					printf("Invalid value of wpa2 cipher suite!\n");	//Added by Jerry
					strcpy(tmpBuf, T("Invalid value of wpa2 cipher suite!"));
					goto setErr_encrypt;
				}
			}
			else
				intVal = WPA_CIPHER_AES;			

			// check if both TKIP and AES cipher are selected in client mode
			apmib_get(MIB_WLAN_MODE, (void *)&val);
			if (val == CLIENT_MODE) {
				apmib_get(MIB_WLAN_NETWORK_TYPE, &val);
				if (val == INFRASTRUCTURE && intVal == WPA_CIPHER_MIXED) {
					printf("Error! Can't set cipher to TKIP + AES when device is set to client mode.\n");	//Added by Jerry
					strcpy(tmpBuf, T("Error! Can't set cipher to TKIP + AES when device is set to client mode."));
					goto setErr_encrypt;							
				}
			}	// david+2006-1-11
				
			if ( apmib_set(MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&intVal) == 0) {
				printf("Set MIB_WLAN_WPA2_CIPHER_SUITE failed!\n");	//Added by Jerry
				strcpy(tmpBuf, T("Set MIB_WLAN_WPA2_CIPHER_SUITE failed!"));
				goto setErr_encrypt;							
			}
		}
//-------------------------------------------------- david, 2005-8-03	
	
		if( ((encrypt ==  ENCRYPT_WPA2) || (encrypt == ENCRYPT_WPA2_MIXED)) &&
		    enableRS == 1){
			sprintf(varName, "preAuth%d", wlan_id);
			strVal = websGetVar(wp, varName, T(""));
			if ( !gstrcmp(strVal, T("ON")))
				intVal = 1 ;
			else
				intVal = 0 ;
			if ( apmib_set(MIB_WLAN_WPA2_PRE_AUTH, (void *)&intVal) == 0) {
				printf("Set MIB_WLAN_WPA_CIPHER_SUITE failed!\n");	//Added by Jerry
				strcpy(tmpBuf, T("Set MIB_WLAN_WPA_CIPHER_SUITE failed!"));
				goto setErr_encrypt;
			}					
		}

		// pre-shared key
		if ( getPSK ) {
			int oldFormat, oldPskLen, i;

			sprintf(varName, "pskFormat%d", wlan_id);
   			strVal = websGetVar(wp, varName, T(""));
			if (!strVal[0]) {
				printf("Error! no psk format.!\n");	//Added by Jerry
	 			strcpy(tmpBuf, T("Error! no psk format."));
				goto setErr_encrypt;
			}
			intVal = strVal[0] - '0';
			if (intVal != 0 && intVal != 1) {
				printf("Error! invalid psk format.!\n");	//Added by Jerry
	 			strcpy(tmpBuf, T("Error! invalid psk format."));
				goto setErr_encrypt;
			}

			// remember current psk format and length to compare to default case "****"
			apmib_get(MIB_WLAN_PSK_FORMAT, (void *)&oldFormat);
			apmib_get(MIB_WLAN_WPA_PSK, (void *)tmpBuf);
			oldPskLen = strlen(tmpBuf);

			sprintf(varName, "pskValue%d", wlan_id);
			strVal = websGetVar(wp, varName, T(""));
			len = strlen(strVal);

			if (oldFormat == intVal && len == oldPskLen ) {
				for (i=0; i<len; i++) {
					if ( strVal[i] != '*' )
						break;
				}
				if (i == len)
					goto rekey_time;
			}

			if ( apmib_set(MIB_WLAN_PSK_FORMAT, (void *)&intVal) == 0) {
				printf("Set MIB_WLAN_PSK_FORMAT failed!\n");	//Added by Jerry
				strcpy(tmpBuf, T("Set MIB_WLAN_PSK_FORMAT failed!"));
				goto setErr_encrypt;
			}

			if (intVal==1) { // hex
				if (len!=MAX_PSK_LEN || !string_to_hex(strVal, tmpBuf, MAX_PSK_LEN)) {
					printf("Error! invalid psk value.\n");	//Added by Jerry
	 				strcpy(tmpBuf, T("Error! invalid psk value."));
					goto setErr_encrypt;
				}
			}
			else { // passphras
				if (len==0 || len > (MAX_PSK_LEN-1) ) {
					printf("Error! invalid psk value.\n");	//Added by Jerry
	 				strcpy(tmpBuf, T("Error! invalid psk value."));
					goto setErr_encrypt;
				}
			}
			if ( !apmib_set(MIB_WLAN_WPA_PSK, (void *)strVal)) {
				printf("Set MIB_WLAN_WPA_PSK error!\n");	//Added by Jerry
				strcpy(tmpBuf, T("Set MIB_WLAN_WPA_PSK error!"));
				goto setErr_encrypt;
			}
		}
rekey_time:
		// group key rekey time
		reKeyTime = 0;
		sprintf(varName, "groupKeyTimeDay%d", wlan_id);
		strVal = websGetVar(wp, varName, T(""));
		if (strVal[0]) {
			if ( !string_to_dec(strVal, &intVal) ) {
				printf("Error! Invalid value of rekey day.\n");	//Added by Jerry
				strcpy(tmpBuf, T("Error! Invalid value of rekey day."));
				goto setErr_encrypt;
			}
			reKeyTime += intVal*86400;
		}
		sprintf(varName, "groupKeyTimeHr%d", wlan_id);
		strVal = websGetVar(wp, varName, T(""));
		if (strVal[0]) {
			if ( !string_to_dec(strVal, &intVal) ) {
				printf("Error! Invalid value of rekey hr.\n");	//Added by Jerry
				strcpy(tmpBuf, T("Error! Invalid value of rekey hr."));
				goto setErr_encrypt;
			}
			reKeyTime += intVal*3600;
		}
		sprintf(varName, "groupKeyTimeMin%d", wlan_id);
		strVal = websGetVar(wp, varName, T(""));
		if (strVal[0]) {
			if ( !string_to_dec(strVal, &intVal) ) {
				printf("Error! Invalid value of rekey min.\n");	//Added by Jerry
				strcpy(tmpBuf, T("Error! Invalid value of rekey min."));
				goto setErr_encrypt;
			}
			reKeyTime += intVal*60;
		}

		sprintf(varName, "groupKeyTimeSec%d", wlan_id);
		strVal = websGetVar(wp, varName, T(""));
		if (strVal[0]) {
			if ( !string_to_dec(strVal, &intVal) ) {
				printf("Error! Invalid value of rekey sec.\n");	//Added by Jerry
				strcpy(tmpBuf, T("Error! Invalid value of rekey sec."));
				goto setErr_encrypt;
			}
			reKeyTime += intVal;
		}
		if (reKeyTime) {
			if ( !apmib_set(MIB_WLAN_WPA_GROUP_REKEY_TIME, (void *)&reKeyTime)) {
				printf("Set MIB_WLAN_WPA_GROUP_REKEY_TIME error!\n");	//Added by Jerry
				strcpy(tmpBuf, T("Set MIB_WLAN_WPA_GROUP_REKEY_TIME error!"));
				goto setErr_encrypt;
			}
		}
	}

	if (enableRS == 1) { // if 1x enabled, get RADIUS server info
#ifdef CONFIG_RTL_802_1X_CLIENT_SUPPORT
		apmib_get( MIB_WLAN_MODE, (void *)&wlan_mode);
		if (wlan_mode == CLIENT_MODE) { // wlan client mode
			sprintf(varName, "eapType%d", wlan_id);
			strVal = websGetVar(wp, varName, T(""));
			if (strVal[0]) {
				if ( !string_to_dec(strVal, &intVal) ) {
					printf("Invalid 802.1x EAP type value!\n");	//Added by Jerry
					strcpy(tmpBuf, T("Invalid 802.1x EAP type value!"));
					goto setErr_encrypt;
				}
				if ( !apmib_set(MIB_WLAN_EAP_TYPE, (void *)&intVal)) {
					printf("Set MIB_WLAN_EAP_TYPE error!\n");	//Added by Jerry
					strcpy(tmpBuf, T("Set MIB_WLAN_EAP_TYPE error!"));
					goto setErr_encrypt;
				}
			}
			else{
				printf("No 802.1x EAP User ID!\n");	//Added by Jerry
				strcpy(tmpBuf, T("No 802.1x EAP type!"));
				goto setErr_encrypt;
			}

			if(intVal == EAP_MD5){
				sprintf(varName, "eapUserId%d", wlan_id);
				strVal = websGetVar(wp, varName, T(""));
				if (strVal[0]) {
					if(strlen(strVal)>MAX_EAP_USER_ID_LEN){
						printf("EAP user ID too long!\n");	//Added by Jerry
						strcpy(tmpBuf, T("EAP user ID too long!"));
						goto setErr_encrypt;
					}
					if ( !apmib_set(MIB_WLAN_EAP_USER_ID, (void *)strVal)) {
						printf("Set MIB_WLAN_EAP_USER_ID error!\n");	//Added by Jerry
						strcpy(tmpBuf, T("Set MIB_WLAN_EAP_USER_ID error!"));
						goto setErr_encrypt;
					}
				}
				else{
					printf("No 802.1x EAP User ID!\n");	//Added by Jerry
					strcpy(tmpBuf, T("No 802.1x EAP User ID!"));
					goto setErr_encrypt;
				}
				
				sprintf(varName, "radiusUserName%d", wlan_id);
				strVal = websGetVar(wp, varName, T(""));
				if (strVal[0]) {
					if(strlen(strVal)>MAX_RS_USER_NAME_LEN){
						printf("RADIUS user name too long!\n");	//Added by Jerry
						strcpy(tmpBuf, T("RADIUS user name too long!"));
						goto setErr_encrypt;
					}
					if ( !apmib_set(MIB_WLAN_RS_USER_NAME, (void *)strVal)) {
						printf("Set MIB_WLAN_RS_USER_NAME error!\n");	//Added by Jerry
						strcpy(tmpBuf, T("Set MIB_WLAN_RS_USER_NAME error!"));
						goto setErr_encrypt;
					}
				}
				else{
					printf("No 802.1x RADIUS User Name!\n");	//Added by Jerry
					strcpy(tmpBuf, T("No 802.1x RADIUS User Name!"));
					goto setErr_encrypt;
				}

				sprintf(varName, "radiusUserPass%d", wlan_id);
				strVal = websGetVar(wp, varName, T(""));
				if (strVal[0]) {
					if(strlen(strVal)>MAX_RS_USER_PASS_LEN){
						printf("RADIUS user password too long!\n");	//Added by Jerry
						strcpy(tmpBuf, T("RADIUS user password too long!"));
						goto setErr_encrypt;
					}
					if ( !apmib_set(MIB_WLAN_RS_USER_PASSWD, (void *)strVal)) {
						printf("Set MIB_WLAN_RS_USER_PASSWD error!\n");	//Added by Jerry
						strcpy(tmpBuf, T("Set MIB_WLAN_RS_USER_PASSWD error!"));
						goto setErr_encrypt;
					}
				}
				else{
					printf("No 802.1x RADIUS User Password!\n");	//Added by Jerry
					strcpy(tmpBuf, T("No 802.1x RADIUS User Password!"));
					goto setErr_encrypt;
				}
			}
			else if(intVal == EAP_TLS){
				sprintf(varName, "eapUserId%d", wlan_id);
				strVal = websGetVar(wp, varName, T(""));
				if (strVal[0]) {
					if(strlen(strVal)>MAX_EAP_USER_ID_LEN){
						printf("EAP user ID too long!\n");	//Added by Jerry
						strcpy(tmpBuf, T("EAP user ID too long!"));
						goto setErr_encrypt;
					}
					if ( !apmib_set(MIB_WLAN_EAP_USER_ID, (void *)strVal)) {
						printf("Set MIB_WLAN_EAP_USER_ID error!\n");	//Added by Jerry
						strcpy(tmpBuf, T("Set MIB_WLAN_EAP_USER_ID error!"));
						goto setErr_encrypt;
					}
				}
				else{
					printf("No 802.1x EAP User ID!\n");	//Added by Jerry
					strcpy(tmpBuf, T("No 802.1x EAP User ID!"));
					goto setErr_encrypt;
				}
				
				sprintf(varName, "radiusUserCertPass%d", wlan_id);
				strVal = websGetVar(wp, varName, T(""));
				if (strVal[0]) {
					if(strlen(strVal)>MAX_RS_USER_CERT_PASS_LEN){
						printf("RADIUS user cert password too long!\n");	//Added by Jerry
						strcpy(tmpBuf, T("RADIUS user cert password too long!"));
						goto setErr_encrypt;
					}
					if ( !apmib_set(MIB_WLAN_RS_USER_CERT_PASSWD, (void *)strVal)) {
						printf("Set MIB_WLAN_RS_USER_CERT_PASSWD error!\n");	//Added by Jerry
						strcpy(tmpBuf, T("Set MIB_WLAN_RS_USER_CERT_PASSWD error!"));
						goto setErr_encrypt;
					}
				}
				else{
					if ( !apmib_set(MIB_WLAN_RS_USER_CERT_PASSWD, (void *)strVal)) {
						printf("Clear MIB_WLAN_RS_USER_CERT_PASSWD error!\n");	//Added by Jerry
						strcpy(tmpBuf, T("Clear MIB_WLAN_RS_USER_CERT_PASSWD error!"));
						goto setErr_encrypt;
					}
					//strcpy(tmpBuf, T("No 802.1x RADIUS user cert password!"));
					//goto setErr_encrypt;
				}

				if(isFileExist(RS_USER_CERT) != 1){
					printf("No 802.1x RADIUS user cert!\nPlease upload it.\n");	//Added by Jerry
					strcpy(tmpBuf, T("No 802.1x RADIUS user cert!\nPlease upload it."));
					goto setErr_encrypt;
				}
				
				if(isFileExist(RS_ROOT_CERT) != 1){
					printf("No 802.1x RADIUS root cert!\nPlease upload it.\n");	//Added by Jerry
					strcpy(tmpBuf, T("No 802.1x RADIUS root cert!\nPlease upload it."));
					goto setErr_encrypt;
				}
			}
			else if(intVal == EAP_PEAP){
				sprintf(varName, "eapInsideType%d", wlan_id);
				strVal = websGetVar(wp, varName, T(""));
				if (strVal[0]) {
					if ( !string_to_dec(strVal, &intVal2) ) {
						printf("Invalid 802.1x inside tunnel type value!\n");	//Added by Jerry
						strcpy(tmpBuf, T("Invalid 802.1x inside tunnel type value!"));
						goto setErr_encrypt;
					}
					if ( !apmib_set(MIB_WLAN_EAP_INSIDE_TYPE, (void *)&intVal2)) {
						printf("Set MIB_WLAN_EAP_INSIDE_TYPE error!\n");	//Added by Jerry
						strcpy(tmpBuf, T("Set MIB_WLAN_EAP_INSIDE_TYPE error!"));
						goto setErr_encrypt;
					}
				}
				else{
					printf("No 802.1x inside tunnel type!\n");	//Added by Jerry
					strcpy(tmpBuf, T("No 802.1x inside tunnel type!"));
					goto setErr_encrypt;
				}

				if(intVal2 == INSIDE_MSCHAPV2){
					sprintf(varName, "eapUserId%d", wlan_id);
					strVal = websGetVar(wp, varName, T(""));
					if (strVal[0]) {
						if(strlen(strVal)>MAX_EAP_USER_ID_LEN){
							printf("EAP user ID too long!\n");	//Added by Jerry
							strcpy(tmpBuf, T("EAP user ID too long!"));
							goto setErr_encrypt;
						}
						if ( !apmib_set(MIB_WLAN_EAP_USER_ID, (void *)strVal)) {
							printf("Set MIB_WLAN_EAP_USER_ID error!\n");	//Added by Jerry
							strcpy(tmpBuf, T("Set MIB_WLAN_EAP_USER_ID error!"));
							goto setErr_encrypt;
						}
					}
					else{
						printf("No 802.1x EAP User ID!\n");	//Added by Jerry
						strcpy(tmpBuf, T("No 802.1x EAP User ID!"));
						goto setErr_encrypt;
					}
					
					sprintf(varName, "radiusUserName%d", wlan_id);
					strVal = websGetVar(wp, varName, T(""));
					if (strVal[0]) {
						if(strlen(strVal)>MAX_RS_USER_NAME_LEN){
							printf("RADIUS user name too long!\n");	//Added by Jerry
							strcpy(tmpBuf, T("RADIUS user name too long!"));
							goto setErr_encrypt;
						}
						if ( !apmib_set(MIB_WLAN_RS_USER_NAME, (void *)strVal)) {
							printf("Set MIB_WLAN_RS_USER_NAME error!\n");	//Added by Jerry
							strcpy(tmpBuf, T("Set MIB_WLAN_RS_USER_NAME error!"));
							goto setErr_encrypt;
						}
					}
					else{
						printf("No 802.1x RADIUS User Name!\n");	//Added by Jerry
						strcpy(tmpBuf, T("No 802.1x RADIUS User Name!"));
						goto setErr_encrypt;
					}

					sprintf(varName, "radiusUserPass%d", wlan_id);
					strVal = websGetVar(wp, varName, T(""));
					if (strVal[0]) {
						if(strlen(strVal)>MAX_RS_USER_PASS_LEN){
							printf("RADIUS user password too long!\n");	//Added by Jerry
							strcpy(tmpBuf, T("RADIUS user password too long!"));
							goto setErr_encrypt;
						}
						if ( !apmib_set(MIB_WLAN_RS_USER_PASSWD, (void *)strVal)) {
							printf("Set MIB_WLAN_RS_USER_PASSWD error!\n");	//Added by Jerry
							strcpy(tmpBuf, T("Set MIB_WLAN_RS_USER_PASSWD error!"));
							goto setErr_encrypt;
						}
					}
					else{
						printf("No 802.1x RADIUS User Password!\n");	//Added by Jerry
						strcpy(tmpBuf, T("No 802.1x RADIUS User Password!"));
						goto setErr_encrypt;
					}

//					if(isFileExist(RS_USER_CERT) == 1){
						sprintf(varName, "radiusUserCertPass%d", wlan_id);
						strVal = websGetVar(wp, varName, T(""));
						if (strVal[0]) {
							if(strlen(strVal)>MAX_RS_USER_CERT_PASS_LEN){
								printf("RADIUS user cert password too long!\n");	//Added by Jerry
								strcpy(tmpBuf, T("RADIUS user cert password too long!"));
								goto setErr_encrypt;
							}
							if ( !apmib_set(MIB_WLAN_RS_USER_CERT_PASSWD, (void *)strVal)) {
								printf("Set MIB_WLAN_RS_USER_CERT_PASSWD error!\n");	//Added by Jerry
								strcpy(tmpBuf, T("Set MIB_WLAN_RS_USER_CERT_PASSWD error!"));
								goto setErr_encrypt;
							}
						}
						else{
							if ( !apmib_set(MIB_WLAN_RS_USER_CERT_PASSWD, (void *)strVal)) {
								printf("[1] Clear MIB_WLAN_RS_USER_CERT_PASSWD error!\n");	//Added by Jerry
								strcpy(tmpBuf, T("[1] Clear MIB_WLAN_RS_USER_CERT_PASSWD error!"));
								goto setErr_encrypt;
							}
							//strcpy(tmpBuf, T("No 802.1x RADIUS user cert password!"));
							//goto setErr_encrypt;
						}
//					}
				}
				else{
					printf("802.1x inside tunnel type not support!\n");	//Added by Jerry
					strcpy(tmpBuf, T("802.1x inside tunnel type not support!"));
					goto setErr_encrypt;
				}
			}
			else{
				printf("802.1x EAP type not support!\n");	//Added by Jerry
				strcpy(tmpBuf, T("802.1x EAP type not support!"));
				goto setErr_encrypt;
			}
		}
		else
#endif
		{
		sprintf(varName, "radiusPort%d", wlan_id);
		strVal = websGetVar(wp, varName, T(""));
		if (!strVal[0]) {
			printf("No RS port number!\n");	//Added by Jerry
			strcpy(tmpBuf, T("No RS port number!"));
			goto setErr_encrypt;
		}
		if (!string_to_dec(strVal, &intVal) || intVal<=0 || intVal>65535) {
			printf("Error! Invalid value of RS port number.\n");	//Added by Jerry
			strcpy(tmpBuf, T("Error! Invalid value of RS port number."));
			goto setErr_encrypt;
		}
		if ( !apmib_set(MIB_WLAN_RS_PORT, (void *)&intVal)) {
			printf("Set RS port error!\n");	//Added by Jerry
			strcpy(tmpBuf, T("Set RS port error!"));
			goto setErr_encrypt;
		}
		sprintf(varName, "radiusIP%d", wlan_id);
		strVal = websGetVar(wp, varName, T(""));
		if (!strVal[0]) {
			printf("No RS IP address!\n");	//Added by Jerry
			strcpy(tmpBuf, T("No RS IP address!"));
			goto setErr_encrypt;
		}
		if ( !inet_aton(strVal, &inIp) ) {
			printf("Invalid RS IP-address value!\n");	//Added by Jerry
			strcpy(tmpBuf, T("Invalid RS IP-address value!"));
			goto setErr_encrypt;
		}
		if ( !apmib_set(MIB_WLAN_RS_IP, (void *)&inIp)) {
			printf("Set RS IP-address error!\n");	//Added by Jerry
			strcpy(tmpBuf, T("Set RS IP-address error!"));
			goto setErr_encrypt;
		}
		sprintf(varName, "radiusPass%d", wlan_id);
		strVal = websGetVar(wp, varName, T(""));
		if (strlen(strVal) > (MAX_RS_PASS_LEN -1) ) {
			printf("RS password length too long!\n");	//Added by Jerry
			strcpy(tmpBuf, T("RS password length too long!"));
			goto setErr_encrypt;
		}
		if ( !apmib_set(MIB_WLAN_RS_PASSWORD, (void *)strVal)) {
			printf("Set RS password error!\n");	//Added by Jerry
			strcpy(tmpBuf, T("Set RS password error!"));
			goto setErr_encrypt;
		}

		sprintf(varName, "radiusRetry%d", wlan_id);
		strVal = websGetVar(wp, varName, T(""));
		if (strVal[0]) {
			if ( !string_to_dec(strVal, &intVal) ) {
				printf("Invalid RS retry value!\n");	//Added by Jerry
				strcpy(tmpBuf, T("Invalid RS retry value!"));
				goto setErr_encrypt;
			}
			if ( !apmib_set(MIB_WLAN_RS_MAXRETRY, (void *)&intVal)) {
				printf("Set MIB_WLAN_RS_MAXRETRY error!\n");	//Added by Jerry
				strcpy(tmpBuf, T("Set MIB_WLAN_RS_MAXRETRY error!"));
				goto setErr_encrypt;
			}
		}
		sprintf(varName, "radiusTime%d", wlan_id);
		strVal = websGetVar(wp, varName, T(""));
		if (strVal[0]) {
			if ( !string_to_dec(strVal, &intVal) ) {
				printf("Invalid RS time value!\n");	//Added by Jerry
				strcpy(tmpBuf, T("Invalid RS time value!"));
				goto setErr_encrypt;
			}
			if ( !apmib_set(MIB_WLAN_RS_INTERVAL_TIME, (void *)&intVal)) {
				printf("Set MIB_WLAN_RS_INTERVAL_TIME error!\n");	//Added by Jerry
				strcpy(tmpBuf, T("Set MIB_WLAN_RS_INTERVAL_TIME error!"));
				goto setErr_encrypt;
			}
		}
		sprintf(varName, "useAccount%d", wlan_id);
		strVal = websGetVar(wp, varName, T(""));
		if ( !gstrcmp(strVal, T("ON")))
			intVal = 1;
		else
			intVal = 0;
		if ( apmib_set( MIB_WLAN_ACCOUNT_RS_ENABLED, (void *)&intVal) == 0) {
			printf("Set MIB_WLAN_ACCOUNT_RS_ENABLED mib error!\n");	//Added by Jerry
  			strcpy(tmpBuf, T("Set MIB_WLAN_ACCOUNT_RS_ENABLED mib error!"));
			goto setErr_encrypt;
		}
		if (intVal == 0)
			goto get_wepkey;

		sprintf(varName, "accountPort%d", wlan_id);
		strVal = websGetVar(wp, varName, T(""));
		if (!strVal[0]) {
			printf("No account RS port number!\n");	//Added by Jerry
			strcpy(tmpBuf, T("No account RS port number!"));
			goto setErr_encrypt;
		}
		if (!string_to_dec(strVal, &intVal) || intVal<=0 || intVal>65535) {
			printf("Error! Invalid value of account RS port number\n");	//Added by Jerry
			strcpy(tmpBuf, T("Error! Invalid value of account RS port number."));
			goto setErr_encrypt;
		}
		if ( !apmib_set(MIB_WLAN_ACCOUNT_RS_PORT, (void *)&intVal)) {
			printf("Set account RS port error!\n");	//Added by Jerry
			strcpy(tmpBuf, T("Set account RS port error!"));
			goto setErr_encrypt;
		}
		sprintf(varName, "accountIP%d", wlan_id);
		strVal = websGetVar(wp, varName, T(""));
		if (!strVal[0]) {
			printf("No account RS IP address!\n");	//Added by Jerry
			strcpy(tmpBuf, T("No account RS IP address!"));
			goto setErr_encrypt;
		}
		if ( !inet_aton(strVal, &inIp) ) {
			printf("Invalid account RS IP-address value!\n");	//Added by Jerry
			strcpy(tmpBuf, T("Invalid account RS IP-address value!"));
			goto setErr_encrypt;
		}
		if ( !apmib_set(MIB_WLAN_ACCOUNT_RS_IP, (void *)&inIp)) {
			printf("Set account RS IP-address error!\n");	//Added by Jerry
			strcpy(tmpBuf, T("Set account RS IP-address error!"));
			goto setErr_encrypt;
		}
		sprintf(varName, "accountPass%d", wlan_id);
		strVal = websGetVar(wp, varName, T(""));
		if (strlen(strVal) > (MAX_RS_PASS_LEN -1) ) {
			printf("Account RS password length too long\n");	//Added by Jerry
			strcpy(tmpBuf, T("Account RS password length too long!"));
			goto setErr_encrypt;
		}
		if ( !apmib_set(MIB_WLAN_ACCOUNT_RS_PASSWORD, (void *)strVal)) {
			printf("Set account RS password error!\n");	//Added by Jerry
			strcpy(tmpBuf, T("Set account RS password error!"));
			goto setErr_encrypt;
		}
		sprintf(varName, "accountRetry%d", wlan_id);
		strVal = websGetVar(wp, varName, T(""));
		if (strVal[0]) {
			if ( !string_to_dec(strVal, &intVal) ) {
				printf("Invalid account RS retry value!\n");	//Added by Jerry
				strcpy(tmpBuf, T("Invalid account RS retry value!"));
				goto setErr_encrypt;
			}
			if ( !apmib_set(MIB_WLAN_ACCOUNT_RS_MAXRETRY, (void *)&intVal)) {
				printf("Set MIB_WLAN_ACCOUNT_RS_MAXRETRY error!\n");	//Added by Jerry
				strcpy(tmpBuf, T("Set MIB_WLAN_ACCOUNT_RS_MAXRETRY error!"));
				goto setErr_encrypt;
			}
		}
		sprintf(varName, "accountTime%d", wlan_id);
		strVal = websGetVar(wp, varName, T(""));
		if (strVal[0]) {
			if ( !string_to_dec(strVal, &intVal) ) {
				printf("Invalid account RS time value!\n");	//Added by Jerry
				strcpy(tmpBuf, T("Invalid account RS time value!"));
				goto setErr_encrypt;
			}
			if ( !apmib_set(MIB_WLAN_ACCOUNT_RS_INTERVAL_TIME, (void *)&intVal)) {
				printf("Set MIB_WLAN_ACCOUNT_RS_INTERVAL_TIME error!\n");	//Added by Jerry
				strcpy(tmpBuf, T("Set MIB_WLAN_ACCOUNT_RS_INTERVAL_TIME error!"));
				goto setErr_encrypt;
			}
		}
		sprintf(varName, "accountUpdateEnabled%d", wlan_id);
		strVal = websGetVar(wp, varName, T(""));
		if ( !gstrcmp(strVal, T("ON")))
			intVal = 1;
		else
			intVal = 0;
		if ( apmib_set( MIB_WLAN_ACCOUNT_RS_UPDATE_ENABLED, (void *)&intVal) == 0) {
			printf("Set MIB_WLAN_ACCOUNT_RS_UPDATE_ENABLED mib error!\n");	//Added by Jerry
			strcpy(tmpBuf, T("Set MIB_WLAN_ACCOUNT_RS_UPDATE_ENABLED mib error!"));
			goto setErr_encrypt;
		}
		sprintf(varName, "accountUpdateTime%d", wlan_id);
		strVal = websGetVar(wp, varName, T(""));
		if (strVal[0]) {
			if ( !string_to_dec(strVal, &intVal) ) {
				printf("Error! Invalid value of update time\n");	//Added by Jerry
				strcpy(tmpBuf, T("Error! Invalid value of update time"));
				goto setErr_encrypt;
			}
			if ( !apmib_set(MIB_WLAN_ACCOUNT_RS_UPDATE_DELAY, (void *)&intVal)) {
				printf("Set MIB_WLAN_ACCOUNT_RS_UPDATE_DELAY mib error!\n");	//Added by Jerry
				strcpy(tmpBuf, T("Set MIB_WLAN_ACCOUNT_RS_UPDATE_DELAY mib error!"));
				goto setErr_encrypt;
			}
		}

get_wepkey:
		// get 802.1x WEP key length
		sprintf(varName, "wepKeyLen%d", wlan_id);
		strVal = websGetVar(wp, varName, T(""));
		if (strVal[0]) {
			if ( !gstrcmp(strVal, T("wep64")))
				intVal = WEP64;
			else if ( !gstrcmp(strVal, T("wep128")))
				intVal = WEP128;
			else {
				printf("Error! Invalid wepkeylen value!\n");	//Added by Jerry
				strcpy(tmpBuf, T("Error! Invalid wepkeylen value."));
				goto setErr_encrypt;
			}
			if ( apmib_set(MIB_WLAN_WEP, (void *)&intVal) == 0) {
				printf("Set MIB_WLAN_WEP failed!\n");	//Added by Jerry
				strcpy(tmpBuf, T("Set MIB_WLAN_WEP failed!"));
				goto setErr_encrypt;
			}
		}
	}
	}

#ifdef WIFI_SIMPLE_CONFIG
#ifdef MBSSID
	if (vwlan_idx == 0)
#endif
	{
		sprintf(varName, "wps_clear_configure_by_reg%d", wlan_id);
		strVal = websGetVar(wp, varName, NULL);
		val = 0;
		if (strVal[0])
			val = atoi(strVal);
		update_wps_configured(val);
	}
#endif

#if defined(UNIVERSAL_REPEATER) && defined(CONFIG_REPEATER_WPS_SUPPORT)
	if (vwlan_idx == NUM_VWLAN_INTERFACE)
	{
		sprintf(varName, "wps_clear_configure_by_reg%d", wlan_id);
		strVal = websGetVar(wp, varName, NULL);
		val = 0;
		if (strVal[0])
			val = atoi(strVal);
		update_wps_configured(val);
	}
#endif

	return 0 ;
setErr_encrypt:
	return -1 ;		
}	
/////////////////////////////////////////////////////////////////////////////
void formWlEncrypt(webs_t wp, char_t *path, char_t *query)
{
	char_t *submitUrl;
	char tmpBuf[100];
//#if  0
//mars add begain
	printf("in formwlsetup\n");
	int mode=-1;
	int warn=0;
	
#if defined(CONFIG_RTL_92D_SUPPORT)
	int wlanif=0;
	
	PHYBAND_TYPE_T phyBandSelect = PHYBAND_OFF; 
	int wlanBand2G5GSelect=PHYBAND_OFF;
#endif
//displayPostDate(wp->postData);	

#if defined(CONFIG_RTL_92D_SUPPORT)		
	apmib_get(MIB_WLAN_BAND2G5G_SELECT,(void *)&wlanBand2G5GSelect);
	
	if(wlanBand2G5GSelect == BANDMODESINGLE)
	{
		char_t *strVal=NULL;
		
		strVal=websGetVar(wp,T("Band2G5GSupport"),T(""));
		if(strVal[0])
		{
			
			phyBandSelect= atoi(strVal);		
			wlanif = whichWlanIfIs(phyBandSelect);			
				

			if(wlanif != 0)
			{
				int val;
				val = 1;
				apmib_set(MIB_WLAN_WLAN_DISABLED, (void *)&val); //close original interface
				
				swapWlanMibSetting(0,wlanif);
				
				val = 0;
				apmib_set(MIB_WLAN_WLAN_DISABLED, (void *)&val); //enable after interface
				//apmib_update_web(CURRENT_SETTING);
			}
		}
	}
#endif //#if defined(CONFIG_RTL_92D_SUPPORT)

	if(wlanHandler(wp, tmpBuf, &mode, wlan_idx) < 0)
		goto setErr_wlan ;
	if (mode == 1) { // not AP mode
		//set cipher suit to AES and encryption to wpa2 only if wpa2 mixed mode is set
		ENCRYPT_T encrypt;
		int intVal;
		apmib_get( MIB_WLAN_ENCRYPT, (void *)&encrypt);
		if(encrypt == ENCRYPT_WPA2_MIXED){
			intVal =   WPA_CIPHER_AES ;
			if ( apmib_set(MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&intVal) == 0) {
				strcpy(tmpBuf, T("Set MIB_WLAN_WPA2_UNICIPHER failed!"));
				goto setErr_wlan;
			}
			encrypt = ENCRYPT_WPA2;
			if ( apmib_set(MIB_WLAN_ENCRYPT, (void *)&encrypt) == 0) {
				strcpy(tmpBuf, T("Set MIB_WLAN_WPA2_UNICIPHER failed!"));
				goto setErr_wlan;
			}

			intVal =   0;
			if ( apmib_set(MIB_WLAN_WPA_CIPHER_SUITE, (void *)&intVal) == 0) {
				strcpy(tmpBuf, T("Set MIB_WLAN_WPA_CIPHER_SUITE failed!"));
				goto setErr_wlan;
			}
			strcpy(tmpBuf, T("Warning! WPA2 Mixed encryption is not supported in client Mode. <BR> Change to WPA2 Encryption."));
			warn = 1;
		}
	}
	printf("end formwlsetup\n");
//mars add end
//#endif
	
#ifdef MBSSID	
	printf("in enc\n");
	char_t *strEncrypt, *strVal, *strVal1;
	char varName[40];
	int ssid_idx, old_idx=-1;

   	strVal1 = websGetVar(wp, "wlan_ssid_id", T(""));
   	strVal = websGetVar(wp, "SSID_Setting", T(""));
		
	if (strVal[0]) {
		ssid_idx = atoi(strVal);
		if (ssid_idx > NUM_VWLAN_INTERFACE) {			
			printf("Invald ssid_id!\n");
			return;
		}			
		mssid_idx = atoi(strVal1); // selected index from UI
		old_idx = vwlan_idx;
		vwlan_idx = ssid_idx;
	
		sprintf(varName, "method%d", wlan_idx);
	   	strEncrypt = websGetVar(wp, varName, T(""));
		ENCRYPT_T encrypt = (ENCRYPT_T) strEncrypt[0] - '0';

		if (encrypt==ENCRYPT_WEP) {
			char_t *strAuth = websGetVar(wp, T("authType"), T(""));
			AUTH_TYPE_T authType;
			if (strAuth[0]) { // new UI
				if (!gstrcmp(strAuth, T("open")))
					authType = AUTH_OPEN;
				else if ( !gstrcmp(strAuth, T("shared")))
					authType = AUTH_SHARED;
				else 
					authType = AUTH_BOTH;
				apmib_set(MIB_WLAN_AUTH_TYPE, (void *)&authType);

				sprintf(varName, "use1x%d", wlan_idx);
				strVal = websGetVar(wp, varName, T(""));		
			
				if (strVal[0] && gstrcmp(strVal, T("ON"))) {
					int intVal = 0;
					apmib_set( MIB_WLAN_ENABLE_1X, (void *)&intVal);			
					formWep(wp, path, query);
					vwlan_idx = old_idx;					
					return;	
				}
			}
		}
	}
	else
			mssid_idx = 0;
#endif // MBSSID
	
	if(wpaHandler(wp, tmpBuf, wlan_idx) < 0) {
#ifdef MBSSID
		if (old_idx >= 0)
			vwlan_idx = old_idx;	
#endif		
		goto setErr_end ;
	}
	printf("end enc\n");

	apmib_update_web(CURRENT_SETTING);

//2011.04.27 Jerry {
#if 0
#ifndef NO_ACTION
	run_init_script("bridge");
#endif

	submitUrl = websGetVar(wp, T("submit-url"), T(""));   // hidden page
	//OK_MSG(submitUrl);//mars mark
	system("sysconf init gw all"); //mars add

#ifdef MBSSID
	if (old_idx >= 0)
		vwlan_idx = old_idx;	
#endif
#endif
//2011.04.27 Jerry
	return;

setErr_end:
	//ERR_MSG(tmpBuf);//mars mark
	printf("goto setErr_end!\n");//mars add

//mars add begain test
setErr_wlan:
	//ERR_MSG(tmpBuf);//mars mark
	printf("goto setErr_wlan!\n");//mars add
//mars add end test
}

#ifdef CONFIG_RTK_MESH

/////////////////////////////////////////////////////////////////////////////
int wlMeshNeighborTable(int eid, webs_t wp, int argc, char_t **argv)
{
        int nBytesSent=0;
        int nRecordCount=0;
        FILE *fh;
        char buf[512], network[100];
        char hwaddr[100],state[100],channel[100],link_rate[100],tx_pkts[10],rx_pkts[10];
        char rssi[100],establish_exp_time[100],bootseq_exp_time[100],dummy[100];

        nBytesSent += websWrite(wp, T("<tr bgcolor=\"#7F7F7F\">"
        "<td align=center width=\"17%%\"><font size=\"2\"><b>MAC Address</b></font></td>\n"
        //"<td align=center width=\"17%%\"><font size=\"2\"><b>State</b></font></td>\n"
        "<td align=center width=\"17%%\"><font size=\"2\"><b>Mode</b></font></td>\n"
        //"<td align=center width=\"17%%\"><font size=\"2\"><b>Channel</b></font></td>\n"
        "<td align=center width=\"17%%\"><font size=\"2\"><b>Tx Packets</b></font></td>\n"
	"<td align=center width=\"17%%\"><font size=\"2\"><b>Rx Packets</b></font></td>\n"
        "<td align=center width=\"17%%\"><font size=\"2\"><b>Tx Rate (Mbps)</b></font></td>\n"
        "<td align=center width=\"17%%\"><font size=\"2\"><b>RSSI</b></font></td>\n"
	"<td align=center width=\"17%%\"><font size=\"2\"><b>Expired Time (s)</b></font></td>\n"
#if defined(_11s_TEST_MODE_)
        "<td align=center width=\"17%%\"><font size=\"2\"><b>BootSeq_ept</b></font></td></tr>\n"
#endif
	));

        fh = fopen(_FILE_MESH_ASSOC, "r");
        if (!fh)
        {
		printf("Warning: cannot open %s\n",_FILE_MESH_ASSOC);
                return -1;
        }

        while( fgets(buf, sizeof buf, fh) != NULL )
        {
                if( strstr(buf,"Mesh MP_info") != NULL )
                {
                        _get_token( fh,"state: ",state );
                        _get_token( fh,"hwaddr: ",hwaddr );
			_get_token( fh,"mode: ",network );
			_get_token( fh,"Tx Packets: ",tx_pkts );
			_get_token( fh,"Rx Packets: ",rx_pkts );
                        _get_token( fh,"Authentication: ",dummy );
                        _get_token( fh,"Assocation: ",dummy );
                        _get_token( fh,"LocalLinkID: ",dummy );
                        _get_token( fh,"PeerLinkID: ",dummy );
                        _get_token( fh,"operating_CH: ", channel );
                        _get_token( fh,"CH_precedence: ", dummy );
                        _get_token( fh,"R: ", link_rate );
                        _get_token( fh,"Ept: ", dummy );
                        _get_token( fh,"rssi: ", rssi );
                        _get_token( fh,"expire_Establish(jiffies): ", dummy );
                        //_get_token( fh,"(mSec): ", establish_exp_time );
			_get_token( fh,"(Sec): ", establish_exp_time );
                        _get_token( fh,"expire_BootSeq & LLSA(jiffies): ", dummy );
                        _get_token( fh,"(mSec): ", bootseq_exp_time );
                        _get_token( fh,"(mSec): ", bootseq_exp_time );
                        _get_token( fh,"retry: ", dummy );

                        switch( atoi(state) )
                        {
                                case 5:
                                case 6:
                                        strcpy(state,"SUBORDINATE");
                                        break;

                                case 7:
                                case 8:
                                        strcpy(state,"SUPERORDINATE");
                                        break;

                                default:
                                        break;
                        }

                        nBytesSent += websWrite(wp,T("<tr bgcolor=\"#b7b7b7\">"
                                "<td align=center width=\"17%%\"><font size=\"2\">%s</td>\n"
                                "<td align=center width=\"17%%\"><font size=\"2\">%s</td>\n"
                                "<td align=center width=\"17%%\"><font size=\"2\">%s</td>\n"
                                "<td align=center width=\"17%%\"><font size=\"2\">%s</td>\n"
				"<td align=center width=\"17%%\"><font size=\"2\">%s</td>\n"
				"<td align=center width=\"17%%\"><font size=\"2\">%s</td>\n"
#if defined(_11s_TEST_MODE_)
				"<td align=center width=\"17%%\"><font size=\"2\">%s</td>\n"
                                "<td align=center width=\"17%%\"><font size=\"2\">%s</td>\n"),
                                        //hwaddr,state,channel,link_rate,rssi,establish_exp_time,bootseq_exp_time);
                                        hwaddr,network,tx_pkts,rx_pkts,link_rate,rssi,establish_exp_time,bootseq_exp_time);
#else
				"<td align=center width=\"17%%\"><font size=\"2\">%s</td>\n"),
					//hwaddr,state,channel,link_rate,rssi);
					hwaddr,network,tx_pkts,rx_pkts,link_rate,rssi,establish_exp_time);
#endif

                        nRecordCount++;
                }
        }

        fclose(fh);

//      printf("\nWarning: recordcount %d\n",nRecordCount);

        if(nRecordCount == 0)
        {
                nBytesSent += websWrite(wp,T("<tr bgcolor=\"#b7b7b7\">"
                        "<td align=center><font size=\"2\">None</td>"
                        "<td align=center width=\"17%%\"><font size=\"2\">---</td>\n"
                        "<td align=center width=\"17%%\"><font size=\"2\">---</td>\n"                        
                        "<td align=center width=\"17%%\"><font size=\"2\">---</td>\n"
                        "<td align=center width=\"17%%\"><font size=\"2\">---</td>\n"
			"<td align=center width=\"17%%\"><font size=\"2\">---</td>\n"
			"<td align=center width=\"17%%\"><font size=\"2\">---</td>\n"
#if defined(_11s_TEST_MODE_)
			"<td align=center width=\"17%%\"><font size=\"2\">---</td>\n"
#endif
			));
        }


        return nBytesSent;
}

/////////////////////////////////////////////////////////////////////////////
int wlMeshRoutingTable(int eid, webs_t wp, int argc, char_t **argv)
{
        int nBytesSent=0;
        int nRecordCount=0;
        FILE *fh;
        char buf[512];
		unsigned char mac[7];
		char putstr[20];
		int tmp;


		struct mesh_entry{
			char destMac[50],nexthopMac[50],dsn[50], isPortal[10];
			char metric[50],hopcount[10], start[50], end[50], diff[50], flag[10];
			struct mesh_entry *prev;
			struct mesh_entry *next;
		};

		struct mesh_entry *head = NULL;
		struct mesh_entry *p, *np;
        
		

        nBytesSent += websWrite(wp, T("<tr bgcolor=\"#7F7F7F\">"
        "<td align=center width=\"15%%\"><font size=\"2\"><b>Destination Mesh Point</b></font></td>\n"
        "<td align=center width=\"15%%\"><font size=\"2\"><b>Next-hop Mesh Point</b></font></td>\n"
	"<td align=center width=\"10%%\"><font size=\"2\"><b>Portal Enable</b></font></td>\n"
        //"<td align=center width=\"10%%\"><font size=\"2\"><b>DSN</b></font></td>\n"
        "<td align=center width=\"10%%\"><font size=\"2\"><b>Metric</b></font></td>\n"
        "<td align=center width=\"10%%\"><font size=\"2\"><b>Hop Count</b></font></td>\n"
	"<td align=center width=\"10%%\"><font size=\"2\"><b>Active Clients List</b></font></td>\n"
#if defined(_11s_TEST_MODE_)
        "<td align=center width=\"10%%\"><font size=\"2\"><b>Gen PREQ</b></font></td>\n"
        "<td align=center width=\"10%%\"><font size=\"2\"><b>Rev PREP</b></font></td>\n"
        "<td align=center width=\"10%%\"><font size=\"2\"><b>Delay</b></font></td>\n"
        "<td align=center width=\"10%%\"><font size=\"2\"><b>Flag</b></font></td></tr>\n"
#endif
	));

        fh = fopen(_FILE_MESH_ROUTE, "r");
        if (!fh)
        {
                printf("Warning: cannot open %s\n",_FILE_MESH_ROUTE );
                return -1;
        }


        while( fgets(buf, sizeof buf, fh) != NULL )
        {
                if( strstr(buf,"Mesh route") != NULL )
                {			                	
					np= malloc(sizeof(struct mesh_entry));
					np->next = NULL;
					np->prev = NULL;
					
//                        _get_token( fh,"isvalid: ",isvalid );
                        _get_token( fh,"destMAC: ", np->destMac );
						tmp = strlen(np->destMac)-1;
						np->destMac[tmp] = '\0';
                        _get_token( fh,"nexthopMAC: ", np->nexthopMac );
						_get_token( fh,"portal enable: ", np->isPortal );
                        _get_token( fh,"dsn: ", np->dsn);
                        _get_token( fh,"metric: ", np->metric );
                        _get_token( fh,"hopcount: ", np->hopcount );
						_get_token( fh,"start: ", np->start );
						_get_token( fh,"end: ", np->end );
						_get_token( fh,"diff: ", np->diff );
						_get_token( fh,"flag: ", np->flag );
						
					if (head == NULL){
						head = np;
					} else {
						p = head;
						while (p!=NULL) {
							if (atoi(np->hopcount)< atoi(p->hopcount)){
								if (p->prev!=NULL) {
									p->prev->next = np;
								}
								np->prev = p->prev;
								np->next = p;
								p->prev = np;
								break;
							} else {
								if (p->next == NULL) {
									p->next = np;
									np->prev = p;
									break;
								}
								else
									p = p->next;
							}
						}
					}
                        nRecordCount++;
                }
        }

        fclose(fh);

//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

								

//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
		
		if( apmib_get(MIB_WLAN_WLAN_MAC_ADDR, (void *)mac)<0 )
			fprintf(stderr,"get mib error \n");
		
		if ( (mac[0]|mac[1]|mac[2]|mac[3]|mac[4]|mac[5]) == 0){
			memset(mac,0x0,sizeof(mac));
			apmib_get(MIB_HW_WLAN_ADDR, (void *)mac);
		}
		
        if(nRecordCount == 0)
        {
                nBytesSent += websWrite(wp,T("<tr bgcolor=\"#b7b7b7\">"
                        "<td><font size=\"2\">None</td>"
                        "<td align=center width=\"15%%\"><font size=\"2\">---</td>\n"
                        "<td align=center width=\"15%%\"><font size=\"2\">---</td>\n"
                        "<td align=center width=\"10%%\"><font size=\"2\">---</td>\n"                        
                        "<td align=center width=\"10%%\"><font size=\"2\">---</td>\n"
#if defined(_11s_TEST_MODE_)
                        "<td align=center width=\"10%%\"><font size=\"2\">---</td>\n"
                        "<td align=center width=\"10%%\"><font size=\"2\">---</td>\n"
                        "<td align=center width=\"10%%\"><font size=\"2\">---</td>\n"
                        "<td align=center width=\"10%%\"><font size=\"2\">---</td>\n"
#endif
			"<td align=center width=\"10%%\"><font size=\"2\">---</td>\n"
			));
        } else {
			
			p = head;

			while (p!=NULL){

				if (p->destMac[0] == 'M') { 	 
					sprintf(putstr, "%02X%02X%02X%02X%02X%02X"
						, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
				} else {
					strcpy(putstr, p->destMac);
				}
					
        		nBytesSent += websWrite(wp,T("<tr bgcolor=\"#b7b7b7\">"
								"<td align=center width=\"15%%\"><font size=\"2\">%s</td>\n"
					"<td align=center width=\"15%%\"><font size=\"2\">%s</td>\n"
								"<td align=center width=\"15%%\"><font size=\"2\">%s</td>\n"
								"<td align=center width=\"10%%\"><font size=\"2\">%s</td>\n"
								"<td align=center width=\"10%%\"><font size=\"2\">%s</td>\n"
#if defined(_11s_TEST_MODE_)
								"<td align=center width=\"10%%\"><font size=\"2\">%s</td>\n"
								"<td align=center width=\"10%%\"><font size=\"2\">%s</td>\n"
								"<td align=center width=\"10%%\"><font size=\"2\">%s</td>\n"
								"<td align=center width=\"10%%\"><font size=\"2\">%s</td>\n"
#endif

					"<td align=center width=\"10%%\"><input type=\"button\" value=\"Show\" size=\"2\" onClick=\"showProxiedMAC(\'%s\')\"></td>\n"
							   ), p->destMac,p->nexthopMac,p->isPortal,p->metric,p->hopcount,putstr
#if defined(_11s_TEST_MODE_)
					, p->start, p->end, p->diff, p->flag
#endif
					);
				p = p->next;
			}
        }


        return nBytesSent;
}

int wlMeshPortalTable(int eid, webs_t wp, int argc, char_t **argv)
{
        int nBytesSent=0;
        int nRecordCount=0;
        FILE *fh;
        char buf[512];
        char mac[100],timeout[100],seq[100];

        nBytesSent += websWrite(wp, T("<tr bgcolor=\"#7F7F7F\">"
        "<td align=center width=\"16%%\"><font size=\"2\"><b>PortalMAC</b></font></td>\n"
#if defined(_11s_TEST_MODE_)
        "<td align=center width=\"16%%\"><font size=\"2\"><b>timeout</b></font></td>\n"
        "<td align=center width=\"16%%\"><font size=\"2\"><b>seqNum</b></font></td></tr>\n"
#endif
	));

        fh = fopen(_FILE_MESH_PORTAL, "r");
        if (!fh)
        {
                printf("Warning: cannot open %s\n",_FILE_MESH_PORTAL );
                return -1;
        }

        while( fgets(buf, sizeof buf, fh) != NULL )
        {
                if( strstr(buf," portal table info..") != NULL )
                {
                        _get_token( fh,"PortalMAC: ",mac );
                        _get_token( fh,"timeout: ",timeout );
                        _get_token( fh,"seqNum: ",seq );

                        nBytesSent += websWrite(wp,T("<tr bgcolor=\"#b7b7b7\">"
                        "<td align=center width=\"16%%\"><font size=\"2\">%s</td>\n"
#if defined(_11s_TEST_MODE_)
                        "<td align=center width=\"16%%\"><font size=\"2\">%s</td>\n"
                        "<td align=center width=\"16%%\"><font size=\"2\">%s</td>\n"
#endif
                                       ), mac
#if defined(_11s_TEST_MODE_)
			,timeout, seq
#endif
			);
                        nRecordCount++;
                }
        }

        fclose(fh);

        if(nRecordCount == 0)
        {
                nBytesSent += websWrite(wp,T("<tr bgcolor=\"#b7b7b7\">"
                        "<td><font size=\"2\">None</td>"
#if defined(_11s_TEST_MODE_)
                        "<td align=center width=\"17%%\"><font size=\"2\">---</td>\n"
                        "<td align=center width=\"17%%\"><font size=\"2\">---</td>\n"
#endif
			));
        }


        return nBytesSent;
}


/////////////////////////////////////////////////////////////////////////////
int wlMeshProxyTable(int eid, webs_t wp, int argc, char_t **argv)
{
        int nBytesSent=0;
        int nRecordCount=0;
        FILE *fh;
        char buf[512];
        char sta[100],owner[100];

        nBytesSent += websWrite(wp, T("<tr bgcolor=\"#7F7F7F\">"
        "<td align=center width=\"50%%\"><font size=\"2\"><b>Owner</b></font></td>\n"
        "<td align=center width=\"50%%\"><font size=\"2\"><b>Client</b></font></td></tr>\n"));

        fh = fopen(_FILE_MESH_PROXY , "r");
        if (!fh)
        {
                printf("Warning: cannot open %s\n",_FILE_MESH_PROXY );
                return -1;
        }

        while( fgets(buf, sizeof buf, fh) != NULL )
        {
                if( strstr(buf,"table info...") != NULL )
                {
                        _get_token( fh,"STA_MAC: ",sta );
                        _get_token( fh,"OWNER_MAC: ",owner );
       

                        nBytesSent += websWrite(wp,T("<tr bgcolor=\"#b7b7b7\">"
                                "<td align=center width=\"50%%\"><font size=\"2\">%s</td>\n"
                                "<td align=center width=\"50%%\"><font size=\"2\">%s</td>\n"),
                                owner,sta);
                        nRecordCount++;
                }
        }

        fclose(fh);

        if(nRecordCount == 0)
        {
                nBytesSent += websWrite(wp,T("<tr bgcolor=\"#b7b7b7\">"
                        "<td><font size=\"2\">None</td>"
                        "<td align=center width=\"17%%\"><font size=\"2\">---</td>\n"));
        }

        return nBytesSent;
}

#ifdef _11s_TEST_MODE_
int wlRxStatics(int eid, webs_t wp, int argc, char_t **argv)
{
        int nBytesSent=0;
        FILE *fh;
        char buf[512];
        char buf2[15][50];

        nBytesSent += websWrite(wp, T("<tr bgcolor=\"#7F7F7F\">"
        "<td align=center width=\"10%%\"><font size=\"2\"><b>jiffies</b></font></td>\n"
        "<td align=center width=\"10%%\"><font size=\"2\"><b>tx_packets</b></font></td>\n"
        "<td align=center width=\"10%%\"><font size=\"2\"><b>tx_retrys</b></font></td>\n"
        "<td align=center width=\"10%%\"><font size=\"2\"><b>tx_errors</b></font></td>\n"
        "<td align=center width=\"10%%\"><font size=\"2\"><b>rx_packets</b></font></td>\n"
        "<td align=center width=\"10%%\"><font size=\"2\"><b>tx_pkts</b></font></td>\n"
		"<td align=center width=\"10%%\"><font size=\"2\"><b>rx_pkts</b></font></td>\n"         
        "<td align=center width=\"10%%\"><font size=\"2\"><b>rx_crc_errors</b></font></td>\n"));


        fh = fopen(_FILE_MESHSTATS , "r");
        if (!fh)
        {
                printf("Warning: cannot open %s\n",_FILE_MESHSTATS );
                return -1;
        }

		if( fgets(buf, sizeof buf, fh) && strstr(buf,"Statistics..."))
        {
				_get_token( fh,"OPMODE: ", buf2[0] );
				_get_token( fh,"jiffies: ",buf2[1] );
		}
        if( fgets(buf, sizeof buf, fh) && strstr(buf,"Statistics..."))
        {
				_get_token( fh,"tx_packets: ",buf2[2] );
				_get_token( fh,"tx_bytes: ",buf2[3] );
                _get_token( fh,"tx_errors: ",buf2[4] );

				_get_token( fh,"rx_packets: ",buf2[5] );
				_get_token( fh,"rx_bytes: ",buf2[6] );
				_get_token( fh,"rx_errors: ",buf2[7] );				
                _get_token( fh,"rx_crc_errors: ",buf2[8] );

                nBytesSent += websWrite(wp,T("<tr bgcolor=\"#b7b7b7\">"
                        "<td align=center width=\"50%%\"><font size=\"2\">%s</td>\n"
                        "<td align=center width=\"50%%\"><font size=\"2\">%s</td>\n"
                        "<td align=center width=\"50%%\"><font size=\"2\">%s</td>\n"
                        "<td align=center width=\"50%%\"><font size=\"2\">%s</td>\n"
                        "<td align=center width=\"50%%\"><font size=\"2\">%s</td>\n"
                        "<td align=center width=\"50%%\"><font size=\"2\">%s</td>\n"                                     
                        "<td align=center width=\"50%%\"><font size=\"2\">%s</td>\n"
                        "<td align=center width=\"50%%\"><font size=\"2\">%s</td>\n"),
                        buf2[1], buf2[2], buf2[3], buf2[4], buf2[5], buf2[6], buf2[7], buf2[8] ); 
        }

        fclose(fh);

        return nBytesSent;
}
#endif

int wlMeshRootInfo(int eid, webs_t wp, int argc, char_t **argv)
{
        int nBytesSent=0;
        FILE *fh;
        char rootmac[100];
		char z12[]= "000000000000";
		
        fh = fopen(_FILE_MESH_ROOT , "r");
        if (!fh)
        {
                printf("Warning: cannot open %s\n",_FILE_MESH_ROOT );
                return -1;
        }
	
        _get_token( fh, "ROOT_MAC: ", rootmac );
		if( memcmp(rootmac,z12,12 ) )
             nBytesSent += websWrite(wp,T("%s"),  rootmac);
		else
		     nBytesSent += websWrite(wp,T("None"));

        fclose(fh);
        return nBytesSent;
}


#endif // CONFIG_RTK_MESH

/////////////////////////////////////////////////////////////////////////////
int wlAcList(int eid, webs_t wp, int argc, char_t **argv)
{
	int nBytesSent=0, entryNum, i;
	MACFILTER_T entry;
	char tmpBuf[100];

	if ( !apmib_get(MIB_WLAN_MACAC_NUM, (void *)&entryNum)) {
  		websError(wp, 400, T("Get table entry error!\n"));
		return -1;
	}

	nBytesSent += websWrite(wp, T("<tr>"
      	"<td align=center width=\"45%%\" bgcolor=\"#808080\"><font size=\"2\"><b>MAC Address</b></font></td>\n"
      	"<td align=center width=\"35%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Comment</b></font></td>\n"
      	"<td align=center width=\"20%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Select</b></font></td></tr>\n"));

	for (i=1; i<=entryNum; i++) {
		*((char *)&entry) = (char)i;
		if ( !apmib_get(MIB_WLAN_MACAC_ADDR, (void *)&entry))
			return -1;

		snprintf(tmpBuf, 100, T("%02x:%02x:%02x:%02x:%02x:%02x"),
			entry.macAddr[0], entry.macAddr[1], entry.macAddr[2],
			entry.macAddr[3], entry.macAddr[4], entry.macAddr[5]);

		nBytesSent += websWrite(wp, T("<tr>"
			"<td align=center width=\"45%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
      			"<td align=center width=\"35%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
       			"<td align=center width=\"20%%\" bgcolor=\"#C0C0C0\"><input type=\"checkbox\" name=\"select%d\" value=\"ON\"></td></tr>\n"),
				tmpBuf, entry.comment, i);
	}
	return nBytesSent;
}

/////////////////////////////////////////////////////////////////////////////
void formWlAc(webs_t wp, char_t *path, char_t *query)
{
	char_t *strAddMac, *strDelMac, *strDelAllMac, *strVal, *submitUrl, *strEnabled;
	char tmpBuf[100];
	int entryNum, i, enabled;
	MACFILTER_T macEntry;

	strAddMac = websGetVar(wp, T("addFilterMac"), T(""));
	strDelMac = websGetVar(wp, T("deleteSelFilterMac"), T(""));
	strDelAllMac = websGetVar(wp, T("deleteAllFilterMac"), T(""));
	strEnabled = websGetVar(wp, T("wlanAcEnabled"), T(""));

	if (strAddMac[0]) {
		/*if ( !gstrcmp(strEnabled, T("ON")))
			enabled = 1;
		else
			enabled = 0; */ //by sc_yang
		 enabled = strEnabled[0] - '0';
		if ( apmib_set( MIB_WLAN_MACAC_ENABLED, (void *)&enabled) == 0) {
  			strcpy(tmpBuf, T("Set enabled flag error!"));
			goto setErr_ac;
		}

		strVal = websGetVar(wp, T("mac"), T(""));
		if ( !strVal[0] ) {
//			strcpy(tmpBuf, T("Error! No mac address to set."));
			goto setac_ret;
		}
		if (strlen(strVal)!=12 || !string_to_hex(strVal, macEntry.macAddr, 12)) {
			strcpy(tmpBuf, T("Error! Invalid MAC address."));
			goto setErr_ac;
		}

		strVal = websGetVar(wp, T("comment"), T(""));
		if ( strVal[0] ) {
			if (strlen(strVal) > COMMENT_LEN-1) {
				strcpy(tmpBuf, T("Error! Comment length too long."));
				goto setErr_ac;
			}
			strcpy(macEntry.comment, strVal);
		}
		else
			macEntry.comment[0] = '\0';

		if ( !apmib_get(MIB_WLAN_MACAC_NUM, (void *)&entryNum)) {
			strcpy(tmpBuf, T("Get entry number error!"));
			goto setErr_ac;
		}
		if ( (entryNum + 1) > MAX_WLAN_AC_NUM) {
			strcpy(tmpBuf, T("Cannot add new entry because table is full!"));
			goto setErr_ac;
		}

		// set to MIB. try to delete it first to avoid duplicate case
		apmib_set(MIB_WLAN_AC_ADDR_DEL, (void *)&macEntry);
		if ( apmib_set(MIB_WLAN_AC_ADDR_ADD, (void *)&macEntry) == 0) {
			strcpy(tmpBuf, T("Add table entry error!"));
			goto setErr_ac;
		}
	}

	/* Delete entry */
	if (strDelMac[0]) {
		if ( !apmib_get(MIB_WLAN_MACAC_NUM, (void *)&entryNum)) {
			strcpy(tmpBuf, T("Get entry number error!"));
			goto setErr_ac;
		}
		for (i=entryNum; i>0; i--) {
			snprintf(tmpBuf, 20, "select%d", i);

			strVal = websGetVar(wp, tmpBuf, T(""));
			if ( !gstrcmp(strVal, T("ON")) ) {

				*((char *)&macEntry) = (char)i;
				if ( !apmib_get(MIB_WLAN_MACAC_ADDR, (void *)&macEntry)) {
					strcpy(tmpBuf, T("Get table entry error!"));
					goto setErr_ac;
				}
				if ( !apmib_set(MIB_WLAN_AC_ADDR_DEL, (void *)&macEntry)) {
					strcpy(tmpBuf, T("Delete table entry error!"));
					goto setErr_ac;
				}
			}
		}
	}

	/* Delete all entry */
	if ( strDelAllMac[0]) {
		if ( !apmib_set(MIB_WLAN_AC_ADDR_DELALL, (void *)&macEntry)) {
			strcpy(tmpBuf, T("Delete all table error!"));
			goto setErr_ac;
		}
	}

setac_ret:
	apmib_update_web(CURRENT_SETTING);

#ifndef NO_ACTION
	run_init_script("bridge");
#endif

	submitUrl = websGetVar(wp, T("submit-url"), T(""));   // hidden page
	OK_MSG( submitUrl );
  	return;

setErr_ac:
	ERR_MSG(tmpBuf);
}

//int advanceHander(webs_t wp ,char *tmpBuf)
int advanceHander(webs_t wp ,char *tmpBuf, int wlan_id)	//2011.05.24 Jerry
{
	char_t *strAuth, *strFragTh, *strRtsTh, *strBeacon, *strPreamble;
	char_t *strRate, /* *strHiddenSSID, */ *strDtim, *strIapp, *strProtection;
	char_t *strTurbo, *strPower;
	char_t *strValue;
	AUTH_TYPE_T authType;
	PREAMBLE_T preamble;
	int val;
	int disabled;	//2011.05.24 Jerry
	char varName[20];	//2011.05.24 Jerry
	char_t *strDisabled;	//2011.05.24 Jerry

#ifdef WIFI_SIMPLE_CONFIG
	memset(&wps_config_info, 0, sizeof(struct wps_config_info_struct));
	wps_config_info.caller_id = CALLED_FROM_ADVANCEHANDLER;
	apmib_get(MIB_WLAN_AUTH_TYPE, (void *)&wps_config_info.shared_type);
#endif
	//2011.05.24 Jerry {
	sprintf(varName, "wlanDisabled%d", wlan_id);
	strDisabled = websGetVar(wp, varName, T(""));
	if ( !gstrcmp(strDisabled, T("ON")))
		disabled = 0;
	else
		disabled = 1;
	if ( apmib_set( MIB_WLAN_WLAN_DISABLED, (void *)&disabled) == 0) {
  		strcpy(tmpBuf, T("Set disabled flag error!"));
		goto setErr_advance;
	}
	//2011.05.24 Jerry }

	strAuth = websGetVar(wp, T("authType"), T(""));
	if (strAuth[0]) {
		if ( !gstrcmp(strAuth, T("open")))
			authType = AUTH_OPEN;
		else if ( !gstrcmp(strAuth, T("shared")))
			authType = AUTH_SHARED;
		else if ( !gstrcmp(strAuth, T("both")))
			authType = AUTH_BOTH;
		else {
			strcpy(tmpBuf, T("Error! Invalid authentication value."));
			goto setErr_advance;
		}
		if ( apmib_set(MIB_WLAN_AUTH_TYPE, (void *)&authType) == 0) {
			strcpy(tmpBuf, T("Set authentication failed!"));
			goto setErr_advance;
		}
	}
	strFragTh = websGetVar(wp, T("fragThreshold"), T(""));
	if (strFragTh[0]) {
		if ( !string_to_dec(strFragTh, &val) || val<256 || val>2346) {
			strcpy(tmpBuf, T("Error! Invalid value of fragment threshold."));
			goto setErr_advance;
		}
		if ( apmib_set(MIB_WLAN_FRAG_THRESHOLD, (void *)&val) == 0) {
			strcpy(tmpBuf, T("Set fragment threshold failed!"));
			goto setErr_advance;
		}
	}
	strRtsTh = websGetVar(wp, T("rtsThreshold"), T(""));
	if (strRtsTh[0]) {
		if ( !string_to_dec(strRtsTh, &val) || val<0 || val>2347) {
			strcpy(tmpBuf, T("Error! Invalid value of RTS threshold."));
			goto setErr_advance;
		}
		if ( apmib_set(MIB_WLAN_RTS_THRESHOLD, (void *)&val) == 0) {
			strcpy(tmpBuf, T("Set RTS threshold failed!"));
			goto setErr_advance;
		}
	}

	strBeacon = websGetVar(wp, T("beaconInterval"), T(""));
	if (strBeacon[0]) {
		if ( !string_to_dec(strBeacon, &val) || val<20 || val>1024) {
			strcpy(tmpBuf, T("Error! Invalid value of Beacon Interval."));
			goto setErr_advance;
		}
		if ( apmib_set(MIB_WLAN_BEACON_INTERVAL, (void *)&val) == 0) {
			strcpy(tmpBuf, T("Set Beacon interval failed!"));
			goto setErr_advance;
		}
	}
#if 0
	// set tx rate
	strRate = websGetVar(wp, T("txRate"), T(""));
	if ( strRate[0] ) {
		if ( strRate[0] == '0' ) { // auto
			val = 1;
			if ( apmib_set(MIB_WLAN_RATE_ADAPTIVE_ENABLED, (void *)&val) == 0) {
				strcpy(tmpBuf, T("Set rate adaptive failed!"));
				goto setErr_advance;
			}
		}
		else  {
			val = 0;
			if ( apmib_set(MIB_WLAN_RATE_ADAPTIVE_ENABLED, (void *)&val) == 0) {
				strcpy(tmpBuf, T("Set rate adaptive failed!"));
				goto setErr_advance;
			}  
			val = atoi(strRate);
			val = 1 << (val-1);
			if ( apmib_set(MIB_WLAN_FIX_RATE, (void *)&val) == 0) {
				strcpy(tmpBuf, T("Set fix rate failed!"));
				goto setErr_advance;
			}
			strRate = websGetVar(wp, T("basicrates"), T(""));
			if ( strRate[0] ) {
				val = atoi(strRate);
				if ( apmib_set(MIB_WLAN_BASIC_RATES, (void *)&val) == 0) {
					strcpy(tmpBuf, T("Set Tx basic rate failed!"));
					goto setErr_advance;
				}
			}

			strRate = websGetVar(wp, T("operrates"), T(""));
			if ( strRate[0] ) {
				val = atoi(strRate);
				if ( apmib_set(MIB_WLAN_SUPPORTED_RATES, (void *)&val) == 0) {
					strcpy(tmpBuf, T("Set Tx operation rate failed!"));
					goto setErr_advance;
				}
			}	
		}
	}
#endif
	val = 0;
	strRate = websGetVar(wp, T("operRate1M"), T(""));
	if (strRate==NULL || strRate[0]==0)
		goto skip_rate_setting;
	if ( !gstrcmp(strRate, T("1M")))
		val |= TX_RATE_1M;
	strRate = websGetVar(wp, T("operRate2M"), T(""));
	if ( !gstrcmp(strRate, T("2M")))
		val |= TX_RATE_2M;
	strRate = websGetVar(wp, T("operRate5M"), T(""));
	if ( !gstrcmp(strRate, T("5M")))
		val |= TX_RATE_5M;
	strRate = websGetVar(wp, T("operRate11M"), T(""));
	if ( !gstrcmp(strRate, T("11M")))
		val |= TX_RATE_11M;
	strRate = websGetVar(wp, T("operRate6M"), T(""));
	if ( !gstrcmp(strRate, T("6M")))
		val |= TX_RATE_6M;
	strRate = websGetVar(wp, T("operRate9M"), T(""));
	if ( !gstrcmp(strRate, T("9M")))
		val |= TX_RATE_9M;
	strRate = websGetVar(wp, T("operRate12M"), T(""));
	if ( !gstrcmp(strRate, T("12M")))
		val |= TX_RATE_12M;
	strRate = websGetVar(wp, T("operRate18M"), T(""));
	if ( !gstrcmp(strRate, T("18M")))
		val |= TX_RATE_18M;			
	strRate = websGetVar(wp, T("operRate24M"), T(""));
	if ( !gstrcmp(strRate, T("24M")))
		val |= TX_RATE_24M;			
	strRate = websGetVar(wp, T("operRate36M"), T(""));
	if ( !gstrcmp(strRate, T("36M")))
		val |= TX_RATE_36M;			
	strRate = websGetVar(wp, T("operRate48M"), T(""));
	if ( !gstrcmp(strRate, T("48M")))
		val |= TX_RATE_48M;			
	strRate = websGetVar(wp, T("operRate54M"), T(""));
	if ( !gstrcmp(strRate, T("54M")))
		val |= TX_RATE_54M;
	if ( apmib_set(MIB_WLAN_SUPPORTED_RATES, (void *)&val) == 0) {
		strcpy(tmpBuf, T("Set Tx operation rate failed!"));
		goto setErr_advance;
	}

	// set basic tx rate
	val = 0;
	strRate = websGetVar(wp, T("basicRate1M"), T(""));
	if (strRate==NULL || strRate[0]==0)
		goto skip_rate_setting;	
	if ( !gstrcmp(strRate, T("1M")))
		val |= TX_RATE_1M;
	strRate = websGetVar(wp, T("basicRate2M"), T(""));
	if ( !gstrcmp(strRate, T("2M")))
		val |= TX_RATE_2M;
	strRate = websGetVar(wp, T("basicRate5M"), T(""));
	if ( !gstrcmp(strRate, T("5M")))
		val |= TX_RATE_5M;
	strRate = websGetVar(wp, T("basicRate11M"), T(""));
	if ( !gstrcmp(strRate, T("11M")))
		val |= TX_RATE_11M;
	strRate = websGetVar(wp, T("basicRate6M"), T(""));
	if ( !gstrcmp(strRate, T("6M")))
		val |= TX_RATE_6M;
	strRate = websGetVar(wp, T("basicRate9M"), T(""));
	if ( !gstrcmp(strRate, T("9M")))
		val |= TX_RATE_9M;
	strRate = websGetVar(wp, T("basicRate12M"), T(""));
	if ( !gstrcmp(strRate, T("12M")))
		val |= TX_RATE_12M;
	strRate = websGetVar(wp, T("basicRate18M"), T(""));
	if ( !gstrcmp(strRate, T("18M")))
		val |= TX_RATE_18M;			
	strRate = websGetVar(wp, T("basicRate24M"), T(""));
	if ( !gstrcmp(strRate, T("24M")))
		val |= TX_RATE_24M;			
	strRate = websGetVar(wp, T("basicRate36M"), T(""));
	if ( !gstrcmp(strRate, T("36M")))
		val |= TX_RATE_36M;			
	strRate = websGetVar(wp, T("basicRate48M"), T(""));
	if ( !gstrcmp(strRate, T("48M")))
		val |= TX_RATE_48M;			
	strRate = websGetVar(wp, T("basicRate54M"), T(""));
	if ( !gstrcmp(strRate, T("54M")))
		val |= TX_RATE_54M;			
	if ( apmib_set(MIB_WLAN_BASIC_RATES, (void *)&val) == 0) {
		strcpy(tmpBuf, T("Set Tx basic rate failed!"));
		goto setErr_advance;
	}		
skip_rate_setting:
	// set preamble
	strPreamble = websGetVar(wp, T("preamble"), T(""));
	if (strPreamble[0]) {
		if (!gstrcmp(strPreamble, T("long")))
			preamble = LONG_PREAMBLE;
		else if (!gstrcmp(strPreamble, T("short")))
			preamble = SHORT_PREAMBLE;
		else {
			strcpy(tmpBuf, T("Error! Invalid Preamble value."));
			goto setErr_advance;
		}
		if ( apmib_set(MIB_WLAN_PREAMBLE_TYPE, (void *)&preamble) == 0) {
			strcpy(tmpBuf, T("Set Preamble failed!"));
			goto setErr_advance;
		}
	}
//move to basic setting page
#if 0
	// set hidden SSID
	strHiddenSSID = websGetVar(wp, T("hiddenSSID"), T(""));
	if (strHiddenSSID[0]) {
		if (!gstrcmp(strHiddenSSID, T("no")))
			val = 0;
		else if (!gstrcmp(strHiddenSSID, T("yes")))
			val = 1;
		else {
			strcpy(tmpBuf, T("Error! Invalid hiddenSSID value."));
			goto setErr_advance;
		}
		if ( apmib_set(MIB_WLAN_HIDDEN_SSID, (void *)&val) == 0) {
			strcpy(tmpBuf, T("Set hidden ssid failed!"));
			goto setErr_advance;
		}
	}
#endif
	strDtim = websGetVar(wp, T("dtimPeriod"), T(""));
	if (strDtim[0]) {
		if ( !string_to_dec(strDtim, &val) || val<1 || val>255) {
			strcpy(tmpBuf, T("Error! Invalid value of DTIM period."));
			goto setErr_advance;
		}
		if ( apmib_set(MIB_WLAN_DTIM_PERIOD, (void *)&val) == 0) {
			strcpy(tmpBuf, T("Set DTIM period failed!"));
			goto setErr_advance;
		}
	}

	strIapp = websGetVar(wp, T("iapp"), T(""));
	if (strIapp[0]) {
		if (!gstrcmp(strIapp, T("no")))
			val = 1;
		else if (!gstrcmp(strIapp, T("yes")))
			val = 0;
		else {
			strcpy(tmpBuf, T("Error! Invalid IAPP value."));
			goto setErr_advance;
		}
		if ( apmib_set(MIB_WLAN_IAPP_DISABLED, (void *)&val) == 0) {
			strcpy(tmpBuf, T("Set MIB_WLAN_IAPP_DISABLED failed!"));
			goto setErr_advance;
		}
	}
	strProtection= websGetVar(wp, T("11g_protection"), T(""));
	if (strProtection[0]) {
		if (!gstrcmp(strProtection, T("no")))
			val = 1;
		else if (!gstrcmp(strProtection, T("yes")))
			val = 0;
		else {
			strcpy(tmpBuf, T("Error! Invalid 11g Protection value."));
			goto setErr_advance;
		}
		if ( apmib_set(MIB_WLAN_PROTECTION_DISABLED, (void *)&val) == 0) {
			strcpy(tmpBuf, T("Set MIB_WLAN_PROTECTION_DISABLED failed!"));
			goto setErr_advance;
		}
	}
#if 0	
// for WMM move to basic setting

	strProtection= websGetVar(wp, T("wmm"), T(""));
	if (strProtection[0]) {
		if (!gstrcmp(strProtection, T("on")))
			val = 1;
		else if (!gstrcmp(strProtection, T("off")))
			val = 0;
		else {
			strcpy(tmpBuf, T("Error! Invalid WMM value."));
			goto setErr_advance;
		}
		if ( apmib_set(MIB_WLAN_WMM_ENABLED, (void *)&val) == 0) {
			strcpy(tmpBuf, T("Set MIB_WLAN_WMM_ENABLED failed!"));
			goto setErr_advance;
		}
	}
#endif	
	strTurbo = websGetVar(wp, T("turbo"), T(""));
	if (strTurbo[0]) {
		if (!gstrcmp(strTurbo, T("off")))
			val = 2;
		else if (!gstrcmp(strTurbo, T("always")))
			val = 1;
		else if (!gstrcmp(strTurbo, T("auto")))
			val = 0;
		else {
			strcpy(tmpBuf, T("Error! Invalid turbo mode value."));
			goto setErr_advance;
		}
		if ( apmib_set(MIB_WLAN_TURBO_MODE, (void *)&val) == 0) {
			strcpy(tmpBuf, T("Set MIB_WLAN_TURBO_MODE failed!"));
			goto setErr_advance;
		}
	}

	strPower= websGetVar(wp, T("RFPower"), T(""));
	if (strPower[0]) {		
		if (!gstrcmp(strPower, T("0")))
			val = 0;
		else if (!gstrcmp(strPower, T("1")))
			val = 1;
		else if (!gstrcmp(strPower, T("2")))
			val = 2;
		else if (!gstrcmp(strPower, T("3")))
			val = 3;
		else if (!gstrcmp(strPower, T("4")))
			val = 4;
		else {
			strcpy(tmpBuf, T("Error! Invalid RF output power value."));
			goto setErr_advance;
		}
		if ( apmib_set(MIB_WLAN_RFPOWER_SCALE, (void *)&val) == 0) {
			strcpy(tmpBuf, T("Set MIB_WLAN_RFPOWER_SCALE failed!"));
			goto setErr_advance;
		}
	}
#if 0
// for 11N
	strProtection= websGetVar(wp, T("channelBond0"), T(""));
	if (strProtection[0]) {
		if ( strProtection[0] == '0')
			val = 0;
		else if (strProtection[0] == '1')
			val = 1;
		else {
			strcpy(tmpBuf, T("Error! Invalid Channel Bonding."));
			goto setErr_advance;
		}
		if ( apmib_set(MIB_WLAN_CHANNEL_BONDING, (void *)&val) == 0) {
			strcpy(tmpBuf, T("Set MIB_WLAN_CHANNEL_BONDING failed!"));
			goto setErr_advance;
		}
	}

	strProtection= websGetVar(wp, T("sideBand0"), T(""));
	if (strProtection[0]) {
		if ( strProtection[0] == '0')
			val = 0;
		else if ( strProtection[0] == '1')
			val = 1;
		else {
			strcpy(tmpBuf, T("Error! Invalid Control SideBand."));
			goto setErr_advance;
		}
		if ( apmib_set(MIB_WLAN_CONTROL_SIDEBAND, (void *)&val) == 0) {
			strcpy(tmpBuf, T("Set MIB_WLAN_CONTROL_SIDEBAND failed!"));
			goto setErr_advance;
		}
	}
#endif	
	strProtection= websGetVar(wp, T("aggregation"), T(""));
	if (strProtection[0]) {
		if (!gstrcmp(strProtection, T("disable")))
			val = DISABLED;	// GANTOE & epopen: DISABLED=0 original is DISABLE=0, Because conflict with ../../auth/include/1x_common.h in AP/net-snmp-5.x.x
		else
			val = A_MIXED;	
		if ( apmib_set(MIB_WLAN_AGGREGATION, (void *)&val) == 0) {
			strcpy(tmpBuf, T("Set MIB_WLAN_AGGREGATION failed!"));
			goto setErr_advance;
		}
	}
	strValue = websGetVar(wp, T("block_relay"), T(""));
		if (strValue[0]) {
			if (!strcmp(strValue, T("enable")))
				val = 1;
			else
				val = 0;			
			apmib_set(MIB_WLAN_BLOCK_RELAY, (void *)&val);
		}
	strProtection= websGetVar(wp, T("shortGI0"), T(""));
	if (strProtection[0]) {
		if (!gstrcmp(strProtection, T("on")))
			val = 1;
		else if (!gstrcmp(strProtection, T("off")))
			val = 0;
		else {
			strcpy(tmpBuf, T("Error! Invalid short GI."));
			goto setErr_advance;
		}
		if ( apmib_set(MIB_WLAN_SHORT_GI, (void *)&val) == 0) {
			strcpy(tmpBuf, T("Set MIB_WLAN_SHORT_GI failed!"));
			goto setErr_advance;
		}
	}

	strValue = websGetVar(wp, T("tx_stbc"), T(""));
		if (strValue[0]) {
			if (!strcmp(strValue, T("enable")))
				val = 1;
			else
				val = 0;	
			apmib_set(MIB_WLAN_STBC_ENABLED, (void *)&val);	
		}
		else
		{		
			int chipVersion = getWLAN_ChipVersion();
			if(chipVersion == 1)
			{
				val = 0;	
				apmib_set(MIB_WLAN_STBC_ENABLED, (void *)&val);	
			}


		}
/*	Edison 2011.5.17
	strValue = websGetVar(wp, T("coexist_"), T(""));
		if (strValue[0]) {
			if (!strcmp(strValue, T("enable")))
				val = 1;
			else
				val = 0;	
			apmib_set(MIB_WLAN_COEXIST_ENABLED, (void *)&val);	
		}
*/
#ifdef WIFI_SIMPLE_CONFIG
	update_wps_configured(1);
#endif

	return 0;
setErr_advance:
	return -1 ;		
}	
/////////////////////////////////////////////////////////////////////////////
void formAdvanceSetup(webs_t wp, char_t *path, char_t *query)
{

	char tmpBuf[100];
	char_t *submitUrl;

	//if(advanceHander(wp ,tmpBuf) < 0)
	if(advanceHander(wp ,tmpBuf, wlan_idx) < 0)	//2011.05.24 Jerry
		goto setErr_end;
	apmib_update_web(CURRENT_SETTING);

//2011.03.28 Jerry {
#if 0
#ifndef NO_ACTION
	run_init_script("bridge");
#endif

	submitUrl = websGetVar(wp, T("submit-url"), T(""));   // hidden page

//	websRedirect(wp, submitUrl);
	//OK_MSG(submitUrl);//mars mark
	system("sysconf init gw all"); //mars add
  	return;

setErr_end:
	//ERR_MSG(tmpBuf);//mars mark
	printf("goto setErr_end!\n");//mars add
#endif
//2011.03.28 Jerry }

setErr_end:
	return;
}

/////////////////////////////////////////////////////////////////////////////
int wirelessClientList(int eid, webs_t wp, int argc, char_t **argv)
{
	int nBytesSent=0, i, found=0;
	WLAN_STA_INFO_Tp pInfo;
	char *buff;
	char mode_buf[20];
	char txrate[20];
	int rateid=0;

	buff = calloc(1, sizeof(WLAN_STA_INFO_T) * (MAX_STA_NUM+1));
	if ( buff == 0 ) {
		printf("Allocate buffer failed!\n");
		return 0;
	}

#ifdef MBSSID
	char Root_WLAN_IF[20];

	if (argc == 2) {
		int virtual_index;
		char virtual_name[20];
		strcpy(Root_WLAN_IF, WLAN_IF);
		virtual_index = atoi(argv[argc-1]) - 1;

#ifdef CONFIG_RTL8196B_GW_8M
		if (virtual_index > 0)
			return 0;
#endif
				
		sprintf(virtual_name, "-va%d", virtual_index);
		strcat(WLAN_IF, virtual_name);
	}
#endif

	if ( getWlStaInfo(WLAN_IF,  (WLAN_STA_INFO_Tp)buff ) < 0 ) {
		printf("Read wlan sta info failed!\n");

#ifdef MBSSID
		if (argc == 2)
			strcpy(WLAN_IF, Root_WLAN_IF);
#endif
		return 0;
	}

#ifdef MBSSID
	if (argc == 2)
		strcpy(WLAN_IF, Root_WLAN_IF);
#endif

	for (i=1; i<=MAX_STA_NUM; i++) {
		pInfo = (WLAN_STA_INFO_Tp)&buff[i*sizeof(WLAN_STA_INFO_T)];
		if (pInfo->aid && (pInfo->flag & STA_INFO_FLAG_ASOC)) {
			
		if(pInfo->network & BAND_11N)
			sprintf(mode_buf, "%s", T(" 11n"));
		else if (pInfo->network & BAND_11G)
			sprintf(mode_buf,"%s",  T(" 11g"));	
		else if (pInfo->network & BAND_11B)
			sprintf(mode_buf, "%s", T(" 11b"));
		else if (pInfo->network& BAND_11A)
			sprintf(mode_buf, "%s", T(" 11a"));	
		else
			sprintf(mode_buf, "%s", T(" ---"));	
		
		//printf("\n\nthe sta txrate=%d\n\n\n", pInfo->txOperaRates);
		
			
		if((pInfo->txOperaRates & 0x80) != 0x80){	
			if(pInfo->txOperaRates%2){
				sprintf(txrate, "%d%s",pInfo->txOperaRates/2, ".5"); 
			}else{
				sprintf(txrate, "%d",pInfo->txOperaRates/2); 
			}
		}else{
			if((pInfo->ht_info & 0x1)==0){ //20M
				if((pInfo->ht_info & 0x2)==0){//long
					for(rateid=0; rateid<16;rateid++){
						if(rate_11n_table_20M_LONG[rateid].id == pInfo->txOperaRates){
							sprintf(txrate, "%s", rate_11n_table_20M_LONG[rateid].rate);
							break;
						}
					}
				}else if((pInfo->ht_info & 0x2)==0x2){//short
					for(rateid=0; rateid<16;rateid++){
						if(rate_11n_table_20M_SHORT[rateid].id == pInfo->txOperaRates){
							sprintf(txrate, "%s", rate_11n_table_20M_SHORT[rateid].rate);
							break;
						}
					}
				}
			}else if((pInfo->ht_info & 0x1)==0x1){//40M
				if((pInfo->ht_info & 0x2)==0){//long
					
					for(rateid=0; rateid<16;rateid++){
						if(rate_11n_table_40M_LONG[rateid].id == pInfo->txOperaRates){
							sprintf(txrate, "%s", rate_11n_table_40M_LONG[rateid].rate);
							break;
						}
					}
				}else if((pInfo->ht_info & 0x2)==0x2){//short
					for(rateid=0; rateid<16;rateid++){
						if(rate_11n_table_40M_SHORT[rateid].id == pInfo->txOperaRates){
							sprintf(txrate, "%s", rate_11n_table_40M_SHORT[rateid].rate);
							break;
						}
					}
				}
			}
			
		}	
			nBytesSent += websWrite(wp,	
	   		T("<tr bgcolor=#b7b7b7><td><font size=2>%02x:%02x:%02x:%02x:%02x:%02x</td>"
			"<td><font size=2>%s</td>"
			"<td><font size=2>%d</td>"
	     		"<td><font size=2>%d</td>"
			"<td><font size=2>%s</td>"
			"<td><font size=2>%s</td>"
			"<td><font size=2>%d</td>"		
			"</tr>"),
			pInfo->addr[0],pInfo->addr[1],pInfo->addr[2],pInfo->addr[3],pInfo->addr[4],pInfo->addr[5],
			mode_buf,
			pInfo->tx_packets, pInfo->rx_packets,
			txrate,
			( (pInfo->flag & STA_INFO_FLAG_ASLEEP) ? "yes" : "no"),
			pInfo->expired_time/100
			);
			found++;
		}
	}
	if (found == 0) {
		nBytesSent += websWrite(wp,
	   		T("<tr bgcolor=#b7b7b7><td><font size=2>None</td>"
			"<td><font size=2>---</td>"
	     		"<td><font size=2>---</td>"
			"<td><font size=2>---</td>"
			"<td><font size=2>---</td>"
			"<td><font size=2>---</td>"
			"<td><font size=2>---</td>"
			"</tr>"));
	}

	free(buff);

	return nBytesSent;
}

/////////////////////////////////////////////////////////////////////////////
void formWirelessTbl(webs_t wp, char_t *path, char_t *query)
{
	char_t *submitUrl;

	submitUrl = websGetVar(wp, T("submit-url"), T(""));
	if (submitUrl[0])
		websRedirect(wp, submitUrl);
}

/////////////////////////////////////////////////////////////////////////////
#ifdef MBSSID
void formWlanMultipleAP(webs_t wp, char_t *path, char_t *query)
{
	char_t *strVal, *submitUrl;
	int idx, disabled, old_vwlan_idx, band_no, val;
	char varName[20];
	char redirectUrl[200];

	old_vwlan_idx = vwlan_idx;

	for (idx=1; idx<=4; idx++) {
		vwlan_idx = idx;		

		sprintf(varName, "wl_disable%d", idx);		
		strVal = websGetVar(wp, varName, T(""));
		if ( !gstrcmp(strVal, T("ON")))
			disabled = 0;
		else
			disabled = 1;	
		apmib_set(MIB_WLAN_WLAN_DISABLED, (void *)&disabled);

		if (disabled)
			continue;

		sprintf(varName, "wl_band%d", idx);
		strVal = websGetVar(wp, varName, T(""));
		if (strVal[0]) {
			band_no = strtol( strVal, (char **)NULL, 10);
			val = (band_no + 1);
			apmib_set(MIB_WLAN_BAND, (void *)&val);
		}

		sprintf(varName, "wl_ssid%d", idx);
		strVal = websGetVar(wp, varName, T(""));
		if (strVal[0]) 
			apmib_set( MIB_WLAN_SSID, (void *)strVal);			
	
		sprintf(varName, "TxRate%d", idx);
		strVal = websGetVar(wp, varName, T(""));
		if (strVal[0]) {
			if ( strVal[0] == '0' ) { // auto
				val = 1;
				apmib_set(MIB_WLAN_RATE_ADAPTIVE_ENABLED, (void *)&val);
			}
			else  {
				val = 0;
				apmib_set(MIB_WLAN_RATE_ADAPTIVE_ENABLED, (void *)&val);
				val = atoi(strVal);
				val = 1 << (val-1);
				apmib_set(MIB_WLAN_FIX_RATE, (void *)&val);
			}
		}

		sprintf(varName, "wl_hide_ssid%d", idx);
		strVal = websGetVar(wp, varName, T(""));
		if (strVal[0]) {
			if ( strVal[0] == '0')
				val = 0;
			else 
				val = 1;
			apmib_set(MIB_WLAN_HIDDEN_SSID, (void *)&val);
		}
	
		sprintf(varName, "wl_wmm_capable%d", idx);
		strVal= websGetVar(wp, varName, T(""));
		if (strVal[0]) {
			if ( strVal[0] == '0')
				val = 0;
			else 
				val = 1;
			apmib_set(MIB_WLAN_WMM_ENABLED, (void *)&val);
		}
		else {	//enable wmm in 11N mode always
			int cur_band;
			apmib_get(MIB_WLAN_BAND, (void *)&cur_band);
			if(cur_band == 10 || cur_band ==11) {
				val = 1;
				apmib_set(MIB_WLAN_WMM_ENABLED, (void *)&val);
			}
		}

		sprintf(varName, "wl_access%d", idx);
		strVal= websGetVar(wp, varName, T(""));
		if (strVal[0]) {
			if ( strVal[0] == '0')
				val = 0;
			else 
				val = 1;
			apmib_set(MIB_WLAN_ACCESS, (void *)&val);
		}

		// force basic and support rate to zero to let driver set default
		val = 0;
		apmib_set(MIB_WLAN_BASIC_RATES, (void *)&val);		
		apmib_set(MIB_WLAN_SUPPORTED_RATES, (void *)&val);
		
		vwlan_idx = old_vwlan_idx;		
	}

	vwlan_idx = old_vwlan_idx;

	apmib_update_web(CURRENT_SETTING);

#ifndef NO_ACTION
	run_init_script("bridge");
#endif

	submitUrl = websGetVar(wp, T("submit-url"), T("")); 
	
	memset(redirectUrl,0x00,sizeof(redirectUrl));
	sprintf(redirectUrl,"/goform/formWlanRedirect?redirect-url=%s&wlan_id=%d",submitUrl,wlan_idx);
	
	OK_MSG(redirectUrl);
}
#endif

/////////////////////////////////////////////////////////////////////////////
void formWlSiteSurvey(webs_t wp, char_t *path, char_t *query)
{
 	char_t *submitUrl, *refresh, *connect, *strSel, *strVal;
	int status, idx, encrypt;
#ifdef CONFIG_RTL_802_1X_CLIENT_SUPPORT
	int wpaPSK;	// For wpa/wpa2
#endif
	unsigned char res, *pMsg=NULL;
	int wait_time, max_wait_time=5;
	char tmpBuf[100];
#ifdef CONFIG_RTK_MESH 
// ==== inserted by GANTOE for site survey 2008/12/26 ==== 
	int mesh_enable=0; 
	
// fixed by Joule 2009.01.10
	if(apmib_get(MIB_WLAN_MODE, (void *)&mesh_enable) == 0 || mesh_enable < 4) 
		mesh_enable = 0; 	
#endif 
	submitUrl = websGetVar(wp, T("submit-url"), T(""));

	refresh = websGetVar(wp, T("refresh"), T(""));
	if ( refresh[0] ) {
		// issue scan request
		wait_time = 0;
		while (1) {
			strVal = websGetVar(wp, T("ifname"), T(""));
			if(strVal[0])
			{
				sprintf(WLAN_IF,"%s",strVal);				
			}
			 
			// ==== modified by GANTOE for site survey 2008/12/26 ==== 
			switch(getWlSiteSurveyRequest(WLAN_IF, &status)) 
			{ 
				case -2: 
					printf("-2\n"); 
					strcpy(tmpBuf, T("Auto scan running!!please wait...")); 
					goto ss_err; 
					break; 
				case -1: 
					printf("-2\n"); 
					strcpy(tmpBuf, T("Site-survey request failed!")); 
					goto ss_err; 
					break; 
				default: 
					break; 
			} 
			// ==== GANTOE ====
/*
			if ( getWlSiteSurveyRequest(WLAN_IF,  &status) < 0 ) {
				strcpy(tmpBuf, T("Site-survey request failed!"));
				goto ss_err;
			}
*/
			if (status != 0) {	// not ready
				if (wait_time++ > 5) {
					strcpy(tmpBuf, T("scan request timeout!"));
					goto ss_err;
				}
#ifdef	CONFIG_RTK_MESH
		// ==== modified by GANTOE for site survey 2008/12/26 ==== 
				usleep(1000000 + (rand() % 2000000));
#else
				sleep(1);
#endif
			}
			else
				break;
		}

		// wait until scan completely
		wait_time = 0;
		while (1) {
			res = 1;	// only request request status
			if ( getWlSiteSurveyResult(WLAN_IF, (SS_STATUS_Tp)&res) < 0 ) {
				strcpy(tmpBuf, T("Read site-survey status failed!"));
				free(pStatus);
				pStatus = NULL;
				goto ss_err;
			}
			if (res == 0xff) {   // in progress
				if (wait_time++ > 10) {
					strcpy(tmpBuf, T("scan timeout!"));
					free(pStatus);
					pStatus = NULL;
					goto ss_err;
				}
				sleep(1);
			}
			else
				break;
		}

		if (submitUrl[0])
			websRedirect(wp, submitUrl);

		return;
	}

	connect = websGetVar(wp, T("connect"), T(""));
	if ( connect[0] ) 
	{
		char_t *wlanifp, *strSSID;
		
#if defined(CONFIG_RTL_92D_SUPPORT)		
		char_t *strChannel;
		int channelIdx;
		int phyBand;
		int i;
		unsigned char wlanIfStr[10];
		int band2g5gselect=0;
		apmib_get(MIB_WLAN_BAND2G5G_SELECT, (void *)&band2g5gselect);
		if(band2g5gselect != BANDMODEBOTH)
		{
			for(i=0 ; i<NUM_WLAN_INTERFACE ; i++)
			{
				unsigned char wlanif[10];
				memset(wlanif,0x00,sizeof(wlanif));
				sprintf(wlanif, "wlan%d",i);
				if(SetWlan_idx(wlanif))
				{
					int intVal = 1;
					apmib_set(MIB_WLAN_WLAN_DISABLED, (void *)&intVal);
					
				}						
			}
		
			strChannel = websGetVar(wp, T("pocket_channel"), T(""));
			
			if(strChannel[0])
			{
				short wlanif;
				
				
				channelIdx = atoi(strChannel);
				
				if(channelIdx > 14) // connect to 5g AP
					phyBand = PHYBAND_5G;
				else
					phyBand = PHYBAND_2G;
					
				wlanif = whichWlanIfIs(phyBand);
				
				memset(wlanIfStr,0x00,sizeof(wlanIfStr));		
				sprintf(wlanIfStr, "wlan%d",wlanif);
			
				if(SetWlan_idx(wlanIfStr))
				{
					int val;
					val = 0;
					apmib_set(MIB_WLAN_WLAN_DISABLED, (void *)&val);												
					
					val = CLIENT_MODE;
					apmib_set(MIB_WLAN_MODE, (void *)&val);												
				}
			
				/* we can't up wlan1 alone, so we swap wlan0 and wlan1 settings */
				if(wlanif != 0)
				{
					swapWlanMibSetting(0,wlanif);			
				}					
			}
		
		}
		
		
#endif //#if defined(CONFIG_RTL_92D_SUPPORT)
		
		wlanifp = websGetVar(wp, T("wlanif"), T(""));
		
//printf("\r\n wlanifp=[%s],__[%s-%u]\r\n",wlanifp,__FILE__,__LINE__);
		
		SetWlan_idx(wlanifp);
		
		strSSID = websGetVar(wp, T("pocketAP_ssid"), T(""));
		apmib_set(MIB_WLAN_SSID, (void *)strSSID);
		
		strSel = websGetVar(wp, T("select"), T(""));
		if (strSel[0]) {
			unsigned char res;
			NETWORK_TYPE_T net;
			int chan;

			if (pStatus == NULL) {
				strcpy(tmpBuf, T("Please refresh again!"));
				goto ss_err;

			}
			sscanf(strSel, "sel%d", &idx);
			if ( idx >= pStatus->number ) { // invalid index
				strcpy(tmpBuf, T("Connect failed 1!"));
				goto ss_err;
			}
#ifdef CONFIG_RTK_MESH 
// ==== inserted by GANTOE for site survey 2008/12/26 ==== 
			if(mesh_enable) 
			{ 
				int i, mesh_index, tmp_index; 
				char original_mesh_id[MESHID_LEN];
				int original_channel = 0;
				
				// backup related info. 
				strcpy(original_mesh_id, "channel");
				if(getWlMib(WLAN_IF, original_mesh_id, strlen(original_mesh_id)) < 0)
				{
					strcpy(tmpBuf, T("get MIB_CHANNEL error!"));
					goto ss_err;
				}
				else
				{
					original_channel = *(int*)original_mesh_id;
				}
				if(apmib_get(MIB_MESH_ID, (void*)original_mesh_id) == 0)
				{
					strcpy(tmpBuf, T("get MIB_MESH_ID error!"));
					goto ss_err;
				}
				
				// send connect request to the driver
				for(tmp_index = 0, mesh_index = 0; tmp_index < pStatus->number && pStatus->number != 0xff; tmp_index++) 
				if(pStatus->bssdb[idx].bdMeshId.Length > 0 && mesh_index++ == idx) 
					break; 
				idx = tmp_index;
				pMsg = "Connect failed 2!!";
				if(!setWlJoinMesh(WLAN_IF, pStatus->bssdb[idx].bdMeshIdBuf - 2, pStatus->bssdb[idx].bdMeshId.Length, pStatus->bssdb[idx].ChannelNumber, 0)) // the problem of padding still exists 
				{ 
					// check whether the link has established
					for(i = 0; i < 10; i++)	// This block might be removed when the mesh peerlink precedure has been completed
					{
						if(!getWlMeshLink(WLAN_IF, pStatus->bssdb[idx].bdBssId, 6))
						{
							char tmp[MESHID_LEN]; 
							int channel; 
							memcpy(tmp, pStatus->bssdb[idx].bdMeshIdBuf - 2, pStatus->bssdb[idx].bdMeshId.Length); // the problem of padding still exists 
							tmp[pStatus->bssdb[idx].bdMeshId.Length] = '\0'; 
							if ( apmib_set(MIB_MESH_ID, (void *)tmp) == 0)
							{ 
								strcpy(tmpBuf, T("Set MeshID error!")); 
								goto ss_err; 
							} 
							// channel = pStatus->bssdb[idx].ChannelNumber; 
							channel = 0; // requirement of Jason, not me 
							if ( apmib_set(MIB_WLAN_CHANNEL, (void*)&channel) == 0)
							{ 
								strcpy(tmpBuf, T("Set Channel error!")); 
								goto ss_err; 
							} 
							apmib_update_web(CURRENT_SETTING); 
							pMsg = "Connect successfully!!"; 
							break;
						}
						usleep(3000000);
					}
				}
				// if failed, reset to the original channel
				if(strcmp(pMsg, "Connect successfully!!"))
				{
					setWlJoinMesh(WLAN_IF, original_mesh_id, strlen(original_mesh_id), original_channel, 1);
				}
			} 
			else 
// ==== GANTOE ==== 
#endif 
			{ 
#if 1
                                unsigned char wlan_idx;
                                char_t *tmpStr, *wlanif;
                                char varName[20];
                                unsigned int i,val;
                                wlanif = websGetVar(wp, T("wlanif"), T(""));
                                //SetWlan_idx(tmpStr);
 
                                tmpStr = websGetVar(wp, T("wlan_idx"), T(""));
                                if(tmpStr[0])
                                        wlan_idx = atoi(tmpStr);
 
                                sprintf(varName, "method%d", wlan_idx);
 
                                tmpStr = websGetVar(wp, varName, T(""));
                                if(tmpStr[0])
                                {
                                        val = atoi(tmpStr);
                                        if(val == ENCRYPT_DISABLED)
                                        {
                                                ENCRYPT_T encrypt = ENCRYPT_DISABLED;
                                                apmib_set( MIB_WLAN_ENCRYPT, (void *)&encrypt);
                                        }
                                        else if(val == ENCRYPT_WEP)
                                        {
                                                if(wepHandler(wp, tmpBuf, wlan_idx) < 0)
                                                {
                                                        goto ss_err;
                                                }
                                        }
                                        else if(val > ENCRYPT_WEP && val <= ENCRYPT_WPA2_MIXED)
                                        {
                                                if(wpaHandler(wp, tmpBuf, wlan_idx) < 0)
                                                {
                                                        goto ss_err;
                                                }
                                        }
#ifdef CONFIG_RTL_WAPI_SUPPORT
						 else if(val == ENCRYPT_WAPI){
						 	if(wpaHandler(wp, tmpBuf, wlan_idx) < 0)
                                             {
                                                        goto ss_err;
                                             }
						 }
#endif
					}
#else                                
			// check encryption type match or not
			if ( !apmib_get( MIB_WLAN_ENCRYPT, (void *)&encrypt) ) {
				strcpy(tmpBuf, T("Check encryption error!"));
				goto ss_err;
			}
			else {
				// no encryption
				if (encrypt == ENCRYPT_DISABLED)
				{
					if (pStatus->bssdb[idx].bdCap & 0x00000010) {
						strcpy(tmpBuf, T("Encryption type mismatch!"));
						goto ss_err;
					}
					else
						; // success
				}
				// legacy encryption
				else if (encrypt == ENCRYPT_WEP)
				{
					if ((pStatus->bssdb[idx].bdCap & 0x00000010) == 0) {
						strcpy(tmpBuf, T("Encryption type mismatch!"));
						goto ss_err;
					}
					else if (pStatus->bssdb[idx].bdTstamp[0] != 0) {
						strcpy(tmpBuf, T("Encryption type mismatch!"));
						goto ss_err;
					}
					else
						; // success
				}
#if defined(CONFIG_RTL_WAPI_SUPPORT)
				else if (encrypt == ENCRYPT_WAPI)
				{
					if ((pStatus->bssdb[idx].bdCap & 0x00000010) == 0) {
						strcpy(tmpBuf, T("Encryption type mismatch!"));
						goto ss_err;
					}
					else if (pStatus->bssdb[idx].bdTstamp[0] != SECURITY_INFO_WAPI) {
						strcpy(tmpBuf, T("Encryption type mismatch!"));
						goto ss_err;
					}
					else
						; // success
				}
#endif
				// WPA/WPA2
				else
				{
					int isPSK, auth;
					apmib_get(MIB_WLAN_WPA_AUTH, (void *)&auth);
					if (auth == WPA_AUTH_PSK)
						isPSK = 1;
					else
						isPSK = 0;					
								
#ifdef CONFIG_RTL_802_1X_CLIENT_SUPPORT
					wpaPSK=isPSK;
#endif
								
					if ((pStatus->bssdb[idx].bdCap & 0x00000010) == 0) {
						strcpy(tmpBuf, T("Encryption type mismatch!"));
						goto ss_err;
					}
					else if (pStatus->bssdb[idx].bdTstamp[0] == 0) {
						strcpy(tmpBuf, T("Encryption type mismatch!"));
						goto ss_err;
					}
					else if (encrypt == ENCRYPT_WPA) {
						if (((pStatus->bssdb[idx].bdTstamp[0] & 0x0000ffff) == 0) || 
								(isPSK && !(pStatus->bssdb[idx].bdTstamp[0] & 0x4000)) ||
								(!isPSK && (pStatus->bssdb[idx].bdTstamp[0] & 0x4000)) ) {						
						strcpy(tmpBuf, T("Encryption type mismatch!"));
						goto ss_err;
					}
					}
					else if (encrypt == ENCRYPT_WPA2) {
						if (((pStatus->bssdb[idx].bdTstamp[0] & 0xffff0000) == 0) ||
								(isPSK && !(pStatus->bssdb[idx].bdTstamp[0] & 0x40000000)) ||
								(!isPSK && (pStatus->bssdb[idx].bdTstamp[0] & 0x40000000)) ) {
							strcpy(tmpBuf, T("Encryption type mismatch!"));
							goto ss_err;
						}
					}	
					else
						; // success
				}
			}
#endif

#if 0
			// Set SSID, network type to MIB
			memcpy(tmpBuf, pStatus->bssdb[idx].bdSsIdBuf, pStatus->bssdb[idx].bdSsId.Length);
			tmpBuf[pStatus->bssdb[idx].bdSsId.Length] = '\0';
			
			memset(tmpBuf,0x00,sizeof(tmpBuf));
			
			tmpStr = websGetVar(wp, T("pocketAP_ssid"), T(""));
			if(tmpStr[0])
				sprintf(tmpBuf,"%s",tmpStr);
			
printf("\r\n tmpBuf=[%s],__[%s-%u]\r\n",tmpBuf,__FILE__,__LINE__);
			
			if ( apmib_set(MIB_WLAN_SSID, (void *)tmpBuf) == 0) {
				strcpy(tmpBuf, T("Set SSID error!"));
				goto ss_err;
			}
#endif

			if ( pStatus->bssdb[idx].bdCap & cESS )
				net = INFRASTRUCTURE;
			else
				net = ADHOC;
			
			if ( apmib_set(MIB_WLAN_NETWORK_TYPE, (void *)&net) == 0) {
				strcpy(tmpBuf, T("Set MIB_WLAN_NETWORK_TYPE failed!"));
				goto ss_err;
			}

			if (net == ADHOC) {
				chan = pStatus->bssdb[idx].ChannelNumber;
				if ( apmib_set( MIB_WLAN_CHANNEL, (void *)&chan) == 0) {
   					strcpy(tmpBuf, T("Set channel number error!"));
					goto ss_err;
				}
				int is_40m_bw = (pStatus->bssdb[idx].bdTstamp[1] & 2) ? 1 : 0;				
				apmib_set(MIB_WLAN_CHANNEL_BONDING, (void *)&is_40m_bw);				
			}

			apmib_update_web(CURRENT_SETTING);

#if 1 //reinit wlan interface and mib
                        unsigned char command[50];
                        sprintf(command,"ifconfig %s down",wlanif);
                        system(command);
                        sprintf(command,"flash set_mib %s",wlanif);
                        system(command);
                        sprintf(command,"ifconfig %s up",wlanif);
                        system(command);

			     // wlan0 entering forwarding state need some time
			     sleep(1);
			     sleep(1);
			     sleep(1);
#endif

			//To reinit wireless
			//unsigned char command[50];
                   sprintf(command,"sysconf wlanapp start %s br0",wlanif);
			system(command);
			sleep(1);

			res = idx;
			wait_time = 0;

			while (1) {
				if ( getWlJoinRequest(WLAN_IF, &pStatus->bssdb[idx], &res) < 0 ) {
					strcpy(tmpBuf, T("Join request failed!"));
					goto ss_err;
				}
				if ( res == 1 ) { // wait
					if (wait_time++ > 5) {
						strcpy(tmpBuf, T("connect-request timeout!"));
						goto ss_err;
					}
					sleep(1);
					continue;
				}
				break;
			}

			if ( res == 2 ) // invalid index
				pMsg = "Connect failed 3!";
			else 
			{
				wait_time = 0;
				while (1) {
					if ( getWlJoinResult(WLAN_IF, &res) < 0 ) {
						strcpy(tmpBuf, T("Get Join result failed!"));
						goto ss_err;
					}
					if ( res != 0xff ) { // completed
					

						break;
					}
					else
					{
						if (wait_time++ > 10) {
							strcpy(tmpBuf, T("connect timeout!"));
							goto ss_err;
						}
					}
					sleep(1);
				}

				if ( res!=STATE_Bss && res!=STATE_Ibss_Idle && res!=STATE_Ibss_Active )
					pMsg = "Connect failed 4!";
				else {					
					status = 0;
					
					apmib_get( MIB_WLAN_ENCRYPT, (void *)&encrypt);
					
					//if (encrypt == ENCRYPT_WPA || encrypt == ENCRYPT_WPA2) {
					if (encrypt == ENCRYPT_WPA || encrypt == ENCRYPT_WPA2 || encrypt == ENCRYPT_WAPI) {
						bss_info bss;
						wait_time = 0;
						
						max_wait_time=10;	//Need more test, especially for 802.1x client mode
						
						while (wait_time++ < max_wait_time) {
							getWlBssInfo(WLAN_IF, &bss);
							if (bss.state == STATE_CONNECTED){
								break;
							}
							sleep(1);
						}
						if (wait_time > max_wait_time)						
							status = 1;
					}

					if (status)
						pMsg = "Connect failed 5!";
					else
						pMsg = "Connect successfully!";
				}
			}
		}
#if defined(CONFIG_POCKET_AP_SUPPORT)
			if(!status)
			{
				pMsg = "Connect successfully! Please wait while rebooting.";
				OK_MSG1(pMsg, submitUrl);
				sleep(2);
				system("reboot");
			} else
#endif //CONFIG_POCKET_AP_SUPPORT
			{
				OK_MSG1(pMsg, submitUrl);
			}
		}
	}
	return;

ss_err:
	ERR_MSG(tmpBuf);
}

/////////////////////////////////////////////////////////////////////////////
int wlSiteSurveyTbl(int eid, webs_t wp, int argc, char_t **argv)
{
	int nBytesSent=0, i;
#ifdef CONFIG_RTK_MESH 
// ==== inserted by GANTOE for site survey 2008/12/26 ==== 
	int mesh_enable; 
#endif 
	BssDscr *pBss;
	char tmpBuf[100], ssidbuf[40], tmp1Buf[10], tmp2Buf[20], wpa_tkip_aes[20],wpa2_tkip_aes[20];
#ifdef CONFIG_RTK_MESH 
// ==== inserted by GANTOE for site survey 2008/12/26 ==== 
	char meshidbuf[40] ;
#endif 

	WLAN_MODE_T mode;
	bss_info bss;

	if (pStatus==NULL) {
		pStatus = calloc(1, sizeof(SS_STATUS_T));
		if ( pStatus == NULL ) {
			printf("Allocate buffer failed!\n");
			return 0;
		}
	}

	pStatus->number = 0; // request BSS DB

	if ( getWlSiteSurveyResult(WLAN_IF, pStatus) < 0 ) {
		//ERR_MSG("Read site-survey status failed!");
		websWrite(wp, "Read site-survey status failed!");
		free(pStatus); //sc_yang
		pStatus = NULL;
		return 0;
	}

	if ( !apmib_get( MIB_WLAN_MODE, (void *)&mode) ) {
		printf("Get MIB_WLAN_MODE MIB failed!");
		return 0;
	}
#ifdef CONFIG_RTK_MESH
// ==== inserted by GANTOE for site survey 2008/12/26 ====
	mesh_enable = mode > 3 ? 1 : 0;	// Might to be corrected after the code refinement
#endif
	if ( getWlBssInfo(WLAN_IF, &bss) < 0) {
		printf("Get bssinfo failed!");
		return 0;
	}

// ==== inserted by GANTOE for site survey 2008/12/26 ==== 
//#ifdef CONFIG_RTK_MESH
#if 0
	if(mesh_enable) 
	{ 
		nBytesSent += websWrite(wp, T("<tr>" 
		"<td align=center width=\"30%%\" bgcolor=\"#808080\"><font size=\"2\"><b>MESHID</b></font></td>\n" 
		"<td align=center width=\"20%%\" bgcolor=\"#808080\"><font size=\"2\"><b>MAC ADDR</b></font></td>\n" 
		"<td align=center width=\"10%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Channel</b></font></td>\n")); 
		nBytesSent += websWrite(wp, T("<td align=center width=\"10%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Select</b></font></td></tr>\n")); 

		for (i=0; i<pStatus->number && pStatus->number!=0xff; i++) 
		{ 
			pBss = &pStatus->bssdb[i]; 
			if(pBss->bdMeshId.Length == 0)
				continue; 

			memcpy(meshidbuf, pBss->bdMeshIdBuf - 2, pBss->bdMeshId.Length); // the problem of padding still exists 
			meshidbuf[pBss->bdMeshId.Length] = '\0'; 

			snprintf(tmpBuf, 200, T("%02x:%02x:%02x:%02x:%02x:%02x"), 
				pBss->bdBssId[0], pBss->bdBssId[1], pBss->bdBssId[2], 
				pBss->bdBssId[3], pBss->bdBssId[4], pBss->bdBssId[5]); 
			memcpy(ssidbuf, pBss->bdSsIdBuf, pBss->bdSsId.Length); 
			ssidbuf[pBss->bdSsId.Length] = '\0'; 
			
			nBytesSent += websWrite(wp, T("<tr>" 
				"<td align=left width=\"30%%\" bgcolor=\"#C0C0C0\"><pre><font size=\"2\">%s</td>\n" 
				"<td align=center width=\"20%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n" 
				"<td align=center width=\"10%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%d</td>\n"), 
				meshidbuf, tmpBuf, pBss->ChannelNumber); 
            
			nBytesSent += websWrite(wp, 
			T("<td align=center width=\"10%%\" bgcolor=\"#C0C0C0\"><input type=\"radio\" name=" 
				"\"select\" value=\"sel%d\" onClick=\"enableConnect()\"></td></tr>\n"), i); 
		} 
	} 
	else 
#endif 
	{ 
	nBytesSent += websWrite(wp, T("<tr>"
	"<td align=center width=\"30%%\" bgcolor=\"#808080\"><font size=\"2\"><b>SSID</b></font></td>\n"
	"<td align=center width=\"20%%\" bgcolor=\"#808080\"><font size=\"2\"><b>BSSID</b></font></td>\n"
	"<td align=center width=\"10%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Channel</b></font></td>\n"
      	"<td align=center width=\"20%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Type</b></font></td>\n"
      	"<td align=center width=\"10%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Encrypt</b></font></td>\n"
	"<td align=center width=\"10%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Signal</b></font></td>\n"));
	if ( mode == CLIENT_MODE )
		nBytesSent += websWrite(wp, T("<td align=center width=\"10%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Select</b></font></td></tr>\n"));
	else
		nBytesSent += websWrite(wp, T("</tr>\n"));

	for (i=0; i<pStatus->number && pStatus->number!=0xff; i++) {
		pBss = &pStatus->bssdb[i];
		snprintf(tmpBuf, 200, T("%02x:%02x:%02x:%02x:%02x:%02x"),
			pBss->bdBssId[0], pBss->bdBssId[1], pBss->bdBssId[2],
			pBss->bdBssId[3], pBss->bdBssId[4], pBss->bdBssId[5]);

		memcpy(ssidbuf, pBss->bdSsIdBuf, pBss->bdSsId.Length);
		ssidbuf[pBss->bdSsId.Length] = '\0';

#if defined(CONFIG_RTK_MESH)
		if( pBss->bdMeshId.Length )
		{
			memcpy(meshidbuf, pBss->bdMeshIdBuf - 2, pBss->bdMeshId.Length);	// the problem of padding still exists

			if( !memcmp(ssidbuf, meshidbuf,pBss->bdMeshId.Length-1) )
				continue;
		}
#endif


		if (pBss->network==BAND_11B)
			strcpy(tmp1Buf, T(" (B)"));
		else if (pBss->network==BAND_11G)
			strcpy(tmp1Buf, T(" (G)"));	
		else if (pBss->network==(BAND_11G|BAND_11B))
			strcpy(tmp1Buf, T(" (B+G)"));
		else if (pBss->network==(BAND_11N))
			strcpy(tmp1Buf, T(" (N)"));		
		else if (pBss->network==(BAND_11G|BAND_11N))
			strcpy(tmp1Buf, T(" (G+N)"));	
		else if (pBss->network==(BAND_11G|BAND_11B | BAND_11N))
			strcpy(tmp1Buf, T(" (B+G+N)"));	
		else if(pBss->network== BAND_11A)
			strcpy(tmp1Buf, T(" (A)"));
		else if(pBss->network== (BAND_11A | BAND_11N))
			strcpy(tmp1Buf, T(" (A+N)"));	
		else
			sprintf(tmp1Buf, T(" -%d-"),pBss->network);

		memset(wpa_tkip_aes,0x00,sizeof(wpa_tkip_aes));
		memset(wpa2_tkip_aes,0x00,sizeof(wpa2_tkip_aes));
		
		if ((pBss->bdCap & cPrivacy) == 0)
			sprintf(tmp2Buf, "no");
		else {
			if (pBss->bdTstamp[0] == 0)
				sprintf(tmp2Buf, "WEP");
#if defined(CONFIG_RTL_WAPI_SUPPORT)
			else if (pBss->bdTstamp[0] == SECURITY_INFO_WAPI)
				sprintf(tmp2Buf, "WAPI");
#endif
			else {
				int wpa_exist = 0, idx = 0;
				if (pBss->bdTstamp[0] & 0x0000ffff) {
					idx = sprintf(tmp2Buf, "WPA");
					if (((pBss->bdTstamp[0] & 0x0000f000) >> 12) == 0x4)
						idx += sprintf(tmp2Buf+idx, "-PSK");
					else if(((pBss->bdTstamp[0] & 0x0000f000) >> 12) == 0x2)
						idx += sprintf(tmp2Buf+idx, "-1X");
					wpa_exist = 1;

					if (((pBss->bdTstamp[0] & 0x00000f00) >> 8) == 0x5)
						sprintf(wpa_tkip_aes,"%s","aes/tkip");
					else if (((pBss->bdTstamp[0] & 0x00000f00) >> 8) == 0x4)
						sprintf(wpa_tkip_aes,"%s","aes");
					else if (((pBss->bdTstamp[0] & 0x00000f00) >> 8) == 0x1)
						sprintf(wpa_tkip_aes,"%s","tkip");
				}
				if (pBss->bdTstamp[0] & 0xffff0000) {
					if (wpa_exist)
						idx += sprintf(tmp2Buf+idx, "/");
					idx += sprintf(tmp2Buf+idx, "WPA2");
					if (((pBss->bdTstamp[0] & 0xf0000000) >> 28) == 0x4)
						idx += sprintf(tmp2Buf+idx, "-PSK");
					else if (((pBss->bdTstamp[0] & 0xf0000000) >> 28) == 0x2)
						idx += sprintf(tmp2Buf+idx, "-1X");

					if (((pBss->bdTstamp[0] & 0x0f000000) >> 24) == 0x5)
						sprintf(wpa2_tkip_aes,"%s","aes/tkip");
					else if (((pBss->bdTstamp[0] & 0x0f000000) >> 24) == 0x4)
						sprintf(wpa2_tkip_aes,"%s","aes");
					else if (((pBss->bdTstamp[0] & 0x0f000000) >> 24) == 0x1)
						sprintf(wpa2_tkip_aes,"%s","tkip");
				}
			}
		}

#if 0
		if( mesh_enable && (pBss->bdMeshId.Length > 0) )
		{
			nBytesSent += websWrite(wp, T("<tr>"
			"<td align=left width=\"20%%\" bgcolor=\"#C0C0C0\"><pre><font size=\"2\">%s</td>\n"
			"<td align=center width=\"20%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
			"<td align=center width=\"10%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%d%s</td>\n"     
      			"<td align=center width=\"20%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
			"<td align=center width=\"10%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
			"<td align=center width=\"10%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%d</td>\n"),
			ssidbuf, tmpBuf, pBss->ChannelNumber, tmp1Buf, "Mesh Node", tmp2Buf, pBss->rssi);
		}
		else
#endif
		{
			nBytesSent += websWrite(wp, T("<tr>"
			"<td align=center width=\"20%%\" bgcolor=\"#C0C0C0\"><pre><font size=\"2\">%s</td>\n"
			"<td align=center width=\"20%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
			"<td align=center width=\"10%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%d%s</td>\n"     
      			"<td align=center width=\"20%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
			"<td align=center width=\"10%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
			"<td align=center width=\"10%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%d</td>\n"),
			ssidbuf, tmpBuf, pBss->ChannelNumber, tmp1Buf,
			((pBss->bdCap & cIBSS) ? "Ad hoc" : "AP"), tmp2Buf, pBss->rssi);
		}

		if ( mode == CLIENT_MODE )
			nBytesSent += websWrite(wp,
			T("<td align=center width=\"10%%\" bgcolor=\"#C0C0C0\"> <input type=\"hidden\" id=\"selSSID_%d\" value=\"%s\" > <input type=\"hidden\" id=\"selChannel_%d\" value=\"%d\" > <input type=\"hidden\" id=\"selEncrypt_%d\" value=\"%s\" > <input type=\"hidden\" id=\"wpa_tkip_aes_%d\" value=\"%s\" > <input type=\"hidden\" id=\"wpa2_tkip_aes_%d\" value=\"%s\" > <input type=\"radio\" name="
			"\"select\" value=\"sel%d\" onClick=\"enableConnect(%d)\"></td></tr>\n"), i,ssidbuf,i,pBss->ChannelNumber,i,tmp2Buf,i,wpa_tkip_aes,i,wpa2_tkip_aes ,i,i);
		else
			nBytesSent += websWrite(wp, T("</tr>\n"));
	}

	if( pStatus->number == 0 )
	{
		if ( mode == CLIENT_MODE )
		{
			nBytesSent += websWrite(wp, T("<tr>"
	                "<td align=center width=\"20%%\" bgcolor=\"#C0C0C0\"><pre><font size=\"2\">None</td>\n"
	                "<td align=center width=\"20%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"></td>\n"
	                "<td align=center width=\"10%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"></td>\n"
	                "<td align=center width=\"20%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"></td>\n"
	                "<td align=center width=\"10%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"></td>\n"
	                "<td align=center width=\"10%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"></td>\n"
	                "<td align=center width=\"20%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"></td>\n"
	                "</tr>\n"));
		}
		else
		{
			nBytesSent += websWrite(wp, T("<tr>"
			"<td align=center width=\"20%%\" bgcolor=\"#C0C0C0\"><pre><font size=\"2\">None</td>\n"
			"<td align=center width=\"20%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"></td>\n"
			"<td align=center width=\"10%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"></td>\n"
			"<td align=center width=\"20%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"></td>\n"
			"<td align=center width=\"10%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"></td>\n"
			"<td align=center width=\"10%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"></td>\n"
			"</tr>\n"));
		}
	}
	nBytesSent += websWrite(wp, T("</table>\n"));

#ifdef CONFIG_RTK_MESH
	if(mesh_enable) 
	{ 
		int mesh_count = 0;

		nBytesSent += websWrite(wp, T("<table border=\"1\" width=\"500\">"
		"<tr><h4><font><br><br>List of Mesh Points</font></tr><tr>"
		"<td align=center width=\"30%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Mesh ID</b></font></td>\n" 
		"<td align=center width=\"20%%\" bgcolor=\"#808080\"><font size=\"2\"><b>MAC Adddress</b></font></td>\n" 
		"<td align=center width=\"10%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Channel</b></font></td>\n")); 
		nBytesSent += websWrite(wp, T("<td align=center width=\"10%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Select</b></font></td></tr>\n"));

		for (i=0; i<pStatus->number && pStatus->number!=0xff; i++) 
		{
			pBss = &pStatus->bssdb[i]; 
			if(pBss->bdMeshId.Length == 0)
				continue; 
			mesh_count++;
			memcpy(meshidbuf, pBss->bdMeshIdBuf - 2, pBss->bdMeshId.Length); // the problem of padding still exists
			meshidbuf[pBss->bdMeshId.Length] = '\0'; 

			snprintf(tmpBuf, 200, T("%02x:%02x:%02x:%02x:%02x:%02x"), 
				pBss->bdBssId[0], pBss->bdBssId[1], pBss->bdBssId[2], 
				pBss->bdBssId[3], pBss->bdBssId[4], pBss->bdBssId[5]); 
			memcpy(ssidbuf, pBss->bdSsIdBuf, pBss->bdSsId.Length); 
			ssidbuf[pBss->bdSsId.Length] = '\0'; 
			
			nBytesSent += websWrite(wp, T("<tr>" 
				"<td align=left width=\"30%%\" bgcolor=\"#C0C0C0\"><pre><font size=\"2\">%s</td>\n" 
				"<td align=center width=\"20%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n" 
				"<td align=center width=\"10%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%d</td>\n"), 
				meshidbuf, tmpBuf, pBss->ChannelNumber); 
            
			nBytesSent += websWrite(wp, 
			T("<td align=center width=\"10%%\" bgcolor=\"#C0C0C0\"><input type=\"radio\" name=" 
				"\"select\" value=\"sel%d\" onClick=\"enableConnect()\"></td></tr>\n"), i); 
		}
		if( mesh_count == 0 )
		{
			nBytesSent += websWrite(wp, T("<tr>"
			"<td align=center width=\"30%%\" bgcolor=\"#C0C0C0\"><pre><font size=\"2\">None</td>\n"
			"<td align=center width=\"20%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"></td>\n"
			"<td align=center width=\"10%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"></td>\n"
			"<td align=center width=\"10%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"></td>\n"));
		}
		nBytesSent += websWrite(wp, T("</table>")); 
	}
#endif
	} 
	return nBytesSent;
}


#ifdef CONFIG_RTK_MESH
/////////////////////////////////////////////////////////////////////////////
void formWlMesh(webs_t wp, char_t *path, char_t *query)
{
	char_t *strAddMac, *strDelMac, *strDelAllMac, *strVal, *submitUrl, *strEnabled;
	char tmpBuf[100];
	int entryNum, i, enabled;
	WDS_T macEntry;

	strAddMac = websGetVar(wp, T("addWdsMac"), T(""));
	strDelMac = websGetVar(wp, T("deleteSelWdsMac"), T(""));
	strDelAllMac = websGetVar(wp, T("deleteAllWdsMac"), T(""));
	strEnabled = websGetVar(wp, T("wlanWdsEnabled"), T(""));

	if (strAddMac[0]) {
		if ( !gstrcmp(strEnabled, T("ON")))
			enabled = 1;
		else
			enabled = 0;
		if ( apmib_set( MIB_WLAN_WDS_ENABLED, (void *)&enabled) == 0) {
  			strcpy(tmpBuf, T("Set enabled flag error!"));
			goto setErr_wds;
		}

		strVal = websGetVar(wp, T("mac"), T(""));
		if ( !strVal[0] )
			goto setWds_ret;

		if (strlen(strVal)!=12 || !string_to_hex(strVal, macEntry.macAddr, 12)) {
			strcpy(tmpBuf, T("Error! Invalid MAC address."));
			goto setErr_wds;
		}

		strVal = websGetVar(wp, T("comment"), T(""));
		if ( strVal[0] ) {
			if (strlen(strVal) > COMMENT_LEN-1) {
				strcpy(tmpBuf, T("Error! Comment length too long."));
				goto setErr_wds;
			}
			strcpy(macEntry.comment, strVal);
		}
		else
			macEntry.comment[0] = '\0';

		if ( !apmib_get(MIB_WLAN_WDS_NUM, (void *)&entryNum)) {
			strcpy(tmpBuf, T("Get entry number error!"));
			goto setErr_wds;
		}
		if ( (entryNum + 1) > MAX_WDS_NUM) {
			strcpy(tmpBuf, T("Cannot add new entry because table is full!"));
			goto setErr_wds;
		}

		// set to MIB. try to delete it first to avoid duplicate case
		apmib_set(MIB_WLAN_WDS_DEL, (void *)&macEntry);
		if ( apmib_set(MIB_WLAN_WDS_ADD, (void *)&macEntry) == 0) {
			strcpy(tmpBuf, T("Add table entry error!"));
			goto setErr_wds;
		}
	}

	/* Delete entry */
	if (strDelMac[0]) {
		if ( !apmib_get(MIB_WLAN_WDS_NUM, (void *)&entryNum)) {
			strcpy(tmpBuf, T("Get entry number error!"));
			goto setErr_wds;
		}
		for (i=entryNum; i>0; i--) {
			snprintf(tmpBuf, 20, "select%d", i);

			strVal = websGetVar(wp, tmpBuf, T(""));
			if ( !gstrcmp(strVal, T("ON")) ) {

				*((char *)&macEntry) = (char)i;
				if ( !apmib_get(MIB_WLAN_WDS, (void *)&macEntry)) {
					strcpy(tmpBuf, T("Get table entry error!"));
					goto setErr_wds;
				}
				if ( !apmib_set(MIB_WLAN_WDS_DEL, (void *)&macEntry)) {
					strcpy(tmpBuf, T("Delete table entry error!"));
					goto setErr_wds;
				}
			}
		}
	}

	/* Delete all entry */
	if ( strDelAllMac[0]) {
		if ( !apmib_set(MIB_WLAN_WDS_DELALL, (void *)&macEntry)) {
			strcpy(tmpBuf, T("Delete all table error!"));
			goto setErr_wds;
		}
	}

setWds_ret:
	apmib_update(CURRENT_SETTING);

#ifndef NO_ACTION
	run_init_script("bridge");
#endif

	submitUrl = websGetVar(wp, T("submit-url"), T(""));   // hidden page
	OK_MSG( submitUrl );
  	return;

setErr_wds:
	ERR_MSG(tmpBuf);
}

#endif // CONFIG_RTK_MESH


/////////////////////////////////////////////////////////////////////////////
void formWlWds(webs_t wp, char_t *path, char_t *query)
{
	char_t *strRate, *strAddMac, *strDelMac, *strDelAllMac, *strVal, *submitUrl, *strEnabled;
	char tmpBuf[100];
	int entryNum, i, enabled, val;
	WDS_T macEntry;

	int maxWDSNum;
	
#ifdef CONFIG_RTL8196B_GW_8M
	maxWDSNum = 4;
#else
	maxWDSNum = MAX_WDS_NUM;
#endif

	strAddMac = websGetVar(wp, T("addWdsMac"), T(""));
	strDelMac = websGetVar(wp, T("deleteSelWdsMac"), T(""));
	strDelAllMac = websGetVar(wp, T("deleteAllWdsMac"), T(""));
	strEnabled = websGetVar(wp, T("wlanWdsEnabled"), T(""));

	if (strAddMac[0]) {
		if ( !gstrcmp(strEnabled, T("ON")))
			enabled = 1;
		else
			enabled = 0;
		if ( apmib_set( MIB_WLAN_WDS_ENABLED, (void *)&enabled) == 0) {
  			strcpy(tmpBuf, T("Set enabled flag error!"));
			goto setErr_wds;
		}

		strVal = websGetVar(wp, T("mac"), T(""));
		if ( !strVal[0] )
			goto setWds_ret;

		if (strlen(strVal)!=12 || !string_to_hex(strVal, macEntry.macAddr, 12)) {
			strcpy(tmpBuf, T("Error! Invalid MAC address."));
			goto setErr_wds;
		}

		strVal = websGetVar(wp, T("comment"), T(""));
		if ( strVal[0] ) {
			if (strlen(strVal) > COMMENT_LEN-1) {
				strcpy(tmpBuf, T("Error! Comment length too long."));
				goto setErr_wds;
			}
			strcpy(macEntry.comment, strVal);
		}
		else
			macEntry.comment[0] = '\0';


		
		strRate = websGetVar(wp, "txRate", T(""));
		if ( strRate[0] ) {
			if ( strRate[0] == '0' ) { // auto
				macEntry.fixedTxRate =0;
			}else  {
				val = atoi(strRate);
				val = 1 << (val-1);
				macEntry.fixedTxRate = val;
			}
		}
	

		
		if ( !apmib_get(MIB_WLAN_WDS_NUM, (void *)&entryNum)) {
			strcpy(tmpBuf, T("Get entry number error!"));
			goto setErr_wds;
		}
		if ( (entryNum + 1) > maxWDSNum) {
			strcpy(tmpBuf, T("Cannot add new entry because table is full!"));
			goto setErr_wds;
		}

		// set to MIB. try to delete it first to avoid duplicate case
		apmib_set(MIB_WLAN_WDS_DEL, (void *)&macEntry);
		if ( apmib_set(MIB_WLAN_WDS_ADD, (void *)&macEntry) == 0) {
			strcpy(tmpBuf, T("Add table entry error!"));
			goto setErr_wds;
		}
	}

	/* Delete entry */
	if (strDelMac[0]) {
		if ( !apmib_get(MIB_WLAN_WDS_NUM, (void *)&entryNum)) {
			strcpy(tmpBuf, T("Get entry number error!"));
			goto setErr_wds;
		}
		for (i=entryNum; i>0; i--) {
			snprintf(tmpBuf, 20, "select%d", i);

			strVal = websGetVar(wp, tmpBuf, T(""));
			if ( !gstrcmp(strVal, T("ON")) ) {

				*((char *)&macEntry) = (char)i;
				if ( !apmib_get(MIB_WLAN_WDS, (void *)&macEntry)) {
					strcpy(tmpBuf, T("Get table entry error!"));
					goto setErr_wds;
				}
				if ( !apmib_set(MIB_WLAN_WDS_DEL, (void *)&macEntry)) {
					strcpy(tmpBuf, T("Delete table entry error!"));
					goto setErr_wds;
				}
			}
		}
	}

	/* Delete all entry */
	if ( strDelAllMac[0]) {
		if ( !apmib_set(MIB_WLAN_WDS_DELALL, (void *)&macEntry)) {
			strcpy(tmpBuf, T("Delete all table error!"));
			goto setErr_wds;
		}
	}

setWds_ret:
	apmib_update_web(CURRENT_SETTING);

#ifndef NO_ACTION
	run_init_script("bridge");
#endif

	submitUrl = websGetVar(wp, T("submit-url"), T(""));   // hidden page
	OK_MSG( submitUrl );
  	return;

setErr_wds:
	ERR_MSG(tmpBuf);
}


/////////////////////////////////////////////////////////////////////////////
int wlWdsList(int eid, webs_t wp, int argc, char_t **argv)
{
	int nBytesSent=0, entryNum, i;
	WDS_T entry;
	char tmpBuf[100];
	char txrate[20];
	int rateid=0;

	if ( !apmib_get(MIB_WLAN_WDS_NUM, (void *)&entryNum)) {
  		websError(wp, 400, T("Get table entry error!\n"));
		return -1;
	}

	nBytesSent += websWrite(wp, T("<tr>"
      	"<td align=center width=\"35%%\" bgcolor=\"#808080\"><font size=\"2\"><b>MAC Address</b></font></td>\n"
      	"<td align=center width=\"25%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Tx Rate (Mbps)</b></font></td>\n"
      	"<td align=center width=\"30%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Comment</b></font></td>\n"
      	"<td align=center width=\"10%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Select</b></font></td></tr>\n"));

	for (i=1; i<=entryNum; i++) {
		*((char *)&entry) = (char)i;
		if ( !apmib_get(MIB_WLAN_WDS, (void *)&entry))
			return -1;

		snprintf(tmpBuf, 100, T("%02x:%02x:%02x:%02x:%02x:%02x"),
			entry.macAddr[0], entry.macAddr[1], entry.macAddr[2],
			entry.macAddr[3], entry.macAddr[4], entry.macAddr[5]);

		if(entry.fixedTxRate == 0){	
				sprintf(txrate, "%s","Auto"); 
		}else{
			for(rateid=0; rateid<28;rateid++){
				if(tx_fixed_rate[rateid].id == entry.fixedTxRate){
					sprintf(txrate, "%s", tx_fixed_rate[rateid].rate);
					break;
				}
			}
		}	
		nBytesSent += websWrite(wp, T("<tr>"
      			"<td align=center width=\"35%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
      			"<td align=center width=\"25%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
      			"<td align=center width=\"30%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
       			"<td align=center width=\"10%%\" bgcolor=\"#C0C0C0\"><input type=\"checkbox\" name=\"select%d\" value=\"ON\"></td></tr>\n"),
				tmpBuf, txrate, entry.comment,i);
	}
	return nBytesSent;
}


/////////////////////////////////////////////////////////////////////////////
void formWdsEncrypt(webs_t wp, char_t *path, char_t *query)
{
   	char_t *strVal, *submitUrl;
	char tmpBuf[100];
	WDS_ENCRYPT_T encrypt;
	int intVal, keyLen=0, oldFormat, oldPskLen, len, i;
	char charArray[16]={'0' ,'1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
	char key[100];
	char varName[20];

	sprintf(varName, "encrypt%d", wlan_idx);
	strVal = websGetVar(wp, varName, T(""));
	if (strVal[0]) {
		encrypt = strVal[0] - '0';
		if (encrypt != WDS_ENCRYPT_DISABLED && encrypt != WDS_ENCRYPT_WEP64 &&
			encrypt != WDS_ENCRYPT_WEP128 && encrypt != WDS_ENCRYPT_TKIP &&
				encrypt != WDS_ENCRYPT_AES) {
 			strcpy(tmpBuf, T("encrypt value not validt!"));
			goto setErr_wdsEncrypt;
		}
		apmib_set( MIB_WLAN_WDS_ENCRYPT, (void *)&encrypt);
	}
	else
		apmib_get( MIB_WLAN_WDS_ENCRYPT, (void *)&encrypt);

	if (encrypt == WDS_ENCRYPT_WEP64 || encrypt == WDS_ENCRYPT_WEP128) {
		sprintf(varName, "format%d", wlan_idx);
		strVal = websGetVar(wp, varName, T(""));
		if (strVal[0]) {
			if (strVal[0]!='0' && strVal[0]!='1') {
				strcpy(tmpBuf, T("Invalid wep key format value!"));
				goto setErr_wdsEncrypt;
		}
			intVal = strVal[0] - '0';
			apmib_set( MIB_WLAN_WDS_WEP_FORMAT, (void *)&intVal);
		}
		else
			apmib_get( MIB_WLAN_WDS_WEP_FORMAT, (void *)&intVal);

		if (encrypt == WDS_ENCRYPT_WEP64)
			keyLen = WEP64_KEY_LEN;
		else if (encrypt == WDS_ENCRYPT_WEP128)
			keyLen = WEP128_KEY_LEN;

		if (intVal == 1) // hex
			keyLen <<= 1;

		sprintf(varName, "wepKey%d", wlan_idx);
		strVal = websGetVar(wp, varName, T(""));
		if  (strVal[0]) {
			if (strlen(strVal) != keyLen) {
				strcpy(tmpBuf, T("Invalid wep key length!"));
				goto setErr_wdsEncrypt;
		}
			if ( !isAllStar(strVal) ) {
				if (intVal == 0) { // ascii
					for (i=0; i<keyLen; i++) {
						key[i*2] = charArray[(strVal[i]>>4)&0xf];
						key[i*2+1] = charArray[strVal[i]&0xf];
				}
					key[i*2] = '\0';
			}
				else  // hex
					strcpy(key, strVal);
				apmib_set( MIB_WLAN_WDS_WEP_KEY, (void *)key);
			}
		}
	}
	if (encrypt == WDS_ENCRYPT_TKIP || encrypt == WDS_ENCRYPT_AES) {
		sprintf(varName, "pskFormat%d", wlan_idx);
		strVal = websGetVar(wp, varName, T(""));
		if (strVal[0]) {
			if (strVal[0]!='0' && strVal[0]!='1') {
				strcpy(tmpBuf, T("Invalid wep key format value!"));
				goto setErr_wdsEncrypt;
				}
			intVal = strVal[0] - '0';
			}
			else
			apmib_get( MIB_WLAN_WDS_PSK_FORMAT, (void *)&intVal);


		// remember current psk format and length to compare to default case "****"
		apmib_get(MIB_WLAN_WDS_PSK_FORMAT, (void *)&oldFormat);
		apmib_get(MIB_WLAN_WDS_PSK, (void *)tmpBuf);
		oldPskLen = strlen(tmpBuf);

		sprintf(varName, "pskValue%d", wlan_idx);
		strVal = websGetVar(wp, varName, T(""));
		len = strlen(strVal);
		if (len > 0 && oldFormat == intVal && len == oldPskLen ) {
			for (i=0; i<len; i++) {
				if ( strVal[i] != '*' )
				break;
			}
			if (i == len)
				goto save_wdsEcrypt;
		}
		if (intVal==1) { // hex
			if (len!=MAX_PSK_LEN || !string_to_hex(strVal, tmpBuf, MAX_PSK_LEN)) {
				strcpy(tmpBuf, T("Error! invalid psk value."));
				goto setErr_wdsEncrypt;
	}
				}
		else { // passphras
			if (len==0 || len > (MAX_PSK_LEN-1) ) {
				strcpy(tmpBuf, T("Error! invalid psk value."));
				goto setErr_wdsEncrypt;
			}
		}
		apmib_set( MIB_WLAN_WDS_PSK_FORMAT, (void *)&intVal);
		apmib_set( MIB_WLAN_WDS_PSK, (void *)strVal);
	}

save_wdsEcrypt:
	intVal = 1;
	apmib_set( MIB_WLAN_WDS_ENABLED, (void *)&intVal);

	apmib_update_web(CURRENT_SETTING);

#ifndef NO_ACTION
	run_init_script("bridge");
#endif

	submitUrl = websGetVar(wp, T("submit-url"), T(""));   // hidden page
	OK_MSG(submitUrl);

	return;

setErr_wdsEncrypt:
	ERR_MSG(tmpBuf);
}


/////////////////////////////////////////////////////////////////////////////
int wdsList(int eid, webs_t wp, int argc, char_t **argv)
{
	int nBytesSent=0, i;
	WDS_INFO_Tp pInfo;
	char *buff;
	char txrate[20];
	int rateid=0;
	int short_gi=0;
	int channel_bandwidth=0;

	buff = calloc(1, sizeof(WDS_INFO_T)*MAX_STA_NUM);
	if ( buff == 0 ) {
		printf("Allocate buffer failed!\n");
		return 0;
	}

	if ( getWdsInfo(WLAN_IF, buff) < 0 ) {
		printf("Read wlan sta info failed!\n");
		return 0;
	}

	for (i=0; i<MAX_WDS_NUM; i++) {
		pInfo = (WDS_INFO_Tp)&buff[i*sizeof(WDS_INFO_T)];

		if (pInfo->state == STATE_WDS_EMPTY)
			break;

		if((pInfo->txOperaRate & 0x80) != 0x80){	
			if(pInfo->txOperaRate%2){
				sprintf(txrate, "%d%s",pInfo->txOperaRate/2, ".5"); 
			}else{
				sprintf(txrate, "%d",pInfo->txOperaRate/2); 
			}
		}else{
			apmib_get(MIB_WLAN_CHANNEL_BONDING, (void *)&channel_bandwidth);
			apmib_get(MIB_WLAN_SHORT_GI, (void *)&short_gi);
			if(channel_bandwidth ==0){ //20M
				if(short_gi==0){//long
					for(rateid=0; rateid<16;rateid++){
						if(rate_11n_table_20M_LONG[rateid].id == pInfo->txOperaRate){
							sprintf(txrate, "%s", rate_11n_table_20M_LONG[rateid].rate);
							break;
						}
					}
				}else if(short_gi==1){//short
					for(rateid=0; rateid<16;rateid++){
						if(rate_11n_table_20M_SHORT[rateid].id == pInfo->txOperaRate){
							sprintf(txrate, "%s", rate_11n_table_20M_SHORT[rateid].rate);
							break;
						}
					}
				}
			}else if(channel_bandwidth ==1){ //40
					if(short_gi==0){//long
						for(rateid=0; rateid<16;rateid++){
							if(rate_11n_table_40M_LONG[rateid].id == pInfo->txOperaRate){
								sprintf(txrate, "%s", rate_11n_table_40M_LONG[rateid].rate);
								break;
							}
						}
					}else if(short_gi==1){//short
						for(rateid=0; rateid<16;rateid++){
							if(rate_11n_table_40M_SHORT[rateid].id == pInfo->txOperaRate){
								sprintf(txrate, "%s", rate_11n_table_40M_SHORT[rateid].rate);
								break;
							}
						}
					}	
			}
		}	
		nBytesSent += websWrite(wp,
	   		"<tr bgcolor=#b7b7b7><td><font size=2>%02x:%02x:%02x:%02x:%02x:%02x</td>"
			"<td><font size=2>%d</td>"
	     		"<td><font size=2>%d</td>"
			"<td><font size=2>%d</td>"
			"<td><font size=2>%s</td>",
			pInfo->addr[0],pInfo->addr[1],pInfo->addr[2],pInfo->addr[3],pInfo->addr[4],pInfo->addr[5],
			pInfo->tx_packets, pInfo->tx_errors, pInfo->rx_packets,
			txrate);
	}

	free(buff);

	return nBytesSent;
}

#ifdef WLAN_EASY_CONFIG
/////////////////////////////////////////////////////////////////////////////
void sigHandler_autoconf(int signo)
{
	int val, reinit=1;
	char tmpbuf[100];	
	
	apmib_get( MIB_WLAN_MODE, (void *)&val);	
	if (val == AP_MODE || val == AP_WDS_MODE) {	
		apmib_get(MIB_WLAN_EASYCFG_KEY, (void *)tmpbuf);	
		if (strlen(tmpbuf) > 0) // key already installed
			reinit = 0;		
	}

#ifdef WIFI_SIMPLE_CONFIG	
{
	#define REINIT_WEB_FILE		T("/tmp/reinit_web")
	struct stat status;

	if (stat(REINIT_WEB_FILE, &status) == 0) { // file existed
        unlink(REINIT_WEB_FILE);
		reinit = 0;		
	}
}
#endif
	
	if (reinit) { // re-init system
		wait_config = 1;
#ifdef REBOOT_CHECK
	run_init_script_flag = 1;
#endif		
#ifndef NO_ACTION
		run_init_script("all");
#endif		
		wait_config = CONFIG_SUCCESS;
	}
	if (apmib_reinit() == 0) 
		printf(T("Re-initialize AP MIB failed!\n"));	
}

/////////////////////////////////////////////////////////////////////////////
void formAutoCfg(webs_t wp, char_t *path, char_t *query)
{
   	char_t *strVal, *submitUrl;
 	int isButtonPress=0, isSave=0, isDelete=0, isDoConfigButton=0, isDoConfigQuestion=0;
	int mode, val, isAP, mode_old, enable, enable_old, wlan_disabled, i, isAdhoc, first=0;
	char tmpBuf[200], wlan_interface_set[100]={0}, hashBuf[33];
	
	strVal = websGetVar(wp, T("cfgEnabled"), T(""));
	if ( !gstrcmp(strVal, T("ON")))
		enable = 1;
	else
		enable = 0;

	apmib_get( MIB_WLAN_EASYCFG_ENABLED, (void *)&enable_old);
	apmib_get( MIB_WLAN_WLAN_DISABLED, (void *)&wlan_disabled);

	strVal = websGetVar(wp, T("buttonClicked"), T(""));
	if (strVal[0])
		isButtonPress = 1;
	else {
		strVal = websGetVar(wp, T("save"), T(""));
		if (strVal[0])
			isSave = 1;
		else {
			strVal = websGetVar(wp, T("deletekey"), T(""));
			if (strVal[0])
				isDelete = 1;
			else {
				strVal = websGetVar(wp, T("doConfigButton"), T(""));
				if (strVal[0])
					isDoConfigButton = 1;
				else {
					strVal = websGetVar(wp, T("doConfigQuestion"), T(""));
					if (strVal[0])
						isDoConfigQuestion = 1;		
					else {
						strcpy(tmpBuf, T("Error, no action is defined!"));
						goto setErr_autocfg;
					}
				}
			}
		}
	}

	apmib_get( MIB_WLAN_MODE, (void *)&val);
	if (val == AP_MODE || val == AP_WDS_MODE) 
		isAP = 1;
	else 
		isAP = 0;

	apmib_set( MIB_WLAN_EASYCFG_WLAN_MODE, (void *)&val);

	apmib_get( MIB_WLAN_EASYCFG_MODE, (void *)&mode_old);
	
	if (isAP && isDoConfigQuestion) {
		strcpy(tmpBuf, T("Error, invalid action request!"));
		goto setErr_autocfg;
	}

	if (!isAP && isButtonPress ) {
		strcpy(tmpBuf, T("Error, invalid action request!"));
		goto setErr_autocfg;
	}

	for (i=0; i<wlan_num; i++) {
		sprintf(tmpBuf, "wlan%d ", i);
		strcat(wlan_interface_set, tmpBuf);
	}

	strVal = websGetVar(wp, T("mode"), T(""));
	if ( strVal[0] ) {
		if (strVal[0]!= '1' && strVal[0]!= '2' && strVal[0]!= '3') {
  			strcpy(tmpBuf, T("Invalid mode value!"));
			goto setErr_autocfg;
		}
		mode = strVal[0] - '0';
	}
	else
		mode = mode_old;

	if (enable != enable_old) {
		int modify=0, aval, cipher;
		unsigned char tmp1[100], tmp2[100];
		
		apmib_set( MIB_WLAN_EASYCFG_ENABLED, (void *)&enable);
		
		apmib_get( MIB_WLAN_EASYCFG_KEY, (void *)&tmpBuf);	
		if (enable && strlen(tmpBuf) > 0) { /* key installed */
			/* see if current setting diff with AUTOCFG value. */
			/* if modify, flush AUTOCFG value */
			apmib_get( MIB_WLAN_WPA_AUTH, (void *)&val);			
			if (val != WPA_AUTH_PSK) 
				modify = 1;
		
			apmib_get( MIB_WLAN_EASYCFG_SSID, (void *)&tmp1);
			apmib_get( MIB_WLAN_SSID, (void *)&tmp2);		
			if ( gstrcmp(tmp1, tmp2))
				modify = 1;			
		
			if (!modify ) {		
				apmib_get( MIB_WLAN_ENCRYPT, (void *)&val);
				apmib_get( MIB_WLAN_EASYCFG_ALG_REQ, (void *)&aval);	
				apmib_get( MIB_WLAN_WPA_CIPHER_SUITE, (void *)&cipher);
				
				if ( !(val & ENCRYPT_WPA) && !(val & ENCRYPT_WPA2)) 
					modify = 1;		
				if (val & ENCRYPT_WPA) {
					if ((aval & ACF_ALGORITHM_WPA_TKIP) && !(cipher & WPA_CIPHER_TKIP))
						modify = 1;
					if ((aval & ACF_ALGORITHM_WPA_AES) && !(cipher & WPA_CIPHER_AES))
						modify = 1;					
				}
			 	if (val & ENCRYPT_WPA2) {
					if ((aval & ACF_ALGORITHM_WPA2_TKIP) && !(cipher & WPA_CIPHER_TKIP))
						modify = 1;
					if ((aval & ACF_ALGORITHM_WPA2_AES) && !(cipher & WPA_CIPHER_AES))
						modify = 1;					
				}
			}		
			if (!modify) {
				apmib_get( MIB_WLAN_EASYCFG_ROLE, (void *)&val);	
				if (isAP) {
					if (val != ROLE_SERVER)
						modify = 1;
				}
				else {					
					apmib_get( MIB_WLAN_NETWORK_TYPE, (void *)&isAdhoc);
					if (val == ROLE_SERVER)
						modify = 1;
					else {
						if ((val == ROLE_CLIENT) && isAdhoc)
							modify = 1;
						else if ((val == ROLE_ADHOC) && !isAdhoc)
							modify = 1;
					}
				}				
			}			
			
			if (modify) {
				tmpBuf[0] = '\0';
				apmib_set(MIB_WLAN_EASYCFG_KEY, (void *)tmpBuf);
				apmib_set(MIB_WLAN_EASYCFG_DIGEST, (void *)tmpBuf);	
			}
		}
	}

	if ((isDoConfigButton || isDoConfigQuestion) && !wlan_disabled) {
		if ((mode & MODE_QUESTION) && isDoConfigQuestion ) {
			MD5_CONTEXT md5ctx;
			unsigned char hash[16];
			int i;
			const char *hex = "0123456789abcdef";
			char *r;

			strVal = websGetVar(wp, T("firstCfg"), T(""));
			if ( !gstrcmp(strVal, T("ON")))
				first = 1;
			else
				first = 0;

			tmpBuf[0]='\0';
			strVal = websGetVar(wp, T("q1"), T(""));
			strcat(tmpBuf, strVal);
			strVal = websGetVar(wp, T("q1ans"), T(""));
			strcat(tmpBuf, strVal);

			strVal = websGetVar(wp, T("q2"), T(""));
			strcat(tmpBuf, strVal);
			strVal = websGetVar(wp, T("q2ans"), T(""));
			strcat(tmpBuf, strVal);

			MD5Init(&md5ctx);
			MD5Update(&md5ctx, tmpBuf, (unsigned int)strlen(tmpBuf));
			MD5Final(hash, &md5ctx);

			/*
 			 *  Prepare the resulting hash string
 			 */
   			for (i = 0, r = hashBuf; i < 16; i++) {
             		*r++ = toupper(hex[hash[i] >> 4]);
               		*r++ = toupper(hex[hash[i] & 0xF]);
   			}
			*r = '\0';
			apmib_get( MIB_WLAN_NETWORK_TYPE, (void *)&isAdhoc);
#if 0			
			if (!isAP && isAdhoc) {
				char tmpBuf1[100];
				apmib_get( MIB_WLAN_EASYCFG_KEY, (void *)tmpBuf1);
				apmib_get( MIB_WLAN_EASYCFG_DIGEST, (void *)tmpBuf);
				if (tmpBuf1[0] && tmpBuf[0] && strcmp(hashBuf, tmpBuf)) {
		  			strcpy(tmpBuf, T("The question selection or answer of Q&A mode is not matched with installed value!"));
					goto setErr_autocfg;					
				}				
			}
#endif			
		}
	}
	
	if (mode != mode_old)
		apmib_set( MIB_WLAN_EASYCFG_MODE, (void *)&mode);

	if (isDelete) {
		tmpBuf[0] = '\0';
		apmib_set(MIB_WLAN_EASYCFG_KEY, (void *)tmpBuf);
		apmib_set(MIB_WLAN_EASYCFG_DIGEST, (void *)tmpBuf);
	}

	if (enable != enable_old || mode != mode_old || isDelete) {
		apmib_update_web(CURRENT_SETTING);
#ifndef NO_ACTION
		if (!wlan_disabled) {	
			sprintf(tmpBuf, "%s/%s start %s %s", _CONFIG_SCRIPT_PATH, 
				_WLAN_APP_SCRIPT_PROG, wlan_interface_set, BRIDGE_IF);
			system( tmpBuf );			
			sleep(2);
		}
#endif		
	}
	
#ifndef NO_ACTION	
	if (isButtonPress && !wlan_disabled) {
		sprintf(tmpBuf, "%s/%s -w wlan%d -press_button", _CONFIG_SCRIPT_PATH, 
			_AUTO_CONFIG_DAEMON_PROG, wlan_idx);
		system( tmpBuf );
	}

	if ((isDoConfigButton || isDoConfigQuestion) && !wlan_disabled) {
		if ((mode & MODE_QUESTION) && isDoConfigQuestion ) {
			sprintf(tmpBuf, "%s/%s start %s %s %s", _CONFIG_SCRIPT_PATH,
				_WLAN_APP_SCRIPT_PROG, wlan_interface_set, BRIDGE_IF, hashBuf);
			if (first)
				strcat(tmpBuf, " qfirst");
			system( tmpBuf );				
			sleep(2);
		}
		else {
			
			sprintf(tmpBuf, "%s/%s -w wlan%d -press_button", _CONFIG_SCRIPT_PATH, 
				_AUTO_CONFIG_DAEMON_PROG, wlan_idx);
			system( tmpBuf );
		}

		wait_config = 1;		
		while (wait_config <= DO_CONFIG_WAIT_TIME &&
					wait_config != CONFIG_SUCCESS) {
			wait_config++;						
			sleep(1);			
		}
		
		submitUrl = websGetVar(wp, T("submit-url"), T(""));   // hidden page
		
		if (wait_config == CONFIG_SUCCESS) {
			OK_MSG1(T("Do Auto-Config successfully!"), submitUrl);
		}
		else {
			sprintf(tmpBuf, "%s/%s -w wlan%d -release_button", _CONFIG_SCRIPT_PATH, 
				_AUTO_CONFIG_DAEMON_PROG, wlan_idx);
			system( tmpBuf );
			
			OK_MSG1(T("Do Auto-Config failed!"), submitUrl);			
			
			if (!isAP) {
				sprintf(tmpBuf, "%s/%s start %s %s", _CONFIG_SCRIPT_PATH,
					_WLAN_APP_SCRIPT_PROG, wlan_interface_set, BRIDGE_IF);		
				system( tmpBuf );	
			}						
		}
		
		wait_config = CONFIG_SUCCESS;		

		return;
	}
#endif

	submitUrl = websGetVar(wp, T("submit-url"), T(""));   // hidden page
	
	if (wlan_disabled && (isButtonPress || isDoConfigButton || isDoConfigQuestion)) {
		OK_MSG1(T("The wireless interface is disabled, can't proceed the request!"), submitUrl);	
	}
	else {	
		if (isButtonPress) {
			OK_MSG1(T("Waiting for client Auto-Config request..."), submitUrl);
		}
		else {		
			OK_MSG(submitUrl);
		}
	}
	return;

setErr_autocfg:
	ERR_MSG(tmpBuf);
}
#endif // WLAN_EASY_CONFIG


#ifdef WIFI_SIMPLE_CONFIG
#ifndef WLAN_EASY_CONFIG
void sigHandler_autoconf(int signo)
{
	#define REINIT_WEB_FILE		T("/tmp/reinit_web")
	struct stat status;
	int reinit=1;

	if (stat(REINIT_WEB_FILE, &status) == 0) { // file existed
        unlink(REINIT_WEB_FILE);
		reinit = 0;		
	}	
	if (reinit) { // re-init system
#ifdef REBOOT_CHECK
	run_init_script_flag = 1;
#endif		
#if defined(CONFIG_DOMAIN_NAME_QUERY_SUPPORT)
	Start_Domain_Query_Process=0;
#endif
#ifndef NO_ACTION
		run_init_script("all");
#endif		
	}
	apmib_reinit();
}
#endif //!WLAN_EASY_CONFIG

//2011.05.05 Jerry {
void call_wps_update()
{
	memset(&wps_config_info, 0, sizeof(struct wps_config_info_struct));
	wps_config_info.caller_id = CALLED_FROM_HTTPD;
	update_wps_configured(0);
}
//2011.05.05 Jerry }

static void update_wps_configured(int reset_flag)
{
	int is_configured, encrypt1, encrypt2, auth, disabled, iVal, format, shared_type;
	char ssid1[100];
	unsigned char tmpbuf[100];	
	
	if (wps_config_info.caller_id == CALLED_FROM_WLANHANDLER) {
		apmib_get(MIB_WLAN_SSID, (void *)ssid1);
		apmib_get(MIB_WLAN_MODE, (void *)&iVal);
		if (strcmp(ssid1, wps_config_info.ssid) || (iVal != wps_config_info.wlan_mode)) {
			apmib_set(MIB_WLAN_WSC_SSID, (void *)ssid1);
			goto configuration_changed;
		}

		return;
	}
	else if (wps_config_info.caller_id == CALLED_FROM_ADVANCEHANDLER) {
		apmib_get(MIB_WLAN_AUTH_TYPE, (void *)&shared_type);
		apmib_get(MIB_WLAN_ENCRYPT, (void *)&encrypt1);
		if (encrypt1 == ENCRYPT_WEP && 
			shared_type != wps_config_info.shared_type) {
			if (shared_type == AUTH_OPEN || shared_type == AUTH_BOTH) {
				if (wps_config_info.shared_type == AUTH_SHARED) {
					auth = WSC_AUTH_OPEN;
					apmib_set(MIB_WLAN_WSC_AUTH, (void *)&auth);
					goto configuration_changed;
				}
			}
			else {
				if (wps_config_info.shared_type == AUTH_OPEN ||
					wps_config_info.shared_type == AUTH_BOTH) {
					auth = WSC_AUTH_SHARED;
					apmib_set(MIB_WLAN_WSC_AUTH, (void *)&auth);
					goto configuration_changed;
				}
			}
		}

		return;
	}

	apmib_get(MIB_WLAN_ENCRYPT, (void *)&encrypt1);
	if (encrypt1 == ENCRYPT_DISABLED) {
		auth = WSC_AUTH_OPEN;
		encrypt2 = WSC_ENCRYPT_NONE;
	}
	else if (encrypt1 == ENCRYPT_WEP) {
		apmib_get(MIB_WLAN_AUTH_TYPE, (void *)&shared_type);
		if (shared_type == AUTH_OPEN || shared_type == AUTH_BOTH)
			auth = WSC_AUTH_OPEN;
		else
			auth = WSC_AUTH_SHARED;
		encrypt2 = WSC_ENCRYPT_WEP;		
	}
	else if (encrypt1 == ENCRYPT_WPA) {
		auth = WSC_AUTH_WPAPSK;
		apmib_get(MIB_WLAN_WPA_CIPHER_SUITE, (void *)&encrypt1);
		if (encrypt1 == WPA_CIPHER_TKIP)
			encrypt2 = WSC_ENCRYPT_TKIP;		
		else if (encrypt1 == WPA_CIPHER_AES)
			encrypt2 = WSC_ENCRYPT_AES;		
		else 
			encrypt2 = WSC_ENCRYPT_TKIPAES;				
	}
	else if (encrypt1 == ENCRYPT_WPA2) {
		auth = WSC_AUTH_WPA2PSK;
		apmib_get(MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&encrypt1);
		if (encrypt1 == WPA_CIPHER_TKIP)
			encrypt2 = WSC_ENCRYPT_TKIP;		
		else if (encrypt1 == WPA_CIPHER_AES)
			encrypt2 = WSC_ENCRYPT_AES;		
		else 
			encrypt2 = WSC_ENCRYPT_TKIPAES;				
	}
	else {
		auth = WSC_AUTH_WPA2PSKMIXED;
		encrypt2 = WSC_ENCRYPT_TKIPAES;			

// When mixed mode, if no WPA2-AES, try to use WPA-AES or WPA2-TKIP
		apmib_get(MIB_WLAN_WPA_CIPHER_SUITE, (void *)&encrypt1);
		apmib_get(MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&iVal);
		if (!(iVal &	WPA_CIPHER_AES)) {
			if (encrypt1 &	WPA_CIPHER_AES) {			
				auth = WSC_AUTH_WPAPSK;
				encrypt2 = WSC_ENCRYPT_AES;	
			}
			else
				encrypt2 = WSC_ENCRYPT_TKIP;	
		}
//-------------------------------------------- david+2008-01-03

	}
	apmib_set(MIB_WLAN_WSC_AUTH, (void *)&auth);
	apmib_set(MIB_WLAN_WSC_ENC, (void *)&encrypt2);

	apmib_get(MIB_WLAN_ENCRYPT, (void *)&encrypt1);
	if (encrypt1 == ENCRYPT_WPA || encrypt1 == ENCRYPT_WPA2 || encrypt1 == ENCRYPT_WPA2_MIXED) {
		apmib_get(MIB_WLAN_WPA_AUTH, (void *)&format);
		if (format & 2) { // PSK
			apmib_get(MIB_WLAN_WPA_PSK, (void *)tmpbuf);
			apmib_set(MIB_WLAN_WSC_PSK, (void *)tmpbuf);					
		}		
	}
	if (reset_flag) {
		reset_flag = 0;
		apmib_set(MIB_WLAN_WSC_CONFIGBYEXTREG, (void *)&reset_flag);		
	}	

	if (wps_config_info.caller_id == CALLED_FROM_WEPHANDLER) {
		apmib_get(MIB_WLAN_ENCRYPT, (void *)&auth);
		if (wps_config_info.auth != auth)
			goto configuration_changed;

		apmib_get(MIB_WLAN_WEP, (void *)&encrypt2);
		if (wps_config_info.wep_enc != encrypt2)
			goto configuration_changed;
		
		apmib_get(MIB_WLAN_WEP_DEFAULT_KEY, (void *)&iVal);
		if (wps_config_info.KeyId != iVal)
			goto configuration_changed;
		
		apmib_get(MIB_WLAN_WEP64_KEY1, (void *)tmpbuf);
		if (strcmp(wps_config_info.wep64Key1, tmpbuf))
			goto configuration_changed;

		apmib_get(MIB_WLAN_WEP64_KEY2, (void *)tmpbuf);
		if (strcmp(wps_config_info.wep64Key2, tmpbuf))
			goto configuration_changed;

		apmib_get(MIB_WLAN_WEP64_KEY3, (void *)tmpbuf);
		if (strcmp(wps_config_info.wep64Key3, tmpbuf))
			goto configuration_changed;

		apmib_get(MIB_WLAN_WEP64_KEY4, (void *)tmpbuf);
		if (strcmp(wps_config_info.wep64Key4, tmpbuf))
			goto configuration_changed;

		apmib_get(MIB_WLAN_WEP128_KEY1, (void *)tmpbuf);
		if (strcmp(wps_config_info.wep128Key1, tmpbuf))
			goto configuration_changed;

		apmib_get(MIB_WLAN_WEP128_KEY2, (void *)tmpbuf);
		if (strcmp(wps_config_info.wep128Key2, tmpbuf))
			goto configuration_changed;

		apmib_get(MIB_WLAN_WEP128_KEY3, (void *)tmpbuf);
		if (strcmp(wps_config_info.wep128Key3, tmpbuf))
			goto configuration_changed;

		apmib_get(MIB_WLAN_WEP128_KEY4, (void *)tmpbuf);
		if (strcmp(wps_config_info.wep128Key4, tmpbuf))
			goto configuration_changed;

		return;
	}
	else if (wps_config_info.caller_id == CALLED_FROM_WPAHANDLER) {
		apmib_get(MIB_WLAN_ENCRYPT, (void *)&auth);
		if (wps_config_info.auth != auth)
			goto configuration_changed;
		
		apmib_get(MIB_WLAN_WPA_CIPHER_SUITE, (void *)&encrypt1);
		if (wps_config_info.wpa_enc != encrypt1)
			goto configuration_changed;
		
		apmib_get(MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&encrypt2);
		if (wps_config_info.wpa2_enc != encrypt2)
			goto configuration_changed;
		
		apmib_get(MIB_WLAN_WPA_PSK, (void *)tmpbuf);
		if (strcmp(wps_config_info.wpaPSK, tmpbuf))
			goto configuration_changed;

		return;
	}
	//2011.05.05 Jerry {
	else if (wps_config_info.caller_id == CALLED_FROM_HTTPD)
		goto configuration_changed;
	//2011.05.05 Jerry }
	else
		return;
	
configuration_changed:	
	reset_flag = 0;
	apmib_set(MIB_WLAN_WSC_CONFIGBYEXTREG, (void *)&reset_flag);
	apmib_get(MIB_WLAN_WSC_DISABLE, (void *)&disabled);	
	apmib_get(MIB_WLAN_WSC_CONFIGURED, (void *)&is_configured);
	//if (!is_configured && !disabled) { //We do not care wsc is enable for disable--20081223
	if (!is_configured && !disabled) {
		is_configured = 1;
		apmib_set(MIB_WLAN_WSC_CONFIGURED, (void *)&is_configured);
		if(wlan_idx==0){
			wlan_idx = 1;
			apmib_set(MIB_WLAN_WSC_CONFIGURED, (void *)&is_configured);
			wlan_idx = 0;			
		}else if(wlan_idx == 1){
			wlan_idx = 0;
			apmib_set(MIB_WLAN_WSC_CONFIGURED, (void *)&is_configured);
			wlan_idx = 1;			
		}
	}
}

#if 0
static void convert_hex_to_ascii(unsigned long code, char *out)
{
	*out++ = '0' + ((code / 10000000) % 10);  
	*out++ = '0' + ((code / 1000000) % 10);
	*out++ = '0' + ((code / 100000) % 10);
	*out++ = '0' + ((code / 10000) % 10);
	*out++ = '0' + ((code / 1000) % 10);
	*out++ = '0' + ((code / 100) % 10);
	*out++ = '0' + ((code / 10) % 10);
	*out++ = '0' + ((code / 1) % 10);
	*out = '\0';
}

static int compute_pin_checksum(unsigned long int PIN)
{
	unsigned long int accum = 0;
	int digit;
	
	PIN *= 10;
	accum += 3 * ((PIN / 10000000) % 10); 	
	accum += 1 * ((PIN / 1000000) % 10);
	accum += 3 * ((PIN / 100000) % 10);
	accum += 1 * ((PIN / 10000) % 10); 
	accum += 3 * ((PIN / 1000) % 10); 
	accum += 1 * ((PIN / 100) % 10); 
	accum += 3 * ((PIN / 10) % 10);

	digit = (accum % 10);
	return (10 - digit) % 10;
}
#endif

////////////////////////////////////////////////////////////////////////////////
void apmib_reset_wlan_to_default(unsigned char *wlanif_name)
{
	SetWlan_idx(wlanif_name);
	memcpy(&pMib->wlan[wlan_idx][vwlan_idx], &pMibDef->wlan[wlan_idx][vwlan_idx], sizeof(CONFIG_WLAN_SETTING_T));	
	if(strstr(wlanif_name,"vxd") != 0)
	{
		if(wlan_idx == 0)
		{
			sprintf(pMib->repeaterSSID1, pMib->wlan[wlan_idx][vwlan_idx].ssid);
			pMib->wlan[wlan_idx][vwlan_idx].wlanDisabled = !pMib->repeaterEnabled1;			
		}
		else
		{
			sprintf(pMib->repeaterSSID2, pMib->wlan[wlan_idx][vwlan_idx].ssid);
			pMib->wlan[wlan_idx][vwlan_idx].wlanDisabled = !pMib->repeaterEnabled2;			
		}
	}
}

void updateVapWscDisable(int wlan_root,int value)
{
	int i=0;
	int wlanif_idx = 0;
	unsigned ifname[20];
	
	for(i=0;i<(NUM_VWLAN_INTERFACE-1);i++) // vap0~vap3
	{
		memset(ifname,0x00,sizeof(ifname));
		sprintf(ifname,"wlan%d-va%d",wlan_root,i);
		SetWlan_idx(ifname);
		apmib_set(MIB_WLAN_WSC_DISABLE, (void *)&value);
	}
	memset(ifname,0x00,sizeof(ifname));
	sprintf(ifname,"wlan%d-vxd",wlan_root);
	SetWlan_idx(ifname);
	apmib_set(MIB_WLAN_WSC_DISABLE, (void *)&value);
	
	memset(ifname,0x00,sizeof(ifname));
	sprintf(ifname,"wlan%d",wlan_root);
	SetWlan_idx(ifname);
}

void formWsc(webs_t wp, char_t *path, char_t *query)
{
	char_t *strVal, *submitUrl, *strResetUnCfg, *wlanIf;
	int intVal;
	char tmpbuf[200];
	int mode;
	int reset_to_unconfig_state_flag = 0;

	// 1104
	int tmpint;	
	char ifname[30];
	memset(ifname,'\0',30);
	
//displayPostDate(wp->postData);	//Comment by Jerry
	
	submitUrl = websGetVar(wp, T("submit-url"), T(""));

	strResetUnCfg = websGetVar(wp, T("resetUnCfg"), T(""));
	if(strResetUnCfg[0] && strResetUnCfg[0]=='1')// reset to unconfig state. Keith
	{				
//#if defined(FOR_DUAL_BAND) //  ; both reset two unterface (wlan0 AND wlan1)
#if defined(CONFIG_RTL_92D_SUPPORT)
		int wlanDisabled[2];
		int wlanMode[2];		
		int wlanPhyBand[2];
		int wlanMacPhy[2];
		int wlanif;
		int isSwapWlwanIf = 0;


		wlanif = whichWlanIfIs(PHYBAND_5G);
		
		if(wlanif != 0)
		{
			swapWlanMibSetting(0,1);
			isSwapWlwanIf = 1;
		}
		wlanDisabled[0] = pMib->wlan[0][0].wlanDisabled;
		wlanDisabled[1] = pMib->wlan[1][0].wlanDisabled;
		wlanMode[0] = pMib->wlan[0][0].wlanMode;
		wlanMode[1] = pMib->wlan[1][0].wlanMode;
		wlanMacPhy[0] = pMib->wlan[0][0].macPhyMode;
		wlanMacPhy[1] = pMib->wlan[1][0].macPhyMode;
			
		printf("reset to OOB %s,%d\n",__FUNCTION__ , __LINE__);
		if(wlanMode[0] != CLIENT_MODE)
		{
			apmib_reset_wlan_to_default("wlan0");
			pMib->wlan[0][0].wlanDisabled = wlanDisabled[0];
			pMib->wlan[0][0].macPhyMode = wlanMacPhy[0];
		}
		if(wlanMode[1] != CLIENT_MODE)
		{
			apmib_reset_wlan_to_default("wlan1");
			pMib->wlan[1][0].wlanDisabled = wlanDisabled[1];
			pMib->wlan[1][0].macPhyMode = wlanMacPhy[1];
		}
		
		if(isSwapWlwanIf == 1)
		{
			swapWlanMibSetting(0,1);
			isSwapWlwanIf = 0;
		}

#else
//		wlanIf = websGetVar(wp, T("wlanIf"), T(""));
//		if(wlanIf[0])
		apmib_reset_wlan_to_default("wlan0");
//		else
//			printf("Reset wlan to default fail!! No wlan name. %s,%d\n",__FUNCTION__ , __LINE__);
#endif
		
#ifdef REBOOT_CHECK
		strVal = websGetVar(wp, T("disableWPS"), T(""));
		if ( !gstrcmp(strVal, T("ON")))
			intVal = 1;
		else
			intVal = 0;
		apmib_set(MIB_WLAN_WSC_DISABLE, (void *)&intVal);
		updateVapWscDisable(wlan_idx,intVal);
		//REBOOT_WAIT(submitUrl); //mars mark
		run_init_script_flag = 1;
#endif

//2011.05.10 Jerry {
#if 0
		apmib_update_web(CURRENT_SETTING);
		
#ifndef NO_ACTION
		run_init_script("bridge");
#endif
#endif
//2011.05.10 Jerry }
		return;
	}
	
#if defined(UNIVERSAL_REPEATER) && defined(CONFIG_REPEATER_WPS_SUPPORT)
	strResetUnCfg = websGetVar(wp, T("resetRptUnCfg"), T(""));
	if(strResetUnCfg[0] && strResetUnCfg[0]=='1')// reset to unconfig state. Keith
	{
		wlanIf = websGetVar(wp, T("wlanIf"), T(""));
		if(wlanIf[0])
			apmib_reset_wlan_to_default(wlanIf);
		else
			printf("Reset wlan to default fail!! No wlan name. %s,%d\n",__FUNCTION__ , __LINE__);		

#ifdef REBOOT_CHECK
		strVal = websGetVar(wp, T("disableWPS"), T(""));
		if ( !gstrcmp(strVal, T("ON")))
			intVal = 1;
		else
			intVal = 0;
		apmib_set(MIB_WLAN_WSC_DISABLE, (void *)&intVal);
		updateVapWscDisable(wlan_idx, intVal);
		//REBOOT_WAIT(submitUrl);//mars mark
		run_init_script_flag = 1;
#endif		

		apmib_update_web(CURRENT_SETTING);
		
#ifndef NO_ACTION
		run_init_script("bridge");
#endif
		return;
	}
#endif //#if defined(UNIVERSAL_REPEATER) && defined(CONFIG_REPEATER_WPS_SUPPORT)

	apmib_get(MIB_WLAN_MODE, (void *)&mode);	
	strVal = websGetVar(wp, T("triggerPBC"), T(""));
	if (strVal[0]) {
		apmib_get(MIB_WLAN_WSC_DISABLE, (void *)&intVal);
		if (intVal) {
			intVal = 0;
			apmib_set(MIB_WLAN_WSC_DISABLE, (void *)&intVal);
                        updateVapWscDisable(wlan_idx, intVal);
			apmib_update_web(CURRENT_SETTING);	// update to flash	
			system("echo 1 > /var/wps_start_pbc");
#ifndef NO_ACTION
			run_init_script("bridge");
#endif			
		}
		else {		
#ifndef NO_ACTION		
			sprintf(tmpbuf, "%s -sig_pbc wlan%d", _WSC_DAEMON_PROG,wlan_idx);
			system(tmpbuf);
#endif
		}
		//OK_MSG2(START_PBC_MSG, ((mode==AP_MODE) ? "client" : "AP"), submitUrl);//mars mark
		return;
	}
#if defined(UNIVERSAL_REPEATER) && defined(CONFIG_REPEATER_WPS_SUPPORT)	
	strVal = websGetVar(wp, T("triggerRptPBC"), T(""));
	if (strVal[0]) {
		apmib_get(MIB_WLAN_WSC_DISABLE, (void *)&intVal);
		if (intVal) {
			intVal = 0;
			apmib_set(MIB_WLAN_WSC_DISABLE, (void *)&intVal);
			updateVapWscDisable(wlan_idx, intVal);
			apmib_update_web(CURRENT_SETTING);	// update to flash
			system("echo 1 > /var/wps_start_pbc");
#ifndef NO_ACTION
			run_init_script("bridge");
#endif			
		}
		else {		
#ifndef NO_ACTION		
			sprintf(tmpbuf, "%s -sig_pbc wlan%d-vxd", _WSC_DAEMON_PROG,wlan_idx);
			system(tmpbuf);
#endif
		}
		//OK_MSG2(START_PBC_MSG, ((mode==AP_MODE) ? "client" : "AP"), submitUrl);//mars mark
		return;
	}
#endif //#if defined(UNIVERSAL_REPEATER) && defined(CONFIG_REPEATER_WPS_SUPPORT)
	strVal = websGetVar(wp, T("triggerPIN"), T(""));
	if (strVal[0]) {
		int local_pin_changed = 0;		
		strVal = websGetVar(wp, T("localPin"), T(""));
		if (strVal[0]) {
			apmib_get(MIB_HW_WSC_PIN, (void *)tmpbuf);
			if (strcmp(tmpbuf, strVal)) {
				apmib_set(MIB_HW_WSC_PIN, (void *)strVal);
				local_pin_changed = 1;				
			}			
		}		
		apmib_get(MIB_WLAN_WSC_DISABLE, (void *)&intVal);
		if (intVal) {
			char localpin[100];
			intVal = 0;			
			apmib_set(MIB_WLAN_WSC_DISABLE, (void *)&intVal);
			updateVapWscDisable(wlan_idx, intVal);
			apmib_update_web(CURRENT_SETTING);	// update to flash	
			system("echo 1 > /var/wps_start_pin");

#ifndef NO_ACTION
			if (local_pin_changed) {
				apmib_get(MIB_HW_WSC_PIN, (void *)localpin);
				sprintf(tmpbuf, "echo %s > /var/wps_local_pin", localpin);
				system(tmpbuf);
			}
			run_init_script("bridge");			
#endif			
		}
		else {		
#ifndef NO_ACTION		
			if (local_pin_changed) {
				system("echo 1 > /var/wps_start_pin");
				
				apmib_update_web(CURRENT_SETTING);					
				run_init_script("bridge");
			}
			else {
				sprintf(tmpbuf, "%s -sig_start wlan%d", _WSC_DAEMON_PROG,wlan_idx);
				system(tmpbuf);
			}			
#endif
		}
		//OK_MSG2(START_PIN_MSG, ((mode==AP_MODE) ? "client" : "AP"), submitUrl);//mars mark
		return;
	}
	
#if defined(UNIVERSAL_REPEATER) && defined(CONFIG_REPEATER_WPS_SUPPORT)
	strVal = websGetVar(wp, T("triggerRptPIN"), T(""));

	if (strVal[0]) {
		int local_pin_changed = 0;		
		strVal = websGetVar(wp, T("localPin"), T(""));
		if (strVal[0]) {
			apmib_get(MIB_HW_WSC_PIN, (void *)tmpbuf);

			if (strcmp(tmpbuf, strVal)) {
				apmib_set(MIB_HW_WSC_PIN, (void *)strVal);
				local_pin_changed = 1;				
			}			
		}		
		apmib_get(MIB_WLAN_WSC_DISABLE, (void *)&intVal);
		if (intVal) {
			char localpin[100];
			intVal = 0;			
			apmib_set(MIB_WLAN_WSC_DISABLE, (void *)&intVal);
			apmib_update_web(CURRENT_SETTING);	// update to flash	
			system("echo 1 > /var/wps_start_pin");

#ifndef NO_ACTION
			if (local_pin_changed) {
				apmib_get(MIB_HW_WSC_PIN, (void *)localpin);
				sprintf(tmpbuf, "echo %s > /var/wps_local_pin", localpin);
				system(tmpbuf);
			}
			run_init_script("bridge");			
#endif			
		}
		else {		
#ifndef NO_ACTION		
			if (local_pin_changed) {
				system("echo 1 > /var/wps_start_pin");
				
				apmib_update_web(CURRENT_SETTING);					
				run_init_script("bridge");
			}
			else {
				sprintf(tmpbuf, "%s -sig_start wlan%d-vxd", _WSC_DAEMON_PROG,wlan_idx);
				system(tmpbuf);
			}			
#endif
		}
		//OK_MSG2(START_PIN_MSG, ((mode==AP_MODE) ? "client" : "AP"), submitUrl);//mars mark
		return;
	}
#endif //#if defined(UNIVERSAL_REPEATER) && defined(CONFIG_REPEATER_WPS_SUPPORT)		
	
	strVal = websGetVar(wp, T("setPIN"), T(""));
	if (strVal[0]) {		
		strVal = websGetVar(wp, T("peerPin"), T(""));
		if (strVal[0]) {
			apmib_get(MIB_WLAN_WSC_DISABLE, (void *)&intVal);
			if (intVal) {
				intVal = 0;
				apmib_set(MIB_WLAN_WSC_DISABLE, (void *)&intVal);
				apmib_update_web(CURRENT_SETTING);	

				sprintf(tmpbuf, "echo %s > /var/wps_peer_pin", strVal);
				system(tmpbuf);

#ifndef NO_ACTION
				run_init_script("bridge");
#endif					
			}
			else {			
#ifndef NO_ACTION
				sprintf(tmpbuf, "iwpriv %s set_mib pin=%s", WLAN_IF, strVal);
				system(tmpbuf);
#endif
			}
			//OK_MSG1(SET_PIN_MSG, submitUrl);//mars mark			
			return;
		}
	}

#if defined(UNIVERSAL_REPEATER) && defined(CONFIG_REPEATER_WPS_SUPPORT)
	strVal = websGetVar(wp, T("setRptPIN"), T(""));
	if (strVal[0]) {		
		strVal = websGetVar(wp, T("peerRptPin"), T(""));
		if (strVal[0]) {
			apmib_get(MIB_WLAN_WSC_DISABLE, (void *)&intVal);
			if (intVal) {
				intVal = 0;
				apmib_set(MIB_WLAN_WSC_DISABLE, (void *)&intVal);
				apmib_update_web(CURRENT_SETTING);	

				sprintf(tmpbuf, "echo %s > /var/wps_peer_pin", strVal);
				system(tmpbuf);

#ifndef NO_ACTION
				run_init_script("bridge");
#endif					
			}
			else {			
#ifndef NO_ACTION
				sprintf(tmpbuf, "iwpriv wlan%d-vxd set_mib pin=%s", wlan_idx, strVal);
				system(tmpbuf);
#endif
			}
			//OK_MSG1(SET_PIN_MSG, submitUrl);//mars mark			
			return;
		}
	}
#endif //#if defined(UNIVERSAL_REPEATER) && defined(CONFIG_REPEATER_WPS_SUPPORT)

	strVal = websGetVar(wp, T("disableWPS"), T(""));
	if ( !gstrcmp(strVal, T("ON")))
		intVal = 1;
	else
		intVal = 0;

	// 1104
	sprintf(ifname,"wlan%d",wlan_idx);
	SetWlan_idx(ifname);
	
	apmib_set(MIB_WLAN_WSC_DISABLE, (void *)&intVal);
	updateVapWscDisable(wlan_idx, intVal);

	strVal = websGetVar(wp, T("localPin"), T(""));
	if (strVal[0])
		apmib_set(MIB_HW_WSC_PIN, (void *)strVal);

//	update_wps_configured(0);

//2011.05.10 Jerry {
#if 0
	apmib_update_web(CURRENT_SETTING);	// update to flash
	
#ifndef NO_ACTION
	run_init_script("bridge");
#endif
// 	strVal = websGetVar(wp, T("disableWPS"), T(""));
// 	if ( !gstrcmp(strVal, T("ON")))
// 	{
// 		printf("disableWPS\n");
// 		system("killall wscd");
// 	}//Lucifer
// 	else
// 	{
// 		
// 		printf("enableWPS\n");
// 		system("echo 2 > /proc/gpio");
// 		system("sysconf init gw all"); //mars add
// 	}//Lucifer
// 	//OK_MSG(submitUrl);//mars mark
	system("sysconf init gw all"); //mars add
#endif
//2011.05.10 Jerry }
}
////////////////////////////////////////////////////////////////////////
#endif // WIFI_SIMPLE_CONFIG


void formWlanRedirect(webs_t wp, char_t *path, char_t *query)
{
	char_t *redirectUrl;
	char_t *strWlanId;
	
        redirectUrl= websGetVar(wp, T("redirect-url"), T(""));   // hidden page
        strWlanId= websGetVar(wp, T("wlan_id"), T(""));   // hidden page
	if(strWlanId[0]){
		wlan_idx = atoi(strWlanId);
		sprintf(WLAN_IF, "wlan%d", wlan_idx);
	}
#ifdef MBSSID	
	mssid_idx = 0;
#endif
        if (redirectUrl[0])
                websRedirect(wp,redirectUrl);
}

#ifdef CONFIG_RTL_WAPI_SUPPORT
void formWapiReKey(webs_t wp, char_t * path, char_t * query)
{
	char *webpage, *strVal;
	char tmpBuf[200];
	int val;
	int mPolicy,policy;
	/*get Mcast Ucast*/
	webpage=websGetVar(wp,T("next_webpage"),T(""));

	strVal=websGetVar(wp,T("KEY_TYPE"),T(""));
//	printf("KEY_TYPE %s \n",strVal);
	strVal=websGetVar(wp,T("MAC"),T(""));
//	printf("MAC %s \n",strVal);

	/*1: off  2: time 3: packet 4:time+packet*/
	strVal=websGetVar(wp,T("REKEY_M_POLICY"),T(""));
	if(strVal)
	{
		mPolicy=strVal[0]-'0';
		if(!apmib_set(MIB_WLAN_WAPI_MCASTREKEY,(void *)&mPolicy))
		{
			strcpy(tmpBuf,"Can not set MCAST key policy!");
			goto setErr_rekey;

		}
//		printf("REKEY_M_POLICY %s \n",strVal);
	}
	
	strVal=websGetVar(wp,T("REKEY_M_TIME"),T(""));
	if(strVal)
	{
		val=atoi(strVal);
		if(!apmib_set(MIB_WLAN_WAPI_MCAST_TIME,(void *)&val))
		{
			strcpy(tmpBuf,"Can not set MCAST TIME!");
			goto setErr_rekey;
		}
//		printf("REKEY_M_TIME %s \n",strVal);
	}
	
	strVal=websGetVar(wp,T("REKEY_M_PACKET"),T(""));
	if(strVal)
	{
		val=atoi(strVal);
		if(!apmib_set(MIB_WLAN_WAPI_MCAST_PACKETS,(void *)&val))
		{
			strcpy(tmpBuf,"Can not set MCAST Packet!");
			goto setErr_rekey;
		}
//		printf("REKEY_M_PACKET %s \n",strVal);
	}	
	
	strVal=websGetVar(wp,T("REKEY_POLICY"),T(""));
	if(strVal)
	{
		policy=strVal[0]-'0';
		if(!apmib_set(MIB_WLAN_WAPI_UCASTREKEY,(void *)&policy))
		{
			strcpy(tmpBuf,"Can not set ucast key policy!");
			goto setErr_rekey;
		}
//		printf("REKEY_POLICY %s \n",strVal);
	}

	strVal=websGetVar(wp,T("REKEY_TIME"),T(""));
	if(strVal)
	{
		val=atoi(strVal);
		if(!apmib_set(MIB_WLAN_WAPI_UCAST_TIME,(void *)&val))
		{
			strcpy(tmpBuf,"Can not set ucast time!");
			goto setErr_rekey;
		}
//		printf("REKEY_TIME %s \n",strVal);
	}
	
	strVal=websGetVar(wp,T("REKEY_PACKET"),T(""));
	if(strVal)
	{
		val=atoi(strVal);
		if(!apmib_set(MIB_WLAN_WAPI_UCAST_PACKETS,(void *)&val))
		{
			strcpy(tmpBuf,"Can not set ucast Packet!");
			goto setErr_rekey;
		}
//		printf("REKEY_PACKET %s \n",strVal);
	}
	
	apmib_update_web(CURRENT_SETTING);	// update configuration to flash
#ifndef NO_ACTION
	run_init_script("all");                
#endif
	OK_MSG(webpage);
//	websRedirect(wp, webpage);
	return;
setErr_rekey:
	ERR_MSG(tmpBuf);
}
#define TMP_CERT "/var/tmp/tmp.cert"
#define AP_CERT "/var/myca/ap.cert"
#define CA_CERT "/var/myca/CA.cert"
#define CA4AP_CERT "/var/myca/ca4ap.cert"
#define CERT_START "-----BEGIN CERTIFICATE-----"
#define CERT_END "-----END CERTIFICATE-----"
void formUploadWapiCert(webs_t wp, char_t * path, char_t * query)
{
	/*save asu and user cert*/
	char *submitUrl,*strVal;
	char tmpBuf[100];
	char cmd[128];
	FILE *fp;
	submitUrl = websGetVar(wp, T("submit-url"), T(""));   // hidden page
//	printf("submitUrl %s\n",submitUrl);
	strVal = websGetVar(wp, T("uploadcerttype"), T(""));
//	printf("uploadcerttype %s\n",strVal);

	if(NULL == strstr(wp->postData,CERT_START) || NULL ==strstr(wp->postData,CERT_END))
	{
		strcpy(tmpBuf,"Not a Cert File!");
		goto upload_ERR;
	}
	fp=fopen(TMP_CERT,"w");
	if(NULL == fp)
	{
		strcpy(tmpBuf,"Can not open tmp cert!");
		goto upload_ERR;
	}
	else
	{
		fwrite(wp->postData,wp->lenPostData,0x1,fp);
		fclose(fp);
		strcpy(cmd,"cp ");
		strcat(cmd,TMP_CERT);
		strcat(cmd," ");
		if(!strcmp(strVal,"user"))
		{
			strcat(cmd,AP_CERT);
			system(cmd);
			system("storeWapiFiles -apCert");
//			system("storeWapiFiles -oneUser");
		}
		if(!strcmp(strVal,"asu"))
		{
		//	strcat(cmd,CA_CERT);
		//	system(cmd);
		//	system("storeWapiFiles -caCert");
			strcat(cmd,CA4AP_CERT);
			system(cmd);
			system("storeWapiFiles -ca4apCert");
		}
	}
	/*check if user or asu cerification*/
	strcpy(tmpBuf,"Cerification Install Success!");
	OK_MSG1(tmpBuf, submitUrl);
	return;
upload_ERR:
	ERR_MSG(tmpBuf);
}

char *getCertSerial(char *src, char *val)
{
	int len=0;

	while (*src && *src!=':') {
		*val++ = *src++;
		len++;
	}
	if (len == 0)
		return NULL;

	*val = '\0';

	if (*src==':')
		src++;

	return src;
}
void formWapiCertManagement(webs_t wp, char_t * path, char_t * query)
{
	char *strVal, sn[32], *webpage;
	char tmpBuf[200];
	// 1---revoke  2----unrevoke 3----del  4---active 5---search 6--clearall
	int operation;
	int val=0;
	webpage=websGetVar(wp,T("next_webpage"),T(""));
	strVal=websGetVar(wp,T("CERT_MNG"),T(""));
//	printf("CERT_MNG %s\n",strVal);
	/*Search  Revoke*/
	if(strVal)
		operation=strVal[0] -'0';
	else
		return;
	if(1 == operation)
	{
		/*get the serial no  122345:34244:343424:*/
		strVal=websGetVar(wp,T("CERT_SN"),T(""));
//		printf("strVal=%s\n",strVal);//Added for test

		strVal=getCertSerial(strVal,sn);
		while(strVal)
		{
			/*call revoke API*/
			strcpy(tmpBuf," revokeUserCert.sh ");
			strcat(tmpBuf,sn);

			strVal=getCertSerial(strVal,sn);
			if(strVal!=NULL)
			{
				//There is more serial to revoke
				strcat(tmpBuf," option");
			}
			
//			printf("tmpBuf=%s\n",tmpBuf);//Added for test
			system(tmpBuf);
		}			
	}
	/*search*/
	if(5 == operation)
	{
		/*set search index*/
		strVal=websGetVar(wp,T("SELECT1"),T(""));
		if(strVal)
		{
			val=strVal[0]-'0';
			if(!apmib_set(MIB_WLAN_WAPI_SEARCHINDEX,(void*)&val))
			{
				strcpy(tmpBuf, T("Set Search Index Error!"));
				goto setErr_cert;
			}
		}
//		printf("SELECT1 %s\n",strVal);
		strVal=websGetVar(wp,T("CERT_INFO"),T(""));
		if(!apmib_set(MIB_WLAN_WAPI_SEARCHINFO,(void*)strVal))
		{
			strcpy(tmpBuf, T("Set Search Info Error!"));
			goto setErr_cert;
		}
//		printf("CERT_INFO %s\n",strVal);
		/*set search key*/
	}

	if(6 == operation)
	{
		system("initCAFiles.sh");
		val=1;
		apmib_set(MIB_WLAN_WAPI_CA_INIT,(void *)&val);
		
		//Keith add for update current time to MIB
	  
	  //if(time_mode == 0) //Manual Mode
	  { 
	   time_t current_secs;
	   int cur_time;
	   struct tm * tm_time;
	   
	   time(&current_secs);
	   tm_time = localtime(&current_secs);
	   cur_time = tm_time->tm_year+ 1900;
	   apmib_set( MIB_SYSTIME_YEAR, (void *)&cur_time);
	   cur_time = tm_time->tm_mon;
	   apmib_set( MIB_SYSTIME_MON, (void *)&cur_time);
	   cur_time = tm_time->tm_mday;
	   apmib_set( MIB_SYSTIME_DAY, (void *)&cur_time);
	   cur_time = tm_time->tm_hour;
	   apmib_set( MIB_SYSTIME_HOUR, (void *)&cur_time);
	   cur_time = tm_time->tm_min;
	   apmib_set( MIB_SYSTIME_MIN, (void *)&cur_time);
	   cur_time = tm_time->tm_sec;
	   apmib_set( MIB_SYSTIME_SEC, (void *)&cur_time);
	   
	   apmib_update_web(CURRENT_SETTING);
	  }

	}
	/*sync to flash*/
	apmib_update_web(CURRENT_SETTING);	// update configuration to flash

	websRedirect(wp, webpage);
	return;
setErr_cert:
	ERR_MSG(tmpBuf);
}

extern void log_goform(char *form);
#define WAPI_USER_CERT  "/var/myca/user.cert"
void formWapiCertDistribute(webs_t wp, char_t * path, char_t * query)
{
	char_t *strVal, *strName,*strTime, *webpage;
	int count=0;
	char tmpbuf[200];
	struct stat status;
	
	/*only 40 actived cert allowed*/
	CERTS_DB_ENTRY_Tp cert=(CERTS_DB_ENTRY_Tp)malloc(128*sizeof(CERTS_DB_ENTRY_T));
	/*update wapiCertInfo*/
	count=searchWapiCert(cert,5,"0");
	free(cert);
	if(count >= 40)
	{
		ERR_MSG("Too many active certifications. Please revoke unused certifications!");
		return;
	}
	/*generate a cert. Call generate API*/
	strVal=websGetVar(wp,T("cert_type"),T(""));
//	printf("cert_type %s\n",strVal);
	strName=websGetVar(wp,T("cert_name"),T(""));
//	printf("cert_name %s\n",strName);
	strTime=websGetVar(wp,T("certPeriod"),T(""));
//	printf("certPeriod %s\n",strTime);
	strVal=websGetVar(wp,T("time_unit"),T(""));
//	printf("time_unit %s\n",strVal);
	webpage=websGetVar(wp,T("nextwebpage"),T(""));
//	printf("webpage %s\n",webpage);
	system("rm -f /var/myca/user.cert");
	system("rm -f /web/user.cer");

	/*To generate user.cert*/
	strcpy(tmpbuf,"genUserCert.sh ");
	strcat(tmpbuf,strName);
	strcat(tmpbuf," ");
	strcat(tmpbuf,strTime);
//	printf("tmpbuf :%s\n",tmpbuf);
	system(tmpbuf);
	
	if ( stat(WAPI_USER_CERT, &status) < 0 ) {
		printf("WAPI cert not generated!\n");
	}
	system("cp /var/myca/user.cert /web/user.cer");
	sleep(1);
	
	//Keith add for update current time to MIB
	//if(time_mode == 0) //Manual Mode
	{	
		time_t current_secs;
		int cur_time;
		struct tm * tm_time;
		
		time(&current_secs);
		tm_time = localtime(&current_secs);
		cur_time = tm_time->tm_year+ 1900;
		apmib_set( MIB_SYSTIME_YEAR, (void *)&cur_time);
		cur_time = tm_time->tm_mon;
		apmib_set( MIB_SYSTIME_MON, (void *)&cur_time);
		cur_time = tm_time->tm_mday;
		apmib_set( MIB_SYSTIME_DAY, (void *)&cur_time);
		cur_time = tm_time->tm_hour;
		apmib_set( MIB_SYSTIME_HOUR, (void *)&cur_time);
		cur_time = tm_time->tm_min;
		apmib_set( MIB_SYSTIME_MIN, (void *)&cur_time);
		cur_time = tm_time->tm_sec;
		apmib_set( MIB_SYSTIME_SEC, (void *)&cur_time);
		
		apmib_update_web(CURRENT_SETTING);
	}
	
		
	websRedirect(wp, webpage);
	log_goform("formWapiCertDistribute");	//To set formWapiCertDistribute valid at security_tbl
	return;
}
#endif

#ifdef CONFIG_RTL_802_1X_CLIENT_SUPPORT
#define RS_CERT_START "-----BEGIN CERTIFICATE-----"
#define RS_CERT_END "-----END CERTIFICATE-----"
#define RS_RSA_PRIV_KEY_START "-----BEGIN RSA PRIVATE KEY-----"
#define RS_RSA_PRIV_KEY_END "-----END RSA PRIVATE KEY-----"
#define RS_PRIV_KEY_TIP "PRIVATE KEY-----"

void formUpload8021xUserCert(webs_t wp, char_t * path, char_t * query)
{
	char *submitUrl,*strVal, *deleteAllCerts;
	char tmpBuf[256];
	char cmd[256];
	FILE *fp;
	char tryFormChange;
	char line[256];
	unsigned char userKeyPass[MAX_RS_USER_CERT_PASS_LEN+1];
	char certOk, userKeyOk;
	
	submitUrl = websGetVar(wp, T("submit-url"), T(""));   // hidden page

	deleteAllCerts = websGetVar(wp, T("delAllCerts"), T(""));   // hidden page

	if(deleteAllCerts[0]=='1')
	{
		//To delete all 802.1x certs
		system("rsCert -rst");

		strcpy(tmpBuf,"Delete all 802.1x cerificates success!");
	}
	else
	{
		//Initial
		tryFormChange=0;
		certOk=0;
		userKeyOk=0;
		
		strVal = websGetVar(wp, T("uploadCertType"), T(""));

		if(NULL == strstr(wp->postData,RS_CERT_START) || NULL ==strstr(wp->postData,RS_CERT_END))
		{
			strcpy(tmpBuf,"No 802.1x cert inclued in upload file!");
			//goto upload_ERR;
			tryFormChange=1;
		}

		if((tryFormChange==0)&&(!strcmp(strVal,"user")))
		{
			if(NULL == strstr(wp->postData,RS_PRIV_KEY_TIP))
			{
				strcpy(tmpBuf,"No 802.1x private key inclued in upload file!");
				//goto upload_ERR;
				tryFormChange=1;
			}
		}

		if(!strcmp(strVal,"user"))
		{
			if(tryFormChange==0)
			{
				fp=fopen(RS_USER_CERT,"w");
				if(NULL == fp)
				{
					sprintf(tmpBuf,"Can not open tmp RS cert(%s)!", RS_USER_CERT);
					goto upload_ERR;
				}

				fwrite(wp->postData,wp->lenPostData,0x1,fp);
				fclose(fp);
			}
			else
			{
				//To store user cert in tmp file: RS_USER_CERT_TMP
				fp=fopen(RS_USER_CERT_TMP,"w");
				if(NULL == fp)
				{
					sprintf(tmpBuf,"[2] Can not open tmp user cert(%s)!", RS_USER_CERT_TMP);
					goto upload_ERR;
				}

				fwrite(wp->postData,wp->lenPostData,0x1,fp);
				fclose(fp);

				// try change user cert form from pfx to pem
				memset(userKeyPass, 0, sizeof(userKeyPass));
				apmib_get( MIB_WLAN_RS_USER_CERT_PASSWD, (void *)userKeyPass);
				sprintf(cmd, "openssl pkcs12 -in %s -nodes -out %s -passin pass:%s", RS_USER_CERT_TMP, RS_USER_CERT, userKeyPass);
				system(cmd);

				sleep(1); // wait for system(cmd);

				fp=fopen(RS_USER_CERT,"r");
				if(NULL == fp)
				{
					sprintf(tmpBuf,"[2] Can not open tmp user cert(%s)!", RS_USER_CERT);
					goto upload_ERR;
				}

				while (fgets(line, sizeof(line), fp))
				{
					if((NULL != strstr(line,RS_CERT_START) ) || (NULL != strstr(line,RS_CERT_END) ))
						certOk=1;
					
					if(NULL != strstr(line,RS_PRIV_KEY_TIP))
						userKeyOk=1;

					if((certOk == 1) && (userKeyOk == 1))
						break;
				}

				if((certOk != 1) || (userKeyOk != 1))
				{
					sprintf(cmd, "rm -rf %s", RS_USER_CERT);
					system(cmd);
					
					sprintf(tmpBuf,"Upload user cert failed. Please make sure: 1) uploaded file in pem or pfx form, 2) uploaded file contain user cert and user key, 3) [User Key Password] have been set correctly firstly!");
					goto upload_ERR;
				}

				fclose(fp);
			}

			//To store 802.1x user cert
			system("rsCert -wrUser");
			strcpy(tmpBuf,"802.1x user cerificate and user key upload success!");
		}
		else if(!strcmp(strVal,"root"))
		{
			if(tryFormChange == 0)
			{
				fp=fopen(RS_ROOT_CERT,"w");
				if(NULL == fp)
				{
					sprintf(tmpBuf,"Can not open tmp RS cert(%s)!", RS_ROOT_CERT);
					goto upload_ERR;
				}

				fwrite(wp->postData,wp->lenPostData,0x1,fp);
				fclose(fp);
			}
			else
			{
				// To store ca cert in tmp file: RS_ROOT_CERT_TMP
				fp=fopen(RS_ROOT_CERT_TMP,"w");
				if(NULL == fp)
				{
					sprintf(tmpBuf,"Can not open tmp RS cert(%s)!", RS_ROOT_CERT_TMP);
					goto upload_ERR;
				}

				fwrite(wp->postData,wp->lenPostData,0x1,fp);
				fclose(fp);
				
				// try change ca cert form from der to pem
				sprintf(cmd, "openssl x509 -inform DER -in %s -outform PEM -out %s",RS_ROOT_CERT_TMP,RS_ROOT_CERT);
				system(cmd);

				sleep(1);	// wait for system(cmd);

				fp=fopen(RS_ROOT_CERT,"r");
				if(NULL == fp)
				{
					sprintf(tmpBuf,"[2] Can not open tmp RS cert(%s)!", RS_ROOT_CERT);
					goto upload_ERR;
				}

				while (fgets(line, sizeof(line), fp))
				{
					if((NULL != strstr(line,RS_CERT_START) ) || (NULL != strstr(line,RS_CERT_END) ))
					{
						certOk=1;
						break;
					}
				}

				if(certOk != 1)
				{
					sprintf(cmd, "rm -rf %s", RS_ROOT_CERT);
					system(cmd);
					
					strcpy(tmpBuf,"[2] No 802.1x cert inclued in upload file!");
					goto upload_ERR;
				}
				
				fclose(fp);
			}

			//To store 802.1x root cert
			system("rsCert -wrRoot");
			strcpy(tmpBuf,"802.1x root cerificate upload success!");
		}
		else
		{
			sprintf(tmpBuf,"Upload cert type(%s) is not supported!", strVal);
			goto upload_ERR;
		}
	}

	OK_MSG1(tmpBuf, submitUrl);
	return;
	
upload_ERR:
	if(fp != NULL)
		fclose(fp);
	
	ERR_MSG(tmpBuf);
}
#endif


#ifdef TLS_CLIENT
#define MAXFNAME	60
#undef WEB_PAGE_OFFSET
#define WEB_PAGE_OFFSET 0x10000

//#define DWORD_SWAP(v) (v)
//#define WORD_SWAP(v) (v)
#define __PACK__	__attribute__ ((packed))
char *tag="CERT";
/////////////////////////////////////////////////////////////////////////////
static int compress(char *inFile, char *outFile)
{
	char tmpBuf[100];

	//sprintf(tmpBuf, "bzip2 -9 -c %s > %s", inFile, outFile);
	sprintf(tmpBuf, "cat %s > %s", inFile, outFile);
	system(tmpBuf);
	return 0;
}

//////////////////////////////////////////////////////////////////////////////
#if 0
static unsigned char CHECKSUM(unsigned char *data, int len)
{
	int i;
	unsigned char sum=0;

	for (i=0; i<len; i++)
		sum += data[i];

	sum = ~sum + 1;
	return sum;
}
#endif

/////////////////////////////////////////////////////////////////////////////
#if 0
static int lookfor_cert_dir(FILE *lp, char *dirpath, int is_for_web)
{
	char file[MAXFNAME];
	char *p;
	struct stat sbuf;

	fseek(lp, 0L, SEEK_SET);
	dirpath[0] = '\0';

	while (fgets(file, sizeof(file), lp) != NULL) {
		if ((p = strchr(file, '\n')) || (p = strchr(file, '\r'))) {
			*p = '\0';
		}
		if (*file == '\0') {
			continue;
		}
		if (stat(file, &sbuf) == 0 && sbuf.st_mode & S_IFDIR) {
			continue;
		}
		if (is_for_web)
			p=strstr(file, "home.asp");

		else
			p=strrchr(file, '/');
		if (p) {

			*p = '\0';
			strcpy(dirpath, file);
// for debug
//printf("Found dir=%s\n", dirpath);
			return 0;
		}
	}
	//printf("error\n");
	return -1;
}
#endif
/////////////////////////////////////////////////////////////////////////////
static void strip_dirpath(char *file, char *dirpath)
{
	char *p, tmpBuf[MAXFNAME];

	if ((p=strstr(file, dirpath))) {
		strcpy(tmpBuf, &p[strlen(dirpath)]);
		strcpy(file, tmpBuf);
	}
// for debug
//printf("adding file %s\n", file);
}
int makeCertImage(char *outFile, char *fileList)
{
	int fh;
	struct stat sbuf;
	FILE *lp;
	char file[MAXFNAME];
	char tmpFile[100], dirpath[100];
	char buf[512];
	FILE_ENTRY_T entry;
	unsigned char	*p;
	int i, len, fd, nFile, pad=0;
	IMG_HEADER_T head;
	char *tmpFile1 = "/var/tmp/cert" ;
	
	fh = open(tmpFile1, O_RDWR|O_CREAT|O_TRUNC);
	if (fh == -1) {
		printf("Create output file error %s!\n", tmpFile1);
		return 0;
	}
	lseek(fh, 0L, SEEK_SET);

	if ((lp = fopen(fileList, "r")) == NULL) {
		printf("Can't open file list %s\n!", fileList);
		return 0;
	}
#if 0	
	if (lookfor_cert_dir(lp, dirpath, 0)<0) {
		printf("Can't find cert dir\n");
		fclose(lp);
		return 0;
	}
#else
	strcpy(dirpath, "/etc/1x");
#endif	
	fseek(lp, 0L, SEEK_SET);
	nFile = 0;
	while (fgets(file, sizeof(file), lp) != NULL) {
		if ((p = strchr(file, '\n')) || (p = strchr(file, '\r'))) {
			*p = '\0';
		}
		if (*file == '\0') {
			continue;
		}
		if (stat(file, &sbuf) == 0 && sbuf.st_mode & S_IFDIR) {
			continue;
		}

		if ((fd = open(file, O_RDONLY)) < 0) {
			printf("Can't open file %s\n", file);
			exit(1);
		}
		lseek(fd, 0L, SEEK_SET);

		strip_dirpath(file, dirpath);

		strcpy(entry.name, file);
#ifndef __mips__	
		entry.size = DWORD_SWAP(sbuf.st_size);
#else		
		entry.size = (sbuf.st_size);
#endif		

		if ( write(fh, (const void *)&entry, sizeof(entry))!=sizeof(entry) ) {
			printf("Write file failed!\n");
			return 0;
		}

		i = 0;
		while ((len = read(fd, buf, sizeof(buf))) > 0) {
			if ( write(fh, (const void *)buf, len)!=len ) {
				printf("Write file failed!\n");
				exit(1);
			}
			i += len;
		}
		close(fd);
		if ( i != sbuf.st_size ) {
			printf("Size mismatch in file %s!\n", file );
		}

		nFile++;
	}

	fclose(lp);
	close(fh);
	sync();

// for debug -------------
#if 0
sprintf(tmpFile, "cp %s web.lst -f", outFile);
system(tmpFile);
#endif
//-------------------------

	sprintf(tmpFile, "%sXXXXXX",  tmpFile1);
	mkstemp(tmpFile);

	if ( compress(tmpFile1, tmpFile) < 0) {
		printf("compress file error!\n");
		return 0;
	}

	// append header
	if (stat(tmpFile, &sbuf) != 0) {
		printf("Create file error!\n");
		return 0;
	}
	if((sbuf.st_size+1)%2)
		pad = 1;
	p = malloc(sbuf.st_size + 1 + pad);
	memset(p, 0 , sbuf.st_size + 1);
	if ( p == NULL ) {
		printf("allocate buffer failed!\n");
		return 0;
	}

	memcpy(head.signature, tag, 4);
	head.len = sbuf.st_size + 1 + pad;
#ifndef __mips__	
	head.len = DWORD_SWAP(head.len);
	head.startAddr = DWORD_SWAP(WEB_PAGE_OFFSET);
	head.burnAddr = DWORD_SWAP(WEB_PAGE_OFFSET);
#else
	head.len = (head.len);
	head.startAddr = (WEB_PAGE_OFFSET);
	head.burnAddr = (WEB_PAGE_OFFSET);
#endif		

	if ((fd = open(tmpFile, O_RDONLY)) < 0) {
		printf("Can't open file %s\n", tmpFile);
		return 0;
	}
	lseek(fd, 0L, SEEK_SET);
	if ( read(fd, p, sbuf.st_size) != sbuf.st_size ) {
		printf("read file error!\n");
		return 0;;
	}
	close(fd);

	p[sbuf.st_size + pad] = CHECKSUM(p, (sbuf.st_size+pad));

	fh = open(outFile, O_RDWR|O_CREAT|O_TRUNC);
	if (fh == -1) {
		printf("Create output file error %s!\n", outFile );
		return 0;
	}
#ifdef __mips__
	lseek(fh, CERT_PAGE_OFFSET , SEEK_SET);
#endif
	if ( write(fh, &head, sizeof(head)) != sizeof(head)) {
		printf("write header failed!\n");
		return 0;
	}

	if ( write(fh, p, (sbuf.st_size+1+pad) ) != (sbuf.st_size+1+pad)) {
		printf("write data failed!\n");
		return 0;
	}

	close(fh);
	chmod(outFile,  DEFFILEMODE);

	sync();

	free(p);
	unlink(tmpFile);

	return 0;
}


#define CERT_PATH "/etc/1x/"
void formCertUpload(webs_t wp, char_t * path, char_t * query)
{
    FILE *       fp;
    int          numWrite;
    char tmpBuf[200];
    int intVal, entryNum, i=0, add_entry=0, update_image=1;
    char_t *submitUrl, *strVal, *loadroot, *name, *loaduser, *strDelRoot, 
    		*strDelAllRoot,*strDelUser, *strDelAllUser, *strSelectCa;
    char fileName[50];
    int num_id, get_id, add_id, del_id, delall_id, max_num,index_id;
    CERTROOT_T rootEntry;
    CERTUSER_T userEntry;
    void *pEntry;

     	submitUrl = websGetVar(wp, T("url"), T(""));   // hidden page
     	loadroot =  websGetVar(wp, T("loadroot"), T("")); 
     	loaduser =  websGetVar(wp, T("loaduser"), T("")); 
     	name =  websGetVar(wp, T("name"), T(""));
     	strDelRoot =   websGetVar(wp, T("deleteSelRoot"), T(""));
     	strDelAllRoot =   websGetVar(wp, T("deleteAllRoot"), T(""));
	strDelUser =   websGetVar(wp, T("deleteSelUser"), T(""));
     	strDelAllUser =   websGetVar(wp, T("deleteAllUser"), T(""));     	
     	strSelectCa =   websGetVar(wp, T("selectca"), T("")); 
     	memset(&rootEntry, '\0', sizeof(rootEntry));
     	
     	if(loadroot[0] || strDelRoot[0] || strDelAllRoot[0] || strSelectCa[0]){
		num_id = MIB_CERTROOT_TBL_NUM;
		max_num = MAX_CERTROOT_NUM;
		add_id = MIB_CERTROOT_ADD;
		del_id = MIB_CERTROOT_DEL ;
		delall_id = MIB_CERTROOT_DELALL ;
		get_id = MIB_CERTROOT_TBL ;
		index_id = MIB_ROOT_IDX;
		memset(&rootEntry, '\0', sizeof(rootEntry));
		pEntry = (void *) & rootEntry ;
			
	}
	else if(loaduser[0] || strDelUser[0] || strDelAllUser[0]){
		num_id = MIB_CERTUSER_TBL_NUM;
		max_num = MAX_CERTUSER_NUM;
		add_id = MIB_CERTUSER_ADD;
		del_id = MIB_CERTUSER_DEL ;
		delall_id = MIB_CERTUSER_DELALL ;
		get_id = MIB_CERTUSER_TBL ;
		index_id = MIB_USER_IDX;
		memset(&userEntry, '\0', sizeof(userEntry));
		pEntry = (void *) & userEntry ;
	}
	else{
		strcpy(tmpBuf, "error handle\n");
		goto  ret_upload;
	}

	if(strSelectCa[0]){ //set ca index
		
		strVal = websGetVar(wp, "rootSelect", T(""));
		if ( !apmib_get(MIB_CERTROOT_TBL_NUM, (void *)&entryNum)) {
				strcpy(tmpBuf, T("Get entry number error!"));
				goto ret_upload;
		}
		if ( strVal[0] ) {
			intVal =  atoi(strVal) ;
			if ( !apmib_set(MIB_ROOT_IDX, (void *)&intVal)) {
				strcpy(tmpBuf, T("Set CA select error!"));
				goto ret_upload;
			}
			if( intVal <= entryNum){
				pEntry = (void *) &rootEntry ;
				*((char *)pEntry) = (char)intVal;
				if ( !apmib_get(MIB_CERTROOT_TBL, (void *)pEntry)){
					sprintf(tmpBuf, "Get Mib Root CA  entry %d error\n", intVal);
					goto ret_upload;      
				}
			}
			else{
					sprintf(tmpBuf, "invalid Root CA entry %d select\n",intVal );
					goto ret_upload;      
			}
		}
		strVal = websGetVar(wp, "userSelect", T(""));
		if ( !apmib_get(MIB_CERTUSER_TBL_NUM, (void *)&entryNum)) {
				strcpy(tmpBuf, T("Get entry number error!"));
				goto ret_upload;
		}
		if ( strVal[0] ) {
			intVal =  atoi(strVal) ;
			if ( !apmib_set(MIB_USER_IDX, (void *)&intVal)) {
				strcpy(tmpBuf, T("Set User select error!"));
				goto ret_upload;
			}
			if( intVal <= entryNum){
				pEntry = (void *) &userEntry ;
				*((char *)pEntry) = (char)intVal;
				if ( !apmib_get(MIB_CERTUSER_TBL, (void *)pEntry)){
					sprintf(tmpBuf, "Get Mib User entry entry %d error\n",i );
					goto ret_upload;      
				}
			}
			else{
					sprintf(tmpBuf, "invalid User entry select %d\n", i);
					goto ret_upload;      
			}
		}	
#if 0
		//printf(" ca files %s %s\n", rootEntry.comment, userEntry.comment); //for debug
		sprintf(tmpBuf, "openssl pkcs12 -des3 -in /etc/1x/%s.pfx -out /etc/1x/user.pem   -passout pass:realtek -passin pass:realtek", userEntry.comment);
		system(tmpBuf);
		sprintf(tmpBuf, "openssl x509 -inform PEM -outform DER -in /etc/1x/user.pem -out /etc/1x/user.der");
		system(tmpBuf);
		sprintf(tmpBuf, "openssl x509 -inform DER -in /etc/1x/%s.cer -outform PEM -out /etc/1x/root.pem", rootEntry.comment);
		system(tmpBuf);
#endif
		update_image=0;
	}
	
     	if(loadroot[0] || loaduser[0]){		//Add entry
		// get entry number to see if it exceeds max
		
		if ( !apmib_get(num_id, (void *)&intVal)) {
				strcpy(tmpBuf, T("Get entry number error!"));
				goto ret_upload;
		}
		if ( (intVal + 1) > max_num) {
			strcpy(tmpBuf, T("Cannot add new entry because table is full!"));
			goto ret_upload;
		}     		
		if(wp->lenPostData == 0){
			strcpy(tmpBuf, T("Error ! Upload file length is 0 !"));
			goto  ret_upload;
		 }
		 
		 for(i=1 ; i <= intVal ; i++) //check the duplicate entry
		 {
		 	*((char *)pEntry) = (char)i;
			if ( !apmib_get(get_id, (void *)pEntry)){
				sprintf(tmpBuf, "Get Mib CA entry %d error\n", i);
				goto ret_upload;      
			}
			if(loadroot[0] && !strcmp(rootEntry.comment,name)){
				sprintf(tmpBuf, "Error! Duplicate Root CA name %s with entry %d\n", name, i);
				goto ret_upload;
			}
			if(loaduser[0] && !strcmp(userEntry.comment,name)){
				sprintf(tmpBuf, "Error! Duplicate User CA name %s with entry %d\n", name, i);
				goto ret_upload;
			}
		 }
		 if(loaduser[0]){
			strVal = websGetVar(wp, "pass", T(""));
			if(strVal[0])
				strcpy(userEntry.pass, strVal);
		 }
		 if(loadroot[0]){
		     	strcpy(fileName, CERT_PATH);
		     	strcat(fileName, name);
			strcat(fileName,".cer");
			strcpy(rootEntry.comment, name);
		 }
		 else{
		     	strcpy(fileName, CERT_PATH);
		     	strcat(fileName, name);
		     	strcat(fileName, ".pfx");
		     	strcpy(userEntry.comment, name);
		 }  
		 if ((fp = fopen(fileName, "w+b")) != NULL) {
			numWrite = fwrite(wp->postData,1, wp->lenPostData, fp);
			if(numWrite < 0) perror("write error");
			if (numWrite == wp->lenPostData)
				sprintf(tmpBuf, T("Update successfully (size = %d bytes)!<br>"), wp->lenPostData);
			else
				sprintf(tmpBuf, T("Writesize=%d %dbytes."), wp->lenPostData, numWrite);
		 }
		 else {
			sprintf(tmpBuf, T("open file error"));
			goto ret_upload;
		 }
		    	
		fclose(fp);
		if ( apmib_set(add_id, (void *)pEntry) == 0) {
			strcpy(tmpBuf, T("Add table entry error!"));
			goto ret_upload;
		}
		add_entry =1 ;
		
    	}
    	/* Delete entry */
	if (strDelRoot[0] || strDelUser[0]) {
		if ( !apmib_get(num_id, (void *)&entryNum)) {
			strcpy(tmpBuf, T("Get entry number error!"));
			goto ret_upload;
		}

		strVal = websGetVar(wp, "selectcert", T(""));
		if ( strVal[0] ) {
			*((char *)pEntry) = atoi(strVal);
			if ( !apmib_get(get_id, (void *)pEntry)) {
				strcpy(tmpBuf, T("Get table entry error!"));
				goto ret_upload;
			}
			if ( !apmib_set(del_id, (void *)pEntry)) {
				strcpy(tmpBuf, T("Delete table entry error!"));
				goto ret_upload;
			}
		}
		if(strDelRoot[0])
			sprintf(tmpBuf, "rm -f %s%s.cer", CERT_PATH, rootEntry.comment);
		else			
			sprintf(tmpBuf, "rm -f %s%s.pfx", CERT_PATH, userEntry.comment);
		
		system(tmpBuf);
	}
	/* Delete all entry */
	if ( strDelAllRoot[0] || strDelAllUser[0]) {
		if ( !apmib_set(delall_id, pEntry)) {
			strcpy(tmpBuf, T("Delete all table error!"));
			goto ret_upload;
		}
		if(strDelAllRoot[0])
			system("rm -f /etc/1x/*.cer");
		else
			system("rm -f /etc/1x/*.pfx");
	}
	apmib_update_web(CURRENT_SETTING);	// update configuration to flash
	if(update_image){
		system("find   /etc/1x/*.pfx  -type f > /var/tmp/cert.list"); 
		system("find   /etc/1x/*.cer  -type f >> /var/tmp/cert.list"); 
#ifdef __mips__
		makeCertImage(FLASH_DEVICE_NAME, "/tmp/cert.list");
#else
		makeCertImage("cert.img", "/var/tmp/cert.list");
#endif
		system("rm -f /var/tmp/cert.list");

	}
#ifndef NO_ACTION
	else
		run_init_script("bridge");
#endif
		
	if(add_entry){
		OK_MSG1(tmpBuf, submitUrl);
	}
	else
	{
		if (submitUrl[0])
			websRedirect(wp, submitUrl);
		else
			websDone(wp, 200);
	}			
    return;

ret_upload:
    ERR_MSG(tmpBuf);
}

int certRootList(int eid, webs_t wp, int argc, char_t **argv)
{
	int	nBytesSent=0, entryNum, i;
	CERTROOT_T entry;

	if ( !apmib_get(MIB_CERTROOT_TBL_NUM, (void *)&entryNum)) {
  		websError(wp, 400, T("Get table entry error!\n"));
		return -1;
	}

	nBytesSent += websWrite(wp, T("<tr>"
      	"<td align=center width=\"30%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Name</b></font></td>\n"
      	"<td align=center width=\"20%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Select</b></font></td></tr>\n"));

	for (i=1; i<=entryNum; i++) {
		*((char *)&entry) = (char)i;
		if ( !apmib_get(MIB_CERTROOT_TBL, (void *)&entry))
			return -1;

		nBytesSent += websWrite(wp, T("<tr>"
			"<td align=center width=\"30%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
      			"<td align=center width=\"20%%\" bgcolor=\"#C0C0C0\"><input type=\"radio\" name=\"selectcert\" value=\"%d\" onClick=\"selectcaClick(this)\">"
      			"</td></tr>\n"), entry.comment, i);
	}
	return nBytesSent;
}

int certUserList(int eid, webs_t wp, int argc, char_t **argv)
{
	int	nBytesSent=0, entryNum, i;
	CERTUSER_T entry;

	if ( !apmib_get(MIB_CERTUSER_TBL_NUM, (void *)&entryNum)) {
  		websError(wp, 400, T("Get table entry error!\n"));
		return -1;
	}

	nBytesSent += websWrite(wp, T("<tr>"
      	"<td align=center width=\"30%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Name</b></font></td>\n"
      	"<td align=center width=\"20%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Select</b></font></td></tr>\n"));

	for (i=1; i<=entryNum; i++) {
		*((char *)&entry) = (char)i;
		if ( !apmib_get(MIB_CERTUSER_TBL, (void *)&entry))
			return -1;

		nBytesSent += websWrite(wp, T("<tr>"
			"<td align=center width=\"30%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
      			"<td align=center width=\"20%%\" bgcolor=\"#C0C0C0\"><input type=\"radio\" name=\"selectcert\" value=\"%d\" onClick=\"selectprClick(this)\"></td></tr>\n"), entry.comment, i);
	}
	return nBytesSent;
}
#endif
