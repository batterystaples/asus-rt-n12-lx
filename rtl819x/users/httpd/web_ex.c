/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 */
/*
 * ASUS Home Gateway Reference Design
 * Web Page Configuration Support Routines
 *
 * Copyright 2001, ASUSTek Inc.
 * All Rights Reserved.
 *
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of ASUSTek Inc.;
 * the contents of this file may not be disclosed to third parties, copied or
 * duplicated in any form, in whole or in part, without the prior written
 * permission of ASUSTek Inc..
 *
 * $Id: web_ex.c,v 1.38 2011/07/13 09:25:20 emily Exp $
 */

typedef unsigned char   bool;

#ifdef WEBS
#include <webs.h>
#include <uemf.h>
#include <ej.h>
#else /* !WEBS */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <httpd.h>
#endif /* WEBS */

#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <sys/klog.h>
#include <stdarg.h>
#include <sys/wait.h>
#include <dirent.h>
//#include <wlutils.h>  Viz banned 2010.08
#include <proto/ethernet.h>   //add by Viz 2010.08
#include <nvram/typedefs.h>
#include <nvram/bcmutils.h>
#include <nvram/bcmnvram.h>
#include <shutils.h>
#include <common.h>

// 2008.08 magic {
#include "dp.h"	//for discover_all()
#include "wireless.h"    /* --Alicia, 08.09.23 */
#include "initial_web_hook.h"
//#endif

#include <net/if.h>
#include <linux/sockios.h>

#include <ralink.h>
#include <semaphore_mfp.h>
#include <netdb.h>  // Alicia, 201011, for WebUsage

#define wan_prefix(unit, prefix)	snprintf(prefix, sizeof(prefix), "wan%d_", unit)
//Uncomment by Jerry-2011/01/21 {
#define csprintf(fmt, args...) do{\
	FILE *cp = fopen("/dev/console", "w");\
	if (cp) {\
		fprintf(cp, fmt, ## args);\
		fclose(cp);\
	}\
}while (0)
//}
// 2008.08 magic }

#include <sys/mman.h>
//typedef uint32_t __u32; //2008.08 magic
#ifndef	O_BINARY		/* should be define'd on __WIN32__ */
#define O_BINARY	0
#endif
#include <image.h>
#ifndef MAP_FAILED
#define MAP_FAILED (-1)
#endif



#ifdef WEBS
#define init_cgi(query)
#define do_file(webs, file)
#endif

//apmib header file
#include "apmib.h"	//Added by Jerry

//Added by Jerry
extern int getInfo(int eid, webs_t wp, int argc, char_t **argv);
extern int getIndex(int eid, webs_t wp, int argc, char_t **argv);
extern int getScheduleInfo(int eid, webs_t wp, int argc, char_t **argv);
extern int wlAcList(int eid, webs_t wp, int argc, char_t **argv);
extern int getModeCombobox(int eid, webs_t wp, int argc, char_t **argv);
extern int getDHCPModeCombobox(int eid, webs_t wp, int argc, char_t **argv);
extern int dhcpClientList(int eid, webs_t wp, int argc, char_t **argv);
extern int dhcpRsvdIp_List(int eid, webs_t wp, int argc, char_t **argv);
extern int portFwList(int eid, webs_t wp, int argc, char_t **argv);
extern int ipFilterList(int eid, webs_t wp, int argc, char_t **argv);
extern int portFilterList(int eid, webs_t wp, int argc, char_t **argv);
extern int macFilterList(int eid, webs_t wp, int argc, char_t **argv);
extern int urlFilterList(int eid, webs_t wp, int argc, char_t **argv);
extern int staticRouteList(int eid, webs_t wp, int argc, char_t **argv);
extern int kernelRouteList(int eid, webs_t wp, int argc, char_t **argv);
extern int sysLogList(int eid, webs_t wp, int argc, char_t **argv);
extern int sysCmdLog(int eid, webs_t wp, int argc, char_t **argv);
extern int wlSchList(int eid, webs_t wp, int argc, char_t **argv);
extern int wirelessClientList(int eid, webs_t wp, int argc, char_t **argv);
extern int wlSiteSurveyTbl(int eid, webs_t wp, int argc, char_t **argv);
extern int wlWdsList(int eid, webs_t wp, int argc, char_t **argv);
extern int wdsList(int eid, webs_t wp, int argc, char_t **argv);
extern int getVirtualIndex(int eid, webs_t wp, int argc, char_t **argv);
extern int getVirtualInfo(int eid, webs_t wp, int argc, char_t **argv);
extern int ipQosList(int eid, webs_t wp, int argc, char_t **argv);

/* Routines exported in fmwlan.c */
extern void formWlanSetup(webs_t wp, char_t *path, char_t *query);
extern void formWlanRedirect(webs_t wp, char_t *path, char_t *query);
extern void formWep(webs_t wp, char_t *path, char_t *query);
extern void formWlAc(webs_t wp, char_t *path, char_t *query);
extern void formAdvanceSetup(webs_t wp, char_t *path, char_t *query);
extern void formWlEncrypt(webs_t wp, char_t *path, char_t *query);
extern void formSchedule(webs_t wp, char_t *path, char_t *query);
extern void formNewSchedule(webs_t wp, char_t *path, char_t *query);
extern void formWirelessTbl(webs_t wp, char_t *path, char_t *query);
extern void formStats(webs_t wp, char_t *path, char_t *query);
extern void formWlSiteSurvey(webs_t wp, char_t *path, char_t *query);
extern void formWlWds(webs_t wp, char_t *path, char_t *query);
extern void formWdsEncrypt(webs_t wp, char_t *path, char_t *query);
extern void formWlanMultipleAP(webs_t wp, char_t *path, char_t *query);
extern void formWsc(webs_t wp, char_t *path, char_t *query);

/* Routines exported in fmtcpip.c */
extern void formTcpipSetup(webs_t wp, char_t *path, char_t *query);
extern void formReflashClientTbl(webs_t wp, char_t *path, char_t *query);
extern void formStaticDHCP(webs_t wp, char_t *path, char_t *query);
extern void formWanTcpipSetup(webs_t wp, char_t *path, char_t *query);
extern void formTcpipSetupAP(webs_t wp, char_t *path, char_t *query);

/* Routines exported in fmfwall.c */
extern void formPortFw(webs_t wp, char_t *path, char_t *query);
extern void formFilter(webs_t wp, char_t *path, char_t *query);
extern void formDMZ(webs_t wp, char_t *path, char_t *query);
extern void formBasicFwallSetup(webs_t wp, char_t *path, char_t *query);
extern void formIpQoS(webs_t wp, char_t *path, char_t *query);

/* Routines exported in fmmgmt.c */
extern void formPasswordSetup(webs_t wp, char_t *path, char_t *query);
extern void formLogout(webs_t wp, char_t *path, char_t *query);
extern void formUpload(webs_t wp, char_t * path, char_t * query);
extern void formOpMode(webs_t wp, char_t * path, char_t * query);
extern void formNtp(webs_t wp, char_t *path, char_t *query);
extern void formWizard(webs_t wp, char_t *path, char_t *query);
extern void formPocketWizard(webs_t wp, char_t *path, char_t *query);
extern void formPocketWizardGW(webs_t wp, char_t *path, char_t *query);
extern void formRebootCheck(webs_t wp, char_t *path, char_t *query);
extern void formSysCmd(webs_t wp, char_t *path, char_t *query);
extern void formSysLog(webs_t wp, char_t *path, char_t *query);
extern void formDosCfg(webs_t wp, char_t *path, char_t *query);
extern void formSaveConfig(webs_t wp, char_t *path, char_t *query);
extern void formSystemSetup(webs_t wp, char_t *path, char_t *query);
extern void formClearSysLog(webs_t wp, char_t *path, char_t *query);
extern int updateConfigIntoFlash(unsigned char *data, int total_len, int *pType, int *pStatus);

#ifdef WIFI_SIMPLE_CONFIG
extern void call_wps_update();	//2011.05.05 Jerry
#endif

/* Routines exported in fmroute.c */
extern void formRoute(webs_t wp, char_t *path, char_t *query);

/* Routines exported in fmddns.c */
extern void formDdns(webs_t wp, char_t *path, char_t *query);

#define sys_default()   eval("flash", "default-sw")	//2011.04.14 Jerry
#define GROUP_FLAG_REFRESH 	0
#define GROUP_FLAG_DELETE 	1
#define GROUP_FLAG_ADD 		2
#define GROUP_FLAG_REMOVE 	3

// 2008.08 magic {
typedef u_int64_t u64;		//Uncomment by Jerry-2011/01/21
typedef u_int32_t u32;		//Uncomment by Jerry-2011/01/21
static u64 restart_needed_bits = 0; 
static u32 restart_tatal_time = 0; 
//static u32 last_arp_info_len = 0, last_disk_info_len = 0;
// 2008.08 magic }

int action;

char *serviceId;
#define MAX_GROUP_ITEM 10
#define MAX_GROUP_COUNT 300
#define MAX_LINE_SIZE 512
char *groupItem[MAX_GROUP_ITEM];
char urlcache[128];
char *next_host;
int delMap[MAX_GROUP_COUNT];
char SystemCmd[64];
char UserID[32]="";
char UserPass[32]="";
char ProductID[32]="";
extern int redirect;
extern int change_passwd;	// 2008.08 magic
extern int reget_passwd;	// 2008.08 magic

extern int modify_lan;	//2011.06.01 Jerry
extern int modify_dhcp;	//2011.06.01 Jerry
extern int modify_tz;	//2011.06.20 Jerry
extern int modify_log;	//2011.06.20 Jerry

int flag_upgrade;	//2011.07.04 Jerry

//2011.03.29 Jerry {
void notify_sysconf(const char *event_name, int do_wait)
{
	char *full_name;
	FILE *fp;
	int close_result;
	int killproc = 1;

	full_name = (char *)(malloc(strlen(event_name) + 100));
	if (full_name == NULL)
	{
		fprintf(stderr,
				"Error: Failed trying to allocate %lu bytes of memory for the "
				"full path of an rc notification marker file, while trying to "
				"notify rc of a `%s' event.\n",
				(unsigned long)(strlen(event_name) + 100), event_name);
		return;
	}

	sprintf(full_name, "/tmp/sysconf_notification/%s", event_name);
	fp = fopen(full_name, "w");
	if (fp == NULL)
	{
		fprintf(stderr,
				"Error: Failed trying to open file %s while trying to notify "
				"rc of an event: %s.\n", full_name, strerror(errno));
		free(full_name);
		return;
	}

	close_result = fclose(fp);
	if (close_result != 0)
	{
		fprintf(stderr,
				"Error: Failed trying to close file %s while trying to notify "
				"rc of an event: %s.\n", full_name, strerror(errno));
	}

	sprintf(full_name, "/tmp/sysconf_action_incomplete/%s", event_name);
	fp = fopen(full_name, "w");
	if (fp == NULL)
	{
		fprintf(stderr,
				"Error: Failed trying to open file %s while trying to notify "
				"rc of an event: %s.\n", full_name, strerror(errno));
		free(full_name);
		return;
	}

	close_result = fclose(fp);
	if (close_result != 0)
	{
		fprintf(stderr,
				"Error: Failed trying to close file %s while trying to notify "
				"rc of an event: %s.\n", full_name, strerror(errno));
	}

	sprintf(full_name, "/tmp/sysconf_notification/%s", event_name);
	fp = fopen(full_name, "w");
	if (fp == NULL)
	{
		fprintf(stderr,
				"Error: Failed trying to open file %s while trying to notify "
				"rc of an event: %s.\n", full_name, strerror(errno));
		free(full_name);
		return;
	}

	close_result = fclose(fp);
	if (close_result != 0)
	{
		fprintf(stderr,
				"Error: Failed trying to close file %s while trying to notify "
				"rc of an event: %s.\n", full_name, strerror(errno));
	}
	
	//wendebug
	killproc = find_pid_by_name("notify_service");
	kill(killproc, SIGTSTP);

	if (do_wait == 1)
	{
		sprintf(full_name, "/tmp/sysconf_action_incomplete/%s", event_name);

		while (TRUE)
		{
			fp = fopen(full_name, "r");
			if (fp == NULL)
				break;
			fclose(fp);
			sleep(1);
		}
	}

	free(full_name);
}
//2011.03.29 Jerry }

int sys_reboot()
{
	printf("[httpd] reboot\n");
	notify_sysconf("restart_reboot", 0);
	return 0;
}

char *
rfctime(const time_t *timep)
{
	static char s[201]="";
	struct tm tm;
	FILE *fp=0;
	char timezone[8]="";
	char setvalue[8]="";

	fp=fopen("/var/TZ", "r"); 
	if(fp!=NULL) 
	{
		while(!feof(fp))
		{
		  fgets(timezone, 8, fp);
		}
		fclose(fp);

		strncpy(setvalue, timezone, strlen(timezone)-1);
		putenv(setvalue);	
	}

	memcpy(&tm, localtime(timep), sizeof(struct tm));
	strftime(s, 200, "%a, %d %b %Y %H:%M:%S %z", &tm);
	return s;
}

void
reltime(unsigned int seconds, char *cs)
{
#ifdef SHOWALL
	int days=0, hours=0, minutes=0;

	if (seconds > 60*60*24) {
		days = seconds / (60*60*24);
		seconds %= 60*60*24;
	}
	if (seconds > 60*60) {
		hours = seconds / (60*60);
		seconds %= 60*60;
	}
	if (seconds > 60) {
		minutes = seconds / 60;
		seconds %= 60;
	}
	sprintf(cs, "%d days, %d hours, %d minutes, %d seconds", days, hours, minutes, seconds);
#else
	sprintf(cs, "%d secs", seconds);
#endif
}

#ifndef WEBS
/******************************************************************************/
/*
 *	Redirect the user to another webs page
 */
 
char *getip(FILE *fp)
{     
    if (next_host==NULL || strcmp(next_host, "")==0)    
    {
	unsigned char buffer[100];
	apmib_get(MIB_IP_ADDR,  (void *)buffer);	//Added by Jerry
	return inet_ntoa(*((struct in_addr *)buffer));
    }
    else
{
	
       return (next_host);
}
} 

//2008.08 magic{
void websRedirect(webs_t wp, char_t *url)
{	
	//printf("Redirect to : %s\n", url);	
	websWrite(wp, T("<html><head>\r\n"));
	//websWrite(wp, T("<meta http-equiv=\"refresh\" content=\"0; url=http://%s/%s\">\r\n"), getip((FILE *)wp), url);//Comment by Mars
	websWrite(wp, T("<meta http-equiv=\"refresh\" content=\"0; url=http://%s%s\">\r\n"), getip((FILE *)wp), url);//Added by Mars
	websWrite(wp, T("<meta http-equiv=\"Content-Type\" content=\"text/html\">\r\n"));
	websWrite(wp, T("</head></html>\r\n"));      
	
	websDone(wp, 200);	
}
#endif
//2008.08 magic}

void sys_script(char *name)
{

     char scmd[64];
	
     sprintf(scmd, "/tmp/%s", name);
     printf("run %s %d %s\n", name, strlen(name), scmd);	// tmp test
     
     //handle special scirpt first

     if (strcmp(name,"syscmd.sh")==0)
     {
	   if (strcmp(SystemCmd, "")!=0)
	   {
	   	//sprintf(SystemCmd, "%s > /tmp/syscmd.log\n", SystemCmd);
		sprintf(SystemCmd, "%s > /tmp/syscmd.log 2>&1\n", SystemCmd);	// oleg patch
	   	system(SystemCmd);
	   }	
	   else
	   {
	   	system("echo None > /tmp/syscmd.log\n");
	   }
     }
     else if (strcmp(name, "syslog.sh")==0)
     {
	   // to nothing
     }	
     else if (strcmp(name, "wan.sh")==0)
     {
	   kill_pidfile_s("/var/run/infosvr.pid", SIGUSR1);
     }
     else if (strcmp(name, "printer.sh")==0)
     {	
	   // update status of printer
	   kill_pidfile_s("/var/run/infosvr.pid", SIGUSR1);
     }
     else if (strcmp(name, "lpr_remove")==0)
     {
	   kill_pidfile_s("/var/run/lpdparent.pid", SIGUSR2);
     }
//#ifdef U2EC
	else if (!strcmp(name, "mfp_requeue")){
		
	}
	else if (!strcmp(name, "mfp_monopolize")){
	}
//#endif
     else if (strcmp(name, "wlan11a.sh")==0 || strcmp(name,"wlan11b.sh")==0)
     {
	  // do nothing	
     }
     else if (strcmp(name,"leases.sh")==0 || strcmp(name,"dleases.sh")==0) /* check here*/
     {		
     }
     else if (strcmp(name,"iptable.sh")==0) 
     {
		// TODO	
     }
     else if (strcmp(name,"route.sh")==0)
     {
		// TODO
     }
     else if (strcmp(name,"dhcpc_renew")==0)
     {
		sleep(1);
     }
     else if (strcmp(name,"dhcpc_release")==0)
     {
		sleep(1);
     }
     else if (strcmp(name,"eject-usb.sh")==0)
     {
		eval("rmstorage");
     }
     else if (strcmp(name,"ddnsclient")==0)
     {
		eval("start_ddns");
     }
#ifdef ASUS_DDNS //2007.03.22 Yau add
     else if (strcmp(name,"hostname_check") == 0)
     {
     }
#endif
     else if (strstr(scmd, " ") == 0) // no parameter, run script with eval
     {
		eval(scmd);
     }
     else
	system(scmd);  
}

void websScan(char_t *str)
{
	unsigned int i, flag;
	char_t *v1, *v2, *v3, *sp;
	char_t groupid[64];
	char_t value[MAX_LINE_SIZE];
	char_t name[MAX_LINE_SIZE];
	
	v1 = strchr(str, '?');
			
	i = 0;
	flag = 0;
				     		
	while (v1!=NULL)
	{	   	    	
	    v2 = strchr(v1+1, '=');
	    v3 = strchr(v1+1, '&');

// 2008.08 magic {
		if (v2 == NULL)
			break;
// 2008.08 magic }
	    
	    if (v3!=NULL)
	    {
	       strncpy(value, v2+1, v3-v2-1);
	       value[v3-v2-1] = 0;  
	    }  
	    else
	    {
	       strcpy(value, v2+1);
	    }
	    
	    strncpy(name, v1+1, v2-v1-1);
	    name[v2-v1-1] = 0;
	    /*printf("Value: %s %s\n", name, value);*/
	    
	    if (v2 != NULL && ((sp = strchr(v1+1, ' ')) == NULL || (sp > v2))) 
	    {	    	
	       if (flag && strncmp(v1+1, groupid, strlen(groupid))==0)
	       {	    		    	   
		   delMap[i] = atoi(value);
		   /*printf("Del Scan : %x\n", delMap[i]);*/
		   if (delMap[i]==-1)  break;		   		   
		   i++;
	       }	
	       else if (strncmp(v1+1,"group_id", 8)==0)
	       {	    				       
		   sprintf(groupid, "%s_s", value);
		   flag = 1;
	       }   
	    }
	    v1 = strchr(v1+1, '&');
	} 
	delMap[i] = -1;
	return;
}


void websApply(webs_t wp, char_t *url)
{
#ifdef TRANSLATE_ON_FLY
	do_ej (url, wp);
	websDone (wp, 200);
#else   // define TRANSLATE_ON_FLY

     FILE *fp;
     char buf[MAX_LINE_SIZE];

     fp = fopen(url, "r");
     
     if (fp==NULL) return;
     
     while (fgets(buf, sizeof(buf), fp))
     {
	websWrite(wp, buf);
     } 
     
     websDone(wp, 200);	
     fclose(fp);
#endif
}

void char_to_ascii(char *output, char *input)
{
	int i;
	char tmp[10];
	char *ptr;

	ptr = output;

	for ( i=0; i<strlen(input); i++ )
	{
		if ((input[i]>='0' && input[i] <='9')
		   ||(input[i]>='A' && input[i]<='Z')
		   ||(input[i] >='a' && input[i]<='z')
		   || input[i] == '!' || input[i] == '*'
		   || input[i] == '(' || input[i] == ')'
		   || input[i] == '_' || input[i] == '-'
		   || input[i] == "'" || input[i] == '.')
		{
			*ptr = input[i];
			ptr++;
		}
		else
		{
			sprintf(tmp, "%%%.02X", input[i]);
			strcpy(ptr, tmp);
			ptr+=3;
		}
	}

	*ptr = '\0';													      
}

static int
ej_apmib_char_to_ascii(int eid, webs_t wp, int argc, char_t **argv)
{
	char *sid, *name;
	int ret = 0;
	char tmpstr[256];
	unsigned char buf[128]; 
	memset(tmpstr, 0x0, sizeof(tmpstr));
	memset(buf, 0x0, sizeof(buf));

	if (ejArgs(argc, argv, "%s %s", &sid, &name) < 2) {
		websError(wp, 400, "Insufficient args\n");
		return -1;
	}

	if(!strcmp(name, "pskValue"))
		apmib_get(MIB_WLAN_WPA_PSK, (void *)buf);
	if(!strcmp(name, "ssid"))
		apmib_get(MIB_WLAN_SSID, (void *)buf);
	char_to_ascii(tmpstr, buf);
	ret += websWrite(wp, "%s", tmpstr);

	return ret;
}


/* Report sys up time */
static int
ej_uptime(int eid, webs_t wp, int argc, char_t **argv)
{

//	FILE *fp;
	char buf[MAX_LINE_SIZE];
	unsigned char NTP_TIMEZONE[16]="";
	unsigned char time1[180]="";
	unsigned char bootcount[32]="";
	char lease_buf[128]="";
//	unsigned long uptime;
	int ret;
	char *str = file2str("/proc/uptime");
	time_t tm;

	time(&tm);
	sprintf(buf, rfctime(&tm));

	if (str) {
		unsigned int up = atoi(str);
		free(str);
		memset(lease_buf, 0, sizeof(lease_buf));
		reltime(up, lease_buf);
		sprintf(buf, "%s(%s since boot)", buf, lease_buf);
	}
	apmib_get(MIB_NTP_SYS_TIMEZONE,  (void *)NTP_TIMEZONE);
	strncpy(time1, buf, 26);
	strncat( time1, NTP_TIMEZONE, 10);
	sprintf(bootcount, "(%s since boot)", lease_buf);
	strncat(time1, bootcount, strlen(bootcount));
	//printf("==== %s:%s  TIME = %s  ====\n", __FILE__, __FUNCTION__, time1); Emily Remove debug message 2011.05.11
	ret = websWrite(wp, time1);  
	return ret;	    
}

static int
ej_sysuptime(int eid, webs_t wp, int argc, char_t **argv)
{
	int ret=0;
	char *str = file2str("/proc/uptime");

	if (str) {
		unsigned int up = atoi(str);
		free(str);

		char lease_buf[128];
		memset(lease_buf, 0, sizeof(lease_buf));
		reltime(up, lease_buf);
		ret = websWrite(wp, "%s since boot", lease_buf);
	}

	return ret;	    
}

static int dump_file(webs_t wp, char *filename)
{
	FILE *fp;
	char buf[MAX_LINE_SIZE];
	int ret;

	fp = fopen(filename, "r");
		
	if (fp==NULL) 
	{
		ret+=websWrite(wp, "");
		return (ret);
	}

	ret = 0;
		
	while (fgets(buf, MAX_LINE_SIZE, fp)!=NULL)
	{	 	
	    ret += websWrite(wp, buf);
	}		    				     		
	 
	fclose(fp);		
	
	return (ret);
}

static int
ej_dump(int eid, webs_t wp, int argc, char_t **argv)
{	
	char filename[32];
	char *file,*script;
	int ret;

	if (ejArgs(argc, argv, "%s %s", &file, &script) < 2) {
		websError(wp, 400, "Insufficient args\n");
		return -1;
	}
	
	if (strcmp(script,"")!=0) sys_script(script); 
	ret = 0;
			   
	if (strcmp(file, "syslog.log")==0)
	{
	   	sprintf(filename, "/tmp/%s-1", file);
	   	ret+=dump_file(wp, filename); 
	}
	   			   
	sprintf(filename, "/tmp/%s", file);
	ret+=dump_file(wp, filename);					
	   
	return ret;	    
}	

enum {
	NOTHING,
	REBOOT,
	RESTART,
};

char *svc_pop_list(char *value, char key)
{    
    char *v, *buf;
    int i;
	       
    if (value==NULL || *value=='\0')
       return (NULL);      
	    
    buf = value;
    v = strchr(buf, key);

    i = 0;
    
    if (v!=NULL)
    {    	
	*v = '\0';  	
	return (buf);    	   
    }    
    return (NULL);
}


static char post_buf[10000] = { 0 };
static char post_buf_backup[10000] = { 0 };

static void do_html_post_and_get(char *url, FILE *stream, int len, char *boundary){
	char *query = NULL;
	
	init_cgi(NULL);
	
	memset(post_buf, 0, sizeof(post_buf));
	memset(post_buf_backup, 0, sizeof(post_buf_backup));
	
	if (fgets(post_buf, MIN(len+1, sizeof(post_buf)), stream)){
		len -= strlen(post_buf);
		
		while (len--)
			(void)fgetc(stream);
	}
	
	query = url;
	strsep(&query, "?");
	
	if (query && strlen(query) > 0){
		if (strlen(post_buf) > 0)
			sprintf(post_buf_backup, "?%s&%s", post_buf, query);
		else
			sprintf(post_buf_backup, "?%s", query);
		
		sprintf(post_buf, "%s", post_buf_backup+1);
	}
	else if (strlen(post_buf) > 0)
		sprintf(post_buf_backup, "?%s", post_buf);
	
	websScan(post_buf_backup);
	init_cgi(post_buf);
}


//2011.03.18 Jerry {
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
//2011.03.18 Jerry}

static int update_variables_ex(int eid, webs_t wp, int argc, char_t **argv){
	char *action_mode;
	char *sid_list;
	char *script;
	int result;

	restart_needed_bits = 0;
	// assign control variables
	action_mode = websGetVar(wp, "action_mode", "");
	script = websGetVar(wp, "action_script", "");
	sid_list = websGetVar(wp, "sid_list", "");
	
	csprintf("Apply: [%s] [%s]\n", action_mode, script); //2009.01 magic for debug

	char *current_url;
	char *preferred_lang;
	unsigned char lang_mib[16];	//2011.04.12 Jerry
	int w_setting = 1;	//2011.04.12 Jerry
	int page_modified = 0;
	int x_setting = 1;
	int wanduckproc = 0;
	current_url = websGetVar(wp, "current_page", "");
	preferred_lang = websGetVar(wp, "preferred_lang", "");

	//Change preferred_lang
	//printf("Preferred_lang(web_ex.c): %s\n", preferred_lang);
	apmib_get( MIB_PREFERRED_LANG, (void *)&lang_mib);
	if (strcmp(preferred_lang, lang_mib) && strlen(preferred_lang) > 0) {
		sprintf(lang_mib, "%s", preferred_lang);
		//printf("lang_mib: %s, preferred_lang: %s\n", lang_mib, preferred_lang);
		apmib_set( MIB_PREFERRED_LANG, (void *)&lang_mib);
		//apmib_update(CURRENT_SETTING);
		page_modified = 1;
	}
	
	if (!strcmp(action_mode, "Restart_Rirewall"))
	{
		restart_needed_bits = RESTART_FIREWALL;
		websWrite(wp, "<script>done_committing();</script>\n");
		page_modified = 1;
	}
	else if (!strcmp(action_mode, "Restart_QoS"))
	{
		restart_needed_bits = RESTART_QOS;
		websWrite(wp, "<script>done_committing();</script>\n");
		//websWrite(wp, "<script>restart_needed_time(%d);</script>\n", restart_tatal_time);
		page_modified = 1;
	}
	//2011.04.19 Jerry {
	else if (!strcmp(action_mode, "Restart_LAN"))
	{
		OPMODE_T op_mode;
		apmib_get(MIB_OP_MODE, (void *)&op_mode);
		if(op_mode == BRIDGE_MODE) {
			restart_tatal_time = ITVL_RESTART_LAN + 25;
			restart_needed_bits |= RESTART_LAN;
		}
		else {
			if( (modify_lan == 1 && modify_dhcp == 1) || modify_lan == 1)
			{
				restart_tatal_time = ITVL_RESTART_LAN;
				restart_needed_bits |= RESTART_LAN;
				restart_needed_bits |= RESTART_WLAN;
				http_logout_change_mode();	
			}
			else if( modify_lan == 0 && modify_dhcp == 1 )
			{
				restart_tatal_time = ITVL_RESTART_DHCPD;
				restart_needed_bits = RESTART_DHCPD;
			}
		}
		websWrite(wp, "<script>done_committing();</script>\n");
		websWrite(wp, "<script>restart_needed_time(%d);</script>\n", restart_tatal_time);
		page_modified = 1;
		//2011.05.18 Jerry {
		//http_logout_change_mode();
		wanduckproc = find_pid_by_name("wanduck");
		if(wanduckproc > 0)
			kill(wanduckproc, SIGUSR2);
		//2011.05.18 Jerry }
	}
	else if (!strcmp(action_mode, "Restart_WAN"))
	{
		int wan_proto = -1;
		apmib_get(MIB_WAN_DHCP, (void *)&wan_proto);
		restart_needed_bits = RESTART_WAN;
		if(wan_proto == PPTP || wan_proto == L2TP)
			restart_tatal_time = ITVL_RESTART_WAN + 20;	//Add 20 sec to wait connection for PPTP and L2TP
		else
			restart_tatal_time = ITVL_RESTART_WAN;			
		websWrite(wp, "<script>done_committing();</script>\n");
		websWrite(wp, "<script>restart_needed_time(%d);</script>\n", restart_tatal_time);
		page_modified = 1;
	}
	else if (!strcmp(action_mode, "Restart_WLAN"))
	{
		restart_tatal_time = ITVL_RESTART_WLAN;
		restart_needed_bits = RESTART_WLAN;
		websWrite(wp, "<script>done_committing();</script>\n");
		websWrite(wp, "<script>restart_needed_time(%d);</script>\n", restart_tatal_time);
		page_modified = 1;
	}
	else if (!strcmp(action_mode, "Restart_Dhcpd"))
	{
		restart_tatal_time = ITVL_RESTART_DHCPD;
		restart_needed_bits = RESTART_DHCPD;
		websWrite(wp, "<script>done_committing();</script>\n");
		websWrite(wp, "<script>restart_needed_time(%d);</script>\n", restart_tatal_time);
		page_modified = 1;
	}
	//2011.04.19 Jerry }
	else if (!strcmp(action_mode, "Reinit"))
	{
		if(!strcmp(current_url, "opmode.asp"))	//2011.04.25 Jerry
			http_logout_change_mode();
		restart_tatal_time = ITVL_RESTART_ALL;
		restart_needed_bits = RESTART_ALL;
		websWrite(wp, "<script>done_committing();</script>\n");
		websWrite(wp, "<script>restart_needed_time(%d);</script>\n", restart_tatal_time);
		page_modified = 1;
	}
	//2011.05.25 Jerry {
	else if (!strcmp(action_mode, "Restart_PPPoE"))
	{
		restart_tatal_time = ITVL_RESTART_ALL;
		restart_needed_bits = RESTART_PPPOE;
		websWrite(wp, "<script>done_committing();</script>\n");
		websWrite(wp, "<script>restart_needed_time(%d);</script>\n", restart_tatal_time);
		page_modified = 1;
	}
	else if (!strcmp(action_mode, "Restart_PPTP"))
	{
		restart_tatal_time = ITVL_RESTART_ALL;
		restart_needed_bits = RESTART_PPTP;
		websWrite(wp, "<script>done_committing();</script>\n");
		websWrite(wp, "<script>restart_needed_time(%d);</script>\n", restart_tatal_time);
		page_modified = 1;
	}
	else if (!strcmp(action_mode, "Restart_L2TP"))
	{
		restart_tatal_time = ITVL_RESTART_ALL;
		restart_needed_bits = RESTART_L2TP;
		websWrite(wp, "<script>done_committing();</script>\n");
		websWrite(wp, "<script>restart_needed_time(%d);</script>\n", restart_tatal_time);
		page_modified = 1;
	}
	//2011.05.25 Jerry }
	//2011.06.20 Jerry {
	else if (!strcmp(action_mode, "Restart_MISC"))
	{
		if(modify_tz == 1) {
			restart_tatal_time += ITVL_RESTART_NTPC;
			restart_needed_bits |= RESTART_NTPC;
		}
		if(modify_log == 1) {
			restart_tatal_time += ITVL_RESTART_SYSLOG;
			restart_needed_bits |= RESTART_SYSLOG;
		}
		websWrite(wp, "<script>done_committing();</script>\n");
		websWrite(wp, "<script>restart_needed_time(%d);</script>\n", restart_tatal_time);
		page_modified = 1;
	}
	//2011.06.20 Jerry }
	else if (!strcmp(action_mode, " QIS_Apply "))
	{	
		apmib_reinit();	//2011.04.25 Jerry
		//int page_modified = 0;
		int op_mode_modified = 0;
		int wireless_modified = 0;

		//2011.05.12 Jerry {
		apmib_get( MIB_PREFERRED_LANG, (void *)&lang_mib);
		if (strcmp(preferred_lang, lang_mib) && strlen(preferred_lang) > 0) {
			sprintf(lang_mib, "%s", preferred_lang);
			apmib_set( MIB_PREFERRED_LANG, (void *)&lang_mib);
		}
		//2011.05.12 Jerry }

		if(!strcmp(current_url, "/qis/QIS_wireless.htm"))
		{
			unsigned char new_ssid[64], new_psk_value[64], old_ssid[64], old_psk_value[64], op_mode_t[5], new_auth_mode[32];
			OPMODE_T op_mode, curr_op_mode;
			ENCRYPT_T encrypt;
			WPA_CIPHER_T wpa_cipher;
			WPA_CIPHER_T wpa2_cipher;
			DHCP_T dhcp = 1;
			WPA_AUTH_T wpa_auth;
			sprintf(new_ssid, "%s", websGetVar(wp, "rt_ssid", ""));
			sprintf(new_psk_value, "%s", websGetVar(wp, "rt_wpa_psk", ""));
			sprintf(op_mode_t, "%s", websGetVar(wp, "sw_mode", ""));
			sprintf(new_auth_mode, "%s", websGetVar(wp, "rt_auth_mode", ""));

			//Set op mode
			apmib_get(MIB_OP_MODE, (void *)&curr_op_mode);
			op_mode = atoi(op_mode_t);
			apmib_set(MIB_OP_MODE, (void *)&op_mode);

			if(curr_op_mode == GATEWAY_MODE && (curr_op_mode != op_mode)) {
				struct in_addr inIp_gw, inMask_gw;
				DHCP_T dhcp_gw;
				op_mode_modified = 1;
				printf("Change to bridge mode\n");
				apmib_get( MIB_DHCP, (void *)&dhcp_gw);
				apmib_set( MIB_DHCP_GW, (void *)&dhcp_gw);
				apmib_get( MIB_IP_ADDR, (void *)&inIp_gw);
				apmib_set( MIB_IP_ADDR_GW, (void *)&inIp_gw);
				apmib_get( MIB_SUBNET_MASK, (void *)&inMask_gw);
				apmib_set( MIB_SUBNET_MASK_GW, (void *)&inMask_gw);
				apmib_set( MIB_DHCP, (void *)&dhcp);	//2011.04.20 Jerry
			}


			if(!strcmp(new_auth_mode, "open"))
			{
				printf("open auth!!!!!\n");
				apmib_set(MIB_WLAN_SSID, (void *)&new_ssid);
				call_wps_update();
				page_modified = 1;
				wireless_modified = 1;
			}
			else if(!strcmp(new_auth_mode, "psk"))
			{
				printf("wpa-psk auth!!!!!\n");
				apmib_set(MIB_WLAN_SSID, (void *)&new_ssid);
				apmib_set(MIB_WLAN_WPA_PSK, (void *)&new_psk_value);
				//encrypt = ENCRYPT_WPA;
				encrypt = ENCRYPT_WPA2_MIXED;
				apmib_set( MIB_WLAN_ENCRYPT, (void *)&encrypt);
				wpa_cipher = WPA_CIPHER_MIXED;
				apmib_set( MIB_WLAN_WPA_CIPHER_SUITE, (void *)&wpa_cipher);
				wpa2_cipher = WPA_CIPHER_MIXED;
				apmib_set( MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&wpa2_cipher);
				wpa_auth = WPA_AUTH_PSK;
				apmib_set( MIB_WLAN_WPA_AUTH, (void *)&wpa_auth);
				call_wps_update();
				page_modified = 1;	
				wireless_modified = 1;
			}
		}

		if(!strcmp(current_url, "/qis/QIS_internet_ip.htm"))
		{
			page_modified = 1;
			char op_mode_t[5], wan_proto_t[5], wan_hostname[32], wan_hwaddr_t[32], wan_dnsenable_t[5], wan_dns1_t[32], wan_dns2_t[32], wan_ipaddr_t[32], wan_netmask_t[32], wan_gateway_t[32], wan_pppoe_username[32], wan_pppoe_passwd[32], vpn_server_ip_t[32];
			char x_DHCPClient_t[5];
			DHCP_T wan_proto = DHCP_CLIENT;
			OPMODE_T op_mode;
			//Get parameters
			sprintf(op_mode_t, "%s", websGetVar(wp, "sw_mode", ""));
			sprintf(wan_proto_t, "%s", websGetVar(wp, "wan_proto", ""));
			sprintf(wan_hostname, "%s", websGetVar(wp, "wan_hostname", ""));
			sprintf(wan_hwaddr_t, "%s", websGetVar(wp, "wan_hwaddr_x", ""));
			sprintf(wan_dnsenable_t, "%s", websGetVar(wp, "wan_dnsenable_x", ""));
			sprintf(wan_dns1_t, "%s", websGetVar(wp, "wan_dns1_x", ""));
			sprintf(wan_dns2_t, "%s", websGetVar(wp, "wan_dns2_x", ""));
			sprintf(wan_ipaddr_t, "%s", websGetVar(wp, "wan_ipaddr", ""));
			sprintf(wan_netmask_t, "%s", websGetVar(wp, "wan_netmask", ""));
			sprintf(wan_gateway_t, "%s", websGetVar(wp, "wan_gateway", ""));
			sprintf(vpn_server_ip_t, "%s", websGetVar(wp, "wan_heartbeat_x", ""));
			sprintf(wan_pppoe_username, "%s", websGetVar(wp, "wan_pppoe_username", ""));
			sprintf(wan_pppoe_passwd, "%s", websGetVar(wp, "wan_pppoe_passwd", ""));
			sprintf(x_DHCPClient_t, "%s", websGetVar(wp, "x_DHCPClient", ""));

			//Set op mode
			op_mode = atoi(op_mode_t);
			apmib_set(MIB_OP_MODE, (void *)&op_mode);

			//typedef enum { DHCP_DISABLED=0, DHCP_CLIENT=1, DHCP_SERVER=2, PPPOE=3, PPTP=4, L2TP=6, DHCP_AUTO=15 , USB3G=16 } DHCP_T;
			if(!strcmp(wan_proto_t, "dhcp")) {
				//Set wan proto
				wan_proto = DHCP_CLIENT;
				apmib_set(MIB_WAN_DHCP, (void *)&wan_proto);
				if(strlen(wan_hostname) > 0)	//Set host name
					apmib_set(MIB_HOST_NAME, (void *)&wan_hostname);
				if(strlen(wan_hwaddr_t) > 0) {	//Set wan mac addr
					char wan_hwaddr[32];
					string_to_hex(wan_hwaddr_t, wan_hwaddr, 12);
					apmib_set(MIB_WAN_MAC_ADDR, (void *)&wan_hwaddr);
				}
				if(strlen(wan_dnsenable_t) > 0) {	//Set dns setting
					int wan_dnsenable = atoi(wan_dnsenable_t);
					DNS_TYPE_T dns_mode;
					if(wan_dnsenable == 1)
						dns_mode = DNS_AUTO;
					else {
						dns_mode = DNS_MANUAL;
						if(strlen(wan_dns1_t) > 0) {	//Set wan dns1
							struct in_addr wan_dns1;
							inet_aton(wan_dns1_t, &wan_dns1);						
							apmib_set(MIB_DNS1, (void *)&wan_dns1);
						}
						if(strlen(wan_dns2_t) > 0) {	//Set wan dns2
							struct in_addr wan_dns2;
							inet_aton(wan_dns2_t, &wan_dns2);						
							apmib_set(MIB_DNS2, (void *)&wan_dns2);
						}
					}
					apmib_set(MIB_DNS_MODE, (void *)&dns_mode);
				}
			}

			if(!strcmp(wan_proto_t, "static")) {
				//Set wan proto
				wan_proto = DHCP_DISABLED;
				apmib_set(MIB_WAN_DHCP, (void *)&wan_proto);
				struct in_addr wan_ipaddr, wan_netmask, wan_gateway;

				//Set wan IP
				inet_aton(wan_ipaddr_t, &wan_ipaddr);						
				apmib_set(MIB_WAN_IP_ADDR, (void *)&wan_ipaddr);

				//Set wan netmask
				inet_aton(wan_netmask_t, &wan_netmask);						
				apmib_set(MIB_WAN_SUBNET_MASK, (void *)&wan_netmask);

				//Set wan gateway
				inet_aton(wan_gateway_t, &wan_gateway);						
				apmib_set(MIB_WAN_DEFAULT_GATEWAY, (void *)&wan_gateway);

				if(strlen(wan_dnsenable_t) > 0) {	//Set dns setting
					int wan_dnsenable = atoi(wan_dnsenable_t);
					DNS_TYPE_T dns_mode;
					if(wan_dnsenable == 1)
						dns_mode = DNS_AUTO;
					else {
						dns_mode = DNS_MANUAL;
						if(strlen(wan_dns1_t) > 0) {	//Set wan dns1
							struct in_addr wan_dns1;
							inet_aton(wan_dns1_t, &wan_dns1);						
							apmib_set(MIB_DNS1, (void *)&wan_dns1);
						}
						if(strlen(wan_dns2_t) > 0) {	//Set wan dns2
							struct in_addr wan_dns2;
							inet_aton(wan_dns2_t, &wan_dns2);						
							apmib_set(MIB_DNS2, (void *)&wan_dns2);
						}
					}
					apmib_set(MIB_DNS_MODE, (void *)&dns_mode);
				}
			}

			if(!strcmp(wan_proto_t, "pptp")) {
				//Set wan proto
				int dhcp_client = atoi(x_DHCPClient_t);
				wan_proto = PPTP;
				apmib_set(MIB_WAN_DHCP, (void *)&wan_proto);
				struct in_addr wan_ipaddr, wan_netmask, wan_gateway, vpn_server_ip;

				//Set user name
				apmib_set(MIB_PPTP_USER_NAME, (void *)&wan_pppoe_username);

				//Set password
				apmib_set(MIB_PPTP_PASSWORD, (void *)&wan_pppoe_passwd);

				if(dhcp_client == 1)	//Dynamic IP
				{
					dhcp_client = 0;
					apmib_set(MIB_PPTP_WAN_IP_DYNAMIC, (void *)&dhcp_client);
				}
				else	//Static IP
				{
					dhcp_client = 1;
					apmib_set(MIB_PPTP_WAN_IP_DYNAMIC, (void *)&dhcp_client);

					//Set pptp IP
					inet_aton(wan_ipaddr_t, &wan_ipaddr);						
					apmib_set(MIB_PPTP_IP_ADDR, (void *)&wan_ipaddr);

					//Set pptp netmask
					inet_aton(wan_netmask_t, &wan_netmask);						
					apmib_set(MIB_PPTP_SUBNET_MASK, (void *)&wan_netmask);

					//Set wan gateway
					inet_aton(wan_gateway_t, &wan_gateway);						
					apmib_set(MIB_PPTP_DEFAULT_GW, (void *)&wan_gateway);
				}

				//Set vpn server ip
				inet_aton(vpn_server_ip_t, &vpn_server_ip);
				apmib_set(MIB_PPTP_SERVER_IP_ADDR, (void *)&vpn_server_ip);

				if(strlen(wan_dnsenable_t) > 0) {	//Set dns setting
					int wan_dnsenable = atoi(wan_dnsenable_t);
					DNS_TYPE_T dns_mode;
					if(wan_dnsenable == 1)
						dns_mode = DNS_AUTO;
					else {
						dns_mode = DNS_MANUAL;
						if(strlen(wan_dns1_t) > 0) {	//Set wan dns1
							struct in_addr wan_dns1;
							inet_aton(wan_dns1_t, &wan_dns1);						
							apmib_set(MIB_DNS1, (void *)&wan_dns1);
						}
						if(strlen(wan_dns2_t) > 0) {	//Set wan dns2
							struct in_addr wan_dns2;
							inet_aton(wan_dns2_t, &wan_dns2);						
							apmib_set(MIB_DNS2, (void *)&wan_dns2);
						}
					}
					apmib_set(MIB_DNS_MODE, (void *)&dns_mode);
				}
			}

			if(!strcmp(wan_proto_t, "l2tp")) {
				//Set wan proto
				int dhcp_client = atoi(x_DHCPClient_t);
				wan_proto = L2TP;
				apmib_set(MIB_WAN_DHCP, (void *)&wan_proto);
				struct in_addr wan_ipaddr, wan_netmask, wan_gateway, vpn_server_ip;

				//Set l2tp user name
				apmib_set(MIB_L2TP_USER_NAME, (void *)&wan_pppoe_username);

				//Set l2tp password
				apmib_set(MIB_L2TP_PASSWORD, (void *)&wan_pppoe_passwd);

				if(dhcp_client == 1)	//Dynamic IP
				{
					dhcp_client = 0;
					apmib_set(MIB_L2TP_WAN_IP_DYNAMIC, (void *)&dhcp_client);
				}
				else	//Static IP
				{
					dhcp_client = 1;
					apmib_set(MIB_L2TP_WAN_IP_DYNAMIC, (void *)&dhcp_client);

					//Set l2tp IP
					inet_aton(wan_ipaddr_t, &wan_ipaddr);						
					apmib_set(MIB_L2TP_IP_ADDR, (void *)&wan_ipaddr);

					//Set l2tp netmask
					inet_aton(wan_netmask_t, &wan_netmask);						
					apmib_set(MIB_L2TP_SUBNET_MASK, (void *)&wan_netmask);

					//Set wan gateway
					inet_aton(wan_gateway_t, &wan_gateway);						
					apmib_set(MIB_L2TP_DEFAULT_GW, (void *)&wan_gateway);
				}

				//Set vpn server ip
				inet_aton(vpn_server_ip_t, &vpn_server_ip);
				apmib_set(MIB_L2TP_SERVER_IP_ADDR, (void *)&vpn_server_ip);

				if(strlen(wan_dnsenable_t) > 0) {	//Set dns setting
					int wan_dnsenable = atoi(wan_dnsenable_t);
					DNS_TYPE_T dns_mode;
					if(wan_dnsenable == 1)
						dns_mode = DNS_AUTO;
					else {
						dns_mode = DNS_MANUAL;
						if(strlen(wan_dns1_t) > 0) {	//Set wan dns1
							struct in_addr wan_dns1;
							inet_aton(wan_dns1_t, &wan_dns1);					
							apmib_set(MIB_DNS1, (void *)&wan_dns1);
						}
						if(strlen(wan_dns2_t) > 0) {	//Set wan dns2
							struct in_addr wan_dns2;
							inet_aton(wan_dns2_t, &wan_dns2);						
							apmib_set(MIB_DNS2, (void *)&wan_dns2);
						}
					}
					apmib_set(MIB_DNS_MODE, (void *)&dns_mode);
				}
			}
		}

		if(!strcmp(current_url, "/qis/QIS_internet_account.htm"))
		{
			page_modified = 1;
			//char op_mode_t[5], wan_proto_t[5], wan_pppoe_username[32], wan_pppoe_passwd[32];
			//DHCP_T wan_proto = DHCP_CLIENT;
			//OPMODE_T op_mode;
char op_mode_t[5], wan_proto_t[5], wan_hostname[32], wan_hwaddr_t[32], wan_dnsenable_t[5], wan_dns1_t[32], wan_dns2_t[32], wan_ipaddr_t[32], wan_netmask_t[32], wan_gateway_t[32], wan_pppoe_username[32], wan_pppoe_passwd[32], vpn_server_ip_t[32];
			char x_DHCPClient_t[5];
			DHCP_T wan_proto = DHCP_CLIENT;
			OPMODE_T op_mode;
			//Get parameters
			sprintf(op_mode_t, "%s", websGetVar(wp, "sw_mode", ""));
			sprintf(wan_proto_t, "%s", websGetVar(wp, "wan_proto", ""));
			sprintf(wan_hostname, "%s", websGetVar(wp, "wan_hostname", ""));
			sprintf(wan_hwaddr_t, "%s", websGetVar(wp, "wan_hwaddr_x", ""));
			sprintf(wan_dnsenable_t, "%s", websGetVar(wp, "wan_dnsenable_x", ""));
			sprintf(wan_dns1_t, "%s", websGetVar(wp, "wan_dns1_x", ""));
			sprintf(wan_dns2_t, "%s", websGetVar(wp, "wan_dns2_x", ""));
			sprintf(wan_ipaddr_t, "%s", websGetVar(wp, "wan_ipaddr", ""));
			sprintf(wan_netmask_t, "%s", websGetVar(wp, "wan_netmask", ""));
			sprintf(wan_gateway_t, "%s", websGetVar(wp, "wan_gateway", ""));
			sprintf(vpn_server_ip_t, "%s", websGetVar(wp, "wan_heartbeat_x", ""));
			sprintf(wan_pppoe_username, "%s", websGetVar(wp, "wan_pppoe_username", ""));
			sprintf(wan_pppoe_passwd, "%s", websGetVar(wp, "wan_pppoe_passwd", ""));
			sprintf(x_DHCPClient_t, "%s", websGetVar(wp, "x_DHCPClient", ""));
			
			//Set op mode
			op_mode = atoi(op_mode_t);
			apmib_set(MIB_OP_MODE, (void *)&op_mode);

			if(!strcmp(wan_proto_t, "pppoe")) {
				//Set wan proto
				wan_proto = PPPOE;
				apmib_set(MIB_WAN_DHCP, (void *)&wan_proto);

				//Set user name
				apmib_set(MIB_PPP_USER_NAME, (void *)&wan_pppoe_username);

				//Set password
				apmib_set(MIB_PPP_PASSWORD, (void *)&wan_pppoe_passwd);
			}

			if(!strcmp(wan_proto_t, "pptp")) {
				//Set wan proto
				int dhcp_client = atoi(x_DHCPClient_t);
				wan_proto = PPTP;
				apmib_set(MIB_WAN_DHCP, (void *)&wan_proto);
				struct in_addr wan_ipaddr, wan_netmask, wan_gateway, vpn_server_ip;

				//Set user name
				apmib_set(MIB_PPTP_USER_NAME, (void *)&wan_pppoe_username);

				//Set password
				apmib_set(MIB_PPTP_PASSWORD, (void *)&wan_pppoe_passwd);

				if(dhcp_client == 1)	//Dynamic IP
				{
					dhcp_client = 0;
					apmib_set(MIB_PPTP_WAN_IP_DYNAMIC, (void *)&dhcp_client);
				}
				else	//Static IP
				{
					dhcp_client = 1;
					apmib_set(MIB_PPTP_WAN_IP_DYNAMIC, (void *)&dhcp_client);

					//Set pptp IP
					inet_aton(wan_ipaddr_t, &wan_ipaddr);						
					apmib_set(MIB_PPTP_IP_ADDR, (void *)&wan_ipaddr);

					//Set pptp netmask
					inet_aton(wan_netmask_t, &wan_netmask);						
					apmib_set(MIB_PPTP_SUBNET_MASK, (void *)&wan_netmask);

					//Set wan gateway
					inet_aton(wan_gateway_t, &wan_gateway);						
					apmib_set(MIB_PPTP_DEFAULT_GW, (void *)&wan_gateway);
				}

				//Set vpn server ip
				inet_aton(vpn_server_ip_t, &vpn_server_ip);
				apmib_set(MIB_PPTP_SERVER_IP_ADDR, (void *)&vpn_server_ip);

				if(strlen(wan_dnsenable_t) > 0) {	//Set dns setting
					int wan_dnsenable = atoi(wan_dnsenable_t);
					DNS_TYPE_T dns_mode;
					if(wan_dnsenable == 1)
						dns_mode = DNS_AUTO;
					else {
						dns_mode = DNS_MANUAL;
						if(strlen(wan_dns1_t) > 0) {	//Set wan dns1
							struct in_addr wan_dns1;
							inet_aton(wan_dns1_t, &wan_dns1);						
							apmib_set(MIB_DNS1, (void *)&wan_dns1);
						}
						if(strlen(wan_dns2_t) > 0) {	//Set wan dns2
							struct in_addr wan_dns2;
							inet_aton(wan_dns2_t, &wan_dns2);						
							apmib_set(MIB_DNS2, (void *)&wan_dns2);
						}
					}
					apmib_set(MIB_DNS_MODE, (void *)&dns_mode);
				}
			}

			if(!strcmp(wan_proto_t, "l2tp")) {
				//Set wan proto
				int dhcp_client = atoi(x_DHCPClient_t);
				wan_proto = L2TP;
				apmib_set(MIB_WAN_DHCP, (void *)&wan_proto);
				struct in_addr wan_ipaddr, wan_netmask, wan_gateway, vpn_server_ip;

				//Set l2tp user name
				apmib_set(MIB_L2TP_USER_NAME, (void *)&wan_pppoe_username);

				//Set l2tp password
				apmib_set(MIB_L2TP_PASSWORD, (void *)&wan_pppoe_passwd);

				if(dhcp_client == 1)	//Dynamic IP
				{
					dhcp_client = 0;
					apmib_set(MIB_L2TP_WAN_IP_DYNAMIC, (void *)&dhcp_client);
				}
				else	//Static IP
				{
					dhcp_client = 1;
					apmib_set(MIB_L2TP_WAN_IP_DYNAMIC, (void *)&dhcp_client);

					//Set l2tp IP
					inet_aton(wan_ipaddr_t, &wan_ipaddr);						
					apmib_set(MIB_L2TP_IP_ADDR, (void *)&wan_ipaddr);

					//Set l2tp netmask
					inet_aton(wan_netmask_t, &wan_netmask);						
					apmib_set(MIB_L2TP_SUBNET_MASK, (void *)&wan_netmask);

					//Set wan gateway
					inet_aton(wan_gateway_t, &wan_gateway);						
					apmib_set(MIB_L2TP_DEFAULT_GW, (void *)&wan_gateway);
				}

				//Set vpn server ip
				inet_aton(vpn_server_ip_t, &vpn_server_ip);
				apmib_set(MIB_L2TP_SERVER_IP_ADDR, (void *)&vpn_server_ip);

				if(strlen(wan_dnsenable_t) > 0) {	//Set dns setting
					int wan_dnsenable = atoi(wan_dnsenable_t);
					DNS_TYPE_T dns_mode;
					if(wan_dnsenable == 1)
						dns_mode = DNS_AUTO;
					else {
						dns_mode = DNS_MANUAL;
						if(strlen(wan_dns1_t) > 0) {	//Set wan dns1
							struct in_addr wan_dns1;
							inet_aton(wan_dns1_t, &wan_dns1);					
							apmib_set(MIB_DNS1, (void *)&wan_dns1);
						}
						if(strlen(wan_dns2_t) > 0) {	//Set wan dns2
							struct in_addr wan_dns2;
							inet_aton(wan_dns2_t, &wan_dns2);						
							apmib_set(MIB_DNS2, (void *)&wan_dns2);
						}
					}
					apmib_set(MIB_DNS_MODE, (void *)&dns_mode);
				}
			}
		}

		//2011.05.27 Jerry {
		if(!strcmp(current_url, "/QIS_wizard.htm"))	//for /qis/QIS_detect.htm
		{
			page_modified = 1;
			char wan_proto_t[5];
			DHCP_T wan_proto = DHCP_CLIENT;

			//Get parameters
			sprintf(wan_proto_t, "%s", websGetVar(wp, "wan_proto", ""));
			if(!strcmp(wan_proto_t, "static"))
				wan_proto = DHCP_DISABLED;			
			else if(!strcmp(wan_proto_t, "dhcp"))
				wan_proto = DHCP_CLIENT;
			else if(!strcmp(wan_proto_t, "pppoe"))
				wan_proto = PPPOE;
			else if(!strcmp(wan_proto_t, "pptp"))
				wan_proto = PPTP;
			else if(!strcmp(wan_proto_t, "l2tp"))
				wan_proto = L2TP;
			apmib_set(MIB_WAN_DHCP, (void *)&wan_proto);			
		}		
		//2011.05.27 Jerry }
 
		
		if(page_modified) 
		{
			if(op_mode_modified){
				restart_needed_bits = RESTART_REBOOT;
				restart_tatal_time = ITVL_RESTART_REBOOT;			
			}
			else if(wireless_modified){
				restart_tatal_time = ITVL_RESTART_WLAN;
				restart_needed_bits = RESTART_WLAN;
			}
			else
			{
				//restart_needed_bits = RESTART_REBOOT;
				//restart_tatal_time = ITVL_RESTART_REBOOT;
				//restart_tatal_time = ITVL_RESTART_ALL;
				//restart_needed_bits = RESTART_ALL;
				
				int wan_proto = -1;
				apmib_get(MIB_WAN_DHCP, (void *)&wan_proto);
				restart_needed_bits = RESTART_WAN;
				if(wan_proto == PPTP || wan_proto == L2TP)
					restart_tatal_time = ITVL_RESTART_WAN + 20;	//Add 20 sec to wait connection for PPTP and L2TP
				else
					restart_tatal_time = ITVL_RESTART_WAN;		
			}
			websWrite(wp, "<script>done_committing();</script>\n");
			csprintf("*** restart_time needs %d seconds.\n", restart_tatal_time);
			//printf("needed time(3) = %d\n", restart_tatal_time);	// tmp test
			websWrite(wp, "<script>restart_needed_time(%d);</script>\n", restart_tatal_time);
		}
	}
	else
	{
		websWrite(wp, "<script>no_changes_and_no_committing();</script>\n");
	}

	if(page_modified) {
		apmib_set(MIB_X_SETTING, (void *)&x_setting);
		apmib_set(MIB_W_SETTING, (void *)&w_setting);	//2011.04.12 Jerry
		apmib_update(CURRENT_SETTING);	//2011.04.12 Jerry

		wanduckproc = find_pid_by_name("wanduck");
		if(wanduckproc > 0)
			kill(wanduckproc, SIGUSR1);
	}

	return 0;
}

static int ej_notify_services(int eid, webs_t wp, int argc, char_t **argv){
	restart_tatal_time = 0;
	int no_run_str = 0;
	if (restart_needed_bits != 0){
		no_run_str = 1;
		if ((restart_needed_bits & RESTART_REBOOT) != 0){
			printf("*** restart_reboot! \n");
			notify_sysconf("restart_reboot", 0);
		}
		else if ((restart_needed_bits & RESTART_ALL) != 0){
			csprintf("*** restart_all! \n");
			notify_sysconf("restart_all", 0);
		}
		else{
			if ((restart_needed_bits & RESTART_QOS) != 0){
				csprintf("*** restart_qos! \n");
				restart_needed_bits &= ~(u32)RESTART_QOS;
				char *reinit_command[] = {"sysconf", "setQos", NULL};
				_eval(reinit_command, NULL, 0, NULL);
			}
			if ((restart_needed_bits & RESTART_SYSLOG) != 0){
				csprintf("*** restart_syslog! \n");
				notify_sysconf("restart_syslog", 0);
				restart_needed_bits &= ~(u32)RESTART_SYSLOG;
			}
			if ((restart_needed_bits & RESTART_FIREWALL) != 0){
				csprintf("*** restart_firewall! \n");
				notify_sysconf("restart_firewall", 0);
				restart_needed_bits &= ~(u32)RESTART_FIREWALL;
			}
			if ((restart_needed_bits & RESTART_NTPC) != 0){
				csprintf("*** restart_NTPC! \n");
				notify_sysconf("restart_ntp", 0);
				restart_needed_bits &= ~(u32)RESTART_NTPC;
			}
			//2011.04.19 Jerry {
			if ((restart_needed_bits & RESTART_LAN) != 0){
				csprintf("*** restart_lan! \n");
				notify_sysconf("restart_lan", 0);
				restart_needed_bits &= ~(u32)RESTART_LAN;
			}
			if ((restart_needed_bits & RESTART_WAN) != 0){
				csprintf("*** restart_wan! \n");
				notify_sysconf("restart_wan", 0);
				restart_needed_bits &= ~(u32)RESTART_WAN;
			}
			if ((restart_needed_bits & RESTART_WLAN) != 0){
				csprintf("*** restart_wlan! \n");
				notify_sysconf("restart_wlan", 0);
				restart_needed_bits &= ~(u32)RESTART_WLAN;
			}
			if ((restart_needed_bits & RESTART_DHCPD) != 0){
				csprintf("*** restart_dhcpd! \n");
				notify_sysconf("restart_dhcpd", 0);
				restart_needed_bits &= ~(u32)RESTART_DHCPD;
			}
			//2011.04.19 Jerry }
			//2011.05.25 Jerry {
			if ((restart_needed_bits & RESTART_PPPOE) != 0){
				csprintf("*** restart_pppoe! \n");
				notify_sysconf("restart_pppoe", 0);
				restart_needed_bits &= ~(u32)RESTART_PPPOE;
			}
			if ((restart_needed_bits & RESTART_PPTP) != 0){
				csprintf("*** restart_pptp! \n");
				notify_sysconf("restart_pptp", 0);
				restart_needed_bits &= ~(u32)RESTART_PPTP;
			}
			if ((restart_needed_bits & RESTART_L2TP) != 0){
				csprintf("*** restart_l2tp! \n");
				notify_sysconf("restart_l2tp", 0);
				restart_needed_bits &= ~(u32)RESTART_L2TP;
			}
			//2011.05.25 Jerry }
		}
		
		restart_needed_bits = 0;
	}
	
	if (no_run_str == 0)
		printf("*** Don't run ej_notify_services!\n");
	
	return 0;
}

// for error_page.htm's detection
static int detect_if_wan(int eid, webs_t wp, int argc, char_t **argv){
	int if_wan = is_phyconnected();
	
	websWrite(wp, "%d", if_wan);
	
	return 0;
}

//2011.03.14 Jerry {
char *getDnsList()
{
    	FILE *f;
	static char dnsList[256];
    	char str[128];
	char *p;
	char *delim = " ";
	int i = 0;
	char *v1 = NULL;

	memset(dnsList, 0, 256);

    	f = fopen("/etc/resolv.conf", "r");
    	if (f == NULL) {
        	printf("fopen(/etc/resolv.conf) failed\n");
        	return "";
	}
	
	while (fgets(str, sizeof(str), f)) {
		if(strstr(str, "nameserver")) {
			strtok(str, delim);
			p = strtok(NULL, delim);
			if((v1 = strchr(p, '\n')) != 0)
				*v1 = '\0';
			if(i != 0)
				strcat(dnsList, " ");
			strcat(dnsList, p);
			i++;
		}
    	}
	printf("DNS List: %s\n", dnsList);
	fclose(f);
	return dnsList;
}
//2011.03.14 Jerry }


// Define of return value: 1st bit is NTP, 2nd bit is WAN DNS, 3rd bit is more open DNS.
static int detect_wan_connection(int eid, webs_t wp, int argc, char_t **argv){
	int MAX_LOOKUP_NUM = 1, lookup_num;
	//int got_ntp = 0, got_ping = 0;
	int result = 0;
	char target[16];
	FILE *fp;
	char buf[128], word[16], *next;
	char *ping_cmd[] = {"ping", word, "-c", "1", NULL};
	char *dns_list = NULL;
	int i;
	char *MORE_DNS = "8.8.8.8 208.67.220.220 208.67.222.222";
	
	memset(buf, 0, 128);
	
	for(lookup_num = 0; lookup_num < MAX_LOOKUP_NUM; ++lookup_num){
			result += 1;
		dns_list = getDnsList();	//2011.03.14 Jerry

		foreach(word, dns_list, next){
			dbg("Try to ping dns: %s...\n", word);
			_eval(ping_cmd, ">/tmp/log.txt", 0, NULL);
			
			if((fp = fopen("/tmp/log.txt", "r")) == NULL)
				continue;
			
			for(i = 0; i < 3 && fgets(buf, 128, fp) != NULL; ++i){	//2011.03.14 Jerry
				dbg("%d. Got the results: %s.\n", i+1, buf);
				if(strstr(buf, "alive") || strstr(buf, " ms"))
					result += 2;
				
				if(result >= 2)
					break;
			}
			fclose(fp);
			
			if(result >= 2)
				break;
		}

		dbg("Try to ping more dns: %s...\n", MORE_DNS);
		int dns_test = 0;
		foreach(word, MORE_DNS, next){
			dbg("Try to ping dns: %s...\n", word);			
			doSystem("/bin/tcpcheck 4 %s:53 >/tmp/log.txt", word);	//2011.03.14 Jerry
			
			if((fp = fopen("/tmp/log.txt", "r")) == NULL)
				continue;
			
			for(i = 0; i < 2 && fgets(buf, 128, fp) != NULL; ++i){
				dbg("%d. Got the results: %s.\n", i+1, buf);
				if(strstr(buf, "alive") || strstr(buf, " ms"))
					result += 4;
				
				if(result >= 4)
					break;
			}
			fclose(fp);
			
			if(result >= 4)
				break;
		}
		
		if(result > 0){
			websWrite(wp, "%d", result);
			break;
		}
		else if(lookup_num == MAX_LOOKUP_NUM-1){
			dbg("Can't get the host from ntp or response from DNS!\n");
			websWrite(wp, "0");
			break;
		}
	}
	
	return 0;
}

void logmessage(char *logheader, char *fmt, ...)
{
  va_list args;
  char buf[512];

  va_start(args, fmt);

  vsnprintf(buf, sizeof(buf), fmt, args);
  openlog(logheader, 0, 0);
  syslog(0, buf);
  closelog();
  va_end(args);
}

static int detect_dhcp_pppoe(int eid, webs_t wp, int argc, char_t **argv){
	int ret;
	OPMODE_T op_mode;	//2011.03.16 Jerry

	eprintf("detect dhcp pppoe\n");	// tmp test

	//2011.03.16 Jerry {
	apmib_get(MIB_OP_MODE, (void *)&op_mode);
	if(op_mode == GATEWAY_MODE)
		;
	else if (op_mode == BRIDGE_MODE) {
		websWrite(wp, "AP mode");
		return 0;
	}
	//2011.03.16 Jerry }

	eprintf("discover all\n");			// tmp test
	ret = discover_all();

	eprintf("get result: %d\n", ret);
	if (ret == 0)
		websWrite(wp, "no-respond");
	else if (ret == 1)
		websWrite(wp, "dhcp");
	else if (ret == 2)
		websWrite(wp, "pppoe");
	else  // -1
		websWrite(wp, "error");
	return 0;
}

static int get_wan_status_log(int eid, webs_t wp, int argc, char_t **argv){
	FILE *fp = fopen("/tmp/wanstatus.log", "r");
	char log_info[64];
	int i;
	
	memset(log_info, 0, 64);
	
	if (fp != NULL){
		fgets(log_info, 64, fp);
		
		i = 0;
		while (log_info[i] != 0){
			if (log_info[i] == '\n'){
				log_info[i] = 0;
				break;
			}
			
			++i;
		}
		
		websWrite(wp, "%s", log_info);
		fclose(fp);
	}
	
	return 0;
}

int file_to_buf(char *path, char *buf, int len){
	FILE *fp;
	memset(buf, 0 , len);
	
	if ((fp = fopen(path, "r")) != NULL){
		fgets(buf, len, fp);
		fclose(fp);
		
		return 1;
	}
	
	return 0;
}

int get_ppp_pid(char *conntype){
	int pid = -1;
	char tmp[80], tmp1[80];
	
	snprintf(tmp, sizeof(tmp), "/var/run/%s.pid", conntype);
	file_to_buf(tmp, tmp1, sizeof(tmp1));
	pid = atoi(tmp1);
	
	return pid;
}

/* Find process name by pid from /proc directory */
char *find_name_by_proc(int pid){
	FILE *fp;
	char line[254];
	char filename[80];
	static char name[80];
	
	snprintf(filename, sizeof(filename), "/proc/%d/status", pid);
	
	if ((fp = fopen(filename, "r")) != NULL){
		fgets(line, sizeof(line), fp);
		/* Buffer should contain a string like "Name:   binary_name" */
		sscanf(line, "%*s %s", name);
		fclose(fp);
		return name;
	}
	
	return "";
}

int check_ppp_exist(){
	DIR *dir;
	struct dirent *dent;
	char task_file[64], cmdline[64];
	int pid, fd;
	
	if((dir = opendir("/proc")) == NULL){
		perror("open proc");
		return -1;
	}
	
	while((dent = readdir(dir)) != NULL){
		if((pid = atoi(dent->d_name)) > 1){
			memset(task_file, 0, 64);
			sprintf(task_file, "/proc/%d/cmdline", pid);
			if((fd = open(task_file, O_RDONLY)) > 0){
				memset(cmdline, 0, 64);
				read(fd, cmdline, 64);
				close(fd);
				
				if(strstr(cmdline, "pppoecd")
						|| strstr(cmdline, "pppd")
						){
					closedir(dir);
					return 0;
				}
			}
			else
				printf("cannot open %s\n", task_file);
		}
	}
	closedir(dir);
	
	return -1;
}

//2011.03.14 Jerry {
#define _PATH_PROCNET_ROUTE	"/proc/net/route"
#define RTF_UP			0x0001          /* route usable                 */
#define RTF_GATEWAY		0x0002          /* destination is a gateway     */
int getDefaultGW(char *interface, struct in_addr *route)
{
	char buff[1024], iface[16];
	char gate_addr[128], net_addr[128], mask_addr[128];
	int num, iflags, metric, refcnt, use, mss, window, irtt;
	FILE *fp = fopen(_PATH_PROCNET_ROUTE, "r");
	char *fmt;
	int found=0;
	unsigned long addr;

	if (!fp) {
       		printf("Open %s file error.\n", _PATH_PROCNET_ROUTE);
		return 0;
    	}

	fmt = "%16s %128s %128s %X %d %d %d %128s %d %d %d";

	while (fgets(buff, 1023, fp)) {
		num = sscanf(buff, fmt, iface, net_addr, gate_addr,
		     		&iflags, &refcnt, &use, &metric, mask_addr, &mss, &window, &irtt);
		if (num < 10 || !(iflags & RTF_UP) || !(iflags & RTF_GATEWAY) || strcmp(iface, interface))
	    		continue;
		sscanf(gate_addr, "%lx", &addr );
		*route = *((struct in_addr *)&addr);

		found = 1;
		break;
	}

    	fclose(fp);
    	return found;
}

typedef enum { IP_ADDR, SUBNET_MASK, DEFAULT_GATEWAY, HW_ADDR } ADDR_T;
int getWanInformation(char *pWanIP, char *pWanMask, char *pWanDefIP, char *pWanHWAddr)
{
	DHCP_T dhcp;
	OPMODE_T opmode=-1;
	char *iface=NULL;
	struct in_addr	intaddr;
	struct sockaddr hwaddr;
	unsigned char *pMacAddr;
	
	if ( !apmib_get( MIB_WAN_DHCP, (void *)&dhcp) )
		return -1;
  
  	if ( !apmib_get( MIB_OP_MODE, (void *)&opmode) )
		return -1;

	DHCP_T wan_proto;
	apmib_get(MIB_WAN_DHCP, (void *)&wan_proto);
	if(wan_proto == DHCP_CLIENT || wan_proto == DHCP_DISABLED)
		iface = "eth1";
	else
		iface = "ppp0";

	if ( iface && getInAddr(iface, IP_ADDR, (void *)&intaddr ) )
		sprintf(pWanIP,"%s",inet_ntoa(intaddr));
	else
		sprintf(pWanIP,"%s","0.0.0.0");
		
	if ( iface && getInAddr(iface, SUBNET_MASK, (void *)&intaddr ) )
		sprintf(pWanMask,"%s",inet_ntoa(intaddr));
	else
		sprintf(pWanMask,"%s","0.0.0.0");
		
	if ( iface && getDefaultGW(iface, &intaddr) )
		sprintf(pWanDefIP,"%s",inet_ntoa(intaddr));
	else
		sprintf(pWanDefIP,"%s","0.0.0.0");

}
//2011.03.14 Jerry }

static int wanlink_hook(int eid, webs_t wp, int argc, char_t **argv){
	FILE *fp;
	char type[32], ip[32], netmask[32], gateway[32], dns[128], statusstr[32];
	int status = 0, unit, s;
	char tmp[100], prefix[] = "wanXXXXXXXXXX_";
	char filename[80], conntype[10];
	struct ifreq ifr;
	struct sockaddr_in *our_ip;
	struct in_addr in;
	char *pwanip = NULL, *ppp_addr, *usb_device;
	
	/* current unit */
		unit = 0;

	//2011.03.16 Jerry {
	DHCP_T dhcp;
	DNS_TYPE_T dns_type;
	apmib_get( MIB_WAN_DHCP, (void *)&dhcp);
	//2011.03.16 Jerry }


	if (!is_phyconnected()){
		status = 0;
		strcpy(statusstr, "Cable is not attached");
	}
	else if (dhcp == PPPOE || dhcp == PPTP || dhcp == L2TP)	//2011.03.16 Jerry 
	{
		DIR *ppp_dir;
		int got_ppp_link;
		struct dirent *entry;

		if((ppp_dir = opendir("/etc/ppp")) == NULL){	//2011.03.16 Jerry
			status = 0;
			strcpy(statusstr, "Disconnected");
		}
		else{
			got_ppp_link = 0;
			while((entry = readdir(ppp_dir)) != NULL){
				if(!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
					continue;
				
				if(strstr(entry->d_name, "link") != NULL){
					got_ppp_link = 1;
					
					break;
				}
			}
			closedir(ppp_dir);
			
			if(got_ppp_link == 0){
				status = 0;
				strcpy(statusstr, "Disconnected");
			}
			else if(check_ppp_exist() == -1){
				status = 0;
				strcpy(statusstr, "Disconnected");
			}
			else{
				status = 1;
				strcpy(statusstr, "Connected");
			}
		}
	}
	else {
		/* Open socket to kernel */
		if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0){
			status = 0;
			strcpy(statusstr, "Disconnected");
			//printf("[status str] chk disconn 3\n");	// tmp test
		}
		else{
			/* Check for valid IP address */
			strncpy(ifr.ifr_name, "eth1", IFNAMSIZ);	//2011.03.16 Jerry
			
			if (!ioctl(s, SIOCGIFADDR, &ifr)){
				our_ip = (struct sockaddr_in *) &ifr.ifr_addr;
				in.s_addr = our_ip->sin_addr.s_addr;
				pwanip = inet_ntoa(in);
				
				if (!strcmp(pwanip, "") || pwanip == NULL){
					status = 0;
					strcpy(statusstr, "Disconnected");
				}

				else{
					status = 1;
					strcpy(statusstr, "Connected");
				}
			}
			else{
				status = 0;
				strcpy(statusstr, "Disconnected");
			}
			
			close(s);
		}
	}
	//2011.03.16 Jerry {
	if(dhcp == PPPOE)
		strcpy(type, "PPPOE");
	else if(dhcp == PPTP)
		strcpy(type, "PPTP");
	else if(dhcp == PPPOE)
		strcpy(type, "L2TP");
	else if(dhcp == DHCP_DISABLED)
		strcpy(type, "Static IP");
	else
		strcpy(type, "Automatic IP");
	//2011.03.16 Jerry }	

	memset(ip, 0, sizeof(ip));
	memset(netmask, 0, sizeof(netmask));
	memset(gateway, 0, sizeof(gateway));
	if (status == 0)
	{
		strcpy(ip, "0.0.0.0");
		strcpy(gateway, "0.0.0.0");	
	}
	else
	{
		//2011.03.14 Jerry {
		char wan_ipaddr[16];
		char wan_netmask[16];
		char wan_gateway[16];
		char wan_hwaddr[18];
		//char wan_subnet[11];
		getWanInformation(wan_ipaddr, wan_netmask, wan_gateway, wan_hwaddr);
		//2011.03.14 Jerry }

		strcpy(ip, wan_ipaddr);
		strcpy(netmask, wan_netmask);
		strcpy(gateway, wan_gateway);
	}
	//2011.03.15 Jerry {
	memset(dns, 0, 128);
	apmib_get(MIB_DNS_MODE, (void *)&dns_type);
	if(dns_type == DNS_MANUAL)
	{
		unsigned char dns1[64], dns2[64];
		apmib_get(MIB_DNS1, (void *)dns1);
		apmib_get(MIB_DNS2, (void *)dns2);
		if( memcmp(dns1, "\x0\x0\x0\x0", 4) && memcmp(dns2, "\x0\x0\x0\x0", 4) )
			sprintf(dns, "%s %s", inet_ntoa(*((struct in_addr *)dns1)), inet_ntoa(*((struct in_addr *)dns2)));
		else if ( memcmp(dns1, "\x0\x0\x0\x0", 4) && !memcmp(dns2, "\x0\x0\x0\x0", 4) )
			sprintf(dns, "%s", inet_ntoa(*((struct in_addr *)dns1)));
		else if (!memcmp(dns1, "\x0\x0\x0\x0", 4) && memcmp(dns2, "\x0\x0\x0\x0", 4) )
			sprintf(dns, "%s", inet_ntoa(*((struct in_addr *)dns2)));
	}
	else
	{
		char *dns_list = NULL;
		int wan_ready;
		dns_list = getDnsList();	//2011.03.14 Jerry
		apmib_get(MIB_WAN_READY, (void *)&wan_ready);
		if(wan_ready == 1 && strlen(dns_list))
			sprintf(dns, "%s", dns_list);
	}
	//2011.03.15 Jerry }
	
	websWrite(wp, "function wanlink_status() { return %d;}\n", status);
	websWrite(wp, "function wanlink_statusstr() { return '%s';}\n", statusstr);
	websWrite(wp, "function wanlink_type() { return '%s';}\n", type);
	websWrite(wp, "function wanlink_ipaddr() { return '%s';}\n", ip);
	websWrite(wp, "function wanlink_netmask() { return '%s';}\n", netmask);
	websWrite(wp, "function wanlink_gateway() { return '%s';}\n", gateway);
	websWrite(wp, "function wanlink_dns() { return '%s';}\n", dns);

	return 0;
}

//2011.03.16 Jerry {
int checkFileExist(char *file_name)
{
	struct stat status;

	if ( stat(file_name, &status) < 0)
		return 0;

	return 1;
}

static int done_auto_mac(int eid, webs_t wp, int argc, char_t **argv){
	websWrite(wp, "%d", checkFileExist("/tmp/done_auto_mac"));
	return 0;
}
//2011.03.16 Jerry }

static int ej_get_parameter(int eid, webs_t wp, int argc, char_t **argv){
//	char *c;
	bool last_was_escaped;
	int ret = 0;
	
	if (argc < 1){
		websError(wp, 400,
				"get_parameter() used with no arguments, but at least one "
				"argument is required to specify the parameter name\n");
		return -1;
	}
	
	last_was_escaped = FALSE;
	
	char *value = websGetVar(wp, argv[0], "");
	websWrite(wp, "%s", value);
	
	return ret;
}

unsigned int getpeerip(webs_t wp){
	int fd, ret;
	struct sockaddr peer;
	socklen_t peerlen = sizeof(struct sockaddr);
	struct sockaddr_in *sa;
	
	fd = fileno((FILE *)wp);
	ret = getpeername(fd, (struct sockaddr *)&peer, &peerlen);
	sa = (struct sockaddr_in *)&peer;
	
	if (!ret){
//		csprintf("peer: %x\n", sa->sin_addr.s_addr);	// J++
		return (unsigned int)sa->sin_addr.s_addr;
	}
	else{
		csprintf("error: %d %d \n", ret, errno);
		return 0;
	}
}

char *get_login_info(char *filename)
{
    	FILE *f;
    	static char info[32];
	int count = 0;
	char *v1 = NULL;
	f = fopen(filename, "r");
    	if (f == NULL) {
        	printf("fopen(%s) failed\n", filename);
        	return "";
	}
	memset(info, 0, 32);
	count = fread(info, 1, 32, f);
	fclose(f);
	if((v1 = strchr(info, '\n')) != 0)
		*v1 = '\0';
	return info;
}

extern long uptime(void);

static int login_state_hook(int eid, webs_t wp, int argc, char_t **argv){
	unsigned int ip, login_ip;
	char ip_str[16], login_ip_str[16];
	unsigned long login_timestamp;
	struct in_addr now_ip_addr, login_ip_addr;
	time_t now;
	const int MAX = 80;
	const int VALUELEN = 18;
	char buffer[MAX], values[6][VALUELEN];
	
	ip = getpeerip(wp);

	now_ip_addr.s_addr = ip;
	memset(ip_str, 0, 16);
	strcpy(ip_str, inet_ntoa(now_ip_addr));
	now = uptime();
	login_ip = (unsigned int)atoll(get_login_info(LOGIN_IP_FILE));	//2011.04.27 Jerry
    	login_ip_addr.s_addr = login_ip;
	memset(login_ip_str, 0, 16);
	strcpy(login_ip_str, inet_ntoa(login_ip_addr));
	login_timestamp = (unsigned long)atol(get_login_info(LOGIN_TIMESTAMP_FILE));	//2011.04.27 Jerry
	
	FILE *fp = fopen("/proc/net/arp", "r");
	if (fp){
		memset(buffer, 0, MAX);
		memset(values, 0, 6*VALUELEN);
		
		while (fgets(buffer, MAX, fp)){
			if (strstr(buffer, "br0") && !strstr(buffer, "00:00:00:00:00:00")){
				if (sscanf(buffer, "%s%s%s%s%s%s", values[0], values[1], values[2], values[3], values[4], values[5]) == 6){
					if (!strcmp(values[0], ip_str)){
						break;
					}
				}
				
				memset(values, 0, 6*VALUELEN);
			}
			
			memset(buffer, 0, MAX);
		}
		
		fclose(fp);
	}
	
	if (ip != 0 && login_ip == ip){
		websWrite(wp, "function is_logined() { return 1; }\n");
		websWrite(wp, "function login_ip_dec() { return '%u'; }\n", login_ip);
		websWrite(wp, "function login_ip_str() { return '%s'; }\n", login_ip_str);
		
		websWrite(wp, "function login_ip_str_now() { return '%s'; }\n", ip_str);
		
		if (values[3] != NULL)
			websWrite(wp, "function login_mac_str() { return '%s'; }\n", values[3]);
		else
			websWrite(wp, "function login_mac_str() { return ''; }\n");
//		time(&login_timestamp);
		login_timestamp = uptime();
	}
	else{
		websWrite(wp, "function is_logined() { return 0; }\n");
		websWrite(wp, "function login_ip_dec() { return '%u'; }\n", login_ip);
		
		if ((unsigned long)(now-login_timestamp) > 60)	//one minitues
			websWrite(wp, "function login_ip_str() { return '0.0.0.0'; }\n");
		else
			websWrite(wp, "function login_ip_str() { return '%s'; }\n", login_ip_str);
		
		websWrite(wp, "function login_ip_str_now() { return '%s'; }\n", ip_str);
		
		if (values[3] != NULL)
			websWrite(wp, "function login_mac_str() { return '%s'; }\n", values[3]);
		else
			websWrite(wp, "function login_mac_str() { return ''; }\n");
	}
	
	return 0;
}

static int ej_get_arp_table(int eid, webs_t wp, int argc, char_t **argv){
	const int MAX = 80;
	const int FIELD_NUM = 6;
	const int VALUELEN = 18;
	char buffer[MAX], values[FIELD_NUM][VALUELEN];
	int num, firstRow;
	
	FILE *fp = fopen("/proc/net/arp", "r");
	if (fp){
		memset(buffer, 0, MAX);
		memset(values, 0, FIELD_NUM*VALUELEN);
		
		firstRow = 1;
		while (fgets(buffer, MAX, fp)){
			if (strstr(buffer, "br0") && !strstr(buffer, "00:00:00:00:00:00")){
				if (firstRow == 1)
					firstRow = 0;
				else
					websWrite(wp, ", ");
				
				if ((num = sscanf(buffer, "%s%s%s%s%s%s", values[0], values[1], values[2], values[3], values[4], values[5])) == FIELD_NUM){
					websWrite(wp, "[\"%s\", \"%s\", \"%s\", \"%s\", \"%s\", \"%s\"]", values[0], values[1], values[2], values[3], values[4], values[5]);
				}
				
				memset(values, 0, FIELD_NUM*VALUELEN);
			}
			
			memset(buffer, 0, MAX);
		}
		
		fclose(fp);
	}
	
	return 0;
}

// for detect static IP's client.
static int ej_get_static_client(int eid, webs_t wp, int argc, char_t **argv){
	FILE *fp = fopen("/tmp/static_ip.inf", "r");
	char buf[1024], *head, *tail, field[1024];
	int len, i, first_client, first_field;
	
	if (fp == NULL){
		csprintf("Don't detect static clients!\n");
		return 0;
	}
	
	memset(buf, 0, 1024);
	
	first_client = 1;
	while (fgets(buf, 1024, fp)){
		if (first_client == 1)
			first_client = 0;
		else
			websWrite(wp, ", ");
		
		len = strlen(buf);
		buf[len-1] = ',';
		head = buf;
		first_field = 1;
		for (i = 0; i < 7; ++i){
			tail = strchr(head, ',');
			if (tail != NULL){
				memset(field, 0, 1024);
				strncpy(field, head, (tail-head));
			}
			
			if (first_field == 1){
				first_field = 0;
				websWrite(wp, "[");
			}
			else
				websWrite(wp, ", ");
			
			if (strlen(field) > 0)
				websWrite(wp, "\"%s\"", field);
			else
				websWrite(wp, "null");
			
			//if (tail+1 != NULL)
				head = tail+1;
			
			if (i == 6)
				websWrite(wp, "]");
		}
		
		memset(buf, 0, 1024);
	}
	
	fclose(fp);
	return 0;
}


// Wireless Client List		 /* Start --Alicia, 08.09.23 */
#define WIF     "ra0"
#define WIF2G	"rai0"
#define RTPRIV_IOCTL_GET_MAC_TABLE	SIOCIWFIRSTPRIV + 0x0F

static int ej_wl_auth_list(int eid, webs_t wp, int argc, char_t **argv)
{
	struct iwreq wrq;
	int i, firstRow;
	char data[4096];
	char mac[ETHER_ADDR_STR_LEN];	
	
	memset(mac, 0, sizeof(mac));
	
	/* query wl for authenticated sta list */
	memset(data, 0, 4096);
	wrq.u.data.pointer = data;
	wrq.u.data.length = 4096;
	wrq.u.data.flags = 0;	
	/*if (wl_ioctl(WIF, RTPRIV_IOCTL_GET_MAC_TABLE, &wrq) < 0)
		goto exit;*/	//Comment by Jerry

	/* build wireless sta list */
	firstRow = 1;
	RT_802_11_MAC_TABLE *mp = (RT_802_11_MAC_TABLE *)wrq.u.data.pointer;
	for (i=0; i<mp->Num; i++)
	{
		char *value;

		if (firstRow == 1)
			firstRow = 0;
		else
			websWrite(wp, ", ");
		websWrite(wp, "[");
				
		sprintf(mac, "%02X:%02X:%02X:%02X:%02X:%02X",
				mp->Entry[i].Addr[0], mp->Entry[i].Addr[1],
				mp->Entry[i].Addr[2], mp->Entry[i].Addr[3],
				mp->Entry[i].Addr[4], mp->Entry[i].Addr[5]);
		websWrite(wp, "\"%s\"", mac);
		
		value = "YES";
		websWrite(wp, ", \"%s\"", value);
		
		value = "";
		websWrite(wp, ", \"%s\"", value);
		
		websWrite(wp, "]");
	}

	/* error/exit */
exit:
	return 0;
}						     /* End --Alicia, 08.09.23 */

int ej_shown_time(int eid, webs_t wp, int argc, char **argv){
	time_t t1;
	
	time(&t1);
	
	websWrite(wp, "%e", t1);
	
	return 0;
}

int ej_shown_language_option(int eid, webs_t wp, int argc, char **argv){
	struct language_table *pLang = NULL;
	char lang[4];
	int i, len;
	FILE *fp = fopen("EN.dict", "r");
	char buffer[1024], key[16], target[16];
	char *follow_info, *follow_info_end;
	unsigned char lang_mib[16];	//2011.04.12 Jerry

	if (fp == NULL){
		fprintf(stderr, "No English dictionary!\n");
		return 0;
	}

	memset(lang, 0, 4);
	//2011.04.12 Jerry {
	apmib_get( MIB_PREFERRED_LANG, (void *)&lang_mib);
	strcpy(lang, lang_mib);
	//2011.04.12 Jerry }

	for (i = 0; i < 20; ++i){
		memset(buffer, 0, sizeof(buffer));
		if ((follow_info = fgets(buffer, sizeof(buffer), fp)) != NULL){
			if (strncmp(follow_info, "LANG_", 5))    // 5 = strlen("LANG_")
				continue;

			follow_info += 5;
			follow_info_end = strstr(follow_info, "=");
			len = follow_info_end-follow_info;
			memset(key, 0, sizeof(key));
			strncpy(key, follow_info, len);

			for (pLang = language_tables; pLang->Lang != NULL; ++pLang){
				if (strcmp(key, pLang->Target_Lang))
					continue;
				follow_info = follow_info_end+1;
				follow_info_end = strstr(follow_info, "\n");
				len = follow_info_end-follow_info;
				memset(target, 0, sizeof(target));
				strncpy(target, follow_info, len);

				if (!strcmp(key, lang))
					websWrite(wp, "<option value=\"%s\" selected>%s</option>\\n", key, target);
				else
					websWrite(wp, "<option value=\"%s\">%s</option>\\n", key, target);
				break;
			}
		}
		else
			break;
	}
	fclose(fp);

	return 0;
}

//Added by Edison 20110406{
static int
telnetd_cgi(webs_t wp, char_t *urlPrefix, char_t *webDir, int arg,
		char_t *url, char_t *path, char_t *query)
{
	char *value;
	int telnetd_pid;
	value = websGetVar(wp, "enable", "");
	telnetd_pid = find_pid_by_name("telnetd");
	if (!telnetd_pid){

	   if (!strcmp(value,"1")){
		system("telnetd -l /bin/sh");
		return 0;
	   }
	}else if (!strcmp(value,"0")){
		system("killall telnetd");
		return 0;
	}
	return 1;
}

static int
apply_cgi(webs_t wp, char_t *urlPrefix, char_t *webDir, int arg,
		char_t *url, char_t *path, char_t *query)
{
	int sid;
	char *value;
	char *current_url;
	char *next_url;
	char *sid_list;
	char *value1;
	char *script;
	char groupId[64];
	char urlStr[64];
	char *groupName;
	
	urlStr[0] = 0;
	
	value = websGetVar(wp, "action", "");
	
	value = websGetVar(wp, "action_mode","");
	
	next_host = websGetVar(wp, "next_host", "");
	cprintf("host:%s\n", next_host);
	current_url = websGetVar(wp, "current_page", "");
	next_url = websGetVar(wp, "next_page", "");
	script = websGetVar(wp, "action_script","");
	
	cprintf("Apply: %s %s %s %s\n", value, current_url, next_url, websGetVar(wp, "group_id", ""));
	
	if (!strcmp(value," Refresh "))
	{
		strcpy(SystemCmd, websGetVar(wp,"SystemCmd",""));
		websRedirect(wp, current_url);
		return 0;
	}
	else if (!strcmp(value," Clear "))
	{
		system("echo \" \" > /var/log/messages");	//2011.04.28 Jerry
		websRedirect(wp, current_url);
		return 0;
	}
	else if (!strcmp(value,"NEXT"))
	{
		websRedirect(wp, next_url);
		return 0;
	}
	
	else if (!strcmp(value, "Restore"))
	{
//2011.03.31 Jerry {
		websApply(wp, "Restarting.asp");
		sys_default();
		sys_reboot();
		return (0);
//2011.03.31 Jerry }
	}
	else
	{
		sid_list = websGetVar(wp, "sid_list", "");
		while ((serviceId = svc_pop_list(sid_list, ';')))
		{
			sid = 0;
			while (GetServiceId(sid) != 0)
			{
				if (!strcmp(GetServiceId(sid), serviceId))
					break;
				
				++sid;
			}
			
			
			sid_list = sid_list+strlen(serviceId)+1;
		}
		
		/* Add for EMI Test page */
		if (strcmp(script, ""))
		{
				
		}
		
		if (!strcmp(value, "  Save  ") || !strcmp(value, " Apply "))
		{
			strcpy(urlcache, next_url);
			websRedirect(wp, next_url);
		}
		else if (!strcmp(value, " Finish "))
			websRedirect(wp, "SaveRestart.asp");
		else if (urlStr[0] == 0)
			websRedirect(wp, current_url);
		else
			websRedirect(wp, urlStr);
		
		cprintf("apply ok\n");
		return 0;
	}
	
	return 1;
}
//2008.08 magic}

//Added by Jerry {
struct form_handler form_handlers[] = {
	{ "formFilter", formFilter},
	{ "formPortFw", formPortFw},
	{ "formWlanSetup", formWlanSetup},
	{ "formWlanRedirect", formWlanRedirect},
	{ "formWep", formWep},
	{ "formTcpipSetup", formTcpipSetup},
	{ "formPasswordSetup", formPasswordSetup},
	{ "formLogout", formLogout},
	{ "formWlAc", formWlAc},
	{ "formAdvanceSetup", formAdvanceSetup},
	{ "formUpload", formUpload},
	{ "formReflashClientTbl", formReflashClientTbl},
	{ "formWlEncrypt", formWlEncrypt},
	{ "formStaticDHCP", formStaticDHCP},
	{ "formWanTcpipSetup", formWanTcpipSetup},
	{ "formRoute", formRoute},
	{ "formDMZ", formDMZ},
	{ "formDdns", formDdns},
	{ "formNtp", formNtp},
	{ "formOpMode", formOpMode},
	{ "formWizard", formWizard},
	{ "formPocketWizard", formPocketWizard},
	{ "formPocketWizardGW", formPocketWizardGW},
	{ "formRebootCheck", formRebootCheck},
	{ "formSysCmd", formSysCmd},
	{ "formSysLog", formSysLog},
	{ "formSaveConfig", formSaveConfig},
	{ "formSchedule", formSchedule},
	{ "formNewSchedule", formNewSchedule},
	{ "formWirelessTbl", formWirelessTbl},
	{ "formStats", formStats},
	{ "formWlSiteSurvey", formWlSiteSurvey},
	{ "formWlWds", formWlWds},
	{ "formWdsEncrypt", formWdsEncrypt},
	{ "formSystemSetup", formSystemSetup},
	{ "formClearSysLog", formClearSysLog},
	{ "formBasicFwallSetup", formBasicFwallSetup},
	{ "formWsc", formWsc},
	{ "formIpQoS", formIpQoS},
	{ "formTcpipSetupAP", formTcpipSetupAP},	//2011.04.20 Jerry
	{ NULL, NULL }
};


static int
process_form(webs_t wp, char_t *urlPrefix, char_t *webDir, int arg,
		char_t *url, char_t *path, char_t *query)
{
	//int sid;
	char *type_form;
	//char *value;
	struct form_handler *handler;

	//value = websGetVar(wp, "action", "");
	type_form = websGetVar(wp, "typeForm", "");
	printf("Form type: %s\n", type_form);	

	for (handler = &form_handlers[0]; handler->pattern; handler++) {
		if (strcmp(handler->pattern, type_form) == 0) {
			printf("Enter %s\n", type_form);
	                handler->formFunc(wp, NULL, NULL);
                        break;
		}
	}
	return 1;
}

static int
apply_cgi_group(webs_t wp, int sid, struct variable *var, char *groupName, int flag)
{	
   struct variable *v;
   int groupCount;

   
   if (v->name == NULL) return 0;    
   
   groupCount = atoi(v->argv[1]);

   if (flag == GROUP_FLAG_ADD)/* if (!strcmp(value, " Refresh ")) || Save condition */
   {    
		return 1;	// 2008.08 magic
   }	  
   else if (flag == GROUP_FLAG_REMOVE)/* if (!strcmp(value, " Refresh ")) || Save condition */
   {    
		return 1; 	// 2008.08 magic
   }	     
  	return 0; // 2008.08 magic
}


//2011.03.31 Jerry 2011.5.5 Edison{
int get_fw_version(int eid, webs_t wp, int argc, char **argv){
	char fw_file[] = "/etc/FwVersion";
	FILE *fp = NULL;
	char buf[64],fwversion[64];
	memset( fwversion, '\0', 64 );
	int count,i=0,dot=0;
	
	if (!(fp = fopen(fw_file, "r"))) {
		printf("open file error(%s)!\n", fw_file);
		websWrite(wp, "Unknown");
		return 0;
	}

	count = fread(buf, 1, 64, fp);
	buf[count - 1] = '\0';
	fclose(fp);
	while(dot<4 && buf[i]!='\0')
	{
   	   if(buf[i+1]=='.') 
	   {
	      dot++;
	   }
	   fwversion[i]=buf[i];
	   i++;
	}
	websWrite(wp, "%s", fwversion);
	
	return 0;
}
//2011.03.31 Jerry }

//2011.05.26 Jerry {
int getWanDns(int eid, webs_t wp, int argc, char **argv){
	char *dns_list = NULL;
	dns_list = getDnsList();	//2011.03.14 Jerry
	websWrite(wp, "%s", dns_list);
	return 0;
}
//2011.05.26 Jerry }

#ifdef WEBS
mySecurityHandler(webs_t wp, char_t *urlPrefix, char_t *webDir, int arg, char_t *url, char_t *path, char_t *query)
{
	char_t *user, *passwd, *digestCalc;
	int flags, nRet;


	user = websGetRequestUserName(wp);
	passwd = websGetRequestPassword(wp);
	flags = websGetRequestFlags(wp);


	nRet = 0;

	if (user && *user)
	{
		if (strcmp(user, "admin")!=0)
		{
			websError(wp, 401, T("Wrong User Name"));
			nRet = 1;
		}
		else if (passwd && *passwd)
		{
			if (strcmp(passwd, websGetPassword())!=0)
			{
				websError(wp, 401, T("Wrong Password"));
				nRet = 1;
			}
		}
#ifdef DIGEST_ACCESS_SUPPORT		
		else if (flags & WEBS_AUTH_DIGEST)
		{
			wp->password = websGetPassword();

			a_assert(wp->digest);
			a_assert(wp->nonce);
			a_assert(wp->password);

			digestCalc = websCalcDigest(wp);
			a_assert(digestCalc);		

			if (gstrcmp(wp->digest, digestCalc)!=0)
			{
				websError(wp, 401, T("Wrong Password"));
				nRet = 1;
			}
			bfree(B_L, digestCalc);
		}
#endif	
	}
	else 
	{
#ifdef DIGEST_ACCESS_SUPPORT
		wp->flags |= WEBS_AUTH_DIGEST;
#endif
		websError(wp, 401, T(""));
		nRet = 1;
	}
	return nRet;

}
#else
static void
do_auth(char *userid, char *passwd, char *realm)
{	
//	time_t tm;
					
	if (strcmp(ProductID,"")==0)
	{
		strncpy(ProductID, MODEL_NAME, 32);	//2011.04.14 Jerry
	}
	if (strcmp(UserID,"")==0)
	{	   
		char tmpBuf[100];
		apmib_get(MIB_SUPER_NAME, (void *)tmpBuf);
		strncpy(UserID, tmpBuf, 32);
		printf("UserID: %s\n", UserID);
	}
	if (strcmp(UserPass, "") == 0 || reget_passwd == 1)
	{
		reget_passwd = 0;
		char tmpBuf[100];
		apmib_get(MIB_SUPER_PASSWORD, (void *)tmpBuf);
		strncpy(UserPass, tmpBuf, 32);
		printf("UserPass: %s\n", UserPass);
	}	
	strncpy(userid, UserID, AUTH_MAX);

	if (!is_auth())
	{
		strcpy(passwd, "");
	}
	else
	{
		strncpy(passwd, UserPass, AUTH_MAX);
	}
	strncpy(realm, ProductID, AUTH_MAX);	
}
#endif


//Added by Edison{
static void
do_telnetd_cgi(char *url, FILE *stream)
{
    telnetd_cgi(stream, NULL, NULL, 0, url, NULL, NULL);
}
//}

static void
do_apply_cgi(char *url, FILE *stream)
{
	/*char *path, *query;
	
	cprintf(" Before Apply : %s\n", url);
	
	websScan(url);	
	query = url;
	path = strsep(&query, "?") ? : url;	
#ifndef HANDLE_POST	
	init_cgi(query);
#endif	
	apply_cgi(stream, NULL, NULL, 0, url, path, query);
#ifndef HANDLE_POST	
	init_cgi(NULL);
#endif	*/
    apply_cgi(stream, NULL, NULL, 0, url, NULL, NULL);
}


#if defined(linux)

//#if defined(ASUS_MIMO) && defined(TRANSLATE_ON_FLY)
#ifdef TRANSLATE_ON_FLY
static int refresh_title_asp = 0;

static void
do_lang_cgi(char *url, FILE *stream)
{
	if (refresh_title_asp)  {
		// Request refreshing pages from browser.
		websHeader(stream);
		websWrite(stream, "<head></head><title>REDIRECT TO INDEX.ASP</title>");

		// The text between <body> and </body> content may be rendered in Opera browser.
		websWrite(stream, "<body onLoad='if (navigator.appVersion.indexOf(\"Firefox\")!=-1||navigator.appName == \"Netscape\"){top.location=\"index.asp\";}else{top.location.reload(true);}'></body>");
		websFooter(stream);
		websDone(stream, 200);
	} else {
		// Send redirect-page if and only if refresh_title_asp is true.
		// If we do not send Title.asp, Firefox reload web-pages again and again.
		// This trick had been deprecated due to compatibility issue with Netscape and Mozilla browser.
		websRedirect(stream, "Title.asp");
	}
}


#endif // TRANSLATE_ON_FLY


int chk_image_err = 1;

// Alicia, 201103 {
void kill_some_processes(void)
{
	system("killall udhcpd");
	system("killall iapp");
	system("killall wscd");
	system("killall iwcontrol");
	system("killall udhcpc");
	system("killall lld2d");
	system("killall reload");
	system("killall syslogd");
	system("killall klogd");
	system("killall dnrd");
	system("killall igmpproxy");
	system("echo > /tmp/fwupgrade");
	system("killall wanduck");
}

void stop_processes_for_upgrade()
{
	int dnrd_pid, detectWAN_pid, syslogd_pid, klogd_pid, infosvr_pid, pppoe_relay_pid;
	flag_upgrade = 0;

	dnrd_pid = find_pid_by_name("dnrd");
	if(dnrd_pid > 0){
		flag_upgrade += 1;
		kill(dnrd_pid, SIGTERM);
	}

	detectWAN_pid = find_pid_by_name("detectWAN");
	if(detectWAN_pid > 0) {
		flag_upgrade += 2;
		kill(detectWAN_pid, SIGTERM);
	}

	syslogd_pid = find_pid_by_name("syslogd");
	if(syslogd_pid > 0) {
		flag_upgrade += 4;
		kill(syslogd_pid, SIGTERM);
	}

	klogd_pid = find_pid_by_name("klogd");
	if(klogd_pid > 0)
		kill(klogd_pid, SIGTERM);

	infosvr_pid = find_pid_by_name("infosvr");
	if(infosvr_pid > 0) {
		flag_upgrade += 8;
		kill(infosvr_pid, SIGTERM);
	}
	pppoe_relay_pid = find_pid_by_name("pppoe-relay");
	if(pppoe_relay_pid > 0)
	{
		flag_upgrade += 16;
		system("killall pppoe-relay");
	}

}

void start_processes_for_upgrade()
{
	int wan_type = 0;
	
	//Restart dnrd
	if(flag_upgrade & 1) notify_sysconf("restart_dnrd", 0);

	//Restart detectWAN
	if(flag_upgrade & 2) notify_sysconf("restart_detectWAN", 0);

	//Restart syslogd and klogd
	if(flag_upgrade & 4) notify_sysconf("restart_syslog", 0);

	//Restart infosvr
	if(flag_upgrade & 8) notify_sysconf("restart_infosvr", 0);
	
	if(flag_upgrade & 16) notify_sysconf("restart_pppoeRelay", 0);	
}

static void
do_upgrade_post(char *url, FILE *stream, int len, char *boundary)
{	
	char upload_fifo[] = "/tmp/fw.bin";
	FILE *fifo = NULL;
	char buf[4096]="", buf_tmp[10]="", model_name[10]="", model_num[10]="";
	int count=0, ret = EINVAL, ch;
	int cnt=0, add_cnt=1;  /*20110526 Emily Add for utility fw header*/
	long filelen, *filelenptr, tmp;
	char cmpHeader;
	unsigned long head_offset = 0;

	printf("[httpd] do_upgrade_post\n");
	printf("[httpd] stop_processes_for_upgrade\n");
	stop_processes_for_upgrade();

	/* Look for our part */
	while (len > 0) 
	{
		if (!fgets(buf, MIN(len + 1, sizeof(buf)), stream))
		{
			goto err;
		}			

		len -= strlen(buf);

		if (!strncasecmp(buf, "Content-Disposition:", 20)
				&& strstr(buf, "name=\"file\""))
			break;
	}

	/* Skip boundary and headers */
	while (len > 0) 
	{
		if (!fgets(buf, MIN(len + 1, sizeof(buf)), stream))
		{
			goto err;
		}
		len -= strlen(buf);
		if (!strcmp(buf, "\n") || !strcmp(buf, "\r\n"))
		{
			break;
		}
	}
//printf("\n#########len: %ld\n", len);

	if (!(fifo = fopen(upload_fifo, "a+")))
		goto err;

	filelen = len;
	cnt = 0;

	/* Pipe the rest to the FIFO */
	cmpHeader = 0;

	while (len>0 && filelen>0) 
	{
		if (waitfor (fileno(stream), 10) <= 0)
		{
			printf("Break while len=%x filelen=%x\n", len, filelen);
			break;
		}
		 
/*20110526 Emily Add for utility fw header*/
		if (add_cnt < 7)
		{
			count = fread(buf_tmp, 1, MIN(len, sizeof(buf_tmp)), stream);
	
			if (add_cnt == 1)		
			{
				if (!(buf_tmp[0] == 0x52 && buf_tmp[1] == 0x54 && buf_tmp[2] == 0x4C && buf_tmp[3] == 0x4B))   //0x52544C4B RTLK
				{
					fprintf(stderr, "Chip vender error: %x %x %x %x\n", buf_tmp[0], buf_tmp[1], buf_tmp[2], buf_tmp[3]);
					len -= count;
					goto err;
				}
			}
			else if (add_cnt == 4)
				sprintf(model_num, "%x%x%x%x", buf_tmp[7], buf_tmp[8], buf_tmp[9], buf_tmp[10]);
				
			else if (add_cnt == 5)
				sprintf(model_name, "%x%x%x%x", buf_tmp[0], buf_tmp[1], buf_tmp[2], buf_tmp[3]);

				if (model_num[0]==0x52 && model_num[1]==0x54 && model_num[2]==0x2D && model_num[3]==0x4E && model_name[0]== 0x31 && model_name[1]== 0x30 & model_name[2]== 0x4C & model_name[3]== 0x58)  //0x5254 2D4E 3130 4C58 RT-N10LX
				{
					fprintf(stderr, "Model name error: %s %s\n", model_num, model_name);
					len -= count;
					goto err;
				}						
		}
	       else
 		{
			
			count = fread(buf, 1, MIN(len, sizeof(buf)), stream);
			if (cnt==0 && count>16)
			{
				if (!(	buf[0] == 0x63 &&	/* linux.bin Image Magic Number: 0x63723663 */
					buf[1] == 0x72 &&
					buf[2] == 0x36 &&
					buf[3] == 0x63)
				)
				{
					fprintf(stderr, "Header %x %x %x %x\n", buf[0], buf[1], buf[2], buf[3]);
					len -= count;
					goto err;
				}
			
				cmpHeader = 1;
				cnt++;
			}
		}
		add_cnt++;
		filelen -= count;
		len -= count;
		fwrite(buf, 1, count, fifo);
	}
//printf("\n#########len: %ld\n", len);

	if (!cmpHeader)
		goto err;

	/* Slurp anything remaining in the request */
	while (len-- > 0)
	{
		ch = fgetc(stream);

		if (filelen>0)
		{
			fwrite(&ch, 1, 1, fifo);
			filelen--;
		}
	}
	
	fseek(fifo, 0, SEEK_END);
	fclose(fifo);
	fifo = NULL;

//printf("\n#######done\n");

err:
	if (fifo)
		fclose(fifo);

	/* Slurp anything remaining in the request */
	while (len-- > 0)
		ch = fgetc(stream);

	if (cmpHeader != 0)
		chk_image_err = 0;
}

static void
do_upgrade_cgi(char *url, FILE *stream)
{
	printf("#### [httpd] do upgrade cgi\n");
	//char *cmd[] = {"killall", "dnrd", NULL};
	//_eval(cmd, NULL, 0, NULL);
	//kill_some_processes();
	// check image
	if (chk_image_err != 0)
		goto err;

	char inFile[] = "/tmp/fw.bin";
	FILE *fh_in = NULL, *fh_out = NULL;
	int ch;
	IMG_HEADER_T pHeader;
/*20110526 Emily change 0 to 60 for utility fw header*/
	unsigned long head_offset = 60;  
	unsigned long linux_bin_len, root_bin_len;
	unsigned short sum = 0;
	unsigned long numWrite;
	int i;
	int order_flag = 0;
	int readLen = 0;

	if (!(fh_in = fopen(inFile, "r")))
	{
		printf("\n#####Open file %s failed!\n", inFile);
		goto err;
	}

	int header_len = sizeof(IMG_HEADER_T);

	// check if firmware upgrade
	while (order_flag < 2)
	{
		fseek(fh_in, head_offset, SEEK_SET);
		if (fread(&pHeader, 1, header_len, fh_in) != header_len)
		{
			printf("\n######Read file %s failed! \n", inFile);
			fclose(fh_in);
			goto err;
		}

		// check linux.bin's signature
		if (order_flag == 0)
		{
			if (!memcmp(pHeader.signature, FW_HEADER, SIGNATURE_LEN) 
				|| !memcmp(pHeader.signature, FW_HEADER_WITH_ROOT, SIGNATURE_LEN))
			{
				linux_bin_len = pHeader.len + header_len;
//printf("###########linux_bin_len: 0x%x(%ld)\n", linux_bin_len, linux_bin_len);
			}
			else
			{
				printf("\n####check linux.bin error!\n");
				fclose(fh_in);
				goto err;
			}
		}
		
		// check root.bin's signature
		if (order_flag == 1)
		{
			if (!memcmp(pHeader.signature, ROOT_HEADER, SIGNATURE_LEN))
			{
				root_bin_len = pHeader.len;
//printf("###########root_bin_len: 0x%x(%ld)\n", root_bin_len, root_bin_len);
			}
			else
			{
				printf("\n####check root.bin error!\n");
				fclose(fh_in);
				goto err;
			}
		}

		// checksum
		for (i=0; i<pHeader.len; i++)
		{
			ch = fgetc(fh_in);
			if ((ch != EOF) && (i % 2 == 0))
				sum += *((unsigned short *)&ch);
		}
//printf("\n####sum: %d\n", sum);
		if (sum != 0)
		{
			printf("\n#####image checksum mismatched!\n");
			fclose(fh_in);
			goto err;
		}


		head_offset += pHeader.len + header_len;
		order_flag++;
	}


	// check ok, then write to flash
	websApply(stream, "Updating.asp");
	fwupgrade_flag = 1;
	printf("fclose(fh_in)\n");
	fclose(fh_in);
	printf("fclose(fh_in-1)\n");
	return;



err:
	printf("####Firmware upgrade failed!\n");
	websApply(stream, "UpdateError.asp");
	unlink(inFile);
	start_processes_for_upgrade();
}
// Alicia, 201103 }

extern int conn_fd;

static void
do_upload_post(char *url, FILE *stream, int len, char *boundary)
{
	#define MAX_VERSION_LEN 64
	char upload_fifo[] = "/tmp/settings_u.prf";
	FILE *fifo = NULL;
	char buf[1024];
	int count, ret = EINVAL, ch;
	int /*eno, */cnt;
	long filelen, *filelenptr;
	char /*version[MAX_VERSION_LEN], */cmpHeader;

	/* Look for our part */
	while (len > 0) {
		if (!fgets(buf, MIN(len + 1, sizeof(buf)), stream)) {
			goto err;
		}

		len -= strlen(buf);

		if (!strncasecmp(buf, "Content-Disposition:", 20)
				&& strstr(buf, "name=\"file\""))
			break;
	}

	/* Skip boundary and headers */
	while (len > 0) {
		if (!fgets(buf, MIN(len + 1, sizeof(buf)), stream)) {
			goto err;
		}

		len -= strlen(buf);
		if (!strcmp(buf, "\n") || !strcmp(buf, "\r\n")) {
			break;
		}
	}

	if (!(fifo = fopen(upload_fifo, "a+")))
		goto err;

	filelen = len;
	cnt = 0;

	/* Pipe the rest to the FIFO */
	printf("Upgrading %d\n", len);
	cmpHeader = 0;

	while (len > 0 && filelen > 0) {
		if (waitfor (conn_fd, 10) <= 0) {
			break;
		}

		count = fread(buf, 1, MIN(len, sizeof(buf)), stream);

		if (cnt == 0 && count > 8) {
		
			if (!strncmp(buf, COMP_HS_SIGNATURE, COMP_SIGNATURE_LEN) ||
			    !strncmp(buf, COMP_DS_SIGNATURE, COMP_SIGNATURE_LEN) ||
			    !strncmp(buf, COMP_CS_SIGNATURE, COMP_SIGNATURE_LEN) )
			{
				//filelenptr = (buf + 8);
				//filelen = (*filelenptr) + 12;
				printf("Configuration signature is ok!\n");
			}
			else
			{
				len -= count;
				goto err;
			}

			cmpHeader = 1;
			++cnt;
		}

		filelen -= count;
		len -= count;

		fwrite(buf, 1, count, fifo);
	}

	if (!cmpHeader)
		goto err;

	/* Slurp anything remaining in the request */
	while (len-- > 0) {
		ch = fgetc(stream);

		if (filelen > 0) {
			fwrite(&ch, 1, 1, fifo);
			--filelen;
		}
	}

	ret = 0;

	fseek(fifo, 0, SEEK_END);
	fclose(fifo);
	fifo = NULL;
	/*printf("done\n");*/

err:
	if (fifo)
		fclose(fifo);

	/* Slurp anything remaining in the request */
	while (len-- > 0)
		ch = fgetc(stream);

	fcntl(conn_fd, F_SETOWN, -ret);
}

static void write_config()
{
	char upload_file[] = "/tmp/settings_u.prf";
	FILE *fp = NULL;
	char buf[40 * 1024];
	int maximum_config_size = 40 * 1024;
	CONFIG_DATA_T type = CURRENT_SETTING;
	int status = 0;
	long filelen, *filelenptr, location;

	if (!(fp = fopen(upload_file, "r"))) {
		printf("open file error(%s)!\n", upload_file);
		return;
	}

	filelen = fread(buf, 1, maximum_config_size, fp);
	filelen = 0;
	location = 0;
	while(1) {
		if (!strncmp( (buf+location), COMP_HS_SIGNATURE, COMP_SIGNATURE_LEN) ||
		    !strncmp( (buf+location), COMP_DS_SIGNATURE, COMP_SIGNATURE_LEN) ||
		    !strncmp( (buf+location), COMP_CS_SIGNATURE, COMP_SIGNATURE_LEN) )
		{
			filelenptr = (buf + location + 8);
			filelen += (*filelenptr) + 12;
			location += (*filelenptr) + 12;
		}
		else
			break;
	}

	updateConfigIntoFlash(buf, filelen, (int *)&type, &status);
	if (status == 0 || type == 0) // checksum error
	{
		free(buf);
		printf("Invalid configuration file!\n");
	}
	else {
		if (type) // upload success
			printf("Upload success!\n");
	}
	fclose(fp);
}
//2011.03.30 Jerry }

static void
do_upload_cgi(char *url, FILE *stream)
{
	int ret;
	
	ret = fcntl(fileno(stream), F_GETOWN, 0);
	
	/* Reboot if successful */
	if (ret == 0)
	{
		websApply(stream, "Uploading.asp");
		write_config();
		sys_reboot();
	}	
	else    
	{
	   	websApply(stream, "UploadError.asp");
	   	//unlink("/tmp/settings_u.prf");
	}   	
	  
}

// Viz 2010.08
static void
do_update_cgi(char *url, FILE *stream)
{
        struct ej_handler *handler;
        const char *pattern;
        int argc;
        char *argv[16];
        char s[32];

        if ((pattern = get_cgi("output")) != NULL) {
                for (handler = &ej_handlers[0]; handler->pattern; handler++) {
                        if (strcmp(handler->pattern, pattern) == 0) {
                                for (argc = 0; argc < 16; ++argc) {
                                        sprintf(s, "arg%d", argc);
                                        if ((argv[argc] = (char *)get_cgi(s)) == NULL) break;
                                }
                                handler->output(0, stream, argc, argv);
                                break;
                        }
                }
        }
}

static void
do_prf_file(char *url, FILE *stream)
{
//2011.03.30 Jerry {
	save_cs_to_file();
	do_file(url, stream);
//2011.03.30 Jerry }
}


#elif defined(vxworks)

static void
do_upgrade_post(char *url, FILE *stream, int len, char *boundary)
{
}

static void
do_upgrade_cgi(char *url, FILE *stream)
{
}

#endif

// 2010.09 James. {
static char no_cache_IE7[] =
"X-UA-Compatible: IE=EmulateIE7\r\n"
"Cache-Control: no-cache\r\n"
"Pragma: no-cache\r\n"
"Expires: 0"
;
// 2010.09 James. }

static char no_cache[] =
"Cache-Control: no-cache\r\n"
"Pragma: no-cache\r\n"
"Expires: 0"
;

static void 
do_log_cgi(char *path, FILE *stream)
{
	dump_file(stream, "/var/log/messages");	//2011.04.28 Jerry
	fputs("\r\n", stream); /* terminator */
	fputs("\r\n", stream); /* terminator */
}

#ifdef WEBS
void
initHandlers(void)
{		
    	websAspDefine("urlcache", ej_urlcache);	
	websAspDefine("uptime", ej_uptime);
	websAspDefine("sysuptime", ej_sysuptime);
	websAspDefine("nvram_dump", ej_dump);	
//    add by Viz  2010.08
	websAspDefine("qrate", ej_qos_packet);
	websAspDefine{"cgi_get", ej_cgi_get};
	websAspDefine("ctdump", ej_ctdump);
        websAspDefine("netdev", ej_netdev);
        websAspDefine("bandwidth", ej_bandwidth);
//  end Viz
	websSecurityDelete();
	websUrlHandlerDefine("", NULL, 0, mySecurityHandler, WEBS_HANDLER_FIRST);	
	websUrlHandlerDefine("/telnetd.cgi", NULL, 0, telnetd_cgi, 0);		//Added by Edison
	websUrlHandlerDefine("/apply.cgi", NULL, 0, apply_cgi, 0);
#ifdef ASUS_DDNS //2007.03.27 Yau add
	websAspDefine("nvram_char_to_ascii", ej_nvram_char_to_ascii);
#endif
}


#else

//2008.08 magic{
struct mime_handler mime_handlers[] = {
	{ "Nologin.asp", "text/html", no_cache_IE7, do_html_post_and_get, do_ej, NULL },
	{ "error_page.htm*", "text/html", no_cache_IE7, do_html_post_and_get, do_ej, NULL },
	{ "gotoHomePage.htm", "text/html", no_cache_IE7, do_html_post_and_get, do_ej, NULL },
	{ "ure_success.htm", "text/html", no_cache_IE7, do_html_post_and_get, do_ej, NULL },
	{ "ureip.asp", "text/html", no_cache_IE7, do_html_post_and_get, do_ej, NULL },
	{ "remote.asp", "text/html", no_cache_IE7, do_html_post_and_get, do_ej, NULL },
	{ "jquery.js", "text/javascript", no_cache_IE7, NULL, do_file, NULL }, // 2010.09 James.
	{ "httpd_check.htm", "text/html", no_cache_IE7, do_html_post_and_get, do_ej, NULL },
	{ "**.htm*", "text/html", no_cache_IE7, do_html_post_and_get, do_ej, do_auth },
	{ "**.asp*", "text/html", no_cache_IE7, do_html_post_and_get, do_ej, do_auth },
	
	{ "**.css", "text/css", NULL, NULL, do_file, NULL },
	{ "**.png", "image/png", NULL, NULL, do_file, NULL },
	{ "**.gif", "image/gif", NULL, NULL, do_file, NULL },
	{ "**.jpg", "image/jpeg", NULL, NULL, do_file, NULL },
	// Viz 2010.08
        { "**.svg", "image/svg+xml", NULL, NULL, do_file, NULL },
        { "**.swf", "application/x-shockwave-flash", NULL, NULL, do_file, NULL  },
        { "**.htc", "text/x-component", NULL, NULL, do_file, NULL  },
	// end Viz

//#if defined(ASUS_MIMO) && defined(TRANSLATE_ON_FLY)
#ifdef TRANSLATE_ON_FLY
	/* Only general.js and quick.js are need to translate. (reduce translation time) */
	{ "general.js|quick.js",  "text/javascript", no_cache_IE7, NULL, do_ej, do_auth },
//#endif  // defined(ASUS_MIMO) && defined(TRANSLATE_ON_FLY)
#endif //TRANSLATE_ON_FLY
	
	{ "**.js",  "text/javascript", no_cache_IE7, NULL, do_ej, do_auth },
	{ "**.cab", "text/txt", NULL, NULL, do_file, do_auth },
	{ "**.CFG", "text/txt", NULL, NULL, do_prf_file, do_auth },
	{ "**.dat", "text/txt", NULL, NULL, do_prf_file, do_auth },	//2011.03.30 Jerry
	{ "apply.cgi*", "text/html", no_cache_IE7, do_html_post_and_get, do_apply_cgi, do_auth },
	{ "telnetd.cgi*", "text/html", no_cache_IE7, do_html_post_and_get, do_telnetd_cgi, do_auth },	//Added by Edison
	{ "upgrade.cgi*", "text/html", no_cache_IE7, do_upgrade_post, do_upgrade_cgi, do_auth},
	{ "upload.cgi*", "text/html", no_cache_IE7, do_upload_post, do_upload_cgi, do_auth },
 	{ "syslog.cgi*", "text/txt", no_cache_IE7, do_html_post_and_get, do_log_cgi, do_auth },
        // Viz 2010.08 vvvvv  
        { "update.cgi*", "text/javascript", no_cache_IE7, do_html_post_and_get, do_update_cgi, do_auth }, // jerry5 
        // end Viz  ^^^^^^^^ 
//#ifdef TRANSLATE_ON_FLY
#ifdef TRANSLATE_ON_FLY
//#endif // TRANSLATE_ON_FLY
#endif //TRANSLATE_ON_FLY
	{ NULL, NULL, NULL, NULL, NULL, NULL }
};
//2008.08 magic}

//2011.03.21 Jerry {
int get_wan_status(int eid, webs_t wp, int argc, char **argv){
	FILE *fp;
	char statusstr[32];
	int s;
	struct ifreq ifr;
	struct sockaddr_in *our_ip;
	struct in_addr in;
	char *pwanip = NULL;
	
	//2011.03.16 Jerry {
	DHCP_T dhcp;
	DNS_TYPE_T dns_type;
	apmib_get( MIB_WAN_DHCP, (void *)&dhcp);
	//2011.03.16 Jerry }

	if (!is_phyconnected())
		strcpy(statusstr, "Disconnected");
	else if (dhcp == PPPOE || dhcp == PPTP || dhcp == L2TP)	//2011.03.16 Jerry 
	{
		DIR *ppp_dir;
		int got_ppp_link;
		struct dirent *entry;

		if((ppp_dir = opendir("/etc/ppp")) == NULL)	//2011.03.16 Jerry
			strcpy(statusstr, "Disconnected");
		else{
			got_ppp_link = 0;
			while((entry = readdir(ppp_dir)) != NULL){
				if(!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
					continue;
				
				if(strstr(entry->d_name, "link") != NULL){
					got_ppp_link = 1;
					break;
				}
			}
			closedir(ppp_dir);
			
			if(got_ppp_link == 0)
				strcpy(statusstr, "Disconnected");
			else if(check_ppp_exist() == -1)
				strcpy(statusstr, "Disconnected");
			else
				strcpy(statusstr, "Connected");
		}
	}
	else {
		/* Open socket to kernel */
		if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
			strcpy(statusstr, "Disconnected");
		else{
			/* Check for valid IP address */
			strncpy(ifr.ifr_name, "eth1", IFNAMSIZ);
			
			if (!ioctl(s, SIOCGIFADDR, &ifr)){
				our_ip = (struct sockaddr_in *) &ifr.ifr_addr;
				in.s_addr = our_ip->sin_addr.s_addr;
				pwanip = inet_ntoa(in);
				
				if (!strcmp(pwanip, "") || pwanip == NULL)
					strcpy(statusstr, "Disconnected");
				else
					strcpy(statusstr, "Connected");
			}
			else
				strcpy(statusstr, "Disconnected");
			
			close(s);
		}
	}
	
	websWrite(wp, "%s", statusstr);
	return 0;
}
//2011.03.21 Jerry }

// 2010.09 James. {
int start_mac_clone(int eid, webs_t wp, int argc, char **argv){
	char *cmd[] = {"start_mac_clone", NULL};
	int pid;

	dbg("start mac clone...\n");
	_eval(cmd, NULL, 0, &pid);
	return 0;
}

int setting_lan(int eid, webs_t wp, int argc, char **argv){
	char lan_ipaddr_t[16];
	char lan_netmask_t[16];
	unsigned int lan_ip_num;
	unsigned int lan_mask_num;
	unsigned int lan_subnet;
	char wan_ipaddr_t[16];
	char wan_netmask_t[16];
	unsigned int wan_ip_num;
	unsigned int wan_mask_num;
	unsigned int wan_subnet;
	const unsigned int MAX_SUBNET = 3232300800;
	const unsigned int MIN_LAN_IP = 3232235521;
	struct in_addr addr;
	unsigned int new_lan_ip_num;
	unsigned int new_dhcp_start_num;
	unsigned int new_dhcp_end_num;
	char new_lan_ip_str[16];
	char new_dhcp_start_str[16];
	char new_dhcp_end_str[16];
	unsigned char buffer[128];

	
	apmib_reinit();	//2011.04.18 Jerry
	//2011.03.21 Jerry {
	memset(lan_ipaddr_t, 0, 16);
	apmib_get( MIB_IP_ADDR,  (void *)buffer);
	memset(&addr, 0, sizeof(addr));
	strcpy(lan_ipaddr_t, inet_ntoa(*((struct in_addr *)buffer)));
	lan_ip_num = ntohl(inet_aton(lan_ipaddr_t, &addr));
	lan_ip_num = ntohl(addr.s_addr);

	memset(lan_netmask_t, 0, 16);
	apmib_get( MIB_SUBNET_MASK,  (void *)buffer);	
	strcpy(lan_netmask_t, inet_ntoa(*((struct in_addr *)buffer)));
	memset(&addr, 0, sizeof(addr));
	lan_mask_num = ntohl(inet_aton(lan_netmask_t, &addr));
	lan_mask_num = ntohl(addr.s_addr);
	lan_subnet = lan_ip_num&lan_mask_num;
	dbg("http: get lan_subnet=%x!\n", lan_subnet);

	char wan_ipaddr[16];
	char wan_netmask[16];
	char wan_gateway[16];
	char wan_hwaddr[18];
	getWanInformation(wan_ipaddr, wan_netmask, wan_gateway, wan_hwaddr);

	memset(wan_ipaddr_t, 0, 16);
	strcpy(wan_ipaddr_t, wan_ipaddr);
	memset(&addr, 0, sizeof(addr));
	wan_ip_num = ntohl(inet_aton(wan_ipaddr_t, &addr));
	wan_ip_num = ntohl(addr.s_addr);

	memset(wan_netmask_t, 0, 16);
	strcpy(wan_netmask_t, wan_netmask);
	memset(&addr, 0, sizeof(addr));
	wan_mask_num = ntohl(inet_aton(wan_netmask_t, &addr));
	wan_mask_num = ntohl(addr.s_addr);
	wan_subnet = wan_ip_num&wan_mask_num;
	dbg("http: get wan_subnet=%x!\n", wan_subnet);
	
	/*int wan_ready;
	apmib_get(MIB_WAN_READY, (void *)&wan_ready); 
	if(wan_ready == 0 || lan_subnet != wan_subnet){
		websWrite(wp, "0");
		return 0;
	}*/
	
	if(lan_subnet >= MAX_SUBNET)
		new_lan_ip_num = MIN_LAN_IP;
	else
		new_lan_ip_num = lan_ip_num+(~lan_mask_num)+1;
	
	new_dhcp_start_num = new_lan_ip_num+1;
	new_dhcp_end_num = new_lan_ip_num+(~inet_network(lan_netmask_t))-2;
	dbg("%u, %u, %u.\n", new_lan_ip_num, new_dhcp_start_num, new_dhcp_end_num);
	memset(&addr, 0, sizeof(addr));
	addr.s_addr = htonl(new_lan_ip_num);
	memset(new_lan_ip_str, 0, 16);
	strcpy(new_lan_ip_str, inet_ntoa(addr));
	memset(&addr, 0, sizeof(addr));
	addr.s_addr = htonl(new_dhcp_start_num);
	memset(new_dhcp_start_str, 0, 16);
	strcpy(new_dhcp_start_str, inet_ntoa(addr));
	memset(&addr, 0, sizeof(addr));
	addr.s_addr = htonl(new_dhcp_end_num);
	memset(new_dhcp_end_str, 0, 16);
	strcpy(new_dhcp_end_str, inet_ntoa(addr));
	dbg("%s, %s, %s.\n", new_lan_ip_str, new_dhcp_start_str, new_dhcp_end_str);

	struct in_addr inIp, inDhcpStart, inDhcpEnd;
	inet_aton(new_lan_ip_str, &inIp);
	apmib_set( MIB_IP_ADDR, (void *)&inIp);
	inet_aton(new_dhcp_start_str, &inDhcpStart);
	apmib_set( MIB_DHCP_CLIENT_START, (void *)&inDhcpStart);
	inet_aton(new_dhcp_end_str, &inDhcpEnd);
	apmib_set( MIB_DHCP_CLIENT_END, (void *)&inDhcpEnd);
	apmib_update(CURRENT_SETTING);
	
	websWrite(wp, "1");
	notify_sysconf("restart_reboot", 0);
	return 0;
	//2011.03.21 Jerry }
}
// 2010.09 James. }

struct ej_handler ej_handlers[] = {
	{ "getInfo", getInfo},
	{ "getIndex", getIndex},
	{ "wlSchList", wlSchList},
	{ "getScheduleInfo", getScheduleInfo},
	{ "wlAcList", wlAcList},
	{ "getModeCombobox", getModeCombobox},
	{ "getDHCPModeCombobox", getDHCPModeCombobox},
	{ "dhcpClientList", dhcpClientList},
	{ "dhcpRsvdIp_List", dhcpRsvdIp_List},
	{ "portFwList", portFwList},
	{ "ipFilterList", ipFilterList},
	{ "portFilterList", portFilterList},
	{ "macFilterList", macFilterList},
	{ "urlFilterList", urlFilterList},
	{ "staticRouteList", staticRouteList},
	{ "kernelRouteList", kernelRouteList},
	{ "sysLogList", sysLogList},
	{ "sysCmdLog", sysCmdLog},
	{ "wirelessClientList", wirelessClientList},
	{ "wlSiteSurveyTbl", wlSiteSurveyTbl},
	{ "wlWdsList", wlWdsList},
	{ "wdsList", wdsList},
	{ "getVirtualIndex", getVirtualIndex},
	{ "getVirtualInfo", getVirtualInfo},
	{ "ipQosList", ipQosList},
	{ "shown_language_option", ej_shown_language_option},
	{ "get_parameter", ej_get_parameter},
	{ "wanlink", wanlink_hook},
	{ "detect_if_wan", detect_if_wan},
	{ "detect_wan_connection", detect_wan_connection},
	{ "detect_dhcp_pppoe", detect_dhcp_pppoe},
	{ "get_wan_status_log", get_wan_status_log},
	{ "login_state_hook", login_state_hook},
	{ "uptime", ej_uptime},
	{ "start_mac_clone", start_mac_clone},
	{ "done_auto_mac", done_auto_mac},
	{ "update_variables", update_variables_ex},
	{ "notify_services", ej_notify_services},
	{ "setting_lan", setting_lan},
	{ "get_wan_status", get_wan_status},
	{ "sysuptime", ej_sysuptime},
	{ "nvram_dump", ej_dump},
	{ "get_arp_table", ej_get_arp_table},
	{ "wl_auth_list", ej_wl_auth_list},
	{ "shown_time", ej_shown_time},
	{ "process_form", process_form},
	{ "get_fw_version", get_fw_version},
	{ "getWanDns", getWanDns},
	{ "apmib_char_to_ascii", ej_apmib_char_to_ascii},
	{ NULL, NULL }
};


#endif /* !WEBS */

/* 
 * Kills process whose PID is stored in plaintext in pidfile
 * @param	pidfile	PID file, signal
 * @return	0 on success and errno on failure
 */
int
kill_pidfile_s(char *pidfile, int sig)
{
	FILE *fp = fopen(pidfile, "r");
	char buf[256];
	extern errno;

	if (fp && fgets(buf, sizeof(buf), fp)) {
		pid_t pid = strtoul(buf, NULL, 0);
		fclose(fp);
		return kill(pid, sig);
  	} else
		return errno;
}


