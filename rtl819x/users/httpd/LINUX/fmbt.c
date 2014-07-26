/*This file handles BT webpage form request
  *
  */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <time.h>
#include <net/route.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <net/if.h>

/*-- Local inlcude files --*/
//#include "../webs.h"	//Comment by Jerry
#include "../httpd.h"	//Added by Jerry
#ifdef HOME_GATEWAY
//#include "../wsIntrn.h"	//Comment by Jerry
#endif
#include "apmib.h"
#include "apform.h"
#include "utility.h"

#ifdef CONFIG_RTL_BT_CLIENT
/* Down Up Dir and Download Limit Upload limt and refresh time
  *Fiv MIB Save To Flash
  *Shell Script should call the dctcs(need to check dir exits)
  *
  */
void formBTBasicSetting(webs_t wp, char_t *path, char_t *query)
{
	char *downdir;
	char *updir;
	char *strptr;
	char *nextwebpage;
	int ulimit;
	int dlimit;
	int refreshtime;
	int enabled;
	int pid;
	char tmpBuf[256];
	nextwebpage=websGetVar(wp, T("nextwebpage"),T(""));
	downdir=websGetVar(wp, T("btdownloaddir"),T(""));
	updir=websGetVar(wp, T("btuploaddir"),T(""));
	char_replace(downdir,'\\', '/');
	char_replace(updir,'\\', '/');
	if(!dirExits(downdir) ||!dirExits(updir))
	{
		ERR_MSG("Directory Not Exists!!!");
		return;
	}
	apmib_set(MIB_BT_UPLOAD_DIR,updir);
	apmib_set(MIB_BT_DOWNLOAD_DIR,downdir);
	strptr=websGetVar(wp, T("totalulimit"),T(""));
	if(strptr)
		ulimit=atoi(strptr);
	apmib_set(MIB_BT_TOTAL_ULIMIT,&ulimit);
	strptr=websGetVar(wp, T("totaldlimit"),T(""));
	if(strptr)
		dlimit=atoi(strptr);
	apmib_set(MIB_BT_TOTAL_DLIMIT,&dlimit);
	strptr=websGetVar(wp, T("refreshtime"),T(""));
	if(strptr)
		refreshtime=atoi(strptr);
	apmib_set(MIB_BT_REFRESH_TIME,&refreshtime);
	strptr=websGetVar(wp, T("bt_enabled"),T(""));
	if(strptr)
		enabled=atoi(strptr);
	apmib_set(MIB_BT_ENABLED,&enabled);
	
	/*Save to flash*/
	apmib_update(CURRENT_SETTING);

	/*run dctcs shell*/
#ifndef NO_ACTION
	pid = fork();
        if (pid) {
	      	waitpid(pid, NULL, 0);
	}
        else if (pid == 0) {
		snprintf(tmpBuf, 100, "%s/%s", _CONFIG_SCRIPT_PATH, _BT_SCRIPT_PROG);
		execl(tmpBuf, _BT_SCRIPT_PROG, NULL);
             exit(1);
        }
#endif
	/*webredirect*/
	websRedirect(wp, nextwebpage);
}

/*Index Format: /index_1/index_2/index_3......*/
unsigned char * getbtclientIndex(unsigned char *indexstr, int *index)
{
	unsigned char buffer[5];
	unsigned char *ptr=indexstr;
	unsigned char *tmpptr=buffer;
	
	if('/' == (*ptr))
		ptr++;
	else
		return NULL;
	
	while(*ptr && ( '/' != *ptr))
	{
		*tmpptr++=*ptr++;
	}
	*tmpptr=0;
	(*index)=atoi(buffer);
	return ptr;
}
/*Show Bt Torrents and add/del/update.... 
  *
  */
void formBTClientSetting(webs_t wp, char_t *path, char_t *query)
{
	char *strptr;
	char *clientptr;
	char *tiptr;
	char *operation;
	char *nextwebpage;
	int index;
	nextwebpage=websGetVar(wp, T("nextwebpage"),T(""));
	operation=websGetVar(wp, T("operation"),T(""));
	//printf("operation value: %s\n",operation);
	/*get index index format /index_1/index_2/...*/
	clientptr=websGetVar(wp,T("clientsindex"),T(""));
	tiptr=websGetVar(wp,T("torrentsindex"),T(""));
	//printf("clientptr value: %s\n",clientptr);
	//printf("tiptr value: %s\n",tiptr);
	/*start del should use tiptr*/
	/*pause update adn quit shoud use clientptr*/
	/*start*/
	if(!strcmp(operation,"start"))
	{	
		/*start only one a time*/
		strptr=tiptr;
		while(strptr=getbtclientIndex(strptr,&index))
		{
			if(index >= 0)
				bt_startTorrent(index);
		}
	}
	/*pause*/
	else if(!strcmp(operation,"pause"))
	{
		strptr=clientptr;
		while(strptr=getbtclientIndex(strptr,&index))
		{
			if(index >= 0)
				bt_clientPause(index);
		}
	}
	/*stop*/
	else if(!strcmp(operation,"stop"))
	{
		strptr=clientptr;
		while(strptr=getbtclientIndex(strptr,&index))
		{
			if(index >= 0)
				bt_clientQuit(index);
		}
	}
	/*update*/
	else if(!strcmp(operation,"update"))
	{
		strptr=clientptr;
		while(strptr=getbtclientIndex(strptr,&index))
		{
			if(index >= 0)
				bt_clientUpdate(index);
		}
	}
	/*delete. delelte torrent or files*/
	else if(!strcmp(operation,"delete"))
	{
		strptr=tiptr;
		while(strptr=getbtclientIndex(strptr,&index))
		{
			if(index >= 0)
				bt_deleteTorrent(index,0);
		}
	}
	else if(!strcmp(operation,"deleteallfiles"))
	{
		strptr=clientptr;
		while(strptr=getbtclientIndex(strptr,&index))
		{
			if(index >= 0)
				bt_deleteTorrent(index,1);
		}
	}
	/*details*/
	else if(!strcmp(operation,"details"))
	{
		
	}
	/*info*/
	else if(!strcmp(operation,"info"))
	{
		
	}
	/*webredirect*/
	websRedirect(wp,nextwebpage);
}
/*Setting BT files to Download
  *
  */
 void formBTFileSetting(webs_t wp, char_t *path, char_t *query)
{	
	char *strptr;
	char *filestr;
	char *nextwebpage;
	int len;
	int clientindex;
	char tmpbuf[128];
	
	nextwebpage=websGetVar(wp, T("nextwebpage"),T(""));
	strptr=websGetVar(wp,T("clientindex"),T(""));
	if(strptr)
		clientindex=atoi(strptr);
	/*get fileindex*/
	filestr=websGetVar(wp,T("selectedfiles"),T(""));
	/*get client index*/
	strptr=websGetVar(wp,T("selectednum"),T(""));
	if(strptr)
		len=atoi(strptr);
	/*call setfile function*/
	bt_setfiles(clientindex, len,filestr);

	/*take a break ~!~*/
	sleep(1);
	strcpy(tmpbuf,nextwebpage);
	sprintf(tmpbuf+strlen(tmpbuf),"?ctorrent=%d",clientindex);
	websRedirect(wp,tmpbuf);
}

/*New BT Torrent*/
void formBTNewTorrent(webs_t wp, char_t *path, char_t *query)
{
#if 0	//Comment by Jerry
	char filepath[128];
	char *strptr;
	char *filename;
	char *nextwebpage;
	nextwebpage=websGetVar(wp, T("submit-url"),T(""));
	strptr=websGetVar(wp,T("filename"),T(""));
	char_replace(strptr,'\\','/');
	filename=strrchr(strptr, '/');
	if(filename == NULL)
	{
		printf("ERROR, filename NULL\n");
		return;
	}
	//printf("filename %s \n",filename);
	if(!apmib_get(MIB_BT_UPLOAD_DIR,filepath))
	{
		ERR_MSG("Get seeds directory failed");
		return;
	}
	if(!dirExits(filepath))
	{
		ERR_MSG("Seeds Directory Not Exists");
		return;
	}
	strcat(filepath,filename);
	//printf("filepath %s\n",filepath);
	bt_saveTorrentfile(filepath,wp->postData, wp->lenPostData);
	websRedirect(wp,nextwebpage);
#endif
}
#endif
