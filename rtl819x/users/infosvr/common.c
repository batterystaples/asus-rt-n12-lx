/*
 *
 *  State Transaction:
 *  0. STOP
 *  1. CONNECTING_PROFILE
 * 	a. scanning
 *  2. CONNECTING_ONE
 *  3. SCANNING
 *  4. CONNECTED
 *  5. BEING_AP
 * 
 *  CONNECTING_PROFILE --> CONNECTED --> SCANNING ---|
 *                     \-> BEING_AP -/               |                 
 *                                                   |
 *                     CONNECTED <- CONNECTING_ONE <--
 *  CONNECTED <- CONNECT_PROFILE <-/
 *  BEING_AP <-/
 *
 *  Environment
 *  1. Power on and connect to existed LAN
 *  2. Power on and connect to existed WLAN
 *  3. Power on and no LAN/WLAN is connected to 
 *
 */

/* 
 *
 *  State Transaction:
 *  0. STOP
 *  1. CONNECTING_PROFILE
 *  2. CONNECTING_ONE
 *  3. SCANNING
 *  4. CONNECTED
 *  5. BEING_AP
 * 
 *  CONNECTING_PROFILE --> CONNECTED --> SCANNING ---|
 *		     \-> BEING_AP -/	       |		 
 *						   |
 *		     CONNECTED <- CONNECTING_ONE <--
 *  CONNECTED <- CONNECT_PROFILE <-/
 *  BEING_AP <-/
 *
 *  Environment
 *  1. Power on and connect to existed LAN
 *  2. Power on and connect to existed WLAN
 *  3. Power on and no LAN/WLAN is connected to 
 *
 */
						
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/vfs.h>	/* get disk type */
#include <net/if.h>
#include <nvram/bcmnvram.h>
#include <shutils.h>
typedef unsigned char   bool;
//#include <wlutils.h>
#include <unistd.h>		// eric++
#include <dirent.h>		// eric++
#include <syslog.h>
#include "iboxcom.h"
#include "apmib.h"	//Edison 2011.4.26 
#include <arpa/inet.h>	//Edison 2011.4.26 
#include "endianness.h"	//Edison 2011.4.28
#define SIOCETHTOOL 0x8946
#define MAX_PROFILE_NUMBER 32
#define MAX_SITE_NUMBER 24

enum 
{
	STA_STATE_STOP = 0,
	STA_STATE_CONNECTING_PROFILE,
	STA_STATE_CONNECTING_ONE,
	STA_STATE_SCANNING_PROFILE,
	STA_STATE_SCANNING,
	STA_STATE_CONNECTED,
	STA_STATE_BEING_AP
} STA_STATE;

#define STA_ISTIMEOUT(t) ((unsigned long)(now-sta_timer)>=t)
#define STA_STATE_TIMEOUT_CONNECTING 10 // 10 sec
#define STA_STATE_TIMEOUT_SCANNING 30 //30 sec
#define STA_STATE_TIMEOUT_SCANNING_PROFILE 1 //1 sec

int sta_state = STA_STATE_STOP;
int sta_profile = 0;
int sta_scan = 0;
time_t sta_timer = 0;
time_t now;
	
char pdubuf_res[INFO_PDU_LENGTH];

PKT_GET_INFO_STA stainfo_g;
int sites_g_count=0;
SITES sites_g[MAX_SITE_NUMBER];
int profiles_g_count=0;
PROFILES profiles_g[MAX_PROFILE_NUMBER];
int scan_g_type;
int scan_g_mode;

int
kill_pidfile_s(char *pidfile, int sig)	// copy from rc/common_ex.c
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

extern char ssid_g[];
extern char netmask_g[];
extern char productid_g[];
extern char firmver_g[];
extern char mac[];

#if 1
//Edison 2011.4.27
int
get_ftype(char *type)	/* get disk type */
{
	struct statfs fsbuf;
	long f_type;
	double free_size;
	char *mass_path =NULL; //nvram_safe_get("usb_mnt_first_path");
	//if (!mass_path)
	//	mass_path = "/media/AiDisk_a1";

	if (statfs(mass_path, &fsbuf))
	{
		perror("infosvr: statfs fail");
		return -1;
	}

	f_type = fsbuf.f_type;
	free_size = (double)((double)((double)fsbuf.f_bfree * fsbuf.f_bsize)/(1024*1024));
	printf("f_type is %x\n", f_type);	// tmp test
	sprintf(type, "%x", f_type);
	return free_size;
}
#endif

char *processPacket(int sockfd, char *pdubuf)
{

    apmib_reinit();

    unsigned char buffer[500];	//Edison
    int opmode;

    IBOX_COMM_PKT_HDR	*phdr;
    IBOX_COMM_PKT_HDR_EX *phdr_ex;
    IBOX_COMM_PKT_RES_EX *phdr_res;
    PKT_GET_INFO *ginfo;

#ifdef WAVESERVER	// eric++
    int fail = 0;
    pid_t pid;
    DIR *dir;
    int fd, ret, bytes;
    unsigned char tmp_buf[15];	// /proc/XXXXXX
    WS_INFO_T *wsinfo;
#endif
//#ifdef WL700G
    STORAGE_INFO_T *st;
//#endif
//    int i;
    char ftype[8], prinfo[128];	/* get disk type */
    int free_space;

    phdr = (IBOX_COMM_PKT_HDR *)pdubuf;  
    phdr_res = (IBOX_COMM_PKT_RES_EX *)pdubuf_res;
	swapbytes16(phdr->OpCode);	//Edison 2011.4.28 normal
	swapbytes32(phdr->Info);	//Edison 2011.4.28 normal
//    printf("Get: %x %x %x\n", phdr->ServiceID, phdr->PacketType, phdr->OpCode);
    
    if (phdr->ServiceID==NET_SERVICE_ID_IBOX_INFO && phdr->PacketType==NET_PACKET_TYPE_CMD)
    {	    
	if (phdr->OpCode!=NET_CMD_ID_GETINFO && phdr->OpCode!=NET_CMD_ID_GETINFO_MANU && phdr_res->OpCode==phdr->OpCode && phdr_res->Info==phdr->Info)
	{	
		// if transaction id is equal to the transaction id of the last response message, just re-send message again;
		return pdubuf_res;
	}	
	swapbytes16(phdr->OpCode);	//Edison 2011.4.28
	phdr_res->ServiceID=NET_SERVICE_ID_IBOX_INFO;
	phdr_res->PacketType=NET_PACKET_TYPE_RES;
	phdr_res->OpCode=phdr->OpCode;
	swapbytes16(phdr->OpCode);	//Edison 2011.4.28 normal
	if (phdr->OpCode!=NET_CMD_ID_GETINFO && phdr->OpCode!=NET_CMD_ID_GETINFO_MANU)
	{
		swapbytes32(phdr->Info);	//Edison 2011.4.28
		swapbytes16(phdr->OpCode);	//Edison 2011.4.28
		phdr_ex = (IBOX_COMM_PKT_HDR_EX *)pdubuf;	
		swapbytes32(phdr->Info);	//Edison 2011.4.28
		swapbytes16(phdr->OpCode);	//Edison 2011.4.28
		// Check Mac Address
		if (memcpy(phdr_ex->MacAddress, mac, 6)==0)
		{
			printf("Mac Error %2x%2x%2x%2x%2x%2x\n",
				(unsigned char)phdr_ex->MacAddress[0],
				(unsigned char)phdr_ex->MacAddress[1],
				(unsigned char)phdr_ex->MacAddress[2],
				(unsigned char)phdr_ex->MacAddress[3],
				(unsigned char)phdr_ex->MacAddress[4],
				(unsigned char)phdr_ex->MacAddress[5]
				);
			return NULL;
		}
		
		// Check Password
		//if (strcmp(phdr_ex->Password, "admin")!=0)
		//{
		//	phdr_res->OpCode = phdr->OpCode | NET_RES_ERR_PASSWORD;
		//	printf("Password Error %s\n", phdr_ex->Password);	
		//	return NULL;
		//}
		swapbytes32(phdr_ex->Info);	//Edison 2011.4.28 unormal
		phdr_res->Info = phdr_ex->Info;
		swapbytes32(phdr_ex->Info);	//Edison 2011.4.28 normal
		memcpy(phdr_res->MacAddress, phdr_ex->MacAddress, 6);
	}
	switch(phdr->OpCode)
	{
		case NET_CMD_ID_GETINFO:
		     ginfo=(PKT_GET_INFO *)(pdubuf_res+sizeof(IBOX_COMM_PKT_RES));
		     memset(ginfo, 0, sizeof(ginfo));
	
		     apmib_get( MIB_WLAN_SSID,  (void *)buffer);
		     strcpy(ssid_g, buffer);

		     strcpy(productid_g, MODEL_NAME);

   		     strcpy(ginfo->SSID, ssid_g);
		     strcpy(ginfo->NetMask, netmask_g);
		     strcpy(ginfo->ProductID, productid_g);	// disable for tmp
		     strcpy(ginfo->FirmwareVersion, firmver_g); // disable for tmp
		     
		     memcpy(ginfo->MacAddress, mac, 6);
#ifdef WCLIENT
		     ginfo->OperationMode = OPERATION_MODE_WB;
		     ginfo->Regulation = 0xff;
#endif

#ifdef WAVESERVER    // eric++
	     	     // search /tmp/waveserver and get information
	     	     wsinfo = (WS_INFO_T*) (pdubuf_res + sizeof (IBOX_COMM_PKT_RES) + sizeof (PKT_GET_INFO));

	     	     fd = open (WS_INFO_FILENAME, O_RDONLY);
	     	     if (fd != -1)	{
				bytes = sizeof (WS_INFO_T);
				while (bytes > 0)	{
			    	ret = read (fd, wsinfo, bytes); 
		    		if (ret > 0)			{ bytes -= ret;		} 
					else if (ret < 0)		{ fail++; break;	} 
					else if (ret == 0)		{ fail++; break;	}
		 		} /* while () */
			} else {
				fail++;
			}

			if (fail == 0 && bytes == 0)	{
				ret = read (fd, &pid, sizeof (pid_t));
				if (ret == sizeof (pid_t))	{
			    	sprintf (tmp_buf, "/proc/%d", pid);
			    	dir = opendir (tmp_buf);
			    	if (dir == NULL)	{	// file exist, but the process had been killed
		    		    fail++;
				    }
				    closedir (dir);
				} else {	// file not found or error occurred
					fail++;
				}
	   		}

			if (fail != 0)	{
		    		memset (wsinfo, 0, sizeof (WS_INFO_T));
			}
#endif /* #ifdef WAVESERVER */
	#ifdef WAVESERVER
	     		st = (STORAGE_INFO_T *) (pdubuf_res + sizeof (IBOX_COMM_PKT_RES) + sizeof (PKT_GET_INFO) + sizeof(WS_INFO_T));
	#else
	     		st = (STORAGE_INFO_T *) (pdubuf_res + sizeof (IBOX_COMM_PKT_RES) + sizeof (PKT_GET_INFO));
	#endif
		  	//getStorageStatus(st);	//Edison 2011.4.27 no use
			sendInfo(sockfd, pdubuf_res);
			return pdubuf_res;		     	

		case NET_CMD_ID_MANU_CMD:
		{
		     #define MAXSYSCMD 256
		     char cmdstr[MAXSYSCMD];
		     PKT_SYSCMD *syscmd;
		     PKT_SYSCMD_RES *syscmd_res;
		     FILE *fp;

		     syscmd = (PKT_SYSCMD *)(pdubuf+sizeof(IBOX_COMM_PKT_HDR_EX));
		     syscmd_res = (PKT_SYSCMD_RES *)(pdubuf_res+sizeof(IBOX_COMM_PKT_RES_EX));

		     if (syscmd->len>=MAXSYSCMD) syscmd->len=MAXSYSCMD;
		     syscmd->cmd[syscmd->len]=0;
		     syscmd->len=strlen(syscmd->cmd);
		     printf("system cmd: %d %s\n", syscmd->len, syscmd->cmd);
   
			if (!strcmp(syscmd->cmd,"nvram get sw_mode"))
			{
				FILE *fp;
				int opmode;
				fp=fopen("/var/sys_op","r");
				fscanf(fp,"%d",&opmode);
				fclose(fp);

				if (opmode==0){
					strcpy(cmdstr, "echo 1 > /tmp/syscmd.out");
				}else if(opmode==1){
					strcpy(cmdstr, "echo 3 > /tmp/syscmd.out");
				}
			}else{
				sprintf(cmdstr, "%s > /tmp/syscmd.out", syscmd->cmd);
			}
			system(cmdstr);

			printf("rund: %s\n", cmdstr);
			fp = fopen("/tmp/syscmd.out", "r");

			if (fp!=NULL)
			{
				strcpy(syscmd->cmd,"nvram get sw_mode");	//Edison 2011.4.27
				syscmd_res->len = fread(syscmd_res->res, 1, sizeof(syscmd_res->res), fp);
				fclose(fp);
			}
			else syscmd_res->len=0;
			printf("%d %s\n", syscmd_res->len, syscmd_res->res);
			/* repeat 3 times for MFG by Yen*/
			sendInfo(sockfd, pdubuf_res);
			sendInfo(sockfd, pdubuf_res);
			sendInfo(sockfd, pdubuf_res);
			/* end of MFG */
		     
	 	     return pdubuf_res;
		}
		default:
			return NULL;	
	}
    }
    return NULL;
}
