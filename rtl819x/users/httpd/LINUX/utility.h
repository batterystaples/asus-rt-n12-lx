/*
 *      Include file of utility.c
 *
 *      Authors: David Hsu	<davidhsu@realtek.com.tw>
 *
 *      $Id: utility.h,v 1.3 2011/05/16 01:56:11 jerry_jian Exp $
 *
 */

#ifndef INCLUDE_UTILITY_H
#define INCLUDE_UTILITY_H

#ifdef CONFIG_RTL_WAPI_SUPPORT
//if SYS_TIME_NOT_SYNC_CA exists, our system hasn't sync time yet
#define SYS_TIME_NOT_SYNC_CA "/var/tmp/notSyncSysTime"
#endif

typedef enum { IP_ADDR, SUBNET_MASK, DEFAULT_GATEWAY, HW_ADDR } ADDR_T;

/* type define */
struct user_net_device_stats {
    unsigned long long rx_packets;	/* total packets received       */
    unsigned long long tx_packets;	/* total packets transmitted    */
    unsigned long long rx_bytes;	/* total bytes received         */
    unsigned long long tx_bytes;	/* total bytes transmitted      */
    unsigned long rx_errors;	/* bad packets received         */
    unsigned long tx_errors;	/* packet transmit problems     */
    unsigned long rx_dropped;	/* no space in linux buffers    */
    unsigned long tx_dropped;	/* no space available in linux  */
    unsigned long rx_multicast;	/* multicast packets received   */
    unsigned long rx_compressed;
    unsigned long tx_compressed;
    unsigned long collisions;

    /* detailed rx_errors: */
    unsigned long rx_length_errors;
    unsigned long rx_over_errors;	/* receiver ring buff overflow  */
    unsigned long rx_crc_errors;	/* recved pkt with crc error    */
    unsigned long rx_frame_errors;	/* recv'd frame alignment error */
    unsigned long rx_fifo_errors;	/* recv'r fifo overrun          */
    unsigned long rx_missed_errors;	/* receiver missed packet     */
    /* detailed tx_errors */
    unsigned long tx_aborted_errors;
    unsigned long tx_carrier_errors;
    unsigned long tx_fifo_errors;
    unsigned long tx_heartbeat_errors;
    unsigned long tx_window_errors;
};

/* Entry info scanned by site survey */

#define SSID_LEN	32

#if defined(CONFIG_RTK_MESH) ||  defined(CONFIG_RTL_819X)  /*add for RTL819X since wlan driver default include mesh data*/
//by GANTOE for site survey 2008/12/26
#define MESHID_LEN 32 
#endif 

#define	MAX_BSS_DESC	64

typedef struct _OCTET_STRING {
    unsigned char *Octet;
    unsigned short Length;
} OCTET_STRING;


typedef enum _BssType {
    infrastructure = 1,
    independent = 2,
} BssType;


typedef	struct _IbssParms {
    unsigned short	atimWin;
} IbssParms;


typedef enum _Capability {
    cESS 		= 0x01,
    cIBSS		= 0x02,
    cPollable		= 0x04,
    cPollReq		= 0x01,
    cPrivacy		= 0x10,
    cShortPreamble	= 0x20,
} Capability;


typedef enum _Synchronization_Sta_State{
    STATE_Min		= 0,
    STATE_No_Bss	= 1,
    STATE_Bss		= 2,
    STATE_Ibss_Active	= 3,
    STATE_Ibss_Idle	= 4,
    STATE_Act_Receive	= 5,
    STATE_Pas_Listen	= 6,
    STATE_Act_Listen	= 7,
    STATE_Join_Wait_Beacon = 8,
    STATE_Max		= 9
} Synchronization_Sta_State;


typedef enum _wlan_mac_state {
    STATE_DISABLED=0, STATE_IDLE, STATE_SCANNING, STATE_STARTED, STATE_CONNECTED, STATE_WAITFORKEY
} wlan_mac_state;


typedef struct _bss_info {
    unsigned char state;
    unsigned char channel;
    unsigned char txRate;
    unsigned char bssid[6];
    unsigned char rssi, sq;	// RSSI  and signal strength
    unsigned char ssid[SSID_LEN+1];
} bss_info;

#if defined(CONFIG_RTL_WAPI_SUPPORT)
#define	SECURITY_INFO_WAPI		0xa5a56789
#endif
typedef struct _BssDscr {
    unsigned char bdBssId[6];
    unsigned char bdSsIdBuf[SSID_LEN];
    OCTET_STRING  bdSsId;

#if defined(CONFIG_RTK_MESH) || defined(CONFIG_RTL_819X) 
	//by GANTOE for site survey 2008/12/26
	unsigned char bdMeshIdBuf[MESHID_LEN]; 
	OCTET_STRING bdMeshId; 
#endif 
    BssType bdType;
    unsigned short bdBcnPer;			// beacon period in Time Units
    unsigned char bdDtimPer;			// DTIM period in beacon periods
    unsigned long bdTstamp[2];			// 8 Octets from ProbeRsp/Beacon
    IbssParms bdIbssParms;			// empty if infrastructure BSS
    unsigned short bdCap;				// capability information
    unsigned char ChannelNumber;			// channel number
    unsigned long bdBrates;
    unsigned long bdSupportRates;		
    unsigned char bdsa[6];			// SA address
    unsigned char rssi, sq;			// RSSI and signal strength
    unsigned char network;			// 1: 11B, 2: 11G, 4:11G
} BssDscr, *pBssDscr;


typedef struct _sitesurvey_status {
    unsigned char number;
    unsigned char pad[3];
    BssDscr bssdb[MAX_BSS_DESC];
} SS_STATUS_T, *SS_STATUS_Tp;

typedef enum _wlan_wds_state {
    STATE_WDS_EMPTY=0, STATE_WDS_DISABLED, STATE_WDS_ACTIVE
} wlan_wds_state;

typedef struct _WDS_INFO {
	unsigned char	state;
	unsigned char	addr[6];
	unsigned long	tx_packets;
	unsigned long	rx_packets;
	unsigned long	tx_errors;
	unsigned char	txOperaRate;
} WDS_INFO_T, *WDS_INFO_Tp;

struct _misc_data_ {
	unsigned char	mimo_tr_hw_support;
	unsigned char	mimo_tr_used;	
	unsigned char	resv[30];
};

/**************************BT*********************************/
#ifdef CONFIG_RTL_BT_CLIENT
#define SERVER_PORT 18000
struct torrent_t {
	char* name;
	unsigned short status;//0 not running 1 running 2 start_paused
	int ctorrent;
	char* dfiles;
	unsigned int n_have, n_total, piece_size;
	unsigned int index;
};

struct stats_t {
	unsigned long long up, down;//byte
	unsigned int totaltime/*sec*/, sumtorrents;
	long double reserverd;
	unsigned long long dsize, dfree;//byte
};

struct ctfile_t {
	unsigned int fileno, priority, n_pieces, n_have, n_available;
	unsigned long long filesize;
	char *filename;
	unsigned short download;
	struct ctfile_t *next;
};

struct ctorrent_t {
	unsigned int seeders;
	unsigned int leechers;
	unsigned int n_have;
	unsigned int n_total;
	unsigned int n_avail;
	unsigned int dl_rate;
	unsigned int ul_rate;
	unsigned long long dl_total;
	unsigned long long ul_total;
	unsigned int dl_limit;
	unsigned int ul_limit;
	unsigned long long size, dsize;
	unsigned int seed_time, total_time;
	unsigned long long start_time;
	double seed_ratio;
	unsigned int piece_size;
	unsigned short cmd_count;
	char* fname;
	int severity;
	char* msg;
	short valid;
	unsigned int udrates[2][3];
	unsigned short udidx;
	int socket;
	unsigned short paused;
	struct ctfile_t files;
	unsigned short protocol;
	char* dfiles;
	unsigned int index;
};
#endif
/**************************BT end*****************************/

int getWlStaNum( char *interface, int *num );
int getWlStaInfo( char *interface,  WLAN_STA_INFO_Tp pInfo );
int getInAddr(char *interface, ADDR_T type, void *pAddr);
int getDefaultRoute(char *interface, struct in_addr *route);
int getWlSiteSurveyResult(char *interface, SS_STATUS_Tp pStatus );
int getWlSiteSurveyRequest(char *interface, int *pStatus);
int getWlJoinRequest(char *interface, pBssDscr pBss, unsigned char *res);
int getWlJoinResult(char *interface, unsigned char *res);
int getWlBssInfo(char *interface, bss_info *pInfo);
int getWdsInfo(char *interface, char *pInfo);
int getMiscData(char *interface, struct _misc_data_ *pData);

#ifdef CONFIG_RTK_MESH 
	//GANTOE for site survey 2008/12/26
int setWlJoinMesh (char*, unsigned char*, int, int, int); 
int getWlMeshLink (char*, unsigned char*, int);	// This function might be removed when the mesh peerlink precedure has been completed
int getWlMib (char*, unsigned char*, int);
#endif

extern pid_t find_pid_by_name( char* pidName);
int getStats(char *interface, struct user_net_device_stats *pStats);
int getEth0PortLink(unsigned int port_index);
unsigned int getEthernetBytesCount(unsigned int port_index);
int getEthernetEeeState(unsigned int port_index);
int getWanLink(char *interface);
int getWanInfo(char *pWanIP, char *pWanMask, char *pWanDefIP, char *pWanHWAddr);
#ifdef UNIVERSAL_REPEATER
int isVxdInterfaceExist(char *interface);
#endif

int displayPostDate(char *postDate);

int fwChecksumOk(char *data, int len);
void kill_processes(void);
void killDaemon(int wait);
//int updateConfigIntoFlash(unsigned char *data, int total_len, int *pType, int *pStatus);

#ifdef CONFIG_CWMP_TR069
#include <fcntl.h>
int getWlanMib(int wlanIndex, int id, void *value);
int setWlanMib(int wlanIndex, int id, void *value);
int getWlanBssInfo(int wlanIndex, void *value);

#if 1//defined(CONFIG_RTL_8196B)
#define FW_SIGNATURE_WITH_ROOT	((char *)"cr6b")
#define FW_SIGNATURE			((char *)"cs6b")
#define WEB_SIGNATURE			((char *)"w6bg")
#define ROOT_SIGNATURE			((char *)"r6br")

#endif

#endif //#ifdef CONFIG_CWMP_TR069

int SetWlan_idx(char * wlan_iface_name);
short whichWlanIfIs(PHYBAND_TYPE_T phyBand);
unsigned int getWLAN_ChipVersion();

#if defined(CONFIG_REPEATER_WPS_SUPPORT) || defined(POWER_CONSUMPTION_SUPPORT)
typedef enum { WLAN_OFF=0, WLAN_NO_LINK=1, WLAN_LINK=2} WLAN_STATE_T;
WLAN_STATE_T updateWlanifState(char *wlanif_name);
#endif

#endif // INCLUDE_UTILITY_H
