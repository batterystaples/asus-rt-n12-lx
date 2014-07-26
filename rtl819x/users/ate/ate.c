#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "apmib.h"
#include "shutils.h"
#include <sys/stat.h>
#include <shutils.h>

//----------------------------WanLanStatus
#include <sys/ioctl.h>
#include <cmd.h>
#include <net/if.h>
#define RTL819X_IOCTL_READ_PORT_STATUS	(SIOCDEVPRIVATE + 0x01)
#define MDIO_BUFSIZE 516 //2 + 2 + 2*255 + 2

int get_lanport_status(int portnum,struct lan_port_status *port_status);
int do_cmd(int id , char *cmd ,int cmd_len ,int relply);
static int _getlanstatus(char *cmd , int cmd_len);
int portname_to_num(char *name);
static int pack_rsp_frame(int cmd_bad, unsigned char cmd_id, int len, unsigned char *in, unsigned char *out);
void mdio_write_data(unsigned char *data, int len);
void print_port_status(char *name,char *status);
static int get_token(char *line, char **token1, char **token2, char **token3, char **token4);
void print_WanLanStatus(char *name,char *line);
static int fd;
char *lan_link_spec[2] = {"DOWN","UP"};
//char *lan_speed_spec[3] = {"10M","100M","1G"};
char *enable_spec[2] = {"DIsable","Enable"};
char *lan_speed_spec[3] = {"M","M","G"};	//M:10/100Mbps  G:1000Mbps
struct cmd_entry cmd_table[]={ \
/*Action cmd - ( name, func) */
	CMD_DEF(cfgwrite,_getlanstatus),
	CMD_DEF(cfgread, _getlanstatus),	
	CMD_DEF(getstainfo, _getlanstatus),
	CMD_DEF(getassostanum,_getlanstatus),
	CMD_DEF(getbssinfo,_getlanstatus),
	CMD_DEF(getwdsinfo,_getlanstatus),	
	CMD_DEF(sysinit, _getlanstatus),
	CMD_DEF(getstats, _getlanstatus),
	CMD_DEF(getlanstatus, _getlanstatus),
	/* last one type should be LAST_ENTRY - */   
	{0}
};

int isFileExist(char *file_name);

int main(int argc, char **argv)
{

   int value, i, argNum=0;
   unsigned char CC[3];
   unsigned char mac[6];
   unsigned char wsc_pin[9];
   unsigned char wsc_pin1[9];
   

   if ( !apmib_init()) {
	printf("Initialize AP HW MIB failed!\n");
	return -1;
   }

   else if (!strcmp(argv[argNum], "ATE_Set_StartATEMode"))
   {
	system("echo > /tmp/StartATEMode");

	if(isFileExist("/tmp/StartATEMode"))
	   puts("1");

	char *argv[] = {"atewatchdog", NULL};
	pid_t pid;
	return _eval(argv, NULL, 0, &pid);
   }

   else if (!strcmp(argv[argNum], "ATE_Set_AllLedOn"))
   {	
	system("echo 1 > /proc/gpio");
	puts("1");
	return 0;
   }

   else if (!strcmp(argv[argNum], "ATE_Set_AllLedOff"))
   {
	system("echo 0 > /proc/gpio");
	puts("1");
	return 0;
   }

   else if (!strcmp(argv[argNum], "ATE_Set_MacAddr_2G")) {
	if (argc == 2)
	{
	   if (ether_atoe(argv[1], mac))
	   {
	      apmib_set(MIB_HW_WLAN_ADDR,mac);
	      apmib_set(MIB_HW_NIC0_ADDR,mac);
	      for(i=5;i>=0;i--){
		if (mac[i]==0xff)
			mac[i]=0x00;
		else{
			mac[i]++;
			break;
		}	
	      }	
	      apmib_set(MIB_HW_NIC1_ADDR,mac);

	      for(i=5;i>=0;i--){
		if (mac[i]==0xff)
			mac[i]=0x00;
		else{
			mac[i]++;
			break;
		}	
	      }	
	      apmib_set(MIB_HW_WLAN_ADDR1,mac);
	      for(i=5;i>=0;i--){
		if (mac[i]==0xff)
			mac[i]=0x00;
		else{
			mac[i]++;
			break;
		}	
	      }	
	      apmib_set(MIB_HW_WLAN_ADDR2,mac);
	      for(i=5;i>=0;i--){
		if (mac[i]==0xff)
			mac[i]=0x00;
		else{
			mac[i]++;
			break;
		}	
	      }	
	      apmib_set(MIB_HW_WLAN_ADDR3,mac);
	      for(i=5;i>=0;i--){
		if (mac[i]==0xff)
			mac[i]=0x00;
		else{
			mac[i]++;
			break;
		}	
	      }	
	      apmib_set(MIB_HW_WLAN_ADDR4,mac);
	      apmib_update(1);
	      apmib_get(MIB_HW_WLAN_ADDR, (void *)mac);
	      printf("%02X:%02X:%02X:%02X:%02X:%02X\n",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
	   }
	}
	return 0;
   }

   else if (!strcmp(argv[argNum], "ATE_Set_RegulationDomain")) {
      if (argc == 2)
      {
	if (strlen(argv[1])!=2)
	{
	printf("error\n");
		return 0;
	}
		
    	else if (!strcmp(argv[1], "CA")){
		value = 2;	//IC
		apmib_set(MIB_HW_REG_DOMAIN,(void *)&value);
		apmib_update(1);
	}else if (!strcmp(argv[1], "ES")){
		value = 4;	//SPAIN
		apmib_set(MIB_HW_REG_DOMAIN,(void *)&value);
		apmib_update(1);
	}
	else if (!strcmp(argv[1], "FR")){
		value = 5;	//FRANCE
		apmib_set(MIB_HW_REG_DOMAIN,(void *)&value);
		apmib_update(1);
	}
	else if (!strcmp(argv[1], "JP")){
		value = 6;	//MKK
		apmib_set(MIB_HW_REG_DOMAIN,(void *)&value);
		apmib_update(1);
	}
	else if ((!strcmp(argv[1], "BR"))||(!strcmp(argv[1], "CO"))||(!strcmp(argv[1], "DB"))
           	||(!strcmp(argv[1], "DO"))||(!strcmp(argv[1], "GT"))||(!strcmp(argv[1], "IL"))
           	||(!strcmp(argv[1], "MX"))||(!strcmp(argv[1], "NO"))||(!strcmp(argv[1], "PA"))
           	||(!strcmp(argv[1], "PH"))||(!strcmp(argv[1], "PR"))||(!strcmp(argv[1], "TW"))
           	||(!strcmp(argv[1], "US"))||(!strcmp(argv[1], "UZ")))
		{
		value = 1;	//FCC
		apmib_set(MIB_HW_REG_DOMAIN,(void *)&value);
		apmib_update(1);
		}
	else if ((!strcmp(argv[1], "AL"))||(!strcmp(argv[1], "DZ"))||(!strcmp(argv[1], "AR"))
           	||(!strcmp(argv[1], "AM"))||(!strcmp(argv[1], "AU"))||(!strcmp(argv[1], "AT"))
           	||(!strcmp(argv[1], "AZ"))||(!strcmp(argv[1], "BH"))||(!strcmp(argv[1], "BY"))
           	||(!strcmp(argv[1], "BE"))||(!strcmp(argv[1], "BZ"))||(!strcmp(argv[1], "BO"))
           	||(!strcmp(argv[1], "BN"))||(!strcmp(argv[1], "BG"))||(!strcmp(argv[1], "CL"))
           	||(!strcmp(argv[1], "CN"))||(!strcmp(argv[1], "CR"))||(!strcmp(argv[1], "HR"))
           	||(!strcmp(argv[1], "CY"))||(!strcmp(argv[1], "CZ"))||(!strcmp(argv[1], "DK"))
           	||(!strcmp(argv[1], "EC"))||(!strcmp(argv[1], "EG"))||(!strcmp(argv[1], "SV"))
           	||(!strcmp(argv[1], "EE"))||(!strcmp(argv[1], "FI"))||(!strcmp(argv[1], "GE"))
           	||(!strcmp(argv[1], "DE"))||(!strcmp(argv[1], "GR"))||(!strcmp(argv[1], "HN"))
           	||(!strcmp(argv[1], "HK"))||(!strcmp(argv[1], "HU"))||(!strcmp(argv[1], "IS"))
           	||(!strcmp(argv[1], "IN"))||(!strcmp(argv[1], "ID"))||(!strcmp(argv[1], "IR"))
           	||(!strcmp(argv[1], "IE"))||(!strcmp(argv[1], "IT"))||(!strcmp(argv[1], "JO"))
           	||(!strcmp(argv[1], "KZ"))||(!strcmp(argv[1], "KP"))||(!strcmp(argv[1], "KR"))
           	||(!strcmp(argv[1], "KW"))||(!strcmp(argv[1], "LV"))||(!strcmp(argv[1], "LB"))
           	||(!strcmp(argv[1], "LI"))||(!strcmp(argv[1], "LT"))||(!strcmp(argv[1], "LU"))
           	||(!strcmp(argv[1], "MO"))||(!strcmp(argv[1], "MK"))||(!strcmp(argv[1], "MY"))
           	||(!strcmp(argv[1], "MC"))||(!strcmp(argv[1], "MA"))||(!strcmp(argv[1], "NL"))
           	||(!strcmp(argv[1], "NZ"))||(!strcmp(argv[1], "OM"))||(!strcmp(argv[1], "PK"))
           	||(!strcmp(argv[1], "PE"))||(!strcmp(argv[1], "PL"))||(!strcmp(argv[1], "PT"))
           	||(!strcmp(argv[1], "QA"))||(!strcmp(argv[1], "RO"))||(!strcmp(argv[1], "RU"))
           	||(!strcmp(argv[1], "SA"))||(!strcmp(argv[1], "SG"))||(!strcmp(argv[1], "SK"))
           	||(!strcmp(argv[1], "SI"))||(!strcmp(argv[1], "ZA"))||(!strcmp(argv[1], "SE"))
           	||(!strcmp(argv[1], "CH"))||(!strcmp(argv[1], "SY"))||(!strcmp(argv[1], "TH"))
           	||(!strcmp(argv[1], "TT"))||(!strcmp(argv[1], "TN"))||(!strcmp(argv[1], "TR"))
           	||(!strcmp(argv[1], "UA"))||(!strcmp(argv[1], "AE"))||(!strcmp(argv[1], "GB"))
           	||(!strcmp(argv[1], "UY"))||(!strcmp(argv[1], "VE"))||(!strcmp(argv[1], "VN"))
           	||(!strcmp(argv[1], "YE"))||(!strcmp(argv[1], "ZW"))||(!strcmp(argv[1], "AF"))
		||(!strcmp(argv[1], "AX")))
		{		
		value = 3;	//ETSI
		apmib_set(MIB_HW_REG_DOMAIN,(void *)&value);
		apmib_update(1);
		}
	else
	{
		return 0;
	}

	apmib_set(MIB_HW_COUNTRY_CODE,(void *)argv[1]);
	apmib_update(1);
	apmib_get(MIB_HW_COUNTRY_CODE, (void *)CC);
        printf("%s\n",CC);
      }
      return 0;
   }

   else if (!strcmp(argv[argNum], "ATE_Set_PINCode")) {
	if (argc == 2)
	{
	   apmib_set(MIB_HW_WSC_PIN, (void *)argv[1]);
	   apmib_update(1);
	   apmib_get(MIB_HW_WSC_PIN, (void *)wsc_pin1);
	   printf("%s\n",wsc_pin1);
	   return 0;
	}
   }

   else if (!strcmp(argv[argNum], "ATE_Set_RestoreDefault")) {
	system("flash default-sw");
	puts("1");
	return 0;
   }

#if 0
   else if (!strcmp(argv[argNum], "reboot")) {
	system("reboot");
	return 0;
   }
#endif

   else if (!strcmp(argv[argNum], "ATE_Get_FWVersion"))
   {
	char fw_file[] = "/etc/FwVersion";
	FILE *fp = NULL;
	char fwversion[64], user_fwversion[64];
	memset( user_fwversion, '\0', 64 );
	int i=0,dot=0;
	int count;
	
	if (!(fp = fopen(fw_file, "r"))) {
		printf("open file error(%s)!\n", fw_file);
		return 0;
	}

	count = fread(fwversion, 1, 64, fp);
	fwversion[count - 1] = '\0';
	fclose(fp);
	while(dot<4 && fwversion[i]!='\0')
	{
   	   if(fwversion[i+1]=='.') 
	   {
	      dot++;
	   }
	   user_fwversion[i]=fwversion[i];
	   i++;
	}
	puts(user_fwversion);
	return 0;
   }

   else if (!strcmp(argv[argNum], "ATE_Get_BootLoaderVersion"))
   {
	char buf[4];
	char ProductID[32]="";
	int ok=1;
	int fh;
	memset( buf, '\0', 4 );
	fh = open("/dev/mtdblock0", O_RDWR);
	if ( fh == -1 ){
	   return 0;
	}
	lseek(fh,0x00005ffa,SEEK_SET);
	if (read(fh, buf, 4) != 4){
	   ok = 0;
	}
	strncpy(ProductID, MODEL_NAME, 32);
	printf("%s-%02d-%02d-%02d-%02d\n",ProductID, buf[0], buf[1], buf[2], buf[3]);   
	close(fh);
	return 0;
   }

   else if (!strcmp(argv[argNum], "ATE_Get_ResetButtonStatus"))
   {
	if(isFileExist("/tmp/resetbtn"))
	   puts("1");
	else
	   puts("0");
	return 0;
   }


   else if (!strcmp(argv[argNum], "ATE_Get_WpsButtonStatus"))
   {
	if(isFileExist("/tmp/wpsbtn"))
	   puts("1");
	else
	   puts("0");
	return 0;
   }

   else if (!strcmp(argv[argNum], "ATE_Get_SWMode"))
   {
	FILE *fp;
	int opmode;
	fp=fopen("/var/sys_op","r");
	fscanf(fp,"%d",&opmode);
	fclose(fp);
	if(opmode==0)
	{
	   puts("1");
	}else if(opmode==1)
	{
	   puts("3");
	}
	return 0;
   }

   else if (!strcmp(argv[argNum], "ATE_Get_MacAddr_2G")) {
   
   apmib_get(MIB_HW_WLAN_ADDR,(void *)mac);
   printf("%02X:%02X:%02X:%02X:%02X:%02X\n",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
   return 0;
   }

   else if (!strcmp(argv[argNum], "ATE_Get_RegulationDomain")) {

	apmib_get(MIB_HW_COUNTRY_CODE, (void *)CC);
	printf("%s\n",CC);

	return 0;
   }

   else if (!strcmp(argv[argNum], "ATE_Get_PINCode")) {
	apmib_get(MIB_HW_WSC_PIN, (void *)wsc_pin);
	printf("%s\n",wsc_pin);
	return 0;
   }

   else if (!strcmp(argv[argNum], "ATE_Get_WanLanStatus")) {

	
	char line[300],name[10];
	
	sprintf(line,"getlanstatus %s","p0");
	strcpy(name,"W0");
	print_WanLanStatus(name,line);

	sprintf(line,"getlanstatus %s","p1");
	strcpy(name,"L1");
	print_WanLanStatus(name,line);

	sprintf(line,"getlanstatus %s","p2");
	strcpy(name,"L2");
	print_WanLanStatus(name,line);

	sprintf(line,"getlanstatus %s","p3");
	strcpy(name,"L3");
	print_WanLanStatus(name,line);

	sprintf(line,"getlanstatus %s","p4");
	strcpy(name,"L4");
	print_WanLanStatus(name,line);
	printf("\n");

   return 0;
   }

   else if (!strcmp(argv[argNum], "ATE_Get_FwReadyStatus")) {
	if(isFileExist("/tmp/fwready"))
	   puts("1");
	else
	   puts("0");
	return 0;
   }
   else
   {
	printf("error command!!!!!\n");
   }

return 0;
}


//---------------------WanLanStatus-------related function
int get_lanport_status(int portnum,struct lan_port_status *port_status)
{
	struct ifreq ifr;
	 int sockfd;
	 char *name="eth0";	 
	 struct lan_port_status status;
	 unsigned int *args;	

	 if(portnum > 5)
	 	return -1;	 	
	 
	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
 	{
      		printf("fatal error socket\n");
      		return -3;
        }
	args = (unsigned int *)&status;
	((unsigned int *)(&ifr.ifr_data))[0] =(struct lan_port_status *)&status;
	*args = portnum;
	
	strcpy((char*)&ifr.ifr_name, name);       

    if (ioctl(sockfd, RTL819X_IOCTL_READ_PORT_STATUS, &ifr)<0)
    {
      		printf("device ioctl:");
      		close(sockfd);
     		 return -1;
     }
     close(sockfd);   	
     memcpy((char *)port_status,(char *)&status,sizeof(struct lan_port_status));
    return 0;
}

int do_cmd(int id , char *cmd ,int cmd_len ,int relply)
{
	int i=0,ret=-1,len=0;
	unsigned char rsp_packet[MAX_HOST_PKT_LEN];

	while (cmd_table[i].id != LAST_ENTRY_ID) {
		if ((cmd_table[i].id == id))	{
			ret = cmd_table[i].func(cmd,cmd_len);
			break;
		}	
		i++;
	}
	//no reply
	if(!relply)
		return ret;

	//reply rsp pkt
	if (ret >= 0) { 
		if (ret == 0) { 
			cmd[0] = '\0';
			ret = 1;
		}
		len = pack_rsp_frame(GOOD_CMD_RSP, (unsigned char)id, ret, cmd, rsp_packet);		
#ifdef CONFIG_SYSTEM_MII_INBAND_CTL
		inband_write_data(rsp_packet, len);
#else
		mdio_write_data(rsp_packet, len);
#endif
	}
	else{ //error rsp		
		cmd[0] = (unsigned char)( ~ret + 1);			
		len = pack_rsp_frame(BAD_CMD_RSP, (unsigned char)id, 1, cmd, rsp_packet);
#ifdef CONFIG_SYSTEM_MII_INBAND_CTL
		inband_write_data(rsp_packet, len);
#else		
		mdio_write_data(rsp_packet, len);
#endif
	}			
	
	return ret;
}

static int _getlanstatus(char *cmd , int cmd_len)
{
	struct lan_port_status port_status;
	int len=sizeof(struct lan_port_status);
	int portnum;

	portnum = portname_to_num(cmd);
	
	if ( get_lanport_status(portnum, &port_status) < 0)
			return -1;
	
	memcpy(cmd,(char *)&port_status,len);
	
	return len;
}

int portname_to_num(char *name)
{
	int portnum=0;
	if(!strncmp(name,"p0",2)) 
		portnum=0;
	else if(!strncmp(name,"p1",2)) 
		portnum=1;
	else if(!strncmp(name,"p2",2)) 
		portnum=2;
	else if(!strncmp(name,"p3",2)) 
		portnum=3;
	else if(!strncmp(name,"p4",2)) 
		portnum=4;
	else if(!strncmp(name,"p5",2)) 
		portnum=5;

	return portnum;
}

static int pack_rsp_frame(int cmd_bad, unsigned char cmd_id, int len, unsigned char *in, unsigned char *out)
{
	int i,data_offset;
	out[TAG_FIELD] = SYNC_BIT;
	
	if (cmd_bad & BAD_CMD_RSP)
		out[TAG_FIELD] |= CMD_BAD_BIT;		
	out[CMD_FIELD] = cmd_id;
	out[2] = 0x00;
	data_offset =4 ; // data0 normal offset

	if(len < 256 ) // one byte len
		out[LEN_FIELD] = (unsigned char)len;
	else{
		out[TAG_FIELD] |= EXTEND_LEN_BIT;
		out[LEN_FIELD] = (unsigned char) ((len>>8)&0xff);
		out[4] = 0x00;
		out[EXT_LEN_FIELD] = (unsigned char) (len&0xff);
		data_offset =6;
	}
	//printf("Rsp len:%d, contend:",len);
	for (i=0; i<len; i++) {
		out[data_offset+i*2] = 0x00;
		out[data_offset+i*2+1] = in[i];
		printf("%d",in[i]);
	}
	//printf("\n");
	return (data_offset+i*2);
}

void mdio_write_data(unsigned char *data, int len) 
{
	if (len > MDIO_BUFSIZE) {
		printf("Write length > MDIO_BUFSIZE!\n");
		return;
	}
	write(fd, data, len);
}

void print_port_status(char *name,char *status)
{
	struct lan_port_status *port_status;
	
	port_status = (struct lan_port_status *)status;
	
if(!strcmp(lan_link_spec[port_status->link],"UP"))
	
	printf("%s:%s;",name,lan_speed_spec[port_status->speed]);
else 
	printf("%s=N;",name);		
}

static int get_token(char *line, char **token1, char **token2, char **token3, char **token4) 
{		
	int len;
	int token_idx = 0, total = strlen(line);

search_next:
	len = 0;
	while (*line== 0x20 ||*line== '\t') {
		line++;
		total--;		
	}

	if (token_idx == 0)
		*token1 = line;		
	else if (token_idx == 1)
		*token2 = line;		
	else	 if (token_idx == 2)
		*token3 = line;		
	else	 if (token_idx == 3)
		*token4 = line;			
	else
		return token_idx;

	while (total > 0 &&  *line && *line != 0x20  && *line != '\t' && *line != '\r' && *line != '\n' ) {
		line++;
		len++;
		total--;
	}

	if (len > 0) {
		*line = '\0';
		line++;
		token_idx++;
		total--;
		goto search_next;
	}

	if (strlen(line)==0 || token_idx ==4 || total <= 0)	
		return token_idx;
	else
		goto search_next;		
}

void print_WanLanStatus(char *name,char *line)
{
        char *t1=NULL, *t2=NULL, *t3=NULL, *t4=NULL;
	char cmd_rsp[MAX_HOST_CMD_LEN];
	get_token(line,  &t1, &t2, &t3, &t4);
	strcpy(cmd_rsp,t2);
	do_cmd(id_getlanstatus,cmd_rsp,strlen(t2)+1, 0);
	print_port_status(name,cmd_rsp);
}

int isFileExist(char *file_name)
{
	struct stat status;

	if ( stat(file_name, &status) < 0)
		return 0;

	return 1;
}
