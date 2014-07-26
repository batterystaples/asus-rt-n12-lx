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
//#include "typedefs.h"
//#include "nvram/typedefs.h"
#include "wanduck.h"
typedef unsigned int __u32;
//#include <ra_ioctl.h>
#include <linux/unistd.h> 
#define __NR_track_flag           (__NR_Linux + 332)
#include <sys/syscall.h>

//_syscall2( int, track_flag, int *, flag, ulong *, ipaddr);	//Trandition method

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define HOME_GATEWAY	//2011.03.10 Jerry
#include "apmib.h"	//2011.03.09 Jerry
#include <sys/sysinfo.h> //2011.06.07 Emily


#define csprintf(fmt, args...) do{\
	FILE *cp = fopen("/dev/console", "w");\
	if(cp) {\
		fprintf(cp, fmt, ## args);\
		fclose(cp);\
	}\
}while(0)

//#define wan_prefix(unit, prefix) snprintf(prefix, sizeof(prefix), "wan%d_", unit)
#define RFC1123FMT "%a, %d %b %Y %H:%M:%S GMT"

#define isdigit(c) (c >= '0' && c <= '9') 

#define CHK_PPP		1
#define CHK_DHCPD	2

//#define RTL8367M_DEV	"/dev/rtl8367m"

int fer = 0;
int sw_mode = 0;
OPMODE_T opmode=-1;	//2011.04.20 Jerry;


void
track_set(char *c_track)
{
        int k_track = atoi(c_track);
        ulong ipaddr = 0;

	if(!syscall(__NR_track_flag, &k_track, &ipaddr))
		printf("track set ok\n");
        else
                printf("track set fail\n");
}

int checkFileExist(char *file_name)
{
	struct stat status;

	if ( stat(file_name, &status) < 0)
		return 0;

	return 1;
}


static void safe_leave(int signo){

	csprintf("\n## wanduck.safeexit ##\n");
	FD_ZERO(&allset);
	close(http_sock);
	close(dns_sock);
	
	int i;
	for(i = 0; i <  maxfd; ++i)
		close(i);
	
	sleep(1);
	
	if(rule_setup == 1 && checkFileExist("/tmp/fwupgrade") == 0){
		csprintf("\n# Disable direct rule(exit wanduck)\n");
		
		if(sw_mode == 2 )
			system("iptables-restore /tmp/fake_nat_rules");
		else
			_eval(del_command, NULL, 0, NULL);
		
		change_redirect_rules(2, 0);
	}
	
// 2007.11 James {
	char *rm_pid[] = {"rm", "-f", "/var/run/wanduck.pid", NULL};
	
	_eval(rm_pid, NULL, 0, NULL);
// 2007.11 James }
	
	csprintf("\n# return(exit wanduck)\n");
	exit(0);
}

void redirect_setting()
{
	FILE *nat_fp = fopen("/tmp/nat_rules", "r");
	FILE *redirect_fp = fopen("/tmp/redirect_rules", "w+");
	FILE *fake_nat_fp = fopen("/tmp/fake_nat_rules", "w+");
	char tmp_buf[1024];
	char http_rule[256], dns_rule[256];
	char lan_ipaddr[16], lan_netmask[16];
	unsigned char buffer[32];
	apmib_get(MIB_IP_ADDR,  (void *)buffer);	
	sprintf(lan_ipaddr, "%s", inet_ntoa(*((struct in_addr *)buffer)));
	apmib_get(MIB_SUBNET_MASK,  (void *)buffer);
	sprintf(lan_netmask, "%s", inet_ntoa(*((struct in_addr *)buffer)));

	if (redirect_fp == NULL) {
		fprintf(stderr, "*** Can't make the file of the redirect rules! ***\n");
		return;
	}
	if (fake_nat_fp == NULL) {
		fprintf(stderr, "*** create fake nat fules fail! ***\n");
		return;
	}

	if (nat_fp != NULL) {
		memset(tmp_buf, 0, sizeof(tmp_buf));
		while ((fgets(tmp_buf, sizeof(tmp_buf), nat_fp)) != NULL
				&& strncmp(tmp_buf, "COMMIT", 6) != 0) {
			fprintf(redirect_fp, "%s", tmp_buf);
			memset(tmp_buf, 0, sizeof(tmp_buf));
		}

		fclose(nat_fp);
	}
	else{
		fprintf(redirect_fp, "*nat\n");
		fprintf(redirect_fp, ":PREROUTING ACCEPT [0:0]\n");
		fprintf(fake_nat_fp, "*nat\n");
		fprintf(fake_nat_fp, ":PREROUTING ACCEPT [0:0]\n");
	}

	memset(http_rule, 0, sizeof(http_rule));
	memset(dns_rule, 0, sizeof(dns_rule));
	sprintf(http_rule, "-A PREROUTING ! -d %s/%s -p tcp --dport 80 -j DNAT --to-destination %s:18017\n", lan_ipaddr, lan_netmask, lan_ipaddr);
	sprintf(dns_rule, "-A PREROUTING -p udp --dport 53 -j DNAT --to-destination %s:18018\n", lan_ipaddr);

	fprintf(redirect_fp, "%s%s", http_rule, dns_rule);
	fprintf(redirect_fp, "COMMIT\n");
	fprintf(fake_nat_fp, "COMMIT\n");

	fclose(redirect_fp);
	fclose(fake_nat_fp);
}


static void rebuild_rule(int signo){
	if(rule_setup == 1){

		apmib_reinit();
		get_related_nvram();
		redirect_setting();

		csprintf("\n# Rebuild rules by SIGUSR2\n");
		_eval(add_command, NULL, 0, NULL);
		
		change_redirect_rules(1, 0);
	}
}


int passivesock(char *service, char *protocol, int qlen){
	//struct servent *pse;
	struct protoent *ppe;
	struct sockaddr_in sin;
	int s, type;
	int protocol_num;
	
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;
	
	// map service name to port number
	if((sin.sin_port = htons((u_short)atoi(service))) == 0){
		perror("cannot get service entry");
		
		return -1;
	}
	
	// map protocol name to protocol number
	if((ppe = getprotobyname(protocol)) == (struct protoent*)0){
		protocol_num = 0;
	}
	else
		protocol_num = ppe->p_proto;
	
	if(!strcmp(protocol, "udp"))
		type = SOCK_DGRAM;
	else
		type = SOCK_STREAM;
	
	s = socket(PF_INET, type, protocol_num);
	if(s < 0){
		perror("cannot create socket");
		return -1;
	}
	
	if(bind(s, (struct sockaddr *)&sin, sizeof(sin)) < 0){
		perror("cannot bind port");
		close(s);
		
		return -1;
	}
	
	if(type == SOCK_STREAM && listen(s, qlen) < 0){
		perror("cannot listen to port");
		close(s);
		
		return -1;
	}
	
	return s;
}


int check_ppp_exist(){
	DIR *dir;
	struct dirent *dent;
	char task_file[64], cmdline[64];
	int pid, fd;
	
	if(!(dir = opendir("/proc"))){
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
				
				if(strstr(cmdline, "pppd")
						|| strstr(cmdline, "l2tpd")
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


char *TASK_TYPE;

unsigned long task_mask;

int
got_wan_ip()
{
	int s;
	struct ifreq ifr;
	struct sockaddr_in *inaddr;
	struct in_addr in_addr;

	/* Retrieve IP info */
	if ((s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
		return 0;

	//2011.03.14 Jerry {
	DHCP_T wan_proto;

	apmib_get(MIB_WAN_DHCP, (void *)&wan_proto);
	if(wan_proto == DHCP_CLIENT || wan_proto == DHCP_DISABLED)
		strncpy(ifr.ifr_name, WAN0_IFNAME, IFNAMSIZ);
	else
		strncpy(ifr.ifr_name, PPP0_IFNAME, IFNAMSIZ);
	//2011.03.14 Jerry }

	inaddr = (struct sockaddr_in *)&ifr.ifr_addr;
	inet_aton("0.0.0.0", &inaddr->sin_addr);	

	/* Get IP address */
	ioctl(s, SIOCGIFADDR, &ifr);
	close(s);

	struct in_addr ip_addr = ((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr;
	if (strcmp("0.0.0.0", inet_ntoa(ip_addr)))
		return 1;
	else
		return 0;
}

int chk_proto(){
	char tmp[100];
	//char filename[80], conntype[10];
	struct ifreq ifr;
	struct sockaddr_in *our_ip;
	struct in_addr in;
	int s;
	FILE *fp;
	char *pwanip = NULL;
	
	/* current unit */
	memset(tmp, 0, 100);

	strcpy(tmp, wan0_proto);

	//2011.03.14 Jerry {
	DHCP_T wan_proto;

	apmib_get(MIB_WAN_DHCP, (void *)&wan_proto);
	if(wan_proto == PPPOE || wan_proto == PPTP || wan_proto == L2TP) {
	//2011.03.14 Jerry }
		DIR *ppp_dir;
		struct dirent *entry;
		int got_ppp_link;
		
		if((ppp_dir = opendir("/etc/ppp")) == NULL){	//2011.03.14 Jerry
			disconn_case = CASE_PPPFAIL;
			
			return DISCONN;
		}
		
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
		
		if(check_ppp_exist() == -1){
			disconn_case = CASE_PPPFAIL;
			
			return DISCONN;
		}
		else if(got_ppp_link == 0){
			disconn_case = CASE_PPPFAIL;
			
			return DISCONN;
		}
		else if(wan_ready == 0){
			disconn_case = CASE_PPPFAIL;
			
			return DISCONN;
		}
		else
			return CONNED;
	}
	else{
// 2010.09 James. {
		if(wan_ready == 1
				&& !strcmp(lan_subnet_t, wan_subnet_t)
				){
			disconn_case = CASE_THESAMESUBNET;
			
			if(wan_proto == DHCP_CLIENT || wan_proto == DHCP_DISABLED)	//Dhcp client and static IP
				system("ifconfig eth1 0.0.0.0");
			else
				system("ifconfig ppp0 0.0.0.0");
			system("killall -9 dnrd 2> /dev/null");
			system("killall -9 ntp_inet 2> /dev/null");
			system("killall -9 ntpclient 2> /dev/null");	
			return DISCONN;
		}
// 2010.09 James. }
		if (got_wan_ip())
			return CONNED;
		else
		{
			disconn_case = CASE_OTHERS;
			return DISCONN;
		}
	}
}


#define NOT_SET		0
#define CAT_SET		1
#define HAD_SET		2

int if_wan_phyconnected(void)
{
        int val = 0, idx = 1, ret;

	if(getWanLink(WAN0_IFNAME))
		return chk_proto();
	else {
		disconn_case = CASE_DISWAN;
                return DISCONN;
	}
}

void enable_wan()
{
#if 0
	if(nvram_match("sw_mode", "1") && nvram_match("wan0_proto", "dhcp"))
	{
		printf("retrieve wan ip\n");	// tmp test
		//system("killall -SIGUSR1 udhcpc");
	}
#endif
}

void update_wan(int isup)
{
        if (!isup)
        {
		//nvram_set("wan_status_t", "Disconnected");
		unlink("/tmp/wan_connected");
        }
        else
        {
                //nvram_set("wan_status_t", "Connected");
		system("echo > /tmp/wan_connected");
        }
}

void change_redirect_rules(int num, int force_link_down_up){
	int i;
	char *clean_ip_conntrack[] = {"cat", "/proc/net/nf_conntrack", NULL};
	
	num = 1;	// tmp test

	track_set("101");
	// In experience, need to clean the ip_conntrack up in three times for a clean ip_conntrack.
	for(i = 0; i < num; ++i){
		csprintf("**** clean ip_conntrack %d time. ****\n", i+1);
		_eval(clean_ip_conntrack, ">/dev/null", 0, NULL);
		
		if(i != num-1)
			sleep(1);
	}
	
	track_set("100");

}

void close_socket(int sockfd, char type){
	close(sockfd);
	FD_CLR(sockfd, &allset);
	client[fd_i].sfd = -1;
	client[fd_i].type = 0;
}

/*int getLanLink()
{
        
      	FILE *fp;
        char c=0;
        fp=fopen("/proc/LanLink", "r");

	if (fp != NULL)
        {
        	while((c=fgetc(fp))!=EOF)
		{
          		fclose(fp);	  		
			return c;
		}
	}
#ifdef DEBUG
	else
		printf("Can't get LanLink Status\n");
#endif

}*/

#define RTL8651_IOCTL_GETWANLINKSTATUS 2000
/* Wan link status detect */
int getWanLink(char *interface)
{
        unsigned int    ret;
        unsigned int    args[0];
        re865xIoctl(interface, RTL8651_IOCTL_GETWANLINKSTATUS, (unsigned int)(args), 0, (unsigned int)&ret) ;
#ifdef DEBUG
	printf("getWanLink; %d\n", ret);
#endif
	if(ret == 0)
		return 1;
        return 0;//return ret;
}

/* IOCTL system call */
static int re865xIoctl(char *name, unsigned int arg0, unsigned int arg1, unsigned int arg2, unsigned int arg3)
{
	unsigned int args[4];
  	struct ifreq ifr;
  	int sockfd;

  	args[0] = arg0;
  	args[1] = arg1;
  	args[2] = arg2;
  	args[3] = arg3;

  	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    	{
      		perror("fatal error socket\n");
      		return -3;
    	}
  
  	strcpy((char*)&ifr.ifr_name, name);
  	((unsigned int *)(&ifr.ifr_data))[0] = (unsigned int)args;

  	if (ioctl(sockfd, SIOCDEVPRIVATE, &ifr)<0)
    	{
      		perror("Wanduck-device ioctl:");
      		close(sockfd);
      		return -1;
    	}
  	close(sockfd);
  	return 0;
} /* end re865xIoctl */

int detectFileExist(char *fname)
{
	FILE *fd;
	if ( (fd == fopen(fname,"r")) == NULL)
		return 0;
	else
	{
		fclose(fd);
		return 1;
	}
	return 0;
}

static const int one = 1;

int setsockopt_broadcast(int fd)
{
    return setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one));
}

int main(int argc, char **argv){
	char *http_servport, *dns_servport;
	socklen_t clilen;
	struct sockaddr_in cliaddr;
	struct timeval  tval;
	int nready, maxi, sockfd, conn_state;

	int x_setting;		//2011.03.14 Jerry
	int wan_ready_t;	//2011.03.14 Jerry
	int ret=0;		//2011.06.03 Emily

#ifdef DEBUG
	printf("Link result: %d\n", getWanLink(WAN0_IFNAME)); //Emily:  0 = Link Up  -1 = Link down  
#endif
	if ( apmib_init() == 0 )
		printf("Initialize AP MIB failed! Can't start wanduck\n");
	else
		printf("Start wanduck!\n");//printf("Initialize AP MIB success!\n");

	redirect_setting();
	umask(0);
	setsid();
	chdir("/");
	
	close(STDIN_FILENO);
	
	struct stat fstatus;
	int fd;
	int max_tbl_sz = getdtablesize();
	for(fd = (STDERR_FILENO+1); fd <= max_tbl_sz; ++fd){
		if(fstat(fd, &fstatus) == 0){
			fprintf(stdout, "The inherited fd(%d) is closed.\n", fd);
			close(fd);
		}
	}
	
	signal(SIGHUP, SIG_IGN);
	signal(SIGTERM, safe_leave);
	//signal(SIGUSR1, get_related_nvram2); // 2010.09 James.
	signal(SIGUSR1, reinit_mib); //2011.03.30 Jerry
	signal(SIGUSR2, rebuild_rule); // 2010.09 James.
	
	if(argc < 3){
		http_servport = DFL_HTTP_SERV_PORT;
		dns_servport = DFL_DNS_SERV_PORT;
	}
	else{
		if(atoi(argv[1]) <= 0)
			http_servport = DFL_HTTP_SERV_PORT;
		else
			http_servport = argv[1];
		
		if(atoi(argv[2]) <= 0)
			dns_servport = DFL_DNS_SERV_PORT;
		else
			dns_servport = argv[2];
	}
	
	if(build_socket(http_servport, dns_servport, &http_sock, &dns_sock) < 0){
		csprintf("\n*** Fail to build socket! ***\n");
		exit(0);
	}
	
	FILE *fp = fopen("/var/run/wanduck.pid", "w");
	
	if(fp != NULL){
		fprintf(fp, "%d", getpid());
		fclose(fp);
	}
	
	maxfd = (http_sock > dns_sock)?http_sock:dns_sock;
	maxi = -1;
	
	tval.tv_sec = 3;
	tval.tv_usec = 0;
	
	FD_ZERO(&allset);
	FD_SET(http_sock, &allset);
	FD_SET(dns_sock, &allset);
	
	for(fd_i = 0; fd_i < MAX_USER; ++fd_i){
		client[fd_i].sfd = -1;
		client[fd_i].type = 0;
	}
	
	rule_setup = 0;
	disconn_case = 0;
	clilen = sizeof(cliaddr);
	
	sleep(3);
	

	apmib_get(MIB_X_SETTING, (void *)&x_setting);
	if(x_setting)
		isFirstUse = 0;
	else
		isFirstUse = 1;
	
	get_related_nvram();
	
	apmib_get(MIB_WAN_READY, (void *)&wan_ready_t);
	if(wan_ready_t == 1){
		wan_ready = 1;
		get_related_nvram2();
	}
	
	err_state = if_wan_phyconnected();
	
	record_conn_status();
	
	if(err_state == DISCONN){
		
		if(nat_enable == 1){	
			csprintf("\n# Enable direct rule\n");
			rule_setup = 1;
			
			_eval(add_command, NULL, 0, NULL);
			
			change_redirect_rules(2, 0);
		}
	}
	else if(err_state == CONNED && isFirstUse){
		
		if(nat_enable == 1){	
			csprintf("\n#CONNED : Enable direct rule\n");
			rule_setup = 1;
			
			_eval(add_command, NULL, 0, NULL);
			
			change_redirect_rules(2, 0);
		}
	}
	
	for(;;)
	{

		rset = allset;
		tval.tv_sec = 1;
		tval.tv_usec = 0;

		apmib_get(MIB_X_SETTING, (void *)&x_setting);
		if(x_setting)
			isFirstUse = 0;
		else
			isFirstUse = 1;

#if 0
		if( !strcmp(wan0_proto, "dhcp") )
		{
			printf("detectWAN_arp()\n");
			ret = detectWAN_arp();
		}
#endif
		
#ifdef DEBUG
		if (ret < 0)
			printf("Failure!\n");
		else
			printf("Success!\n");
#endif
		
		apmib_get(MIB_WAN_READY, (void *)&wan_ready_t);
		if((wan_ready == 0 && wan_ready_t == 1))
		{
			wan_ready = 1;
			get_related_nvram2();
			
			if(isFirstUse == 1)	// 0608 add
			{
				csprintf("\n# Rebuild rules\n");
				_eval(add_command, NULL, 0, NULL);
				change_redirect_rules(1, 0);
			}
		}

		
		apmib_get(MIB_OP_MODE, (void *)&opmode);
		if(opmode == GATEWAY_MODE)
			nat_enable = 1;
		else
			nat_enable = 0;
		
		if(nat_enable == 1)
		{	
			conn_state = if_wan_phyconnected();
			
			if(conn_state == CONNED){
				if(err_state == DISCONN)
					err_state = D2C;
			}
			else if(conn_state == DISCONN){
				if(err_state == CONNED)
					err_state = C2D;
			}
			
			record_conn_status();
			
			if(err_state == C2D || (err_state == CONNED && isFirstUse)){
				err_state = DISCONN;
				if(rule_setup == 0){	
					csprintf("\n# Enable direct rule(C2D)\n");
					rule_setup = 1;
					
					_eval(add_command, NULL, 0, NULL);
					
					change_redirect_rules(2, 1);
					update_wan(0);
				}
			}
			else if(err_state == D2C || err_state == CONNED){
				err_state = CONNED;
				
				if(rule_setup == 1 && !isFirstUse){
					csprintf("\n#w Disable direct rule(D2C)\n");
					rule_setup = 0;
					
                			if(sw_mode == 2 )
                        			system("iptables-restore /tmp/fake_nat_rules");
                			else
					{
						enable_wan();
						_eval(del_command, NULL, 0, NULL);
					}
					change_redirect_rules(2, 0);
					update_wan(1);
				}
			}
		}
		else{	// ap mode
			nat_enable = 0;
			get_related_nvram2();
			if(rule_setup == 1){
				csprintf("\n#AP Disable direct rule(D2C)\n");
				rule_setup = 0;
				
                		if(sw_mode == 2 )
                        		system("iptables-restore /tmp/fake_nat_rules");
                		else
				{
					enable_wan();
					_eval(del_command, NULL, 0, NULL);
				}

				change_redirect_rules(2, 0);
				update_wan(1);
			}
		}

		if((nready = select(maxfd+1, &rset, NULL, NULL, &tval)) <= 0)
			continue;
		
		if(FD_ISSET(dns_sock, &rset)){
#ifdef DEBUG
			printf("# run fake dns service\n");
#endif
			run_dns_serv(dns_sock);
			if(--nready <= 0)
				continue;
		}
		else if(FD_ISSET(http_sock, &rset)){
#ifdef DEBUG
			printf("# run fake httpd service\n");
#endif
			if((connfd = accept(http_sock, (struct sockaddr *)&cliaddr, &clilen)) <= 0){
				perror("http accept");
				continue;
			}
			cur_sockfd = connfd;
			
			for(fd_i = 0; fd_i < MAX_USER; ++fd_i){
				if(client[fd_i].sfd < 0){
					client[fd_i].sfd = cur_sockfd;
					client[fd_i].type = T_HTTP;
					break;
				}
			}
			
			if(fd_i == MAX_USER){
				csprintf("wanduck servs full\n");
				close(cur_sockfd);
				
				continue;
			}
			
			FD_SET(cur_sockfd, &allset);
			if(cur_sockfd > maxfd)
				maxfd = cur_sockfd;
			if(fd_i > maxi)
				maxi = fd_i;		
			if(--nready <= 0)
				continue;	// no more readable descriptors
		}
		
		// polling
		for(fd_i = 0; fd_i <= maxi; ++fd_i)
		{
			if((sockfd = client[fd_i].sfd) < 0)
				continue;
			if(FD_ISSET(sockfd, &rset))
			{
				int nread;
				ioctl(sockfd, FIONREAD, &nread);
				if(nread == 0)
				{
					close_socket(sockfd, T_HTTP);
					continue;
				}				
				cur_sockfd = sockfd;				
				run_http_serv(sockfd);				
				if(--nready <= 0)
					break;
			}
		}
	}
	
	csprintf("wanduck exit error\n");
	exit(1);
}

void run_http_serv(int sockfd){
	ssize_t n;
	char line[MAXLINE];
	
	memset(line, 0, sizeof(line));
	
	if((n = read(sockfd, line, MAXLINE)) == 0){	// client close
		close_socket(sockfd, T_HTTP);
		
		return;
	}
	else if(n < 0){
		perror("readline");
		return;
	}
	else{
		if(client[fd_i].type == T_HTTP)
			handle_http_req(sockfd, line);
		else
			close_socket(sockfd, T_HTTP);
	}
}

void run_dns_serv(int sockfd){
	int n;
	char line[MAXLINE];
	struct sockaddr_in cliaddr;
	int clilen = sizeof(cliaddr);
	
	memset(line, 0, MAXLINE);
	memset(&cliaddr, 0, clilen);

	if((n = recvfrom(sockfd, line, MAXLINE, 0, (struct sockaddr *)&cliaddr, &clilen)) == 0)	// client close
		return;
	else if(n < 0){
		perror("readline");
		return;
	}
	else
		handle_dns_req(sockfd, line, n, (struct sockaddr *)&cliaddr, clilen);
}

void parse_dst_url(char *page_src){
	int i, j;
	char dest[STRLEN], host[64];
	char host_strtitle[7], *hp;
	
	j = 0;
	memset(dest, 0, sizeof(dest));
	memset(host, 0, sizeof(host));
	memset(host_strtitle, 0, sizeof(host_strtitle));
	
	for(i = 0; i < strlen(page_src); ++i){
		if(i >= STRLEN)
			break;
		
		if(page_src[i] == ' ' || page_src[i] == '?'){
			dest[j] = '\0';
			break;
		}
		
		dest[j++] = page_src[i];
	}
	
	host_strtitle[0] = '\n';
	host_strtitle[1] = 'H';
	host_strtitle[2] = 'o';
	host_strtitle[3] = 's';
	host_strtitle[4] = 't';
	host_strtitle[5] = ':';
	host_strtitle[6] = ' ';
	
	if((hp = strstr(page_src, host_strtitle)) != NULL){
		hp += 7;
		j = 0;
		for(i = 0; i < strlen(hp); ++i){
			if(i >= 64)
				break;
			
			if(hp[i] == '\r' || hp[i] == '\n'){
				host[j] = '\0';
				break;
			}
			
			host[j++] = hp[i];
		}
	}
	
	memset(dst_url, 0, sizeof(dst_url));
	sprintf(dst_url, "%s/%s", host, dest);
}

void parse_req_queries(char *content, char *lp, int len, int *reply_size){
	int i, rn;
	
	rn = *(reply_size);
	for(i = 0; i < len; ++i){
		content[rn+i] = lp[i];
		if(lp[i] == 0){
			++i;
			break;
		}
	}
	
	if(i >= len)
		return;
	
	content[rn+i] = lp[i];
	content[rn+i+1] = lp[i+1];
	content[rn+i+2] = lp[i+2];
	content[rn+i+3] = lp[i+3];
	i += 4;
	
	*reply_size += i;
}

void handle_http_req(int sfd, char *line){
	int len;
	
	if(!strncmp(line, "GET /", 5)){
		parse_dst_url(line+5);
		
		len = strlen(dst_url);
		if((dst_url[len-4] == '.') &&
				(dst_url[len-3] == 'i') &&
				(dst_url[len-2] == 'c') &&
				(dst_url[len-1] == 'o')){
			close_socket(sfd, T_HTTP);
			
			return;
		}
		send_page(sfd, NULL, dst_url);
	}
	else
		close_socket(sfd, T_HTTP);
}

void handle_dns_req(int sfd, char *line, int maxlen, struct sockaddr *pcliaddr, int clen){
	dns_query_packet d_req;
	dns_response_packet d_reply;
	int reply_size;
	char reply_content[MAXLINE];
	
	reply_size = 0;
	memset(reply_content, 0, MAXLINE);
	memset(&d_req, 0, sizeof(d_req));
	memcpy(&d_req.header, line, sizeof(d_req.header));

	// header
	memcpy(&d_reply.header, &d_req.header, sizeof(dns_header));
	//d_reply.header.flag_set.flag_num = htons(0x8580);
	d_reply.header.flag_set.flag_num = htons(0x8180);
	d_reply.header.answer_rrs = htons(0x0001);
	memcpy(reply_content, &d_reply.header, sizeof(d_reply.header));
	reply_size += sizeof(d_reply.header);

// 2009.02 James. Force to send answer response.{
	reply_content[5] = 1;	// Questions
	reply_content[7] = 1;	// Answer RRS
	reply_content[9] = 0;	// Authority RRS
	reply_content[11] = 0;	// Additional RRS
// 2009.02 James. }

	// queries
	parse_req_queries(reply_content, line+sizeof(dns_header), maxlen-sizeof(dns_header), &reply_size);

	// answers
	d_reply.answers.name = htons(0xc00c);
	d_reply.answers.type = htons(0x0001);
	d_reply.answers.ip_class = htons(0x0001);
	//d_reply.answers.ttl = htonl(0x00000001);
	d_reply.answers.ttl = htonl(0x00000000);
	d_reply.answers.data_len = htons(0x0004);
	d_reply.answers.addr = htonl(0x0a000001);	// 10.0.0.1

	memcpy(reply_content+reply_size, &d_reply.answers, sizeof(d_reply.answers));
	reply_size += sizeof(d_reply.answers);
	sendto(sfd, reply_content, reply_size, 0, pcliaddr, clen);
}

void send_page(int sfd, char *file_dest, char *url){
	char buf[2*MAXLINE];
	time_t now;
	char timebuf[100];
	
	memset(buf, 0, sizeof(buf));
	now = time((time_t*)0);
	(void)strftime(timebuf, sizeof(timebuf), RFC1123FMT, gmtime(&now));
	
	sprintf(buf, "%s%s%s%s%s%s", buf, "HTTP/1.0 302 Moved Temporarily\r\n", "Server: wanduck\r\n", "Date: ", timebuf, "\r\n");
	
	if(sw_mode == 2 && disconn_case == CASE_FIRST_REPEATER)
		sprintf(buf, "%s%s%s%s%s%s%s" ,buf , "Connection: close\r\n", "Location:http://", lan_ipaddr_t, "/survey.htm", "\r\nContent-Type: text/plain\r\n", "\r\n<html></html>\r\n");
	else if((err_state == C2D || err_state == DISCONN) && disconn_case == CASE_THESAMESUBNET) // 2010.09 James.
		sprintf(buf, "%s%s%s%s%s%d%s%s" ,buf , "Connection: close\r\n", "Location:http://", lan_ipaddr_t, "/error_page.htm?flag=", disconn_case, "\r\nContent-Type: text/plain\r\n", "\r\n<html></html>\r\n");
	else if(isFirstUse)	// 2008.01 James.
		sprintf(buf, "%s%s%s%s%s%s%s" ,buf , "Connection: close\r\n", "Location:http://", lan_ipaddr_t, "/QIS_wizard.htm?flag=detect", "\r\nContent-Type: text/plain\r\n", "\r\n<html></html>\r\n");
	else if(err_state == C2D || disconn_case == CASE_FIRST_REPEATER)
		sprintf(buf, "%s%s%s%s%s%s%s" ,buf , "Connection: close\r\n", "Location:http://", lan_ipaddr_t, "/survey.htm", "\r\nContent-Type: text/plain\r\n", "\r\n<html></html>\r\n");
	else if(err_state == C2D || err_state == DISCONN)
		sprintf(buf, "%s%s%s%s%s%d%s%s" ,buf , "Connection: close\r\n", "Location:http://", lan_ipaddr_t, "/error_page.htm?flag=", disconn_case, "\r\nContent-Type: text/plain\r\n", "\r\n<html></html>\r\n");
	
	write(sfd, buf, strlen(buf));
	close_socket(sfd, T_HTTP);
}

// 2008.02 James. {
void record_conn_status(){
	if(err_state == DISCONN || err_state == C2D){
		if(disconn_case == CASE_DISWAN){
			if(Dr_Surf_case == 1)
				return;
			Dr_Surf_case = 1;
			
			logmessage("WAN Connection", "Ethernet link down.");
		}
		else if(disconn_case == CASE_PPPFAIL){
			if(Dr_Surf_case == 2)
				return;
			Dr_Surf_case = 2;
			
			FILE *fp = fopen("/tmp/wanstatus.log", "r");
			char log_info[64];
			
			if(fp == NULL){
				logmessage("WAN Connection", "WAN was exceptionally disconnected.");
				return;
			}
			
			memset(log_info, 0, 64);
			fgets(log_info, 64, fp);
			fclose(fp);
			
			if(strstr(log_info, "Failed to authenticate ourselves to peer") != NULL)
				logmessage("WAN Connection", "PPPoE or PPTP authentification failed.");
			else
				logmessage("WAN Connection", "No response from the remote server.");
		}
		else if(disconn_case == CASE_DHCPFAIL){
			if(Dr_Surf_case == 3)
				return;
			Dr_Surf_case = 3;
			
			if(!strcmp(wan0_proto, "dhcp"))
				logmessage("WAN Connection", "ISP's DHCP did not function properly.");
			else
				logmessage("WAN Connection", "Detected that the WAN Connection Type was PPPoE. But the PPPoE Setting was not complete.");
		}
		else if(disconn_case == CASE_MISROUTE){
			if(Dr_Surf_case == 4)
				return;
			Dr_Surf_case = 4;
			
			logmessage("WAN Connection", "The router's ip was the same as gateway's ip. It led to your packages couldn't dispatch to internet correctly.");
		}
		else if(disconn_case == CASE_THESAMESUBNET){
			if(Dr_Surf_case == 6)
				return;
			Dr_Surf_case = 6;
			
			logmessage("WAN Connection", "The LAN's subnet may be the same with the WAN's subnet.");
		}
		else{	// disconn_case == CASE_OTHERS
			if(Dr_Surf_case == 5)
				return;
			Dr_Surf_case = 5;
			
			logmessage("WAN Connection", "WAN was exceptionally disconnected.");
		}
	}
	else if(err_state == D2C){
		if(Dr_Surf_case == 10)
			return;
		Dr_Surf_case = 10;
		
		logmessage("WAN Connection", "WAN was restored.");
	}
}

void logmessage(char *logheader, char *fmt, ...){
	va_list args;
	char buf[512];
	
	va_start(args, fmt);
	
	vsnprintf(buf, sizeof(buf), fmt, args);
	openlog(logheader, 0, 0);
	syslog(0, buf);
	closelog();
	va_end(args);
}
// 2008.02 James. }

int readline(int fd,char *ptr,int maxlen){  // read a line(\n, \r\n) each time
	int n,rc;
	char c;
	*ptr = 0;
	
	for(n = 1; n < maxlen; ++n){
		if((rc = read(fd, &c, 1)) == 1){
			*ptr++ = c;
			
			if(c == '\n')
				break;
		}
		else if(rc == 0){
			if(n == 1)
				return(0);
			else
				break;
		}
		else
			return(-1);
	}
	
	return(n);
}

int build_socket(char *http_port, char *dns_port, int *hd, int *dd){
	if((*hd = passivesock(http_port, "tcp", 10)) < 0){
		csprintf("Fail to socket for httpd port: %s.\n", http_port);
		return -1;
	}
	
	if((*dd = passivesock(dns_port, "udp", 10)) < 0){
		csprintf("Fail to socket for DNS port: %s.\n", dns_port);
		return -1;
	}
	
	return 0;
}

void get_related_nvram(){

	memset(wan0_ifname, 0, 16);
	memset(wan1_ifname, 0, 16);
	memset(wan0_proto, 0, 16);
	memset(wan1_proto, 0, 16);
	memset(lan_ipaddr_t, 0, 16);

	OPMODE_T opmode=-1;

	apmib_get(MIB_OP_MODE, (void *)&opmode);
	if(opmode == GATEWAY_MODE)
		nat_enable = 1;
	else
		nat_enable = 0;
	
	wan_unit = 1;
	strcpy(wan0_ifname, WAN0_IFNAME);
	strcpy(wan1_ifname, WAN0_IFNAME);
	
	DHCP_T wan_proto;
	char wan_proto_str[16];
	apmib_get(MIB_WAN_DHCP, (void *)&wan_proto);
	switch(wan_proto) {
		case DHCP_DISABLED:
			strcpy(wan_proto_str, "static");
			break;
		case DHCP_CLIENT:
			strcpy(wan_proto_str, "dhcp");
			break;
		case PPPOE:
			strcpy(wan_proto_str, "pppoe");
			break;
		case PPTP:
			strcpy(wan_proto_str, "pptp");
			break;
		case L2TP:
			strcpy(wan_proto_str, "l2tp");
			break;
	}

	strcpy(wan0_proto, wan_proto_str);
	strcpy(wan1_proto, wan_proto_str);
	
	
	char lan_ipaddr[16], lan_netmask[16], lan_subnet[11];
	unsigned char buffer[64];
	memset(lan_ipaddr, 0, 16);
	memset(lan_netmask, 0, 16);
	memset(lan_subnet, 0, 11);
	apmib_get( MIB_IP_ADDR,  (void *)buffer);
	sprintf(lan_ipaddr, "%s", inet_ntoa(*((struct in_addr *)buffer)));
	sprintf(lan_ipaddr_t, "%s", inet_ntoa(*((struct in_addr *)buffer)));

	apmib_get( MIB_SUBNET_MASK,  (void *)buffer);
	sprintf(lan_netmask, "%s", inet_ntoa(*((struct in_addr *)buffer)));

	sprintf(lan_subnet_t, "0x%x", inet_network(lan_ipaddr)&inet_network(lan_netmask));
}

void get_related_nvram2(){

	memset(wan_gateway_t, 0, 16);
	char wan_ipaddr[16];
	char wan_netmask[16];
	char wan_gateway[16];
	char wan_subnet[11];
	char wan_hwaddr[18];
	getWanInfo(wan_ipaddr, wan_netmask, wan_gateway, wan_hwaddr);
#ifdef DEBUG
	printf("%s:%s:%d ipaddr = %s netmask = %s gateway = %s wan_hwaddr = %s\n", __FILE__,__FUNCTION__,__LINE__,wan_ipaddr,wan_netmask, wan_gateway, wan_hwaddr);
#endif
	strcpy(wan_ipaddr_t, wan_ipaddr);
	strcpy(wan_hwaddr_t, wan_hwaddr);

	strcpy(wan_gateway_t, wan_gateway);
	memset(wan_subnet_t, 0, 11);

	sprintf(wan_subnet, "0x%x", inet_network(wan_ipaddr)&inet_network(wan_netmask));
	strcpy(wan_subnet_t, wan_subnet);
}

//2011.03.14 Jerry {
#define _PATH_PROCNET_ROUTE	"/proc/net/route"
#define RTF_UP			0x0001          /* route usable                 */
#define RTF_GATEWAY		0x0002          /* destination is a gateway     */
int getInAddr( char *interface, ADDR_T type, void *pAddr )
{
    struct ifreq ifr;
    int skfd=0, found=0;
    struct sockaddr_in *addr;

    skfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(skfd==-1)
		return 0;
		
    strcpy(ifr.ifr_name, interface);
    if (ioctl(skfd, SIOCGIFFLAGS, &ifr) < 0){
    	close( skfd );
		return (0);
	}
    if (type == HW_ADDR) {
    	if (ioctl(skfd, SIOCGIFHWADDR, &ifr) >= 0) {
		memcpy(pAddr, &ifr.ifr_hwaddr, sizeof(struct sockaddr));
		found = 1;
	}
    }
    else if (type == IP_ADDR) {
	if (ioctl(skfd, SIOCGIFADDR, &ifr) == 0) {
		addr = ((struct sockaddr_in *)&ifr.ifr_addr);
		*((struct in_addr *)pAddr) = *((struct in_addr *)&addr->sin_addr);
		found = 1;
	}
    }
    else if (type == SUBNET_MASK) {
	if (ioctl(skfd, SIOCGIFNETMASK, &ifr) >= 0) {
		addr = ((struct sockaddr_in *)&ifr.ifr_addr);
		*((struct in_addr *)pAddr) = *((struct in_addr *)&addr->sin_addr);
		found = 1;
	}
    }
    close( skfd );
    return found;
}

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

int getWanInfo(char *pWanIP, char *pWanMask, char *pWanDefIP, char *pWanHWAddr)
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

	if(opmode == GATEWAY_MODE)
	  {
	if(wan_proto == DHCP_CLIENT || wan_proto == DHCP_DISABLED)
			iface = WAN0_IFNAME;
	else
			iface = PPP0_IFNAME;

#ifdef DEBUG
		printf("%s:%s GATEWAY MODE\n", __FILE__,__FUNCTION__);
#endif
	  }
     	else if (opmode == BRIDGE_MODE)
	  {
			iface= LAN0_IFNAME;
#ifdef DEBUG
		printf("%s:%s BRIDGE MODE\n", __FILE__,__FUNCTION__);
#endif
	  }

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
	
	if ( getInAddr(iface, HW_ADDR, (void *)&hwaddr ) ) 
	{
		pMacAddr = hwaddr.sa_data;
		sprintf(pWanHWAddr,"%02x:%02x:%02x:%02x:%02x:%02x",pMacAddr[0], pMacAddr[1],pMacAddr[2], pMacAddr[3], pMacAddr[4], pMacAddr[5]);
	}
	else
		sprintf(pWanHWAddr,"%s","00:00:00:00:00:00");

	return 1;
}
//2011.03.14 Jerry }

//2011.03.30 Jerry {
void reinit_mib()
{
	//printf("Reinit mib!!\n");
	apmib_reinit();
	get_related_nvram2();
}
//2011.03.30 Jerry }

