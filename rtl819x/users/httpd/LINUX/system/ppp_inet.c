/* 
 */
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include "sysconf.h"
//#include "sys_utility.h"
#include <errno.h>
#include <signal.h>
#include <sys/stat.h>
#include <netdb.h>
#include <stdarg.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/wait.h>



static int isDaemon=0;
static int WanType=0;
static int ConnectType=0;

int DoCmd(char *const argv[], char *file)
{    
	pid_t pid;
	int status;
	int fd;
	char _msg[30];
	switch (pid = fork()) {
			case -1:	/* error */
				perror("fork");
				return errno;
			case 0:	/* child */
				
				signal(SIGINT, SIG_IGN);
				if(file){
					if((fd = open(file, O_RDWR | O_CREAT))==-1){ /*open the file */
						sprintf(_msg, "open %s", file); 
  						perror(_msg);
  						exit(errno);
					}
					dup2(fd,STDOUT_FILENO); /*copy the file descriptor fd into standard output*/
					dup2(fd,STDERR_FILENO); /* same, for the standard error */
					close(fd); /* close the file descriptor as we don't need it more  */
				}else{
			#ifndef SYS_DEBUG		
					close(2); //do not output error messages
			#endif	
				}
				setenv("PATH", "/sbin:/bin:/usr/sbin:/usr/bin", 1);
				execvp(argv[0], argv);
				perror(argv[0]);
				exit(errno);
			default:	/* parent */
			{
				
				waitpid(pid, &status, 0);
			#ifdef SYS_DEBUG	
				if(status != 0)
					printf("parent got child's status:%d, cmd=%s %s %s\n", status, argv[0], argv[1], argv[2]);
			#endif		
				if (WIFEXITED(status)){
			#ifdef SYS_DEBUG	
					printf("parent will return :%d\n", WEXITSTATUS(status));
			#endif		
					return WEXITSTATUS(status);
				}else{
					
					return status;
				}
			}
	}
}
int RunSystemCmd(char *filepath, ...)
{
	va_list argp;
	char *argv[24]={0};
	int status;
	char *para;
	int argno = 0;
	va_start(argp, filepath);

	while (1){ 
		para = va_arg( argp, char*);
		if ( strcmp(para, "") == 0 )
			break;
		argv[argno] = para;
		//printf("Parameter %d is: %s\n", argno, para); 
		argno++;
	} 
	argv[argno+1] = NULL;
	status = DoCmd(argv, filepath);
	va_end(argp);
	return status;
}

int isFileExist(char *file_name)
{
	struct stat status;

	if ( stat(file_name, &status) < 0)
		return 0;

	return 1;
}

int main(int argc, char *argv[])
{
	int i;
	int cnt;//patch for l2tp dial-on-demand wantype
	
	for(i=1; i<argc; i++)
	{
		if(argv[i][0]!='-')
		{
			fprintf(stderr, "%s: Unknown option\n", argv[i]);
		}
		else switch(argv[i][1])
		{
		case 'c':
			ConnectType = atoi(argv[++i]);
			break;	
		case 't':
			WanType = atoi(argv[++i]);
			break;
		case 'x':
			isDaemon = 1;
			break;
		default:
			fprintf(stderr, "%s: Unknown option\n", argv[i]);
		}
	}

	if(isDaemon==1){
		if (daemon(0, 1) == -1) {
			perror("ppp_inet fork error");
			return 0;
		}
	}

	cnt=0;//patch for l2tp dial-on-demand wantype
	for (;;) {
		//if(isFileExist(PPP_CONNECT_FILE)==0){
		if((isFileExist(PPP_CONNECT_FILE)==0) && (isFileExist(PPP_PATCH_FILE)==0)){
			sleep(3);	//To avoid ppp1
			if(WanType==3){
				if(isFileExist("/var/disc")==0){
					RunSystemCmd(PPP_CONNECT_FILE, "echo", "pass", NULL_STR);
					system("pppd &");
				}
			}
			
			if(WanType==4){
				if(isFileExist("/var/disc")==0){
					RunSystemCmd(PPP_CONNECT_FILE, "echo", "pass", NULL_STR);
					system("pppd call rpptp &");
				}
			}
			
			if(WanType==6){
				if(isFileExist("/var/disc")==0){
					usleep(1200000); //wait l2tpd init finish
					RunSystemCmd(PPP_CONNECT_FILE, "echo", "pass", NULL_STR);
					system("echo \"c client\" > /var/run/l2tp-control &");
				}
			}
        #ifdef RTK_USB3G
            if(WanType==16){
                if(isFileExist("/var/disc")==0){
                    RunSystemCmd(PPP_CONNECT_FILE, "echo", "pass", NULL_STR);
                    system("pppd file /var/usb3g.option &");
                }
            }
        #endif /* #ifdef RTK_USB3G */
		}else{
			if(WanType==6 && ConnectType==1){
				if(isFileExist(PPPD_PID_FILE)==0){

					//patch for l2tp dial-on-demand wantype
					//after 3 times, restart l2tpd
					if(cnt<3){
						cnt++;
					}else{
						RunSystemCmd(NULL_FILE, "killall", "-9", "l2tpd", NULL_STR);
						sleep(1);
						system("l2tpd &");
					}
						
			  		unlink(PPP_CONNECT_FILE); /*force start pppd*/
	  			}
	  		}
  		}
  		
		if(ConnectType==2) 
			break;
		sleep(5);
	}
	return 0;
}



