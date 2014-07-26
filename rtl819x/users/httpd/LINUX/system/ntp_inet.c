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

#define NTPTMP_FILE "/tmp/ntp_tmp"
#define TZ_FILE "/etc/TZ"

static int isDaemon=0;

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
	unsigned char	ntp_server[40];
	unsigned char command[100];
	unsigned short fail_wait_time = 300;
	unsigned int succ_wait_time = 86400;
	unsigned char daylight_save_str[5];

	for(i=1; i<argc; i++)
	{
		if(argv[i][0]!='-')
		{
			fprintf(stderr, "%s: Unknown option\n", argv[i]);
		}
		else 
			switch(argv[i][1])
			{
				case 'x':
					isDaemon = 1;
					break;
				
				default:
					fprintf(stderr, "%s: Unknown option\n", argv[i]);
			}
	}

	sprintf(ntp_server, "%s", argv[2]);
	sprintf(command, "%s", argv[3]);
	sprintf(daylight_save_str, "%s", argv[4]);
	
	if(isDaemon==1){
		if (daemon(0, 1) == -1) {
			perror("ntp_inet fork error");
			return 0;
		}
	}
	
	
	for (;;) {
		int ret=1;
		unsigned char cmdBuffer[100];
		
		RunSystemCmd(NULL_FILE, "rm", "/tmp/ntp_tmp", NULL_STR);
		RunSystemCmd(NULL_FILE, "rm", "/var/TZ", NULL_STR);

		//ret = RunSystemCmd(NTPTMP_FILE, "ntpclient", "-s", "-h", ntp_server, "-i", "5", ">", NULL_STR);
		sprintf(cmdBuffer, "ntpclient -s -h %s -i 5 > %s", ntp_server, NTPTMP_FILE);
		system(cmdBuffer);
		
		if(isFileExist(NTPTMP_FILE))
		{
			FILE *fp=NULL;	
			unsigned char ntptmp_str[100];
			memset(ntptmp_str,0x00,sizeof(ntptmp_str));
			
			fp=fopen(NTPTMP_FILE, "r");
			if(fp!=NULL){
				fgets(ntptmp_str,sizeof(ntptmp_str),fp);
				fclose(fp);

				if(strlen(ntptmp_str) != 0)
				{
					
					// success

					RunSystemCmd(TZ_FILE, "echo", command, NULL_STR);
					if(strcmp(daylight_save_str, "1") == 0)
					{
						sprintf(cmdBuffer,"date > %s",  NTPTMP_FILE);
						system(cmdBuffer);
						//RunSystemCmd(NTPTMP_FILE, "date", ">", NULL_STR);
					}
					RunSystemCmd(NULL_FILE, "echo", "ntp client success", NULL_STR);
					sleep(succ_wait_time);
					
				}
				else
				{
					//RunSystemCmd(NULL_FILE, "echo", "ntp client fail", NULL_STR);
					sleep(5);
				}									
			}
			else
			{
				RunSystemCmd(NULL_FILE, "echo", "Can't connect ntp server!!", NULL_STR);
				sleep(fail_wait_time);
			}
		}
		else
		{
			//RunSystemCmd(NULL_FILE, "echo", "Can't create ntp tmp file!!", NULL_STR);
			sleep(fail_wait_time);
		}
		
	}
	
	
	return 0;
}



