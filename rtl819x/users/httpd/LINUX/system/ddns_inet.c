/* 
 */
 
#include <stdio.h>
#include <unistd.h>
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
    
#define FIRSTDDNS "/var/firstddns"

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
	unsigned char command[100];
	//unsigned short fail_wait_time = 300;
	//unsigned int succ_wait_time = 86400;
	unsigned char ddns_type[10];
	unsigned char ddns_domanin_name[51];
	unsigned char ddns_user_name[51];
	unsigned char ddns_password[51];

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

	sprintf(ddns_type, "%s", argv[2]);
	sprintf(ddns_user_name, "%s", argv[3]);
	sprintf(ddns_password, "%s", argv[4]);
	sprintf(ddns_domanin_name, "%s", argv[5]);

	sprintf(command, "%s:%s", ddns_user_name, ddns_password);
	if(isDaemon==1){
		if (daemon(0, 1) == -1) {
			perror("ntp_inet fork error");
			return 0;
		}
	}
	
	RunSystemCmd(FIRSTDDNS, "echo", "pass", NULL_STR);
	for (;;) {
		//unsigned char cmdBuffer[100];
		int ret;

		ret = RunSystemCmd(NULL_FILE, "updatedd", ddns_type, command, ddns_domanin_name, NULL_STR);

		if(ret == 0) // success
		{
			RunSystemCmd(NULL_FILE, "echo", "DDNS update successfully", NULL_STR);
			sleep(86430);
		}
		else // fail
		{
			sleep(300);
		}
		
	}
	
	
	return 0;
}



