#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>

int isFileExist(char *file_name);

int main(void)
{
   while(isFileExist("/tmp/StartATEMode"))
   {
	FILE *fp;
	char c1[2];
	fp=fopen("/proc/gpio","r");
	fscanf(fp,"%s",c1);
	fclose(fp);
	if(c1[0]=='1')
	   system("echo > /tmp/wpsbtn");
	if(c1[1]=='1')
	   system("echo > /tmp/resetbtn");
	usleep(100000);
   }
   return 0;
}

int isFileExist(char *file_name)
{
	struct stat status;

	if ( stat(file_name, &status) < 0)
		return 0;

	return 1;
}

