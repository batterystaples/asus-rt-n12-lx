#include <stdio.h>
#include <signal.h>
#include <sys/reboot.h>

#define HOME_GATEWAY
#include "apmib.h"

void kill_daemons(void)
{
	printf("kill_daemons!\n");
	/*system("killall udhcpd");
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
	system("killall sysconf");
	system("killall infosvr");
	system("killsh.sh");*/	// kill all running script
	
	system("killall -9 sleep 2> /dev/null");
	system("killall -9 routed 2> /dev/null");
	system("killall -9 pppoe 2> /dev/null");
	system("killall -9 pppd 2> /dev/null");
	system("killall -9 pptp 2> /dev/null");
	system("killall -9 dnrd 2> /dev/null");
	system("killall -9 ntp_inet 2> /dev/null");
	system("killall -9 ntpclient 2> /dev/null");
	system("killall -9 miniigd 2> /dev/null");	//comment for miniigd iptables rule recovery
	system("killall -9 lld2d 2> /dev/null");
	system("killall -9 l2tpd 2> /dev/null");	
	system("killall -9 udhcpc 2> /dev/null");	
	system("killall -9 udhcpd 2> /dev/null");	
	system("killall -9 reload 2> /dev/null");		
	system("killall -9 iapp 2> /dev/null");	
	system("killall -9 wscd 2> /dev/null");
	system("killall -9 mini_upnpd 2> /dev/null");
	system("killall -9 iwcontrol 2> /dev/null");
	system("killall -9 auth 2> /dev/null");
	system("killall -9 disc_server 2> /dev/null");
	system("killall -9 igmpproxy 2> /dev/null");
	system("echo 1,0 > /proc/br_mCastFastFwd");
	system("killall -9 syslogd 2> /dev/null");
	system("killall -9 klogd 2> /dev/null");
	
	system("killall -9 ppp_inet 2> /dev/null");
	system("echo > /tmp/fwupgrade");
	system("killall -9 wanduck 2> /dev/null");
	//system("killall -9 sysconf 2> /dev/null");
	system("killall -9 notify_service 2> /dev/null");
	system("killall -9 infosvr 2> /dev/null");
	system("killall -9 detectWAN 2> /dev/null");
	system("killsh.sh");
}

void kill_processes(void)
{
	printf("upgrade: killing tasks...\n");
	
	kill(1, SIGTSTP);		/* Stop init from reforking tasks */
	kill(1, SIGSTOP);		
	kill(2, SIGSTOP);		
	kill(3, SIGSTOP);		
	kill(4, SIGSTOP);		
	kill(5, SIGSTOP);		
	kill(6, SIGSTOP);		
	kill(7, SIGSTOP);		
	//atexit(restartinit);		/* If exit prematurely, restart init */
	sync();	

	signal(SIGTERM,SIG_IGN);	/* Don't kill ourselves... */
	setpgrp(); 			/* Don't let our parent kill us */
	sleep(1);
	signal(SIGHUP, SIG_IGN);	/* Don't die if our parent dies due to
					 * a closed controlling terminal */
}

int main(int argc, char **argv)
{
	char inFile[] = "/tmp/fw.bin";
	FILE *fh_in = NULL, *fh_out = NULL;
	int ch;
	IMG_HEADER_T pHeader;
	unsigned long head_offset = 60;
	unsigned long linux_bin_len, root_bin_len;
	int i;
	int order_flag = 0;

	printf("Do firmware upgrade......\n");
	if (!(fh_in = fopen(inFile, "r")))
	{
		printf("\n#####Open file %s failed!\n", inFile);
		return;
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
			return;
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
				return;
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
				return;
			}
		}

		head_offset += pHeader.len + header_len;
		order_flag++;
	}
	
	if (!(fh_out = fopen(FLASH_DEVICE_NAME2, "w")))
	{
		printf("\n#####Open file %s failed!\n", FLASH_DEVICE_NAME2);
		fclose(fh_in);
		return;
	}
	kill_daemons();
	sleep(2);

	system("ifconfig br0 down 2> /dev/null");
	system("ifconfig eth0 down 2> /dev/null");
	system("ifconfig eth1 down 2> /dev/null");
	system("ifconfig ppp0 down 2> /dev/null");
	system("ifconfig wlan0 down 2> /dev/null");
	system("ifconfig wlan0-vxd down 2> /dev/null");		
	system("ifconfig wlan0-va0 down 2> /dev/null");		
	system("ifconfig wlan0-va1 down 2> /dev/null");		
	system("ifconfig wlan0-va2 down 2> /dev/null");		
	system("ifconfig wlan0-va3 down 2> /dev/null");
	system("ifconfig wlan0-wds0 down 2> /dev/null");
	system("ifconfig wlan0-wds1 down 2> /dev/null");
	system("ifconfig wlan0-wds2 down 2> /dev/null");
	system("ifconfig wlan0-wds3 down 2> /dev/null");
	system("ifconfig wlan0-wds4 down 2> /dev/null");
	system("ifconfig wlan0-wds5 down 2> /dev/null");
	system("ifconfig wlan0-wds6 down 2> /dev/null");
	system("ifconfig wlan0-wds7 down 2> /dev/null");

	kill_processes();
	sleep(2);

	// write linux.bin to flash
	fseek(fh_in, SKIP_UTILITY_HEADER, SEEK_SET);

	printf("\n###Start to write linux.bin to flash...\n");
	for (i=0; i<linux_bin_len; i++)
	{
		ch = fgetc(fh_in);
		if (ch != EOF)
			fputc(ch, fh_out);
	}
	printf("\n#######done\n");

	// write root.bin to flash
	/*system("ifconfig br0 down 2> /dev/null");
	system("ifconfig eth0 down 2> /dev/null");
	system("ifconfig eth1 down 2> /dev/null");
	system("ifconfig ppp0 down 2> /dev/null");
	system("ifconfig wlan0 down 2> /dev/null");
	system("ifconfig wlan0-vxd down 2> /dev/null");		
	system("ifconfig wlan0-va0 down 2> /dev/null");		
	system("ifconfig wlan0-va1 down 2> /dev/null");		
	system("ifconfig wlan0-va2 down 2> /dev/null");		
	system("ifconfig wlan0-va3 down 2> /dev/null");
	system("ifconfig wlan0-wds0 down 2> /dev/null");
	system("ifconfig wlan0-wds1 down 2> /dev/null");
	system("ifconfig wlan0-wds2 down 2> /dev/null");
	system("ifconfig wlan0-wds3 down 2> /dev/null");
	system("ifconfig wlan0-wds4 down 2> /dev/null");
	system("ifconfig wlan0-wds5 down 2> /dev/null");
	system("ifconfig wlan0-wds6 down 2> /dev/null");
	system("ifconfig wlan0-wds7 down 2> /dev/null");

	kill_processes();
	sleep(2);*/

	fseek(fh_in, linux_bin_len + header_len + SKIP_UTILITY_HEADER, SEEK_SET);

	printf("\n###Start to write root.bin to flash...\n");
	for (i=0; i<root_bin_len; i++)
	{
		ch = fgetc(fh_in);
		if (ch != EOF)
			fputc(ch, fh_out);
	}
	printf("\n#######done\n");
	sleep(15);
	
	printf("fclose(fh_out)\n");
	fclose(fh_out);
	printf("fclose(fh_in)\n");
	fclose(fh_in);
	//printf("Delete file!!!\n");
	//unlink(inFile);
	//sleep(5);
	printf("Reboot!\n");
	/* Reboot if successful */
	//system("reboot");
	reboot(RB_AUTOBOOT);
	return;
}

