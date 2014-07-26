#include <stdio.h>
#include <signal.h>
#include <dirent.h>

static void handle_notifications(void)
{
	DIR *directory = opendir("/tmp/sysconf_notification");
	
	printf("handle_notifications() start\n");
	
	if (directory == NULL)
		return;
	
	while (1) {
		struct dirent *entry;
		char *full_name;
		FILE *test_fp;

		entry = readdir(directory);
		if (entry == NULL)
			break;
		if (strcmp(entry->d_name, ".") == 0)
			continue;
		if (strcmp(entry->d_name, "..") == 0)
			continue;

		/* Remove the marker file. */
		full_name = (char *)(malloc(strlen(entry->d_name) + 100));
		if (full_name == NULL)
		{
			fprintf(stderr,
					"Error: Failed trying to allocate %lu bytes of memory for "
					"the full name of an sysconf notification marker file.\n",
					(unsigned long)(strlen(entry->d_name) + 100));
			break;
		}
		sprintf(full_name, "/tmp/sysconf_notification/%s", entry->d_name);
		remove(full_name);
		
//		printf("Flag : %s\n", entry->d_name);

		/* Take the appropriate action. */
		if (strcmp(entry->d_name, "restart_reboot") == 0)
		{
			fprintf(stderr, "sysconf rebooting the system.\n");
			sleep(1);	// wait httpd sends the page to the browser.
			system("reboot -f");
			return;
		}
		else if (strcmp(entry->d_name, "restart_firewall") == 0)
		{
			fprintf(stderr, "sysconf restarting firewall.\n");
			system("sysconf firewall");	//Edison 2011.04.12
			//setFirewallIptablesRules(NULL, NULL);
		}
		else if (strcmp(entry->d_name, "restart_all") == 0)
		{
			fprintf(stderr, "sysconf restarting all.\n");
			system("sysconf init gw all");
		}
		//2011.04.19 Jerry {
		else if (strcmp(entry->d_name, "restart_lan") == 0)
		{
			fprintf(stderr, "sysconf restarting lan.\n");
			system("sysconf restart_lan");
		}
		else if (strcmp(entry->d_name, "restart_wan") == 0)
		{
			fprintf(stderr, "sysconf restarting wan.\n");
			system("sysconf restart_wan");
		}
		else if (strcmp(entry->d_name, "restart_wlan") == 0)
		{
			fprintf(stderr, "sysconf restarting wlan.\n");
			system("sysconf restart_wlan");
		}
		else if (strcmp(entry->d_name, "restart_dhcpd") == 0)
		{
			fprintf(stderr, "sysconf restarting dhcpd.\n");
			system("sysconf restart_dhcpd");
		}
		//2011.04.19 Jerry }
		//2011.04.27 Jerry {
		else if  (strcmp(entry->d_name, "fw_upgrade") == 0)
		{
			fprintf(stderr, "sysconf firmware upgrade.\n");
			system("fwupgrade &");
		}
		//2011.04.27 Jerry }
		//2011.05.25 Jerry {
		else if  (strcmp(entry->d_name, "restart_pppoe") == 0)
		{
			fprintf(stderr, "sysconf pppoe connect.\n");
			system("sysconf pppoe connect eth1");
		}
		else if  (strcmp(entry->d_name, "restart_pptp") == 0)
		{
			fprintf(stderr, "sysconf pptp connect.\n");
			system("sysconf pptp connect eth1");
		}
		else if  (strcmp(entry->d_name, "restart_l2tp") == 0)
		{
			fprintf(stderr, "sysconf l2tp connect.\n");
			system("killall -9 l2tpd 2> /dev/null");
			system("rm -f /var/run/l2tpd.pid 2> /dev/null");
			system("sysconf l2tp connect eth1");
		}
		//2011.05.25 Jerry }
		//2011.06.20 Jerry {
		else if  (strcmp(entry->d_name, "restart_syslog") == 0)
		{
			fprintf(stderr, "sysconf restarting syslog.\n");
			system("sysconf restart_syslog");
		}
		else if  (strcmp(entry->d_name, "restart_ntp") == 0)
		{
			fprintf(stderr, "sysconf restarting ntp client.\n");
			system("sysconf restart_ntpc");
		}
		//2011.06.20 Jerry }
		else if  (strcmp(entry->d_name, "restart_detectWAN") == 0)
		{
			fprintf(stderr, "sysconf restarting detectWAN.\n");
			system("sysconf restart_detectWAN");
		}
		else if  (strcmp(entry->d_name, "restart_dnrd") == 0)
		{
			fprintf(stderr, "sysconf restarting dnrd.\n");
			system("sysconf restart_dnrd");
		}
		else if  (strcmp(entry->d_name, "restart_infosvr") == 0)
		{
			fprintf(stderr, "sysconf restarting infosvr.\n");
			system("infosvr br0 &");
		}
		else if  (strcmp(entry->d_name, "restart_pppoeRelay") == 0)
		{
			fprintf(stderr, "sysconf restarting pppoeRelay.\n");
			system("sysconf pppoeRelay");
		}
		else
		{
			fprintf(stderr,
					"WARNING: sysconf notified of unrecognized event `%s'.\n",
					entry->d_name);
		}

		/*
		 * If there hasn't been another request for the same event made since
		 * we started, we can safely remove the ``action incomplete'' marker.
		 * Otherwise, we leave the marker because we'll go through here again
		 * for this even and mark it complete only after we've completed it
		 * without getting another request for the same event while handling
		 * it.
		 */
		test_fp = fopen(full_name, "r");
		if (test_fp != NULL)
		{
			fclose(test_fp);
		}
		else
		{
			/* Remove the marker file. */
			sprintf(full_name, "/tmp/sysconf_action_incomplete/%s", entry->d_name);
			remove(full_name);
		}

		free(full_name);
	} 
	
	closedir(directory);
}

int main(int argc, char **argv)
{
	signal(SIGTSTP, handle_notifications);
	for(;;){
		pause();
	}
	return 0;
}

