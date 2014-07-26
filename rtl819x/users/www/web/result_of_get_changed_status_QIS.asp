<% wanlink(); %>

new_ifWANConnect = <% detect_if_wan(); %>;
detectType = "<% detect_dhcp_pppoe(); %>";
new_wan_status_log = "<% get_wan_status_log(); %>";

wan_subnet = '<% getInfo("wan-subnet"); %>';
lan_subnet = '<% getInfo("lan-subnet"); %>';


