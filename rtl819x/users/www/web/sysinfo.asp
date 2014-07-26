<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<html xmlns:v>
<head>
<meta http-equiv="X-UA-Compatible" content="IE=EmulateIE7"/>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta HTTP-EQUIV="Pragma" CONTENT="no-cache">
<meta HTTP-EQUIV="Expires" CONTENT="-1">
<link rel="shortcut icon" href="images/favicon.png">
<link rel="icon" href="images/favicon.png">
<title>ASUS Wireless Router <#Web_Title#> - <#menu5_6_2#></title>
<link rel="stylesheet" type="text/css" href="index_style.css"> 
<link rel="stylesheet" type="text/css" href="form_style.css">
<script language="JavaScript" type="text/javascript" src="/state.js"></script>
<script language="JavaScript" type="text/javascript" src="/general.js"></script>
<script language="JavaScript" type="text/javascript" src="/popup.js"></script>
<script type="text/javascript" language="JavaScript" src="/help.js"></script>
<script type="text/javascript" language="JavaScript" src="/detect.js"></script>
<script>
var wlanmode, wlanclientnum;
var opmode= <% getIndex("opMode"); %>;
function initial(){
	show_banner(1);
	show_menu(5,6,3);	
	show_footer();
}

function hide_wan_block()
{
	if(opmode == 0) {	
		document.getElementById("wan_title").style.display = "";
		document.getElementById("wan_proto").style.display = "";
		document.getElementById("wan_ip").style.display = "";
		document.getElementById("wan_submask").style.display = "";
		document.getElementById("wan_gw").style.display = "";
		document.getElementById("wan_mac").style.display = "";
	}
}
</script>

</head>

<body onload="initial();" onunLoad="disable_auto_hint(11, 3);return unload_body();">
<div id="TopBanner"></div>

<div id="Loading" class="popup_bg"></div>

<iframe name="hidden_frame" id="hidden_frame" src="" width="0" height="0" frameborder="0"></iframe>

<form name="form">
<input type="hidden" name="preferred_lang" id="preferred_lang" value="<% getInfo("preferred_lang"); %>">	<!--2011.04.14 Jerry-->
</form>

<table class="content" align="center" cellpadding="0" cellspacing="0">
  <tr>
	<td width="23">&nbsp;</td>
	
	<!--=====Beginning of Main Menu=====-->
	<td valign="top" width="202">
	  <div id="mainMenu"></div>
	  <div id="subMenu"></div>
	</td>
		
    <td valign="top">
	<div id="tabMenu" class="submenuBlock"></div><br />
		<!--===================================Beginning of Main Content===========================================-->
<table width="98%" border="0" align="center" cellpadding="0" cellspacing="0">
	<tr>
		<td valign="top" >
<table width="500" border="0" align="center" cellpadding="5" cellspacing="0" class="FormTitle" table>
	<thead>
	<tr>
		<td><#menu5_6#> - <#menu5_6_2#></td>
	</tr>
	</thead>
	<tbody>
	<tr>
		<td bgcolor="#FFFFFF"><#SYSINFO_sectiondesc#></td>
	</tr>
	</tbody>	
	<tr>
	  <td bgcolor="#FFFFFF">
	  <table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3"  class="FormTable">
<thead>
<tr>
  <td colspan="2"><#SYSINFO_itemname#></td>
</tr>
</thead>

<tr>
  <th><#General_x_SystemUpTime_itemname#></th>
  <td><% getInfo("uptime"); %></td>
</tr>

<tr>
  <th><#General_x_FirmwareVersion_itemname#></th>
  <td><% get_fw_version(); %></td>
</tr>

<tr>
  <th><#SYSINFO_Build_Time#></th>
  <td><% getInfo("buildTime"); %></td>
</tr>

  <script>
	var wlan_num = <% getIndex("wlan_num"); %>;
 	var isNewMeshUI =  <% getIndex("isNewMeshUI"); %> ;
  	var wlanMode =new Array();
  	var networkType =new Array();
  	var band=new Array();
  	var ssid_drv=new Array();
  	var channel_drv=new Array();
  	var wep=new Array();
  	var wdsEncrypt=new Array();
  	var meshEncrypt=new Array();
  	var bssid_drv=new Array();
  	var clientnum=new Array();
  	var state_drv=new Array();
  	var rp_enabled=new Array();
	var rp_mode=new Array();
  	var rp_encrypt=new Array();
  	var rp_clientnum=new Array();
  	var rp_ssid=new Array();
  	var rp_bssid=new Array();
  	var rp_state=new Array();
	var wlanDisabled=new Array();

	var mssid_num=<% getIndex("wlan_mssid_num"); %>;
	
	var mssid_disable=new Array(wlan_num);
	var mssid_bssid_drv=new Array(wlan_num);
	var mssid_clientnum=new Array(wlan_num);
	var mssid_band=new Array(wlan_num);
  var mssid_ssid_drv=new Array(wlan_num);
  var mssid_wep=new Array(wlan_num);
	
	for(i=0; i<wlan_num; i++)
	{
		mssid_disable[i] = new Array(mssid_num);
		mssid_bssid_drv[i] = new Array(mssid_num);
		mssid_clientnum[i] = new Array(mssid_num);
		mssid_band[i] = new Array(mssid_num);
		mssid_ssid_drv[i] = new Array(mssid_num);
		mssid_wep[i] = new Array(mssid_num);		
	}
		  	
	for (i=0; i<wlan_num; i=i+1)
	{
		wlanMode[i] = <% getIndex("wlanMode"); %>;
		networkType[i] = <% getIndex("networkType"); %>;
		band[i] = <% getIndex("band"); %>;
		ssid_drv[i] = "<% getInfo("ssid_drv"); %>";
		channel_drv[i] = "<% getInfo("channel_drv"); %>";
		wep[i] = "<% getInfo("wep"); %>";
		wdsEncrypt[i] = "<% getInfo("wdsEncrypt"); %>";
		meshEncrypt[i] = "";
		
		if (<% getIndex("isMeshDefined"); %> == 1)
			meshEncrypt[i] = "<% getInfo("meshEncrypt"); %>";

		bssid_drv[i] = "<% getInfo("bssid_drv"); %>";	
		clientnum[i] = "<% getInfo("clientnum"); %>";
		state_drv[i] = "<% getInfo("state_drv"); %>";
		wlanDisabled[i] = "<% getInfo("wlanDisabled"); %>";

		rp_enabled[i] = <% getIndex("isRepeaterEnabled"); %>;
		rp_mode[i] = <% getIndex("repeaterMode"); %>;
		rp_encrypt[i] = "<% getVirtualInfo("wep", 5); %>";
		rp_ssid[i] = "<% getInfo("repeaterSSID_drv"); %>";
		rp_bssid[i] = "<% getInfo("repeaterBSSID"); %>";
		rp_state[i] = "<% getInfo("repeaterState"); %>";
		rp_clientnum[i] = "<% getInfo("repeaterClientnum"); %>";

		for (k=0; k< mssid_num; k=k+1)
		{
			if(k == 0)
			{
				mssid_ssid_drv[i][k] = "<% getVirtualInfo("ssid_drv", 1); %>";
				mssid_band[i][k] = "<% getVirtualInfo("band", 1); %>";
				mssid_disable[i][k] = "<% getVirtualInfo("wlanDisabled", 1); %>";
				mssid_bssid_drv[i][k] = "<% getVirtualInfo("bssid_drv", 1); %>";
				mssid_clientnum[i][k] = "<% getVirtualInfo("clientnum", 1); %>";
				mssid_wep[i][k] = "<% getVirtualInfo("wep", 1); %>";
			}
			
			if(k == 1)
			{
				mssid_ssid_drv[i][k] = "<% getVirtualInfo("ssid_drv", 2); %>";
				mssid_band[i][k] = "<% getVirtualInfo("band", 2); %>";
				mssid_disable[i][k] = "<% getVirtualInfo("wlanDisabled", 2); %>";
				mssid_bssid_drv[i][k] = "<% getVirtualInfo("bssid_drv", 2); %>";
				mssid_clientnum[i][k] = "<% getVirtualInfo("clientnum", 2); %>";
				mssid_wep[i][k] = "<% getVirtualInfo("wep", 2); %>";
			}

			if(k == 2)
			{
				mssid_ssid_drv[i][k] = "<% getVirtualInfo("ssid_drv", 3); %>";
				mssid_band[i][k] = "<% getVirtualInfo("band", 3); %>";
				mssid_disable[i][k] = "<% getVirtualInfo("wlanDisabled", 3); %>";
				mssid_bssid_drv[i][k] = "<% getVirtualInfo("bssid_drv", 3); %>";
				mssid_clientnum[i][k] = "<% getVirtualInfo("clientnum", 3); %>";
				mssid_wep[i][k] = "<% getVirtualInfo("wep", 3); %>";
			}

			if(k == 3)
			{
				mssid_ssid_drv[i][k] = "<% getVirtualInfo("ssid_drv", 4); %>";
				mssid_band[i][k] = "<% getVirtualInfo("band", 4); %>";
				mssid_disable[i][k] = "<% getVirtualInfo("wlanDisabled", 4); %>";
				mssid_bssid_drv[i][k] = "<% getVirtualInfo("bssid_drv", 4); %>";
				mssid_clientnum[i][k] = "<% getVirtualInfo("clientnum", 4); %>";
				mssid_wep[i][k] = "<% getVirtualInfo("wep", 4); %>";
			}
		}	
	}
	
    	for(i=0; i < wlan_num ; i++)
   	{
   		if(ssid_drv[i]=="")
			mssid_num=0;
	    	else
			mssid_num=<% getIndex("wlan_mssid_num"); %>;
	     		
   		if(wlanDisabled[i] == 1)
   			continue;
		if(<% getIndex("wlan_num"); %> > 1)
			document.write('<thead><tr><td colspan="2">Wireless ' + (i+1) + ' Configuration</td></tr></thead><tr><th>Mode</th><td>');
		else
			document.write('<thead><tr><td colspan="2"><#QKSet_wireless_webtitle#></td></tr></thead>');

	/* band */
	document.write('<tr><th><#WLANConfig11b_x_Mode11g_itemname1#></th><td>');
		if (band[i] == 1)
   		document.write( "2.4 GHz (B)");
    if (band[i] == 2)
   		document.write( "2.4 GHz (G)");
    
    if (band[i] == 8)
   	{
    	if(channel_drv[i] > 14)
    		document.write( "5 GHz (N)");
    	else
   			document.write( "2.4 GHz (N)");   		
   	}
   	
   	if (band[i] == 3)
   		document.write( "2.4 GHz (B+G)");
    if (band[i] == 4)
   		document.write( "5 GHz (A)");
   	if (band[i] == 10)
   		document.write( "2.4 GHz (G+N)");
   	if (band[i] == 11)
   		document.write( "2.4 GHz (B+G+N)");		
   	if (band[i] == 12)
   		document.write( "5 GHz (A+N)");
	
	document.write('</td></tr>\
	<tr>\
    	<th><#WLANConfig11b_SSID_itemname1#></th>\
    	<td>');
	if (wlanMode[i] != 2) {
		document.write(ssid_drv[i]);
	}
	document.write('</td>\
	</tr>\
	<tr>\
	<th><#WLANConfig11b_Channel_itemname1#></th>\
	<td>'+channel_drv[i] +'</td>\
	</tr>\
	<tr>\
	<th><#WLANConfig11b_WEPType_itemname1#></th>\
	<td>');
	if (wlanMode[i] == 0 || wlanMode[i] == 1)
    		document.write(wep[i]);
    	else if (wlanMode[i] == 2)
    		document.write(wdsEncrypt[i]);
    	else if (wlanMode[i] == 3)
    		document.write(wep[i] + '(AP),  ' + wdsEncrypt[i] + '(WDS)');
    	else if (wlanMode[i] == 4 || wlanMode[i] == 6)
    		document.write(wep[i] + '(AP),  ' + meshEncrypt[i] + '(Mesh)');    	
    	else if (wlanMode[i] == 5|| wlanMode[i] == 7)
    		document.write( meshEncrypt[i] + '(Mesh)');

	document.write('</td>\
  	</tr>\
  	<tr>\
    	<th>BSSID：</th>\
    	<td>'+bssid_drv[i]+'</td>\
  	</tr>');
	if (wlanMode[i]!=2) {	//2 means WDS mode
		document.write('<tr>\n');
		if (wlanMode[i]==0 || wlanMode[i]==3 || wlanMode[i]==4) {
			document.write("<th><#Full_Clients1#></th>\n");
			document.write("<td>"+clientnum[i]+"</td></tr>");
		}
		else {
			document.write("<th>State</th>\n");
			document.write('<td>'+state_drv[i]+'</td></tr>');
		}
        }

    if (rp_enabled[i])	// start of repeater
    {
	if(<% getIndex("wlan_num"); %> > 1)
			document.write('<thead><tr><td colspan="2">Wireless ' + (i+1) + ' Repeater Interface Configuration</td></tr></thead><tr><th>Mode</th><td>');
	if(<% getIndex("wlan_num"); %> > 1)
			document.write('<thead><tr><td colspan="2">Wireless Repeater Interface Configuration</td></tr></thead><tr><th>Mode</th><td>');
    	/* mode */
    	if(rp_mode[i] == 0)
    		document.write("AP");
    	else
    		document.write( "Infrastructure Client");
    	document.write('</td>\
    	</tr>\
    	<tr>\
    	<th><#WLANConfig11b_SSID_itemname1#></th>\
    	<td>'+rp_ssid[i] +'</td>\
    	</tr>\
    	<tr>\
    	<th>Encryption</th>\
    	<td>'+rp_encrypt[i] +'</td>\
    	</tr>\
    	<tr>\
    	<th>BSSID</th>\
    	<td>'+rp_bssid[i] +'</td>\
    	</tr>');
    	document.write('<tr>\n');
    	if (rp_mode[i]==0 || rp_mode[i]==3) {
    		document.write("<th><#Full_Clients1#></th>\n");
    		document.write("<td>"+rp_clientnum[i]+"</td></tr>");
    	}
    	else {
    		document.write("<th><#t2Status#></th>\n");
    		document.write('<td>'+rp_state[i]+'</td></tr>');
    	}
	}	// end of repeater
   }//end of wlan_num for
  </script>
<% getInfo("pocketRouter_html_lan_hide_s"); %> 
<thead> 
<tr>
  <td colspan="2"><#LANHostConfig_display1_sectionname#></td>
</tr>
</thead>

<tr>
  <th><#PPPConnection_ConnectionType_itemname#></th>
  <td><% getInfo("dhcp-current"); %></td>
</tr>

<tr>
  <th><#LANHostConfig_x_LANIPAddress_itemname#></th>
  <td><% getInfo("ip"); %></td>
</tr>

<tr>
  <th><#LANHostConfig_x_LANSubnetMask_itemname#></th>
  <td><% getInfo("mask"); %></td>
</tr>

<tr>
  <th><#LANHostConfig_x_LANGateway_itemname#></th>
  <td><% getInfo("gateway"); %></td>
</tr>

<tr>
  <th><#t2DHCP1#></th>
  <td>
<script>
	var choice_tmp = <% getIndex("dhcp-current"); %>;
	if ( choice_tmp == 0 ) document.write( "Disabled" );
	if ( choice_tmp == 2 ) document.write( "Enabled" );
	if ( choice_tmp == 15 ) document.write( "Auto" );
</script>
  </td>
</tr>

<tr>
  <th><#PPPConnection_x_MacAddressForISP_itemname#></th>
  <td><% getInfo("hwaddr"); %></td>
</tr>
<% getInfo("pocketRouter_html_lan_hide_e"); %>

<% getInfo("pocketRouter_html_wan_hide_s"); %>

<thead>
<tr id="wan_title" style="display:none">
  <td colspan="2"><#menu5_3_1#></td>
</tr>
</thead>

<tr id="wan_proto" style="display:none">
  <th><#Layer3Forwarding_x_ConnectionType_itemname#></th>
  <td><% getInfo("wanDhcp-current"); %></td>
</tr>

<tr id="wan_ip" style="display:none">
  <th><#PPPConnection_x_WANIPAddress_itemname#></th>
  <td><% getInfo("wan-ip"); %></td>
</tr>

<tr id="wan_submask" style="display:none">
  <th><#PPPConnection_x_WANSubnetMask_itemname#></th>
  <td><% getInfo("wan-mask"); %></td>
</tr>

<tr id="wan_gw" style="display:none">
  <th><#IPConnection_x_ExternalGateway_itemname#></th>
  <td><% getInfo("wan-gateway"); %></td>
</tr>

<tr id="wan_mac" style="display:none">
  <th><#PPPConnection_x_MacAddressForISP_itemname#></td>
  <td><% getInfo("wan-hwaddr"); %></td>
</tr>

<% getInfo("pocketRouter_html_wan_hide_e"); %>  
  <% getInfo("voip_status"); %>
</table>

</td></tr>

</table></td>
</form>

<script>hide_wan_block();</script>

          <td id="help_td" style="width:15px;" valign="top">
<form name="hint_form"></form>
            <div id="helpicon" onClick="openHint(0,0);" title="<#Help_button_default_hint#>"><img src="images/help.gif" /></div>
            <div id="hintofPM" style="display:none;">
              <table width="100%" cellpadding="0" cellspacing="1" class="Help" bgcolor="#999999">
			  	<thead>
                <tr>
                  <td><div id="helpname" class="AiHintTitle"></div><a href="javascript:void(0);" onclick="closeHint()" ><img src="images/button-close.gif" class="closebutton" /></a></td>
                </tr>
				</thead>
                <tr>				
                  <td valign="top" >
  				    <div class="hint_body2" id="hint_body"></div>
  				    <iframe id="statusframe" name="statusframe" class="statusframe" src="" frameborder="0"></iframe>
				</td>
                </tr>
              </table>
          </div>
		  </td>
        </tr>
      </table>				
		<!--===================================Ending of Main Content===========================================-->		
	</td>
		
    <td width="10" align="center" valign="top">&nbsp;</td>
	</tr>
</table>

<div id="footer"></div>
</body>
</html>
