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
<title>Wireless Router <#Web_Title#> - <#menu5_3_1#></title>
<link rel="stylesheet" type="text/css" href="index_style.css"> 
<link rel="stylesheet" type="text/css" href="form_style.css">
<script type="text/javascript" src="/state.js"></script>
<script type="text/javascript" src="/general.js"></script>
<script type="text/javascript" src="/popup.js"></script>
<script type="text/javascript" src="/help.js"></script>
<script type="text/javascript" src="/detect.js"></script>
<script type="text/javascript" src="util_gw.js"> </script>
<SCRIPT>
var initialDnsMode, pppConnectStatus=0;

function initial(){
	show_banner(1);
	show_menu(5,3,1);
	show_footer();
}

function setPPPConnected()
{
   pppConnectStatus = 1;
}
function resetClicked()
{
   if(document.tcpip.wanType.selectedIndex != 0){
	   if(document.tcpip.dnsMode[0].checked)
	      disableDNSinput();
	   else
	      enableDNSinput();
   }

   document.tcpip.reset;
}

function disableDNSinput()
{
   disableTextField(document.tcpip.dns1);
   disableTextField(document.tcpip.dns2);
   disableTextField(document.tcpip.dns3);
}

function enableDNSinput()
{
   enableTextField(document.tcpip.dns1);
   enableTextField(document.tcpip.dns2);
   enableTextField(document.tcpip.dns3);
}

function autoDNSclicked()
{
  disableDNSinput();
}

function manualDNSclicked()
{
  enableDNSinput();
}
function pptpConnectClick(connect)
{
  if (document.tcpip.pptpConnectType.selectedIndex == 2 && pppConnectStatus==connect) {
      if (document.tcpip.pptpUserName.value=="") {
	  alert('<#JS_fieldblank#>');
	  document.tcpip.pptpUserName.value = document.tcpip.pptpUserName.defaultValue;
	  document.tcpip.pptpUserName.focus();
	  return false;
      }
      if (document.tcpip.pptpPassword.value=="") {
	  alert('<#JS_fieldblank#>');
	  document.tcpip.pptpPassword.value = document.tcpip.pptpPassword.defaultValue;
	  document.tcpip.pptpPassword.focus();
	  return false;
      }
	//2011.05.25 Jerry {
	document.tcpip.action_mode.value = "";
	if(pppConnectStatus == 0)
		document.tcpip.action_mode.value = "Restart_PPTP";
	showLoading();
	//2011.05.25 Jerry }
      return true;
  }
  return false;
}
function l2tpConnectClick(connect)
{
  if (document.tcpip.l2tpConnectType.selectedIndex == 2 && pppConnectStatus==connect) {
      if (document.tcpip.l2tpUserName.value=="") {
	  alert('<#JS_fieldblank#>');
	  document.tcpip.l2tpUserName.value = document.tcpip.l2tpUserName.defaultValue;
	  document.tcpip.l2tpUserName.focus();
	  return false;
      }
      if (document.tcpip.l2tpPassword.value=="") {
	  alert('<#JS_fieldblank#>');
	  document.tcpip.l2tpPassword.value = document.tcpip.l2tpPassword.defaultValue;
	  document.tcpip.l2tpPassword.focus();
	  return false;
      }
	//2011.05.25 Jerry {
	document.tcpip.action_mode.value = "";
	if(pppConnectStatus == 0)
		document.tcpip.action_mode.value = "Restart_L2TP";
	showLoading();
	//2011.05.25 Jerry }
      return true;
  }
  return false;
}
function USB3GConnectClick(connect)
{
    if (document.tcpip.USB3GConnectType.selectedIndex == 2 && pppConnectStatus==connect) {
        return true;
    }
    return false;
}
function pppConnectClick(connect)
{
  if (document.tcpip.pppConnectType.selectedIndex == 2 && pppConnectStatus==connect) {
      if (document.tcpip.pppUserName.value=="") {
	  alert('<#JS_fieldblank#>');
	  document.tcpip.pppUserName.value = document.tcpip.pppUserName.defaultValue;
	  document.tcpip.pppUserName.focus();
	  return false;
      }
      if (document.tcpip.pppPassword.value=="") {
	  alert('<#JS_fieldblank#>');
	  document.tcpip.pppPassword.value = document.tcpip.pppPassword.defaultValue;
	  document.tcpip.pppPassword.focus();
	  return false;
      }
	//2011.05.25 Jerry {
	document.tcpip.action_mode.value = "";
	if(pppConnectStatus == 0)
		document.tcpip.action_mode.value = "Restart_PPPoE";
	showLoading();
	//2011.05.25 Jerry }
      return true;
  }
  return false;
}
function pppConnection_Init()
{
	disableButton(document.tcpip.pppConnect);
	disableButton(document.tcpip.pppDisconnect);
	disableTextField(document.tcpip.pppIdleTime);
	disableButton(document.tcpip.pptpConnect);
	disableButton(document.tcpip.pptpDisconnect);
	disableTextField(document.tcpip.pptpIdleTime);
	disableTextField(document.tcpip.pptpIpAddr);
	disableTextField(document.tcpip.pptpSubnetMask);
	disableTextField(document.tcpip.pptpDefGw)

	disableButton(document.tcpip.l2tpConnect);
	disableButton(document.tcpip.l2tpDisconnect);
	disableTextField(document.tcpip.l2tpIdleTime);
	disableTextField(document.tcpip.l2tpIpAddr);
	disableTextField(document.tcpip.l2tpSubnetMask);
	disableTextField(document.tcpip.l2tpDefGw);

    /* USB3G */
    disableButton(document.tcpip.USB3GConnect);
    disableButton(document.tcpip.USB3GDisconnect);
    disableTextField(document.tcpip.USB3GIdleTime);
}
function pppTypeSelection(wan_type)
{
	if(wan_type == 0){
		  if ( document.tcpip.pppConnectType.selectedIndex == 2) {
		  	if (pppConnectStatus==0) {
		  		enableButton(document.tcpip.pppConnect);
				disableButton(document.tcpip.pppDisconnect);
			}
			else {
		 		disableButton(document.tcpip.pppConnect);
				enableButton(document.tcpip.pppDisconnect);
			}
			disableTextField(document.tcpip.pppIdleTime);
		  }
		  else {
			disableButton(document.tcpip.pppConnect);
			disableButton(document.tcpip.pppDisconnect);
			if (document.tcpip.pppConnectType.selectedIndex == 1)
				enableTextField(document.tcpip.pppIdleTime);
			else
				disableTextField(document.tcpip.pppIdleTime);
		  }
	}
	if(wan_type == 1){
		if(document.tcpip.wan_pptp_use_dynamic_carrier_radio[0].checked == true){	//Use dynamic wan ip
			disableTextField(document.tcpip.pptpIpAddr);
			disableTextField(document.tcpip.pptpSubnetMask);
			disableTextField(document.tcpip.pptpDefGw);
		}
		else{	//Use static wan ip
			enableTextField(document.tcpip.pptpIpAddr);
			enableTextField(document.tcpip.pptpSubnetMask);
			enableTextField(document.tcpip.pptpDefGw);
		}
		  if ( document.tcpip.pptpConnectType.selectedIndex == 2) {
		  	if (pppConnectStatus==0) {
		  		enableButton(document.tcpip.pptpConnect);
				disableButton(document.tcpip.pptpDisconnect);
			}
			else {
		 		disableButton(document.tcpip.pptpConnect);
				enableButton(document.tcpip.pptpDisconnect);
			}
			disableTextField(document.tcpip.pptpIdleTime);
		  }
		  else {
			disableButton(document.tcpip.pptpConnect);
			disableButton(document.tcpip.pptpDisconnect);
			if (document.tcpip.pptpConnectType.selectedIndex == 1)
				enableTextField(document.tcpip.pptpIdleTime);
			else
				disableTextField(document.tcpip.pptpIdleTime);
		  }
	}
	if(wan_type == 2){
		if(document.tcpip.wan_l2tp_use_dynamic_carrier_radio[0].checked == true){	//Use dynamic wan ip
			disableTextField(document.tcpip.l2tpIpAddr);
			disableTextField(document.tcpip.l2tpSubnetMask);
			disableTextField(document.tcpip.l2tpDefGw);
		}
		else{	//Use static wan ip
			enableTextField(document.tcpip.l2tpIpAddr);
			enableTextField(document.tcpip.l2tpSubnetMask);
			enableTextField(document.tcpip.l2tpDefGw);
		}
		  if ( document.tcpip.l2tpConnectType.selectedIndex == 2) {
		  	if (pppConnectStatus==0) {
		  		enableButton(document.tcpip.l2tpConnect);
				disableButton(document.tcpip.l2tpDisconnect);
			}
			else {
		 		disableButton(document.tcpip.l2tpConnect);
				enableButton(document.tcpip.l2tpDisconnect);
			}
			disableTextField(document.tcpip.l2tpIdleTime);
		  }
		  else {
			disableButton(document.tcpip.l2tpConnect);
			disableButton(document.tcpip.l2tpDisconnect);
			if (document.tcpip.l2tpConnectType.selectedIndex == 1)
				enableTextField(document.tcpip.l2tpIdleTime);
			else
				disableTextField(document.tcpip.l2tpIdleTime);
		  }
	}
	/* USB3G connect type */
    if(wan_type == 3){
          if ( document.tcpip.USB3GConnectType.selectedIndex == 2) {
            if (pppConnectStatus==0) {
                enableButton(document.tcpip.USB3GConnect);
                disableButton(document.tcpip.USB3GDisconnect);
            }
            else {
                disableButton(document.tcpip.USB3GConnect);
                enableButton(document.tcpip.USB3GDisconnect);
            }
            disableTextField(document.tcpip.USB3GIdleTime);
          }
          else {
            disableButton(document.tcpip.USB3GConnect);
            disableButton(document.tcpip.USB3GDisconnect);
            if (document.tcpip.USB3GConnectType.selectedIndex == 1)
                enableTextField(document.tcpip.USB3GIdleTime);
            else
                disableTextField(document.tcpip.USB3GIdleTime);
          }
    }
}
function wanTypeSelection(field)
{
  if(!document.getElementById){
	alert("<#WAN_CSS_warning#>");
  	return;
  }
  
  /* # keith: add l2tp support. 20080515 */
  if(field.selectedIndex == 0){	//static ip
  	wanShowDiv(0 ,1, 0, 0, 1, 0, 0); //pptp, dns, dnsMode, pppoe, static (div), l2tp, USB3G
	enableDNSinput();	
	document.tcpip.dnsMode[1].checked = true ; // dns change to manual mode
  }
  else if(field.selectedIndex == 1){ //Dhcp
  	wanShowDiv(0 ,1, 1, 0, 0, 0, 0);   
	if(document.tcpip.dnsMode[0].checked)
		disableDNSinput();	
  }else if(field.selectedIndex == 2){ //pppoe
  	wanShowDiv(0 ,1, 1, 1, 0, 0, 0); 
	if(document.tcpip.dnsMode[0].checked)
		disableDNSinput();	
  }else if(field.selectedIndex == 3){ //pptp
  	wanShowDiv(1, 1, 1, 0, 0, 0, 0); 
	if(document.tcpip.dnsMode[0].checked)
		disableDNSinput();	
  }else if(field.selectedIndex == 4){ //l2tp
  	wanShowDiv(0, 1, 1, 0, 0, 1, 0); 
	if(document.tcpip.dnsMode[0].checked)
		disableDNSinput();	
  }else if(field.selectedIndex == 5){ //USB3G
  	wanShowDiv(0, 1, 1, 0, 0, 0, 1);
	if(document.tcpip.dnsMode[0].checked)
		disableDNSinput();	
  }
  var wan_connection_type=document.tcpip.wanType.selectedIndex;
   if(wan_connection_type == 2)
   		pppTypeSelection(0);
   	else if(wan_connection_type == 3)
   		pppTypeSelection(1);
   	else if(wan_connection_type == 4)
   		pppTypeSelection(2);
   	else if(wan_connection_type == 5) //USB3G
 		pppTypeSelection(3);
   	else
   		pppConnection_Init();
}

function wan_pptp_use_dynamic_carrier_selector(index, mode){
	var dF=document.tcpip;

	if(mode == "dynamicIP") {
		dF.wan_pptp_use_dynamic_carrier_radio[index].checked = true;
		dF.pptpIpAddr.disabled = true;
		dF.pptpSubnetMask.disabled = true;
		dF.pptpDefGw.disabled = true;
	} else {
		dF.wan_pptp_use_dynamic_carrier_radio[index].checked = true;
		dF.pptpIpAddr.disabled = false;
		dF.pptpSubnetMask.disabled = false;
		dF.pptpDefGw.disabled = false;
	}
}

function wan_l2tp_use_dynamic_carrier_selector(index, mode){
	var dF=document.tcpip;

	if(mode == "dynamicIP") {
		dF.wan_l2tp_use_dynamic_carrier_radio[index].checked = true;
		dF.l2tpIpAddr.disabled = true;
		dF.l2tpSubnetMask.disabled = true;
		dF.l2tpDefGw.disabled = true;
	} else {
		dF.wan_l2tp_use_dynamic_carrier_radio[index].checked = true;
		dF.l2tpIpAddr.disabled = false;
		dF.l2tpSubnetMask.disabled = false;
		dF.l2tpDefGw.disabled = false;
	}
}

//2011.03.28 Jerry {
function applyRule()
{
	if(saveChanges_wan(document.tcpip))
	{
		showLoading();
		document.tcpip.submit();
	}
}
//2011.03.28 Jerry }

</SCRIPT>
</head>

<body onload="initial();" onunLoad="disable_auto_hint(7, 19);return unload_body();">
<script>
	if(sw_mode == 3){
		alert("<#page_not_support_mode_hint#>");
		//location.href = "/as.asp";
		location.href = "/index.asp";
	}
</script>
<div id="TopBanner"></div>
<div id="Loading" class="popup_bg"></div>
<iframe name="hidden_frame" id="hidden_frame" src="" width="0" height="0" frameborder="0"></iframe>

<form action="/start_apply.htm" method=POST name="tcpip" target="hidden_frame">
<input type="hidden" name="current_page" value="tcpipwan.asp">
<input type="hidden" value="pptp" name="ipMode">
<input type="hidden" value="formWanTcpipSetup" name="typeForm">
<input type="hidden" value="/tcpipwan.asp" name="submit-url">
<input type="hidden" name="action_mode" value="Restart_WAN">	<!--2011.04.19 Jerry-->
<input type="hidden" name="flag" value="nodetect">	<!--2011.03.28 Jerry-->
<input type="hidden" name="preferred_lang" id="preferred_lang" value="<% getInfo("preferred_lang"); %>">	<!--2011.04.14 Jerry-->

<table border="0" class="content" align="center" cellpadding="0" cellspacing="0">
  <tr>
	<td width="23">&nbsp;</td>
	<!--=====Beginning of Main Menu=====-->
	<td valign="top" width="202">
	  <div id="mainMenu"></div>
	  <div id="subMenu"></div>
	</td>
	
	<td height="430" valign="top">
	  <div id="tabMenu" class="submenuBlock"></div><br />
	  
	  <!--===================================Beginning of Main Content===========================================-->
<table width="98%" border="0" align="center" cellpadding="0" cellspacing="0">
	<tr>
		<td align="left" valign="top">
			<table width="98%" border="0" align="center" cellpadding="5" cellspacing="0" class="FormTitle">
				<thead>
				<tr>
					<td><#menu5_3#> - <#menu5_3_1#></td>
				</tr>
				</thead>
				
				<tbody>
				<tr>
					<td bgcolor="#FFFFFF"><#Layer3Forwarding_x_ConnectionType_sectiondesc#></td>
				</tr>
				</tbody>	
				
				<tr>
					<td bgcolor="#FFFFFF">
						<table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3"  class="FormTable">

<tr>
  <!--<th width="30%">WAN Access Type:</th>-->
  <th width="30%"><#Layer3Forwarding_x_ConnectionType_itemname#></th>
  <td>
	<select size="1" name="wanType" class="input" onChange="wanTypeSelection(this)">
<script>
	var wanDhcp_tmp = <% getIndex("wanDhcp"); %>;
	var fixedIp_tmp = "";
	var autoIp_tmp = "";
	var ppp_tmp = "";
	var pptp_tmp = "";
	var l2tp_tmp = "";
	if(wanDhcp_tmp == 0)
		fixedIp_tmp = "selected";
	if(wanDhcp_tmp == 1)
		autoIp_tmp = "selected";
	if(wanDhcp_tmp == 3)
		ppp_tmp = "selected";
	if(wanDhcp_tmp == 4)
		pptp_tmp = "selected";
	if(wanDhcp_tmp == 6)
		l2tp_tmp = "selected";
	document.write("<option " + fixedIp_tmp + " value=\"fixedIp\">Static IP</option>\n");
	document.write("<option " + autoIp_tmp + " value=\"autoIp\">Automatic IP</option>\n");
	document.write("<option " + ppp_tmp + " value=\"ppp\">PPPoE</option>\n");
	document.write("<option " + pptp_tmp + " value=\"pptp\">PPTP</option>\n");
	document.write("<option " + l2tp_tmp + " value=\"l2tp\">L2TP</option>\n");
</script>
	</select>
  </td>
<tr>

<tr>
  <th width="200"><a class="hintstyle" href="javascript:void(0);" onClick="openHint(17,6);"><#BasicConfig_EnableMediaServer_itemname#></a></th>
  <td>
<script>
	var upnpEnabled_tmp = <% getIndex("upnpEnabled"); %>;
	var upnpEnabled_ON = "";
	var upnpEnabled_OFF = "";
	if(upnpEnabled_tmp)
		upnpEnabled_ON = "checked";
	else
		upnpEnabled_OFF = "checked";
	document.write("<input type=\"radio\" name=\"upnpEnabled\" value=\"ON\" " + upnpEnabled_ON + "><#checkbox_Yes#>\n");
	document.write("<input type=\"radio\" name=\"upnpEnabled\" value=\"OFF\" " + upnpEnabled_OFF + "><#checkbox_No#>\n");
</script>
  </td>       
</tr>

	<tr>
  	 <th><a class="hintstyle" href="javascript:void(0);" onClick="openHint(7,11);"><#PPPConnection_x_PPPoERelay_itemname#></a></th>
    	<td>
    	<script>
        	var pppoeRelayEnabled_tmp = <%getIndex("pppoeRelayEnabled"); %>;
        	var pppoeRelay_ON = "";
        	var pppoeRelay_OFF = "";
        	if(pppoeRelayEnabled_tmp)
        		pppoeRelay_ON = "checked";
        	else
        		pppoeRelay_OFF = "checked";
        	document.write("<input type=\"radio\" name=\"pppoeRelayEnabled\" value=\"ON\" " + pppoeRelay_ON + "><#checkbox_Yes#>\n");
        	document.write("<input type=\"radio\" name=\"pppoeRelayEnabled\" value=\"OFF\" " + pppoeRelay_OFF + "><#checkbox_No#>\n");
  </script>
    	
      </td>
  </tr>

</table>
</td><tr>

<tr id="static_div" style="display:none">
  <td bgcolor="#FFFFFF">
<table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3"  class="FormTable">
<tr>
  <!--<th width="30%">IP Address:</th>-->
  <th width="30%"><a class="hintstyle" href="javascript:void(0);" onClick="openHint(7,1);"><#IPConnection_ExternalIPAddress_itemname#></a></th>
  <td>
	<input type="text" name="wan_ip" class="input" size="18" maxlength="15" value="<% getInfo("wan-ip-rom"); %>">
  </td>
</tr>

<tr>
  <!--<th width="30%">Subnet Mask:</th>-->
  <th><a class="hintstyle" href="javascript:void(0);" onClick="openHint(7,2);"><#IPConnection_x_ExternalSubnetMask_itemname#></a></th>
  <td>
	<input type="text" name="wan_mask" class="input" size="18" maxlength="15" value="<% getInfo("wan-mask-rom"); %>">
  </td>
</tr>

<tr>
  <!--<th width="30%">Default Gateway:</th>-->
  <th><a class="hintstyle" href="javascript:void(0);" onClick="openHint(7,3);"><#IPConnection_x_ExternalGateway_itemname#></a></th>
  <td>
	<input type="text" name="wan_gateway" class="input" size="18" maxlength="15" value="<% getInfo("wan-gateway-rom"); %>">
  </td>
</tr>

<tr>
  <!--<th width="30%">MTU Size:</th>-->
  <th><a class="hintstyle" href="javascript:void(0);" onClick="openHint(7,7);"><#PPPConnection_x_PPPoEMTU_itemname#></a></th>
  <td>
	<input type="text" name="fixedIpMtuSize" class="input" size="10" maxlength="10" value="<% getInfo("fixedIpMtuSize"); %>">&nbsp;(1400-1500 bytes)
  </td>
</tr>
</table>
</td></tr>
  
<tr id="pppoe_div" style="display:none">
  <td bgcolor="#FFFFFF">
<table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3"  class="FormTable">
<tr>
  <!--<th width="30%">User Name:</th>-->
  <th width="30%"><a class="hintstyle" href="javascript:void(0);" onClick="openHint(7,4);"><#PPPConnection_UserName_itemname#></a></th>
  <td>
	<input type="text" name="pppUserName" class="input" size="18" maxlength="128" value="<% getInfo("pppUserName"); %>">
  </td>
</tr>

<tr>
  <!--<th width="30%">Password:</th>-->
  <th><a class="hintstyle" href="javascript:void(0);" onClick="openHint(7,5);"><#PPPConnection_Password_itemname#></a></th>
  <td>
	<input type="password" name="pppPassword" class="input" size="18" maxlength="128" value="<% getInfo("pppPassword"); %>">
  </td>
</tr>

<tr>
  <!--<th width="30%">Service Name:</th>-->
  <th><a class="hintstyle" href="javascript:void(0);" onClick="openHint(7,9);"><#PPPConnection_x_ServiceName_itemname#></a></th>
  <td>
	<input type="text" name="pppServiceName" class="input" size="18" maxlength="40" value="<% getInfo("pppServiceName"); %>">
  </td>
</tr>

<tr>
  <th width="30%">Connection Type:</th>
  <td>
	<select size="1" name="pppConnectType" class="input" onChange="pppTypeSelection(0)">
<script>
		var type_1 = <% getIndex("pppConnectType"); %>
	     	if ( type_1 == 0 ) {
	      	  	document.write( "<option selected value=\"0\">Continuous</option>" );
    	   	  	document.write( "<option value=\"1\">Connect on Demand</option>" );
    		  	document.write( "<option value=\"2\">Manual</option>" );
	     	}
	     	if ( type_1 == 1 ) {
	      	  	document.write( "<option value=\"0\">Continuous</option>" );
    	   	  	document.write( "<option selected value=\"1\">Connect on Demand</option>" );
    		  	document.write( "<option value=\"2\">Manual</option>" );
	     	}
	     	if ( type_1 == 2 ) {
	      	  	document.write( "<option value=\"0\">Continuous</option>" );
    	   	  	document.write( "<option value=\"1\">Connect on Demand</option>" );
    		  	document.write( "<option selected value=\"2\">Manual</option>" );
	     	}
</script>
        </select>&nbsp;&nbsp;
	<input type="submit" value="Connect" name="pppConnect" class="button" onClick="return pppConnectClick(0)">&nbsp;&nbsp;
	<input type="submit" value="Disconnect" name="pppDisconnect" class="button" onClick="return pppConnectClick(1)">
<script>
	var pppConnectStatus_tmp = <% getIndex("pppConnectStatus"); %>;
	if(pppConnectStatus_tmp)
		setPPPConnected();
</script>
  </td>
</tr>

<tr>
  <!--<th width="30%">Idle Time:</th>-->
  <th><a class="hintstyle" href="javascript:void(0);" onClick="openHint(7,6);"><#PPPConnection_IdleDisconnectTime_itemname#></a></th>
  <td>
	<input type="text" name="pppIdleTime" class="input" size="10" maxlength="10" value="<% getInfo("wan-ppp-idle"); %>">&nbsp;(1-1000 minutes)
  </td>
</tr>

<tr>
  <!--<th width="30%">MTU Size:</th>-->
  <th><a class="hintstyle" href="javascript:void(0);" onClick="openHint(7,7);"><#PPPConnection_x_PPPoEMTU_itemname#></a></th>
  <td>
	<input type="text" name="pppMtuSize" class="input" size="10" maxlength="10" value="<% getInfo("pppMtuSize"); %>">&nbsp;(1360-1492 bytes)
  </td>
</tr>

</table>
</td></tr>
<tr id="pptp_div" style="display:none">
  <td bgcolor="#FFFFFF">
<table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3"  class="FormTable">
<tr>
  <th width="30%"><#Layer3Forwarding_x_DHCPClient_itemname#></th>
  <td>
<script>
	var pptp_dhcp_tmp = <% getIndex("pptp_wan_ip_mode"); %>;
	var pptp_dhcp_auto = "";
	var pptp_dhcp_manual = "";
	if(pptp_dhcp_tmp)
		pptp_dhcp_manual = "checked";
	else
		pptp_dhcp_auto = "checked";
	document.write("<input type=\"radio\" value=\"dynamicIP\" name=\"wan_pptp_use_dynamic_carrier_radio\" " + pptp_dhcp_auto + " onClick=\"wan_pptp_use_dynamic_carrier_selector(0, this.value)\"><#checkbox_Yes#>\n");
	document.write("<input type=\"radio\" value=\"staticIP\" name=\"wan_pptp_use_dynamic_carrier_radio\" " + pptp_dhcp_manual + " onClick=\"wan_pptp_use_dynamic_carrier_selector(1, this.value)\"><#checkbox_No#>\n");
</script>
  </td>
</tr>

<tr>
  <!--<th width="30%">IP Address:</th>-->
  <th width="30%"><a class="hintstyle" href="javascript:void(0);" onClick="openHint(7,1);"><#IPConnection_ExternalIPAddress_itemname#></a></th>
  <td>
	<input type="text" name="pptpIpAddr" class="input" size="18" maxlength="30" value="<% getInfo("pptpIp"); %>">
  </td>
</tr>

<tr>
  <!--<th width="30%">Subnet Mask:</th>-->
  <th><a class="hintstyle" href="javascript:void(0);" onClick="openHint(7,2);"><#IPConnection_x_ExternalSubnetMask_itemname#></a></th>
  <td>
	<input type="text" name="pptpSubnetMask" class="input" size="18" maxlength="30" value="<% getInfo("pptpSubnet"); %>">
  </td>
</tr>
<tr>
  <th width="30%"><a class="hintstyle" href="javascript:void(0);" onClick="openHint(7,3);"><#IPConnection_x_ExternalGateway_itemname#></a></th>
  <td>
        <input type="text" name="pptpDefGw" class="input" size="18" maxlength="30" value="<% getInfo("pptpDefGw"); %>">
  </td>
</tr>

<tr>
  <!--<th width="30%">Server IP Address:</th>-->
  <th width="30%"><a class="hintstyle" href="javascript:void(0);" onClick="openHint(7,19);"><#PPPConnection_x_HeartBeat_itemname#></a></th>
  <td>
	<input type="text" name="pptpServerIpAddr" class="input" size="18" maxlength="30" value="<% getInfo("pptpServerIp"); %>">
  </td>
</tr>

<tr>
  <!--<th width="30%">User Name:</th>-->
  <th width="30%"><a class="hintstyle" href="javascript:void(0);" onClick="openHint(7,4);"><#PPPConnection_UserName_itemname#></a></th>
  <td>
	<input type="text" name="pptpUserName" class="input" size="18" maxlength="128" value="<% getInfo("pptpUserName"); %>">
  </td>
</tr>

<tr>
  <!--<th width="30%">Password:</th>-->
  <th><a class="hintstyle" href="javascript:void(0);" onClick="openHint(7,5);"><#PPPConnection_Password_itemname#></a></th>
  <td>
	<input type="password" name="pptpPassword" class="input" size="18" maxlength="128" value="<% getInfo("pptpPassword"); %>">
  </td>
</tr>

<tr>
  <th width="30%">Connection Type:</th>
  <td>
	<select size="1" name="pptpConnectType" class="input" onChange="pppTypeSelection(1)">
<script>
		var type_2 = <% getIndex("pptpConnectType"); %>;
	     	if ( type_2 == 0 ) {
	      	  	document.write( "<option selected value=\"0\">Continuous</option>" );
    	   	  	document.write( "<option value=\"1\">Connect on Demand</option>" );
    		  	document.write( "<option value=\"2\">Manual</option>" );
	     	}
	     	if ( type_2 == 1 ) {
	      	  	document.write( "<option value=\"0\">Continuous</option>" );
    	   	  	document.write( "<option selected value=\"1\">Connect on Demand</option>" );
    		  	document.write( "<option value=\"2\">Manual</option>" );
	     	}
	     	if ( type_2 == 2 ) {
	      	  	document.write( "<option value=\"0\">Continuous</option>" );
    	   	  	document.write( "<option value=\"1\">Connect on Demand</option>" );
    		  	document.write( "<option selected value=\"2\">Manual</option>" );
	     	}
</script>
        </select>&nbsp;&nbsp;
	<input type="submit" value="Connect" name="pptpConnect" class="button" onClick="return pptpConnectClick(0)">&nbsp;&nbsp;
	<input type="submit" value="Disconnect" name="pptpDisconnect" class="button" onClick="return pptpConnectClick(1)">
<script>
	var pppConnectStatus_tmp1 = <% getIndex("pppConnectStatus"); %>;
	if(pppConnectStatus_tmp1)
		setPPPConnected();
</script>
  </td>
</tr>   

<tr>
  <!--<th width="30%">Idle Time:</th>-->
  <th><a class="hintstyle" href="javascript:void(0);" onClick="openHint(7,6);"><#PPPConnection_IdleDisconnectTime_itemname#></a></th>
  <td>
	<input type="text" name="pptpIdleTime" class="input" size="10" maxlength="10" value="<% getInfo("wan-pptp-idle"); %>">&nbsp;(1-1000 minutes)
  </td>
</tr>  

<tr>
  <!--<th width="30%">MTU Size:</th>-->
  <th><a class="hintstyle" href="javascript:void(0);" onClick="openHint(7,7);"><#PPPConnection_x_PPPoEMTU_itemname#></a></th>
  <td>
	<input type="text" name="pptpMtuSize" class="input" size="10" maxlength="10" value="<% getInfo("pptpMtuSize"); %>">&nbsp;(1400-1460 bytes)
  </td>
</tr>

<tr>
  <th>Request MPPE Encryption</th>
  <td>
<script>
	var pptpSecurity_tmp = <% getIndex("pptpSecurity"); %>;
	var pptpSecurity_ON = "";
	var pptpSecurity_OFF = "";
	if(pptpSecurity_tmp)
		pptpSecurity_ON = "checked";
	else
		pptpSecurity_OFF = "checked";
	document.write("<input type=\"radio\" name=\"pptpSecurity\" value=\"ON\" " + pptpSecurity_ON + "><#checkbox_Yes#>\n");
	document.write("<input type=\"radio\" name=\"pptpSecurity\" value=\"OFF\" " + pptpSecurity_OFF + "><#checkbox_No#>\n");
</script>
  </td>       
</tr>

<tr>
  <th>Request MPPC Compression</th>
  <td>
<script>
	var pptpCompress_tmp = <% getIndex("pptpCompress"); %>;
	var pptpCompress_ON = "";
	var pptpCompress_OFF = "";
	if(pptpCompress_tmp)
		pptpCompress_ON = "checked";
	else
		pptpCompress_OFF = "checked";
	document.write("<input type=\"radio\" name=\"pptpCompress\" value=\"ON\" " + pptpCompress_ON + "><#checkbox_Yes#>\n");
	document.write("<input type=\"radio\" name=\"pptpCompress\" value=\"OFF\" " + pptpCompress_OFF + "><#checkbox_No#>\n");
</script>
  </td>       
</tr>


</table>
</td></tr>

<tr id="l2tp_div" style="display:none">
  <td bgcolor="#FFFFFF">
<table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3"  class="FormTable">
<tr>
  <th width="30%"><#Layer3Forwarding_x_DHCPClient_itemname#></th>
  <td>
<script>
	var l2tp_dhcp_tmp = <% getIndex("l2tp_wan_ip_mode"); %>;
	var l2tp_dhcp_auto = "";
	var l2tp_dhcp_manual = "";
	if(l2tp_dhcp_tmp)
		l2tp_dhcp_manual = "checked";
	else
		l2tp_dhcp_auto = "checked";
	document.write("<input type=\"radio\" value=\"dynamicIP\" name=\"wan_l2tp_use_dynamic_carrier_radio\" " + l2tp_dhcp_auto + " onClick=\"wan_l2tp_use_dynamic_carrier_selector(0, this.value);\"><#checkbox_Yes#>\n");
	document.write("<input type=\"radio\" value=\"staticIP\" name=\"wan_l2tp_use_dynamic_carrier_radio\" " + l2tp_dhcp_manual + " onClick=\"wan_l2tp_use_dynamic_carrier_selector(1, this.value);\"><#checkbox_No#>\n");
</script>
  </td>
</tr>
<tr>
  <!--<th width="30%">IP Address:</th>-->
  <th width="30%"><a class="hintstyle" href="javascript:void(0);" onClick="openHint(7,1);"><#IPConnection_ExternalIPAddress_itemname#></a></th>
  <td>
	<input type="text" name="l2tpIpAddr" class="input" size="18" maxlength="30" value="<% getInfo("l2tpIp"); %>">
  </td>
</tr>

<tr>
  <!--<th width="30%">Subnet Mask:</th>-->
  <th><a class="hintstyle" href="javascript:void(0);" onClick="openHint(7,2);"><#IPConnection_x_ExternalSubnetMask_itemname#></a></th>
  <td>
	<input type="text" name="l2tpSubnetMask" class="input" size="18" maxlength="30" value="<% getInfo("l2tpSubnet"); %>">
  </td>
</tr>

<tr>
  <th width="30%"><a class="hintstyle" href="javascript:void(0);" onClick="openHint(7,3);"><#IPConnection_x_ExternalGateway_itemname#></a></th>
  <td>
        <input type="text" name="l2tpDefGw" class="input" size="18" maxlength="30" value="<% getInfo("l2tpDefGw"); %>">
  </td>
</tr>

<tr>
  <!--<th width="30%">Server IP Address:</th>-->
  <th width="30%"><a class="hintstyle" href="javascript:void(0);" onClick="openHint(7,19);"><#PPPConnection_x_HeartBeat_itemname#></a></th>
  <td>
	<input type="text" name="l2tpServerIpAddr" class="input" size="18" maxlength="30" value="<% getInfo("l2tpServerIp"); %>">
  </td>
</tr>

<tr>
  <!--<th width="30%">User Name:</th>-->
  <th width="30%"><a class="hintstyle" href="javascript:void(0);" onClick="openHint(7,4);"><#PPPConnection_UserName_itemname#></a></th>
  <td>
	<input type="text" name="l2tpUserName" class="input" size="18" maxlength="128" value="<% getInfo("l2tpUserName"); %>">
  </td>
</tr>

<tr>
  <!--<th width="30%">Password:</th>-->
  <th><a class="hintstyle" href="javascript:void(0);" onClick="openHint(7,5);"><#PPPConnection_Password_itemname#></a></th>
  <td>
	<input type="password" name="l2tpPassword" class="input" size="18" maxlength="128" value="<% getInfo("l2tpPassword"); %>">
  </td>
</tr>

<tr>
  <th width="30%">Connection Type:</th>
  <td>
	<select size="1" name="l2tpConnectType" class="input" onChange="pppTypeSelection(2)">
<script>
		var type_3 = <% getIndex("l2tpConnectType"); %>;
	     	if ( type_3 == 0 ) {
	      	  	document.write( "<option selected value=\"0\">Continuous</option>" );
    	   	  	document.write( "<option value=\"1\">Connect on Demand</option>" );
    		  	document.write( "<option value=\"2\">Manual</option>" );
	     	}
	     	if ( type_3 == 1 ) {
	      	  	document.write( "<option value=\"0\">Continuous</option>" );
    	   	  	document.write( "<option selected value=\"1\">Connect on Demand</option>" );
    		  	document.write( "<option value=\"2\">Manual</option>" );
	     	}
	     	if ( type_3 == 2 ) {
	      	  	document.write( "<option value=\"0\">Continuous</option>" );
    	   	  	document.write( "<option value=\"1\">Connect on Demand</option>" );
    		  	document.write( "<option selected value=\"2\">Manual</option>" );
	     	}
</script>
        </select>&nbsp;&nbsp;
	<input type="submit" value="Connect" name="l2tpConnect" class="button" onClick="return l2tpConnectClick(0)">&nbsp;&nbsp;
	<input type="submit" value="Disconnect" name="l2tpDisconnect" class="button" onClick="return l2tpConnectClick(1)">
<script>
	var pppConnectStatus_tmp2 = <% getIndex("pppConnectStatus"); %>;
	if(pppConnectStatus_tmp2)
		setPPPConnected();
</script>
  </td>
</tr>   

<tr>
  <!--<th width="30%">Idle Time:</th>-->
  <th><a class="hintstyle" href="javascript:void(0);" onClick="openHint(7,6);"><#PPPConnection_IdleDisconnectTime_itemname#></a></th>
  <td>
	<input type="text" name="l2tpIdleTime" class="input" size="10" maxlength="10" value="<% getInfo("wan-l2tp-idle"); %>">&nbsp;(1-1000 minutes)
  </td>
</tr>  

<tr>
  <!--<th width="30%">MTU Size:</th>-->
  <th><a class="hintstyle" href="javascript:void(0);" onClick="openHint(7,7);"><#PPPConnection_x_PPPoEMTU_itemname#></a></th>
  <td>
	<input type="text" name="l2tpMtuSize" class="input" size="10" maxlength="10" value="<% getInfo("pptpMtuSize"); %>">&nbsp;(1400-1460 bytes)
  </td>
</tr>  

</table>
</td></tr>

<tr id="USB3G_div" style="display:none">
  <td bgcolor="#FFFFFF">
<table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3"  class="FormTable">
<tr>
  <th width="30%">User Name:</th>
  <td>
	<input type="text" name="USB3G_USER" class="input" size="18" maxlength="30" value="<% getInfo("USB3G_USER"); %>">
  </td>
</tr>

<tr>
  <th width="30%">Password:</th>
  <td>
	<input type="password" name="USB3G_PASS" class="input" size="18" maxlength="30" value="<% getInfo("USB3G_PASS"); %>">
  </td>
</tr>

<tr>
  <th width="30%">PIN:</th>
  <td>
	<input type="password" name="USB3G_PIN" class="input" size="18" maxlength="30" value="<% getInfo("USB3G_PIN"); %>">
  </td>
</tr>

<tr>
  <th width="30%">APN:</th>
  <td>
	<input type="text" name="USB3G_APN" class="input" size="18" maxlength="128" value="<% getInfo("USB3G_APN"); %>">
  </td>
</tr>

<tr>
  <th width="30%">Dial Number:</th>
  <td>
	<input type="text" name="USB3G_DIALNUM" class="input" size="18" maxlength="128" value="<% getInfo("USB3G_DIALNUM"); %>">
  </td>
</tr>

<tr>
  <th width="30%"><#TCPIPWAN_Connectiontyp#></th>
  <td>
	<select size="1" name="USB3GConnectType" class="input" onChange="pppTypeSelection(3)">

<script>
	    var type_4 = 0;
            if ( type_4 == 0 ) {
                document.write( "<option selected value=\"0\">Continuous</option>" );
                document.write( "<option value=\"1\">Connect on Demand</option>" );
                document.write( "<option value=\"2\">Manual</option>" );
            }
            if ( type_4 == 1 ) {
                document.write( "<option value=\"0\">Continuous</option>" );
                document.write( "<option selected value=\"1\">Connect on Demand</option>" );
                document.write( "<option value=\"2\">Manual</option>" );
            }
            if ( type_4 == 2 ) {
                document.write( "<option value=\"0\">Continuous</option>" );
                document.write( "<option value=\"1\">Connect on Demand</option>" );
                document.write( "<option selected value=\"2\">Manual</option>" );
            }
</script>
        </select>&nbsp;&nbsp;
    	<input type="submit" value="Connect" name="USB3GConnect" onClick="return USB3GConnectClick(0)">&nbsp;&nbsp;
    	<input type="submit" value="Disconnect" name="USB3GDisconnect" onClick="return USB3GConnectClick(1)">
<script>
	var pppConnectStatus_tmp3 = <% getIndex("pppConnectStatus"); %>;
	if(pppConnectStatus_tmp3)
		setPPPConnected();
</script>
  </td>
</tr>

<tr>
  <th width="30%">Idle Time:</th>
  <td>
	<input type="text" name="USB3GIdleTime" class="input" size="10" maxlength="10" value="<% getInfo("wan-USB3G-idle"); %>">&nbsp;(1-1000 minutes)
  </td>
</tr>

<tr>
  <th width="30%">MTU Size:</th>
  <td>
	<input type="text" name="USB3GMtuSize" class="input" size="10" maxlength="10" value="<% getInfo("USB3GMtuSize"); %>">&nbsp;(1420-1490 bytes)
  </td>
</tr>

</table>
</td></tr>

<tr id="dns_div" style="display:none">
  <td bgcolor="#FFFFFF">
<table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3"  class="FormTable">
<thead>
<tr>
  <td colspan="2"><#IPConnection_x_DNSServerEnable_sectionname#></td>
</tr>
</thead>

<tr id="dnsMode_div" style="display:none">
  <th width="30%"><a class="hintstyle" href="javascript:void(0);" onClick="openHint(7,12);"><#IPConnection_x_DNSServerEnable_itemname#></a></th>
  <td>
<script>
	var wanDNS_tmp = <% getIndex("wanDNS"); %>;
	var wanDNS_auto = "";
	var wanDNS_manual = "";
	if(wanDNS_tmp)
		wanDNS_manual = "checked";
	else
		wanDNS_auto = "checked";
	document.write("<input type=\"radio\" value=\"dnsAuto\" name=\"dnsMode\" " + wanDNS_auto + " onClick=\"autoDNSclicked()\"><#checkbox_Yes#>\n");
	document.write("<input type=\"radio\" value=\"dnsManual\" name=\"dnsMode\" " + wanDNS_manual + " onClick=\"manualDNSclicked()\"><#checkbox_No#>\n");
</script>
  </td>
</tr>

<tr>
  <!--<th width="30%">DNS 1:</th>-->
  <th width="30%"><a class="hintstyle" href="javascript:void(0);" onClick="openHint(7,13);"><#IPConnection_x_DNSServer1_itemname#></a></th>
  <td>
	<input type="text" name="dns1" class="input" size="18" maxlength="15" value=<% getInfo("wan-dns1"); %>>
  </td>
</tr>

<tr>
  <!--<th width="30%">DNS 2:</th>-->
  <th><a class="hintstyle" href="javascript:void(0);" onClick="openHint(7,14);"><#IPConnection_x_DNSServer2_itemname#></a></th>
  <td>
	<input type="text" name="dns2" class="input" size="18" maxlength="15" value=<% getInfo("wan-dns2"); %>>
  </td>
</tr>

<tr style="display:none">
  <th width="30%">DNS 3:</th>
  <td>
	<input type="text" name="dns3" class="input" size="18" maxlength="15" value=<% getInfo("wan-dns3"); %>>
  </td>
</tr>

</table>
</td></tr>

<tr>
  <td bgcolor="#FFFFFF">
<table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3"  class="FormTable">
<thead>
<tr>
  <td colspan="2"><#PPPConnection_x_HostNameForISP_sectionname#></td>
</tr>
</thead>

<tr id="dhcp_div" style="display:none">
  <!--<th width="30%">Host Name:</th>-->
  <th width="30%"><a class="hintstyle" href="javascript:void(0);" onClick="openHint(7,15);"><#PPPConnection_x_HostNameForISP_itemname#></a></th>
  <td>
	<input type="text" name="hostName" class="input" size="18" maxlength="30" value="<% getInfo("hostName"); %>">
  </td>
</tr>

<tr> 
  <!--<th width="30%">Clone MAC Address:</th>-->
  <th width="30%"><a class="hintstyle" href="javascript:void(0);" onClick="openHint(7,16);"><#PPPConnection_x_MacAddressForISP_itemname#></a></th>
  <td>
	<input type="text" name="wan_macAddr" class="input" size="18" maxlength="12" value=<% getInfo("wanMac"); %>>
  </td>
</tr>

<tr style="display:none;">
  <td colspan="2">
<script>
	var igmpproxyEnabled_tmp = 0;
	var igmpproxyEnabled_checked = "";
	if(igmpproxyEnabled_tmp == 0)
		igmpproxyEnabled_checked = "checked";
	document.write("<input type=\"checkbox\" name=\"igmpproxyEnabled\" value=\"ON\" " + igmpproxyEnabled_checked + ">&nbsp;&nbsp;Enable IGMP Proxy\n");
</script>
  </td>
</tr>

<tr style="display:none;">
  <td colspan="2">
<script>
	var pingWanAccess_tmp = <% getIndex("pingWanAccess"); %>;
	var pingWanAccess_checked = "";
	if(pingWanAccess_tmp)
		pingWanAccess_checked = "checked";
	document.write("<input type=\"checkbox\" name=\"pingWanAccess\" value=\"ON\" " + pingWanAccess_checked + ">&nbsp;&nbsp;Enable Ping Access on WAN\n");
</script>
  </td>
</tr>
        
<tr style="display:none;">
  <td colspan="2">
<script>
	var webWanAccess_tmp = <% getIndex("webWanAccess"); %>;
	var webWanAccess_checked = "";
	if(webWanAccess_tmp)
		webWanAccess_checked = "checked";
	document.write("<input type=\"checkbox\" name=\"webWanAccess\" value=\"ON\" " + webWanAccess_checked + ">&nbsp;&nbsp;Enable Web Server Access on WAN\n");
</script>
  </td>
</tr>        

<tr style="display:none;">
  <td colspan="2">
<script>
	var VPNPassThruIPsec_tmp = <% getIndex("VPNPassThruIPsec"); %>;
	var VPNPassThruIPsec_checked = "";
	if(VPNPassThruIPsec_tmp)
		VPNPassThruIPsec_checked = "checked";
	document.write("<input type=\"checkbox\" name=\"WANPassThru1\" value=\"ON\" " + VPNPassThruIPsec_checked + ">&nbsp;&nbsp;Enable IPsec pass through on VPN connection\n");
</script>
  </td>
</tr>

<tr style="display:none;">
  <td colspan="2">
<script>
	var VPNPassThruPPTP_tmp = <% getIndex("VPNPassThruPPTP"); %>;
	var VPNPassThruPPTP_checked = "";
	if(VPNPassThruPPTP_tmp)
		VPNPassThruPPTP_checked = "checked";
	document.write("<input type=\"checkbox\" name=\"WANPassThru2\" value=\"ON\" " + VPNPassThruPPTP_checked + ">&nbsp;&nbsp;Enable PPTP pass through on VPN connection\n");
</script>
  </td>
</tr>

<tr style="display:none;">
  <td colspan="2">
<script>
	var VPNPassThruL2TP_tmp = <% getIndex("VPNPassThruL2TP"); %>;
	var VPNPassThruL2TP_checked = "";
	if(VPNPassThruL2TP_tmp)
		VPNPassThruL2TP_checked = "checked";
	document.write("<input type=\"checkbox\" name=\"WANPassThru3\" value=\"ON\" " + VPNPassThruL2TP_checked + ">&nbsp;&nbsp;Enable L2TP pass through on VPN connection\n");
</script>
  </td>
</tr>

	<!-- disable ipv6 pass throuth for release jungle sdk v2.2, add "<" before %if (getIndex... enable it-->
<tr style="display:none;">
  <td colspan="2">
<script>
	var ipv6passthrouh_tmp = <% getIndex("ipv6passthrouh"); %>;
	var ipv6passthrouh_checked = "";
	if(ipv6passthrouh_tmp)
		ipv6passthrouh_checked = "checked";
	document.write("<input type=\"checkbox\" name=\"ipv6_passthru_enabled\" value=\"ON\" " + ipv6passthrouh_checked + ">&nbsp;&nbsp;Enable IPv6 pass through on VPN connection\n");
</script>
  </td>
</tr>

</table>
</td></tr>

<tr>
<td bgcolor="#FFFFFF">
		<table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3"  class="FormTable">
<tr align="right">
  <td colspan="2">
	<input type="button" value="<#CTL_apply#>" name="save" class="button" onClick="applyRule()">
  </td>
</tr>

</table>

<script>
	var wan_connection_type=document.tcpip.wanType.selectedIndex;
   	wanTypeSelection(document.tcpip.wanType);
   	if(wan_connection_type == 2)
   		pppTypeSelection(0);
   	else if(wan_connection_type == 3)
   		pppTypeSelection(1);
   	else if(wan_connection_type == 4)
   		pppTypeSelection(2);
   	else if(wan_connection_type == 5)
   		pppTypeSelection(3);
   	else
   		pppConnection_Init();
</script>

</td></tr>

</table>
</td>
</form>

					<td id="help_td" style="width:15px;" valign="top">
						<form name="hint_form"></form>
            <div id="helpicon" onClick="openHint(0,0);" title="<#Help_button_default_hint#>">
            	<img src="images/help.gif">
            </div>
						<div id="hintofPM" style="display:none;">
							<table width="100%" cellpadding="0" cellspacing="1" class="Help" bgcolor="#999999">
								<thead>
								<tr>
									<td>
										<div id="helpname" class="AiHintTitle"></div>
										<a href="javascript:void(0);" onclick="closeHint()">
											<img src="images/button-close.gif" class="closebutton">
										</a>
									</td>
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
		</td>
		<!--===================================Ending of Main Content===========================================-->
	
    <td width="10" align="center" valign="top">&nbsp;</td>
	</tr>
</table>

<!--</blockquote>-->
<div id="footer"></div>
</body>
</html>
