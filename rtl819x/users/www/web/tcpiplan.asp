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
<title>ASUS Wireless Router <#Web_Title#> - <#menu5_2_1#></title>
<link rel="stylesheet" type="text/css" href="index_style.css"> 
<link rel="stylesheet" type="text/css" href="form_style.css">
<link rel="stylesheet" type="text/css" href="other.css">
<script type="text/javascript" src="/state.js"></script>
<script type="text/javascript" src="/general.js"></script>
<script type="text/javascript" src="/popup.js"></script>
<script type="text/javascript" src="/help.js"></script>
<script type="text/javascript" src="/detect.js"></script>
<script type="text/javascript" src="util_gw.js"> </script>
<script>
var initialDhcp;

function initial(){
	show_banner(1);
	show_menu(5,2,1);
	show_footer();
}

function checkMode()
{
	var opmode=<% getIndex("wlanMode"); %> ;
	if( opmode > 3 )
		disableTextField(document.tcpip.stp);
}

function dhcpChange()
{
  	var dF = document.tcpip;
  	var index;
	if(dF.dhcp[0].checked)	//Enbable dhcp server
	{
		index = dF.dhcp[0].value;
	}
	else	//Disable dhcp server
	{
		index = dF.dhcp[1].value;
	}
	
	if ( index == 0 || index == 1) {
		disableTextField(dF.dhcpRangeStart);
   		disableTextField(dF.dhcpRangeEnd);
		disableTextField(dF.dhcpLease);
   		enableTextField(dF.lan_gateway);
   		disableTextField(dF.domainName);	  	  
  	}
  	else {
   		enableTextField(dF.dhcpRangeStart);
   		enableTextField(dF.dhcpRangeEnd);
		enableTextField(dF.dhcpLease);
   		disableTextField(dF.lan_gateway);
   		enableTextField(dF.domainName);	  
  	}
  	if ( index == 1 ) {
 		disableTextField(dF.lan_ip);
		disableTextField(dF.lan_mask);
		disableTextField(dF.lan_gateway);
  	}
  	else {
 		enableTextField(dF.lan_ip);
		enableTextField(dF.lan_mask);
   		enableTextField(dF.lan_gateway);
	}
}

function checkClientRange(start,end)
{
  start_d = getDigit(start,4);
  start_d += getDigit(start,3)*256;
  start_d += getDigit(start,2)*256;
  start_d += getDigit(start,1)*256;

  end_d = getDigit(end,4);
  end_d += getDigit(end,3)*256;
  end_d += getDigit(end,2)*256;
  end_d += getDigit(end,1)*256;

  if ( start_d <= end_d )
	return true;

  return false;
}


function saveChanges()
{
	if ( checkIpAddr(document.tcpip.lan_ip, 'Invalid IP address value! ') == false )
		return false;

	if (checkIPMask(document.tcpip.lan_mask) == false)
		return false ;

	if ( document.tcpip.dhcp[0].checked) {
  		if ( checkIpAddr(document.tcpip.dhcpRangeStart, 'Invalid DHCP client start address! ') == false )
	    		return false;

		if ( !checkSubnet(document.tcpip.lan_ip.value,document.tcpip.lan_mask.value,document.tcpip.dhcpRangeStart.value)) {
			alert(document.tcpip.dhcpRangeStart.value + '<#JS_validip#>');
			document.tcpip.dhcpRangeStart.value = document.tcpip.dhcpRangeStart.defaultValue;
			document.tcpip.dhcpRangeStart.focus();
			return false;
		}
  		if ( checkIpAddr(document.tcpip.dhcpRangeEnd, 'Invalid DHCP client End address! ') == false )
	    		return false;	

		if ( !checkSubnet(document.tcpip.lan_ip.value,document.tcpip.lan_mask.value,document.tcpip.dhcpRangeEnd.value)) {
			alert(document.tcpip.dhcpRangeEnd.value + '<#JS_validip#>');
			document.tcpip.dhcpRangeEnd.value = document.tcpip.dhcpRangeEnd.defaultValue;
			document.tcpip.dhcpRangeEnd.focus();
			return false;
		}
        	if ( !checkClientRange(document.tcpip.dhcpRangeStart.value,document.tcpip.dhcpRangeEnd.value) ) {
			alert("<#LANHostConfig_LANDHCPClient_warning#>\n<#JS_validip2#>");
			document.tcpip.dhcpRangeStart.focus();
			return false;
        	}

   	}
   	if ( document.tcpip.dhcp[1].checked) {
   		if ( document.tcpip.lan_gateway.value=="")
			document.tcpip.lan_gateway.value = '0.0.0.0';
	
		if (document.tcpip.lan_gateway.value!="0.0.0.0") {
			if ( checkIpAddr(document.tcpip.lan_gateway, 'Invalid DHCP client End address! ') == false )
	    			return false;
	    		if ( !checkSubnet(document.tcpip.lan_ip.value,document.tcpip.lan_mask.value,document.tcpip.lan_gateway.value)) {
				alert(document.tcpip.lan_gateway.value + '<#JS_validip#>');
				document.tcpip.lan_gateway.value = document.tcpip.lan_gateway.defaultValue;
				document.tcpip.lan_gateway.focus();
				return false;
      			}
		}
  	}

  	var str = document.tcpip.lan_macAddr.value;
   	if(str.length ==0){
  		document.tcpip.lan_macAddr.value = "000000000000";
  		return true;
  	}
  	if ( str.length > 0 && str.length < 12) {
		alert('<#JS_validmac#>');
		document.tcpip.lan_macAddr.focus();
		return false;
  	}

  	for (var i=0; i<str.length; i++) {
    		if ( (str.charAt(i) >= '0' && str.charAt(i) <= '9') ||
			(str.charAt(i) >= 'a' && str.charAt(i) <= 'f') ||
			(str.charAt(i) >= 'A' && str.charAt(i) <= 'F') )
			continue;
		alert('<#JS_validmac#>');
		document.tcpip.lan_macAddr.focus();
		return false;
  	}
	showLoading();	//2011.03.28 Jerry
  	return true;
}

function addClick()
{
	if(get_by_id("ip_addr").value == "" && get_by_id("mac_addr").value == "") {
		showLoading();	//2011.03.28 Jerry
		return true;
	}
	
	var str = document.formStaticDHCPAdd.mac_addr.value;
	if ( checkIpAddr(document.formStaticDHCPAdd.ip_addr, 'Invalid IP address value! ') == false )
		return false;
	if ( str.length < 12) {
		alert('<#JS_validmac#>');
		document.formStaticDHCPAdd.mac_addr.focus();
		return false;
	}
	for (var i=0; i<str.length; i++) {
		if ( (str.charAt(i) >= '0' && str.charAt(i) <= '9') ||
			(str.charAt(i) >= 'a' && str.charAt(i) <= 'f') ||
			(str.charAt(i) >= 'A' && str.charAt(i) <= 'F') )
			continue;

		alert('<#JS_validmac#>');
		document.formStaticDHCPAdd.mac_addr.focus();
		return false;
	}   	    
	var entryNum = <% getIndex("staticDhcpNum"); %>;
	var Max_Filter_Num = <% getIndex("maxFilterNum"); %>;
	if(maxfilter(entryNum,Max_Filter_Num))
	{
	return false; 
	}
  	showLoading();	//2011.03.28 Jerry
	return true;
}


function deleteClick()
{
	acl_num = <% getIndex("wlanAcNum"); %> ;
	delNum = 0 ;
	for(i=1 ; i <= acl_num ; i++){
  		if(document.formStaticDHCP.elements["select"+i].checked)
  			delNum ++ ;
  	}
	if ( !confirm("<#Delete_confirm1#>") ) {
		return false;
	}
	else {
		showLoading();	//2011.03.28 Jerry
		return true;
	}
}

function deleteAllClick()
{
   if ( !confirm("<#Delete_confirm2#>") ) {
	return false;
  }
  else
	return true;
}
function disableDelButton()
{
	disableButton(document.formStaticDHCP.deleteSelRsvIP);
}

function updateState()
{
  if (document.formStaticDHCPAdd.static_dhcp[0].checked) {
 	enableTextField(document.formStaticDHCPAdd.ip_addr);
 	enableTextField(document.formStaticDHCPAdd.mac_addr);
  }
  else {
 	disableTextField(document.formStaticDHCPAdd.ip_addr);
 	disableTextField(document.formStaticDHCPAdd.mac_addr);
  }
}
</script>
</head>

<body onload="initial();checkMode();" onunLoad="disable_auto_hint(4, 2);return unload_body();">
<div id="TopBanner"></div>
<div id="hiddenMask" class="popup_bg">
	<table cellpadding="5" cellspacing="0" id="dr_sweet_advise" class="dr_sweet_advise" align="center">
		<tr>
		<td>
			<div class="drword" id="drword" style="height:110px;"><#Main_alert_proceeding_desc4#> <#Main_alert_proceeding_desc1#>...
				<br/>
				<br/>
	    </div>
		  <div class="drImg"><img src="images/DrsurfImg.gif"></div>
			<div style="height:70px;"></div>
		</td>
		</tr>
	</table>
<!--[if lte IE 6.5]><iframe class="hackiframe"></iframe><![endif]-->
</div>

<div id="Loading" class="popup_bg"></div>

<iframe name="hidden_frame" id="hidden_frame" src="" width="0" height="0" frameborder="0"></iframe>

<table class="content" align="center" cellpadding="0" cellspacing="0">
  <tr>
	<td width="23">&nbsp;</td>
	
	<!--=====Beginning of Main Menu=====-->
	<td valign="top" width="202">
	  <div id="mainMenu"></div>
	  <div id="subMenu"></div>
	</td>
	
    <td valign="top">
	<div id="tabMenu" class="submenuBlock"></div>
		<br>
		<!--===================================Beginning of Main Content===========================================-->
<table width="98%" border="0" align="center" cellpadding="0" cellspacing="0">
	<tr>
		<td align="left" valign="top" >
		
  <table width="98%" border="0" align="center" cellpadding="5" cellspacing="0" class="FormTitle" table>
	<thead>
	<tr>
		<td><#menu5_2#> - <#menu5_2_1#></td>
	</tr>
	</thead>
	<tbody>
	  <tr>
	    <td bgcolor="#FFFFFF"><#LANHostConfig_display1_sectiondesc#></td>
	  </tr>
	</tbody>
	
	<tr>
	  <td bgcolor="#FFFFFF">

<form action="/start_apply.htm" method=POST name="tcpip" target="hidden_frame">
<input type="hidden" name="current_page" value="tcpiplan.asp">
<input type="hidden" value="formTcpipSetup" name="typeForm">
<input type="hidden" value="/tcpiplan.asp" name="submit-url">
<input type="hidden" name="action_mode" value="Restart_LAN">	<!--2011.04.19 Jerry-->
<input type="hidden" name="flag" value="nodetect">	<!--2011.03.28 Jerry-->
<input type="hidden" name="preferred_lang" id="preferred_lang" value="<% getInfo("preferred_lang"); %>">	<!--2011.04.14 Jerry-->

<table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3"  class="FormTable">

<tr>
      <!--<th>IP Address:</th>-->
  <th width="40%"><a class="hintstyle" href="javascript:void(0);" onClick="openHint(4,1);"><#LANHostConfig_IPRouters_itemname#></a></th>
  <td>
	<input type="text" name="lan_ip" class="input" size="15" maxlength="15" value=<% getInfo("ip-rom"); %>>
  </td>
</tr>

<tr>
      <!--<th>Subnet Mask:</th>-->
  <th><a class="hintstyle"  href="javascript:void(0);" onClick="openHint(4,2);"><#LANHostConfig_SubnetMask_itemname#></a></th>
  <td>
	<input type="text" name="lan_mask" class="input" size="15" maxlength="15" value="<% getInfo("mask-rom"); %>">
  </td>
</tr>

<tr style="display:none">
      <!--<th>Default Gateway:</th>-->
  <th><a class="hintstyle" href="javascript:void(0);" onClick="openHint(5,6);"><#LANHostConfig_x_LGateway_itemname#></a></th>  
  <td>
	<input type="text" name="lan_gateway" size="15" maxlength="15" value="<% getInfo("gateway-rom"); %>">
  </td>
</tr>
</td></tr>

<tr>

<tr>
  <th width="40%"><a class="hintstyle" href="javascript:void(0);" onClick="openHint(5,1);"><#LANHostConfig_DHCPServerConfigurable_itemname#></a></th>
  <td>
<script>
	var dhcp_tmp = <% getIndex("dhcp"); %>;
	var dhcp_disabled = "";
	var dhcp_server = "";
	if( dhcp_tmp == 0)	//Disabled
		dhcp_disabled = "checked";
	else if( dhcp_tmp == 2 )	//DHCP server
		dhcp_server = "checked";
	document.write("<input type=\"radio\" value=\"2\" name=\"dhcp\" class=\"content_input_fd\" onClick=\"dhcpChange();\" " + dhcp_server + "><#checkbox_Yes#>\n");
	document.write("<input type=\"radio\" value=\"0\" name=\"dhcp\" class=\"content_input_fd\" onClick=\"dhcpChange();\" " + dhcp_disabled + "><#checkbox_No#>\n");
</script>
  </td>
</tr>

<tr>
  <!--<th>Domain Name:</th>-->
  <th><a class="hintstyle" href="javascript:void(0);" onClick="openHint(5,2);"><#LANHostConfig_DomainName_itemname#></a></th>
  <td>
	<input type="text" name="domainName" class="input" size="15" maxlength="30" value="<% getInfo("domainName"); %>">
  </td>
</tr>

<tr>
  <th><a class="hintstyle" href="javascript:void(0);" onClick="openHint(5,3);"><#LANHostConfig_MinAddress_itemname#></a></th>
  <td>
	<input type="text" name="dhcpRangeStart" class="input" size="12" maxlength="15" value="<% getInfo("dhcpRangeStart"); %>">
  </td>
</tr>

<tr>
  <th><a class="hintstyle" href="javascript:void(0);" onClick="openHint(5,4);"><#LANHostConfig_MaxAddress_itemname#></a></th>
  <td>
	<input type="text" name="dhcpRangeEnd" class="input" size="12" maxlength="15" value="<% getInfo("dhcpRangeEnd"); %>">
  </td>
</tr>

<tr>
  <th><a class="hintstyle" href="javascript:void(0);" onClick="openHint(5,5);"><#LANHostConfig_LeaseTime_itemname#></a></th>
  <td>
  	<input type="text" maxlength="5" size="5" name="dhcpLease" class="input" value="<% getIndex("dhcpLease"); %>" onKeyPress="return is_number(this)">
  </td>
</tr>

<tr style="display:none">
  <th>Static DHCP:</th>
  <td>
	<input type="button" value="Set Static DHCP" name="staticdhcpTbl" class="button" onClick="staticdhcpTblClick('/tcpip_staticdhcp.asp')" >    
  </td>
</tr>

<tr style="display:none">
  <th>802.1d Spanning Tree:</th>
  <td>
	<select size="1" name="stp" class="input">
<script>
	var stp_tmp = <% getIndex("stp"); %>;
	var stp_enabled = "";
	var stp_disabled = "";	
	if(stp_tmp)
		stp_enabled = "selected";
	else
		stp_disabled = "selected";
	document.write("<option value=\"0\" " + stp_disabled + ">Disabled</option>\n");
	document.write("<option value=\"1\" " + stp_enabled + ">Enabled</option>\n");
</script>
	</select>
  </td>
</tr>

<tr style="display:none">
  <th>Clone MAC Address:</th>
  <td>
	<input type="text" name="lan_macAddr" size="15" maxlength="12" value="<% getInfo("bridgeMac"); %>">
  </td>
</tr>

<script>
	dhcpChange();
</script>

<tr align="right">
  <td colspan="2">
	<input type="submit" value="<#CTL_apply#>" name="save" class="button" onClick="return saveChanges()">
  </td>
</tr>

</table>
</form>
</td></tr>

<!--Static dhcp part-->
<tr>
  <td bgcolor="#FFFFFF">
<table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable">

<form action="/start_apply.htm" method=POST name="formStaticDHCPAdd" target="hidden_frame">
<input type="hidden" name="current_page" value="tcpiplan.asp">
<input type="hidden" value="formStaticDHCP" name="typeForm">
<input type="hidden" value="/tcpiplan.asp" name="submit-url">
<input type="hidden" name="action_mode" value="Restart_Dhcpd">	<!--2011.04.19 Jerry-->
<input type="hidden" name="flag" value="nodetect">	<!--2011.03.28 Jerry-->

<thead>
<tr>
  <td colspan="2"><#LANHostConfig_ManualDHCPList_groupitemdesc#></td>
</tr>
</thead>

<tr>
  <th width="40%"><a class="hintstyle" href="javascript:void(0);" onClick="openHint(5,9);"><#LANHostConfig_ManualDHCPEnable_itemname#></a></th>
  <td>
<script>
	var static_dhcp_tmp = <% getInfo("static_dhcp_onoff"); %>;
	var static_dhcp_ON = "";
	var static_dhcp_OFF = "";
	if( static_dhcp_tmp)
		static_dhcp_ON = "checked";
	else
		static_dhcp_OFF = "checked";
	document.write("<input type=\"radio\" value=\"1\" name=\"static_dhcp\" class=\"content_input_fd\" onClick=\"updateState();\" " + static_dhcp_ON + "><#checkbox_Yes#>\n");
	document.write("<input type=\"radio\" value=\"0\" name=\"static_dhcp\" class=\"content_input_fd\" onClick=\"updateState();\" " + static_dhcp_OFF + "><#checkbox_No#>\n");
</script>
  </td>
</tr>

<tr>
  <th><#LANHostConfig_ManualIP_itemname#>:</th>
  <td>
	<input type="text" id="ip_addr" name="ip_addr" class="input" size="16" maxlength="15" value="">
  </td>
</tr>

<tr>
  <th><#LANHostConfig_ManualMac_itemname#>:</th>
  <td>
 	<input type="text" id="mac_addr" name="mac_addr" class="input" size="15" maxlength="12" value=""> 
  </td>
</tr>

<tr style="display:none;">
  <th>Comment:</th>
  <td>
 	<input type="text" id="hostname" name="hostname" class="input" size="20" maxlength="19" value="">
  </td>
</tr>

<tr>
  <td colspan="2" align="right">
	<input type="submit" value="<#CTL_apply#>" id="addRsvIP" name="addRsvIP" class="button" onClick="return addClick()">
  </td>
</tr>

    </form>
</table>
</td></tr>

<tr>
  <td bgcolor="#FFFFFF">
<table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable">
<form action="/start_apply.htm" method=POST name="formStaticDHCP" target="hidden_frame">
<input type="hidden" name="current_page" value="tcpiplan.asp">
<input type="hidden" value="formStaticDHCP" name="typeForm">
<input type="hidden" value="/tcpiplan.asp" name="submit-url">
<input type="hidden" name="action_mode" value="Restart_Dhcpd">	<!--2011.04.19 Jerry-->
<input type="hidden" name="flag" value="nodetect">	<!--2011.03.28 Jerry-->

<thead>
<tr>
  <td colspan="3"><#LANHostConfig_x_DHCP_List#></td>
</tr>
</thead>
<tr>
	<td align=center width=\"20%%\" bgcolor=\"#808080\"><#LANHostConfig_x_Select_itemname#></td>
      	<td align=center width=\"40%%\" bgcolor=\"#808080\"><#LANHostConfig_ManualIP_itemname#></td>
      	<td align=center width=\"40%%\" bgcolor=\"#808080\"><#LANHostConfig_ManualMac_itemname#></td>
</tr>
  <% dhcpRsvdIp_List();%>

<tr>
  <td colspan="3" align="right">
	<input type="submit" value="<#CTL_del#>" id="deleteSelRsvIP" name="deleteSelRsvIP" class="button" onClick="return deleteClick()">
  </td>
</tr>
<script>
	var entryNum = <% getIndex("staticDhcpNum"); %>;
	if( entryNum == 0 )
		disableDelButton();
	updateState();
</script>

</form>
</table>
</td></tr>


  </table>		
					
		</td>
					
					<!--==============Beginning of hint content=============-->
					<td id="help_td" style="width:15px;" valign="top">
						<form name="hint_form"></form>
						<div id="helpicon" onClick="openHint(0,0);" title="<#Help_button_default_hint#>"><img src="images/help.gif" /></div>
						<div id="hintofPM" style="display:none;">
							<table width="100%" cellpadding="0" cellspacing="1" class="Help" bgcolor="#999999">
								<thead>
								<tr>
									<td>
										<div id="helpname" class="AiHintTitle"></div>
										<a href="javascript:closeHint();">
											<img src="images/button-close.gif" class="closebutton">
										</a>
									</td>
								</tr>
								</thead>
								
								<tr>
									<td valign="top">
										<div class="hint_body2" id="hint_body"></div>
										<iframe id="statusframe" name="statusframe" class="statusframe" src="" frameborder="0"></iframe>
									</td>
								</tr>
							</table>
						</div>
					</td>
					<!--==============Ending of hint content=============-->
					
				</tr>
			</table>				
		</td>
		
    <td width="10" align="center" valign="top">&nbsp;</td>
	</tr>
</table>

<div id="footer"></div>
</body>
</html>
