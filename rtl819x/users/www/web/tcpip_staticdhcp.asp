<html>
<! Copyright (c) Realtek Semiconductor Corp., 2003. All Rights Reserved. ->
<head>
<meta http-equiv="X-UA-Compatible" content="IE=EmulateIE7"/>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta HTTP-EQUIV="Pragma" CONTENT="no-cache">
<meta HTTP-EQUIV="Expires" CONTENT="-1">
<link rel="shortcut icon" href="images/favicon.png">
<link rel="icon" href="images/favicon.png">

<title>ASUS Wireless Router <#Web_Title#> - <#menu5_2_2#></title>
<link rel="stylesheet" type="text/css" href="index_style.css"> 
<link rel="stylesheet" type="text/css" href="form_style.css">
<script language="JavaScript" type="text/javascript" src="/state.js"></script>
<script language="JavaScript" type="text/javascript" src="/general.js"></script>
<script language="JavaScript" type="text/javascript" src="/popup.js"></script>
<script type="text/javascript" language="JavaScript" src="/help.js"></script>
<script type="text/javascript" language="JavaScript" src="/detect.js"></script>
<script type="text/javascript" src="util_gw.js"> </script>
<script>
function initial(){
	show_banner(1);
	show_menu(5,2,2);
	show_footer();
}
function addClick()
{
	if(get_by_id("ip_addr").value == "" && get_by_id("mac_addr").value == "")
		return true;
	
  var str = document.formStaticDHCPAdd.mac_addr.value;
   if ( checkIpAddr(document.formStaticDHCPAdd.ip_addr, 'Invalid IP address value! ') == false )
      	    return false;
   if ( str.length < 12) {
	alert("Input MAC address is not complete. It should be 12 digits in hex.");
	document.formStaticDHCPAdd.mac_addr.focus();
	return false;
  }
  for (var i=0; i<str.length; i++) {
    if ( (str.charAt(i) >= '0' && str.charAt(i) <= '9') ||
			(str.charAt(i) >= 'a' && str.charAt(i) <= 'f') ||
			(str.charAt(i) >= 'A' && str.charAt(i) <= 'F') )
			continue;

	alert("Invalid MAC address. It should be in hex number (0-9 or a-f).");
	document.formStaticDHCPAdd.mac_addr.focus();
	return false;
  }   	    
  
  
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
  if ( !confirm('Do you really want to delete the selected entry?') ) {
	return false;
  }
  else
	return true;
}

function deleteAllClick()
{
   if ( !confirm('Do you really want to delete the all entries?') ) {
	return false;
  }
  else
	return true;
}
function disableDelButton()
{
	disableButton(document.formStaticDHCP.deleteSelRsvIP);
	disableButton(document.formStaticDHCP.deleteAllRsvIP);
}

function enableAc()
{
  enableTextField(document.formStaticDHCPAdd.mac_addr);
  enableTextField(document.formStaticDHCPAdd.hostname);
}

function disableAc()
{
  disableTextField(document.formStaticDHCPAdd.mac_addr);
  disableTextField(document.formStaticDHCPAdd.hostname);
}

function init()
{
  static_dhcp_onoff_select(get_by_id("static_dhcp").value);

}

function static_dhcp_onoff_select(value)
{
	if(value == true || value == 1)
	{
		get_by_id("static_dhcp").value = 1;
		get_by_id("static_dhcp_onoff").checked = true;
	}
	else
	{
		get_by_id("static_dhcp").value = 0;
		get_by_id("static_dhcp_onoff").checked = false;
	}
	
	static_dhcp_tbl_onoff_disabled(get_by_id("static_dhcp").value);
}

function static_dhcp_tbl_onoff_disabled(value)
{
	var is_disable;
	if(value == 1)
	{
		is_disable = false;
	}
	else
	{
		is_disable = true;
	}
	
	get_by_id("ip_addr").disabled = is_disable;
	get_by_id("mac_addr").disabled = is_disable;
	get_by_id("hostname").disabled = is_disable;
	get_by_id("deleteSelRsvIP").disabled = is_disable;
	get_by_id("deleteAllRsvIP").disabled = is_disable;
	get_by_id("reset").disabled = is_disable;
	
}
</script>
</head>

<body onload="initial();init();" onunLoad="disable_auto_hint(5, 7);return unload_body();">
<div id="TopBanner"></div>

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
	<div id="tabMenu" class="submenuBlock"></div><br />

<!--===================================Beginning of Main Content===========================================-->
<table width="98%" border="0" align="center" cellpadding="0" cellspacing="0">
  <tr>
	<td align="left" valign="top">
	  <table width="500" border="0" align="center" cellpadding="4" cellspacing="0" class="FormTitle" table>
		<thead>
		  <tr>
			<td><#menu5_2#> - <#menu5_2_2#></td>
		  </tr>
		</thead>
		
		<tr>
		  <td bgcolor="#FFFFFF">This page allows you reserve IP addresses, and assign the same IP address to the network device with the specified MAC address any time it requests an IP address. This is almost the same as when a device has a static IP address except that the device must still request an IP address from the DHCP server.</td>
		</tr>
		
		<tbody>
		<tr>
		  <td bgcolor="#FFFFFF">
			<table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable">
			  
<form action=/goform/formStaticDHCP method=POST name="formStaticDHCPAdd">

<tr>
  <td colspan="2">
    	<input type='hidden' id='static_dhcp' name='static_dhcp' value='<% getInfo("static_dhcp_onoff"); %>'>
	<input id="static_dhcp_onoff" type="checkbox" onclick='static_dhcp_onoff_select(this.checked);'>&nbsp;&nbsp;Enable Static DHCP</b><br>
  </td>
</tr>
 
<tr>
  <th>IP Address:</th>
  <td>
	<input type="text" id="ip_addr" name="ip_addr" class="input" size="16" maxlength="15" value="">
  </td>
</tr>

<tr>
   <th>MAC Address:</th>
   <td>
 	<input type="text" id="mac_addr" name="mac_addr" class="input" size="15" maxlength="12" value=""> 
  </td>
</tr>

<tr>
  <th>Comment:</th>
  <td>
 	<input type="text" id="hostname" name="hostname" class="input" size="20" maxlength="19" value="">
  </td>
</tr>

<tr>
  <td colspan="2" align="right">
	<input type="submit" value="<#CTL_apply#>" id="addRsvIP" name="addRsvIP" class="button" onClick="return addClick()">
        <input type="reset" value="Reset" id="reset_tbl" name="reset_tbl" class="button">
        <input type="hidden" value="/tcpip_staticdhcp.asp" name="submit-url">
  </td>
</tr>
    </form>
</table>

<br>
<form action=/goform/formStaticDHCP method=POST name="formStaticDHCP">
  <table border="0" width=640>
  <tr><font size=2><b>Static DHCP List:</b></font></tr>
  <% dhcpRsvdIp_List();%>
  </table>
  <br>
  <input type="submit" value="Delete Selected" id="deleteSelRsvIP" name="deleteSelRsvIP" onClick="return deleteClick()">&nbsp;&nbsp;
  <input type="submit" value="Delete All" id="deleteAllRsvIP" name="deleteAllRsvIP" onClick="return deleteAllClick()">&nbsp;&nbsp;&nbsp;
  <input type="reset" value="Reset" id="reset" name="reset">
  <input type="hidden" value="/tcpip_staticdhcp.asp" name="submit-url">
</form>

</td></tr>
		</tbody>
	  </table>		
	</td>
	<!-- help block -->
	<td id="help_td" style="width:15px;" valign="top">
<form name="hint_form"></form>
	  <div id="helpicon" onClick="openHint(0,0);" title="<#Help_button_default_hint#>">
	  	<img src="images/help.gif" />
	  </div>
      
	  <div id="hintofPM" style="display:none;">
		<table width="100%" cellpadding="0" cellspacing="1" class="Help" bgcolor="#999999">
		  <thead>
		  <tr>
			<td>
			  <div id="helpname" class="AiHintTitle"></div>
			  <a href="javascript:;" onclick="closeHint()" ><img src="images/button-close.gif" class="closebutton" /></a>
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
	<!--==============Ending of hint content=============-->
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
