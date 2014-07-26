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
<title>ASUS Wireless Router <#Web_Title#> - <#menu5_2_3#></title>
<link rel="stylesheet" type="text/css" href="index_style.css"> 
<link rel="stylesheet" type="text/css" href="form_style.css">
<script language="JavaScript" type="text/javascript" src="/state.js"></script>
<script language="JavaScript" type="text/javascript" src="/general.js"></script>
<script language="JavaScript" type="text/javascript" src="/popup.js"></script>
<script type="text/javascript" language="JavaScript" src="/help.js"></script>
<script type="text/javascript" language="JavaScript" src="/detect.js"></script>
<script type="text/javascript" src="util_gw.js"> </script>
<script>
var wan_type=<% getIndex("wanDhcp"); %>;	
var system_opmode =<% getIndex("opMode"); %>;
var total_StaticNumber=<% getIndex("staticRouteNum"); %>;
function initial(){
	show_banner(1);
	show_menu(5,2,2);
	show_footer();
}
function validateNum(str)
{
  for (var i=0; i<str.length; i++) {
   	if ( !(str.charAt(i) >='0' && str.charAt(i) <= '9')) {
		alert("<#UTIL_GW_error2#>");
		return false;
  	}
  }
  return true;
}
function checkIpSubnetAddr(field, msg)
{
  if (field.value=="") {
	alert(field.value + '<#JS_fieldblank#>');
	field.value = field.defaultValue;
	field.focus();
	return false;
  }
   if ( validateKey(field.value) == 0) {
	alert(field.value + '<#JS_validip#>');
      field.value = field.defaultValue;
      field.focus();
      return false;
   }
   if ( !checkDigitRange(field.value,1,1,223) ) {
	alert(field.value + '<#JS_validip#>');
      field.value = field.defaultValue;
      field.focus();
      return false;
   }
   if ( !checkDigitRange(field.value,2,0,255) ) {
	alert(field.value + '<#JS_validip#>');
      field.value = field.defaultValue;
      field.focus();
      return false;
   }
   if ( !checkDigitRange(field.value,3,0,255) ) {
	alert(field.value + '<#JS_validip#>');
      field.value = field.defaultValue;
      field.focus();
      return false;
   }
   if ( !checkDigitRange(field.value,4,0,255) ) {
	alert(field.value + '<#JS_validip#>');
      field.value = field.defaultValue;
      field.focus();
      return false;
   }
   return true;
}
function checkSubnet(ip, mask)
{
  
  ip_d = getDigit(ip.value, 1);
  mask_d = getDigit(mask.value, 1);
  ip_d = ip_d & mask_d ;
  strIp = ip_d + '.' ;

  ip_d = getDigit(ip.value, 2);
  mask_d = getDigit(mask.value, 2);
  ip_d = ip_d & mask_d ;
  strIp += ip_d + '.' ;
  

  ip_d = getDigit(ip.value, 3);
  mask_d = getDigit(mask.value, 3);
  ip_d = ip_d & mask_d ;
  strIp += ip_d + '.' ;
  

  ip_d = getDigit(ip.value, 4);
  mask_d = getDigit(mask.value, 4);
  ip_d = ip_d & mask_d ;
  strIp += ip_d ;
  ip.value = strIp ;  
 
  return true ;
}

function addClick()
{
	var t1; 	
	var first_ip;
	var route_meteric;
	if (!document.formRouteAdd.enabled[0].checked) {
		showLoading();	//2011.03.28 Jerry
		return true;
	}

  	if (document.formRouteAdd.ipAddr.value=="" && document.formRouteAdd.subnet.value==""
  		&& document.formRouteAdd.gateway.value=="" ) {
		showLoading();	//2011.03.28 Jerry
		return true;
	}
  	if ( checkIpSubnetAddr(document.formRouteAdd.ipAddr, 'Invalid IP address value! ') == false )
              	return false;

	t1=document.formRouteAdd.ipAddr.value.indexOf('.');
	if(t1 !=-1)
	first_ip=document.formRouteAdd.ipAddr.value.substring(0,t1);
	if(first_ip=='127'){
		alert('<#JS_validip#>');
		return false;
	}

  	if (checkIPMask(document.formRouteAdd.subnet) == false)
		return false ;
  
  	if ( checkIpAddr(document.formRouteAdd.gateway, 'Invalid Gateway address! ') == false )
              	return false;
  	checkSubnet(document.formRouteAdd.ipAddr, document.formRouteAdd.subnet);
  
  	if ( validateNum(document.formRouteAdd.metric.value) == 0 ) {
  		document.formRouteAdd.metric.focus();
		return false;
  	}
  	route_metric = parseInt(document.formRouteAdd.metric.value);
  	if((document.formRouteAdd.metric.value=="") || (route_metric > 15 ) || (route_metric < 1)){
		alert("<#Route_Metric_range#>");
  		return false
  	}
/*Edison 2011.4.20*/
	var entryNum = <% getIndex("staticRouteNum"); %>;
	var Max_Filter_Num = <% getIndex("maxFilterNum"); %>;
	if(maxfilter(entryNum,Max_Filter_Num))
	{
	return false; 
	}
/*------------------*/
	showLoading();	//2011.03.28 Jerry
   	return true;
}

function deleteClick()
{
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
	disableButton(document.formRouteDel.deleteSelRoute);
}

function Route_updateState()
{
  if (document.formRouteAdd.enabled[0].checked) {
 	enableTextField(document.formRouteAdd.ipAddr);
 	enableTextField(document.formRouteAdd.subnet);
 	enableTextField(document.formRouteAdd.gateway);
 	enableTextField(document.formRouteAdd.metric);
 	document.formRouteAdd.iface.disabled=false;
  }
  else {
 	disableTextField(document.formRouteAdd.ipAddr);
 	disableTextField(document.formRouteAdd.subnet);
 	disableTextField(document.formRouteAdd.gateway);
 	disableTextField(document.formRouteAdd.metric);
 	document.formRouteAdd.iface.disabled=true;
  }
}
function updateStateRip()
{
	var dF=document.formRouteRip;
  if (document.formRouteRip.enabled.checked) {
 	enableRadioGroup(document.formRouteRip.nat_enabled);
	enableRadioGroup(document.formRouteRip.rip_tx);
	enableRadioGroup(document.formRouteRip.rip_rx);
	//ppp wan type will force NAT is enabled
	  if ((wan_type != 0) && (wan_type != 1)){
   			dF.nat_enabled[0].disabled = true;
   			dF.nat_enabled[1].disabled = true;
   			dF.nat_enabled[0].checked=true;
	}
	nat_setting_ripTx();
  }
  else {
  	disableRadioGroup(document.formRouteRip.nat_enabled);
	disableRadioGroup(document.formRouteRip.rip_tx);
	disableRadioGroup(document.formRouteRip.rip_rx);
  }
  
}

function nat_setting_ripTx(){
	var dF=document.forms[0];
	var nat = get_by_name("nat_enabled");
	var tx = get_by_name("rip_tx");
	var dynamic_route=document.formRouteRip.enabled.checked;
	for (var i = 0; i < 3; i++){
		if(dynamic_route==true)
			tx[i].disabled = nat[0].checked;
		else
			tx[i].disabled=true;
	}
	
	if (nat[0].checked){
		tx[0].checked = true;
	}
}

function RIP_LoadSetting()
{
	var dF=document.formRouteRip;
	var nat_setting=<% getIndex("nat_enabled"); %>;
	var rip_tx_setting=<% getIndex("ripLanTx"); %>;
	var rip_rx_setting=<% getIndex("ripLanRx"); %>;
	var rip_enabled = <% getIndex("ripEnabled");%>;
	if(rip_enabled==1){
		dF.enabled.checked=true;
	}else
		dF.enabled.checked=false;
		
	updateStateRip();	
	if(nat_setting==1){
		dF.nat_enabled[0].checked=true;
	}else{
		dF.nat_enabled[1].checked=true;
	}
	
	//ppp wan type will force NAT is enabled
	  if ((wan_type != 0) && (wan_type != 1)){
   			dF.nat_enabled[0].disabled = true;
   			dF.nat_enabled[1].disabled = true;
   			dF.nat_enabled[0].checked=true;
	}
	dF.rip_tx[rip_tx_setting].checked=true;
	dF.rip_rx[rip_rx_setting].checked=true;
	nat_setting_ripTx();
}	
function Route_LoadSetting()
{
	var dF=document.formRouteAdd;
	var dFDel=document.formRouteDel;
	Route_updateState();
	if(dF.enabled[0].checked==false){
		for(entry_index=1;entry_index<=total_StaticNumber;entry_index++){
			dFDel.elements["select"+entry_index].disabled=true;
		}
	}
}

function SetRIPClick()
{
	var dF=document.formRouteRip;
	 if ((wan_type != 0) && (wan_type != 1)){
	 	if(dF.enabled.checked==true){
	 		if(dF.nat_enabled[1].checked==true){
	 			alert("You can not disable NAT in PPP wan type!");
	 			return false;
	 		}
	 	}
	}
}
function Set_Opmode()
{
	var dF;
	var entry_index;
	if(system_opmode == 1){
		dF=document.formRouteRip;
		dF.enabled.disabled=true;
		dF.nat_enabled[0].disabled=true;
		dF.nat_enabled[1].disabled=true;
		dF.rip_tx[0].disabled=true;
		dF.rip_tx[1].disabled=true;
		dF.rip_tx[2].disabled=true;
		dF.rip_rx[0].disabled=true;
		dF.rip_rx[1].disabled=true;
		dF.rip_rx[2].disabled=true;
		dF.ripSetup.disabled=true;
		dF.reset.disabled=true;
		dF=document.formRouteAdd;
		dF.enabled.disabled=true;
		dF.ipAddr.disabled=true;
		dF.subnet.disabled=true;
		dF.gateway.disabled=true;
		dF.iface.disabled=true;
		dF.addRoute.disabled=true;
		dF.reset.disabled=true;
		dF.showRoute.disabled=true;
		dF=document.formRouteDel;
		dF.deleteSelRoute.disabled=true;
		dF.reset.disabled=true;
		for(entry_index=1;entry_index<=total_StaticNumber;entry_index++){
			dF.elements["select"+entry_index].disabled=true;
		}
	}
}



</script>
</head>

<body onload="initial();RIP_LoadSetting();Route_LoadSetting();Set_Opmode();" onunLoad="disable_auto_hint(6, 5);return unload_body();">
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
	<td valign="top" >
	  <table width="550" border="0" align="center" cellpadding="5" cellspacing="0" class="FormTitle" table>
		<thead>
		<tr>
		  <td><#menu5_2#> - <#menu5_2_3#></td>
		</tr>
		</thead>
		
		<tr>
		  <td bgcolor="#FFFFFF"><#RouterConfig_GWStaticEnable_sectiondesc#></td>
		</tr>
		
		<tbody>
		<tr>
		  <td bgcolor="#FFFFFF"></td>
		</tr>

		<tr style="display:none;">
		  <td bgcolor="#FFFFFF">
			<table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable">

<form action=/goform/formRoute method=POST name="formRouteRip">
<tr>
  <td colspan="2">
   	<input type="checkbox" name="enabled" value="ON" onclick="updateStateRip()">&nbsp;&nbsp;Enable Dynamic Route
  </td>
</tr>


<tr>
  <th>NAT:</th>
  <td>
	<input type="radio" name="nat_enabled" value="0" onClick="nat_setting_ripTx()">Enabled&nbsp;&nbsp;
	<input type="radio" name="nat_enabled" value="1" onClick="nat_setting_ripTx()">Disabled</td>
</tr>

<tr>
  <th>Transmit:</th>
  <td>
      	<input type="radio" name="rip_tx" value="0">Disabled&nbsp;&nbsp;
      	<input type="radio" name="rip_tx" value="1">RIP 1
      	<input type="radio" name="rip_tx" value="2">RIP 2
  </td>
</tr>

<tr>
  <th>Receive:</th>
  <td>
      	<input type="radio" name="rip_rx" value="0">Disabled&nbsp;&nbsp;
      	<input type="radio" name="rip_rx" value="1">RIP 1
      	<input type="radio" name="rip_rx" value="2">RIP 2
  </td>
</tr>

<tr>
  <td colspan="2" align="right">
	<input type="submit" value="<#CTL_apply#>" name="ripSetup" class="button" onClick="return SetRIPClick()"> 
   	<input type="button" value="Reset" name="reset" class="button" onClick="RIP_LoadSetting()">
	<input type="hidden" value="/route.asp" name="submit-url">
  </td>
</tr>
</form>
</table>
</td></tr>

<tr>
<td bgcolor="#FFFFFF">
<table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable">

<form action="/start_apply.htm" method=POST name="formRouteAdd" target="hidden_frame">
<input type="hidden" name="current_page" value="route.asp">
<input type="hidden" value="formRoute" name="typeForm">
<input type="hidden" value="/route.asp" name="submit-url">
<input type="hidden" name="action_mode" value="Reinit">	<!--2011.03.28 Jerry-->
<input type="hidden" name="flag" value="nodetect">	<!--2011.03.28 Jerry-->
<input type="hidden" name="preferred_lang" id="preferred_lang" value="<% getInfo("preferred_lang"); %>">	<!--2011.04.14 Jerry-->

<tr>
  <th width="50%"><#RouterConfig_GWMulticastEnable_itemname#></th>
  <td>
<script>
	var igmp_disabled = <% getIndex("igmpproxyDisabled"); %>;
	var igmp_Enabled = "";
	var igmp_Disabled = "";
	if(igmp_disabled)
		igmp_Disabled = "checked";
	else
		igmp_Enabled = "checked";
	document.write("<input type=\"radio\" name=\"igmpproxyEnabled\" value=\"ON\" " + igmp_Enabled + "><#checkbox_Yes#>\n");
	document.write("<input type=\"radio\" name=\"igmpproxyEnabled\" value=\"OFF\" " + igmp_Disabled + "><#checkbox_No#>\n");
</script>
  </td>
</tr>

<tr>
  <th><#RouterConfig_GWStaticEnable_itemname#></th>
  <td>
<script>
	var static_route_enabled = <% getIndex("staticRouteEnabled"); %>;
	var static_route_ON = "";
	var static_route_OFF = "";
	if(static_route_enabled)
		static_route_ON = "checked";
	else
		static_route_OFF = "checked";
	document.write("<input type=\"radio\" name=\"enabled\" value=\"ON\" onclick=\"Route_updateState()\" " + static_route_ON + "><#checkbox_Yes#>\n");
	document.write("<input type=\"radio\" name=\"enabled\" value=\"OFF\" onclick=\"Route_updateState()\" " + static_route_OFF + "><#checkbox_No#>\n");
</script>
  </td>
</tr>


<tr>
  <!--<th>IP Address:</th>-->
  <th><a class="hintstyle" href="javascript:void(0);" onClick="openHint(6,1);"><#RouterConfig_GWStaticIP_itemname#></a></th>
  <td>
        <input type="text" name="ipAddr" class="input" size="18" maxlength="15" value="">
  </td>
</tr>

<tr>
  <!--<th>Subnet Mask:</th>-->
  <th><a class="hintstyle" href="javascript:void(0);" onClick="openHint(6,2);"><#RouterConfig_GWStaticMask_itemname#></a></th>
  <td>
	<input type="text" name="subnet" class="input" size="18" maxlength="15" value="">
  </td>
</tr>
    
<tr>
  <!--<th>Gateway:</th>-->
  <th><a class="hintstyle" href="javascript:void(0);" onClick="openHint(6,3);"><#RouterConfig_GWStaticGW_itemname#></a></th>
  <td>
	<input type="text" name="gateway" class="input" size="18" maxlength="15" value="">
  </td>
</tr>

<tr>
  <!--<th>Metric:</th>-->
  <th><a class="hintstyle" href="javascript:void(0);" onClick="openHint(6,4);"><#RouterConfig_GWStaticMT_itemname#></a></th>
  <td>
	<input type="text" id="metric" name="metric" class="input" size="3" maxlength="2" value="">
  </td>
</tr>
 
<tr>
  <!--<th>Interface:</th>-->
  <th><a class="hintstyle" href="javascript:void(0);" onClick="openHint(6,5);"><#RouterConfig_GWStaticIF_itemname#></a></th>
  <td>
  	<select size="1" id="iface" name="iface" class="input">
  	<option value="0">LAN</option>
 	<option value="1">WAN</option>
 	</select>
  </td>
</tr>
 
<tr>
  <td colspan="2" align="right">
    	<input type="submit" value="<#CTL_apply#>" name="addRoute" class="button" onClick="return addClick()">
  </td>
</tr>

</form>
</table>
</td></tr>

<form action="/start_apply.htm" method=POST name="formRouteDel" target="hidden_frame">
<input type="hidden" name="current_page" value="route.asp">
<input type="hidden" value="formRoute" name="typeForm">
<input type="hidden" value="/route.asp" name="submit-url">
<input type="hidden" name="action_mode" value="Reinit">	<!--2011.03.28 Jerry-->
<input type="hidden" name="flag" value="nodetect">	<!--2011.03.28 Jerry-->

<tr>
<td bgcolor="#FFFFFF">
<table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable">

<thead>
<tr>
  <td colspan="6"><#RouterConfig_GWStatic_groupitemdesc#></td>
</tr>
</thead>
<tr>
	<td align=center width=\"10%%\" bgcolor=\"#808080\"><#LANHostConfig_x_Select_itemname#></td>
      	<td align=center width=\"23%%\" bgcolor=\"#808080\"><#RouterConfig_GWStaticIP_itemname#></td>
      	<td align=center width=\"23%%\" bgcolor=\"#808080\"><#RouterConfig_GWStaticMask_itemname#></td>
      	<td align=center width=\"23%%\" bgcolor=\"#808080\"><#RouterConfig_GWStaticGW_itemname#></td>
      	<td align=center width=\"10%%\" bgcolor=\"#808080\"><#RouterConfig_GWStaticMT_itemname#></td>
      	<td align=center width=\"10%%\" bgcolor=\"#808080\"><#RouterConfig_GWStaticIF_itemname#></td>
</tr>
  <% staticRouteList(); %>

<tr>
  <td colspan="6" align="right">
	<input type="submit" value="<#CTL_del#>" name="deleteSelRoute" class="button" onClick="return deleteClick()">
  </td>
</tr>
</form>
 <script>
	var entryNum = <% getIndex("staticRouteNum"); %>;
   	if ( entryNum == 0 )
      	  	disableDelButton();
 </script>

</table>
</td></tr>

</table>
</td>

	<!--==============Beginning of hint content=============-->
	<td id="help_td" style="width:15px;"  valign="top">
	  <div id="helpicon" onClick="openHint(0, 0);" title="<#Help_button_default_hint#>">
		<img src="images/help.gif">
	  </div>
	  
	  <div id="hintofPM" style="display:none;">
<form name="hint_form"></form>
		<table width="100%" cellpadding="0" cellspacing="1" class="Help" bgcolor="#999999">
		  <thead>
		  <tr>
			<td>
			  <div id="helpname" class="AiHintTitle"></div>
			  <a href="javascript:closeHint();"><img src="images/button-close.gif" class="closebutton" /></a>
			</td>
		  </tr>
		  </thead>
		  
		  <tbody>
		  <tr>
			<td valign="top">
			  <div id="hint_body" class="hint_body2"></div>
			  <iframe id="statusframe" name="statusframe" class="statusframe" src="" frameborder="0"></iframe>
			</td>
		  </tr>
		  </tbody>
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
