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

<script type="text/javascript" src="/state.js"></script>
<script type="text/javascript" src="/general.js"></script>
<script type="text/javascript" src="/popup.js"></script>
<script type="text/javascript" src="/help.js"></script>
<script>


function initial(){
	final_flag = 1;	// for the function in general.js
	
	show_banner(1);
	show_menu(5,2,1);
	show_footer();
	
	if(document.form.dhcp[0].checked == true){
		inputCtrl(document.form.lan_ipaddr, 0);
		inputCtrl(document.form.lan_netmask, 0);
		inputCtrl(document.form.lan_gateway, 0);
		$('lan_ipaddr').value = "";
		$('lan_netmask').value = "";
		$('lan_gateway').value = "";
	}
	else{
		inputCtrl(document.form.lan_ipaddr, 1);
		inputCtrl(document.form.lan_netmask, 1);
		inputCtrl(document.form.lan_gateway, 1);
	}
}

function checkIP(){
	var strIP = $('lan_ipaddr').value;
	var re=/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/g;
	if(document.form.dhcp[1].checked == 1){
		if(re.test(strIP)){
			if( RegExp.$1 == 192 && RegExp.$2 == 168 && RegExp.$3 < 256 && RegExp.$4 < 256){
				applyRule();
				re.test(strIP);
			}
			else if( RegExp.$1 == 172 && RegExp.$2 > 15 && RegExp.$2 < 32 && RegExp.$3 < 256 && RegExp.$4 < 256){
				applyRule();
				re.test(strIP);
			}
			else if( RegExp.$1 == 10 && RegExp.$2 < 2 && RegExp.$3 < 256 && RegExp.$4 < 256){
				applyRule();
				re.test(strIP);
			}
			else{
				alert('"'+strIP+'"'+" <#BM_alert_IP2#>");
				re.test(strIP);
			}
		}
		else alert('"'+strIP+'"'+" <#JS_validip#>");
	}
	else
		applyRule();
}

function applyRule(){
	if(validForm()){
		showLoading();		
		document.form.submit();
	}
}

function validForm(){
	if(document.form.dhcp[0].checked == 1)
		return true;
	
	if(!validate_ipaddr_final(document.form.lan_ipaddr, 'lan_ipaddr') ||
			!validate_ipaddr_final(document.form.lan_netmask, 'lan_netmask') ||
			!validate_ipaddr_final(document.form.lan_gateway, 'lan_gateway'))
		return false;
	
	return true;
}

function done_validating(action){
	refreshpage();
}

function dhcpChange()
{
	if(document.form.dhcp[0].checked == true){
		inputCtrl(document.form.lan_ipaddr, 0);
		inputCtrl(document.form.lan_netmask, 0);
		inputCtrl(document.form.lan_gateway, 0);
	}
	else{
		inputCtrl(document.form.lan_ipaddr, 1);
		inputCtrl(document.form.lan_netmask, 1);
		inputCtrl(document.form.lan_gateway, 1);
	}
}
</script>
</head>

<body onload="initial();" onunLoad="disable_auto_hint(4, 2);return unload_body();">
<div id="TopBanner"></div>

<div id="Loading" class="popup_bg"></div>

<iframe name="hidden_frame" id="hidden_frame" src="" width="0" height="0" frameborder="0"></iframe>
<form action="/start_apply.htm" method=POST name="form" target="hidden_frame">
<input type="hidden" name="current_page" value="tcpiplan_ap.asp">
<input type="hidden" value="formTcpipSetupAP" name="typeForm">
<input type="hidden" value="/tcpiplan_ap.asp" name="submit-url">
<input type="hidden" name="action_mode" value="Restart_LAN">	<!--2011.04.19 Jerry-->
<input type="hidden" name="flag" value="nodetect">	<!--2011.03.28 Jerry-->
<input type="hidden" name="preferred_lang" id="preferred_lang" value="<% getInfo("preferred_lang"); %>">	<!--2011.04.14 Jerry-->
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
		<br />
		
		<!--===================================Beginning of Main Content===========================================-->
<table width="98%" border="0" align="center" cellpadding="0" cellspacing="0">
	<tr>
		<td align="left" valign="top" >
		
<table width="98%" border="0" align="center" cellpadding="5" cellspacing="0" class="FormTitle" table>
	<thead>
	<tr>
		<td><#LANHostConfig_display1_sectionname#></td>
	</tr>
	</thead>
	<tbody>
	  <tr>
	    <td bgcolor="#FFFFFF"><#LANHostConfig_display1_sectiondesc#></td>
	  </tr>
	</tbody>
	
	<tr>
		<td bgcolor="#FFFFFF">
			<table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable">
				<tr>
					<th width="30%">
						<#LANHostConfig_x_LANDHCPClient_itemname#>
					</th>
					
					<td>
<script>
	var dhcp_tmp = <% getIndex("dhcp"); %>;
	var static_ip = "";
	var dhcp_client = "";
	if( dhcp_tmp == 0)	//Static IP
		static_ip = "checked";
	else if( dhcp_tmp == 1 )	//DHCP client
		dhcp_client = "checked";
	document.write("<input type=\"radio\" id=\"dhcp\" value=\"1\" name=\"dhcp\" class=\"input\" onClick=\"dhcpChange();\" " + dhcp_client + "><#checkbox_Yes#>\n");
	document.write("<input type=\"radio\" id=\"dhcp\" value=\"0\" name=\"dhcp\" class=\"input\" onClick=\"dhcpChange();\" " + static_ip + "><#checkbox_No#>\n");
</script>
					</td>
				</tr>
				
		  	<tr>
					<th width="30%">
						<a class="hintstyle" href="javascript:void(0);" onClick="openHint(4,1);"><#LANHostConfig_IPRouters_itemname#></a>
					</th>
					
					<td>
						<input type="text" id="lan_ipaddr" name="lan_ipaddr" value="<% getInfo("ip-rom"); %>" maxlength="15" class="input" size="15" onKeyPress="return is_ipaddr(this);" onKeyUp="change_ipaddr(this);">
					</td>
				</tr>
				
				<tr>
					<th>
						<a class="hintstyle" href="javascript:void(0);" onClick="openHint(4,2);"><#LANHostConfig_SubnetMask_itemname#></a>
					</th>
					
					<td>
						<input type="text" id="lan_netmask" name="lan_netmask" value="<% getInfo("mask-rom"); %>" maxlength="15" class="input" size="15" onkeypress="return is_ipaddr(this);" onkeyup="change_ipaddr(this);" />
					</td>
				</tr>
		  	
				<tr>
					<th>
						<a class="hintstyle" href="javascript:void(0);" onClick="openHint(4,3);"><#LANHostConfig_x_Gateway_itemname#></a>
					</th>
					
					<td>
						<input type="text" id="lan_gateway" name="lan_gateway" value="<% getInfo("gateway-rom"); %>" maxlength="15" class="input" size="15" onkeypress="return is_ipaddr(this);" onkeyup="change_ipaddr(this);" />
					</td>
				</tr>
		  	
				<tr align="right">
					<td colspan="2">
						<input class="button" onclick="checkIP();" type="button" value="<#CTL_apply#>"/>
					</td>
				</tr>
			</table>
		</td>
	</tr>
</table>		
					
		</td>
</form>

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
