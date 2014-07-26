<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<html xmlns:v>
<head>
<meta http-equiv="Content-Type" content="text/html">
<meta http-equiv="X-UA-Compatible" content="IE=EmulateIE7"/>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta HTTP-EQUIV="Pragma" CONTENT="no-cache">
<meta HTTP-EQUIV="Expires" CONTENT="-1">
<link rel="shortcut icon" href="images/favicon.png">
<link rel="icon" href="images/favicon.png">
<title>ASUS Wireless Router <#Web_Title#> - <#menu5_1_2#></title>
<link rel="stylesheet" type="text/css" href="index_style.css"> 
<link rel="stylesheet" type="text/css" href="form_style.css">
<script type="text/javascript" src="/state.js"></script>
<script type="text/javascript" src="/help.js"></script>
<script type="text/javascript" src="/general.js"></script>
<script type="text/javascript" src="/popup.js"></script>
<script type="text/javascript" src="/ajax.js"></script>
<script type="text/javascript" src="/detect.js"></script>
<script type="text/javascript" src="util_gw.js"> </script>
<script>
var val = <% getIndex("wlanMode"); %>;
var isClient;
if(val == 1)
	isClient=1;
else
	isClient=0;

var isConfig=<% getIndex("wscConfig"); %>;
var wps_auth=<% getIndex("wps_auth"); %>;
var wps_enc=<% getIndex("wps_enc"); %>;
var wps_key="<%getInfo("wps_key");%>";

var encrypt=<% getIndex("encrypt");%>; //ENCRYPT_DISABLED=0, ENCRYPT_WEP=1, ENCRYPT_WPA=2, ENCRYPT_WPA2=4, ENCRYPT_WPA2_MIXED=6 ,ENCRYPT_WAPI=7				
var enable1x=<% getIndex("enable1X");%>;
var wpa_auth=<% getIndex("wpaAuth");%>; //WPA_AUTH_AUTO=1, WPA_AUTH_PSK=2
var mode=<% getIndex("wlanMode");%>; //AP_MODE=0, CLIENT_MODE=1, WDS_MODE=2, AP_WDS_MODE=3, AP_MPP_MODE=4, MPP_MODE=5, MAP_MODE=6, MP_MODE=7
var is_adhoc=<% getIndex("networkType");%>; //INFRASTRUCTURE=0, ADHOC=1


var is_rpt=<% getIndex("repeaterEnabled");%>;
var is_rpt_wps_support=<% getIndex("is_rpt_wps_support");%>;

var isRptConfig=<% getIndex("wscRptConfig"); %>;
var wpsRpt_auth=<% getIndex("wpsRpt_auth"); %>;
var wpsRpt_enc=<% getIndex("wpsRpt_enc"); %>;
var wpsRpt_key="<%getInfo("wpsRpt_key");%>";

var encrypt_rpt=<% getIndex("encrypt_rpt");%>; //ENCRYPT_DISABLED=0, ENCRYPT_WEP=1, ENCRYPT_WPA=2, ENCRYPT_WPA2=4, ENCRYPT_WPA2_MIXED=6 ,ENCRYPT_WAPI=7				
var enable1x_rpt=<% getIndex("enable1x_rpt");%>;
var wpa_auth_rpt=<% getIndex("wpa_auth_rpt");%>; //WPA_AUTH_AUTO=1, WPA_AUTH_PSK=2
var mode_rpt=<% getIndex("wlanMode_rpt");%>; //AP_MODE=0, CLIENT_MODE=1, WDS_MODE=2, AP_WDS_MODE=3, AP_MPP_MODE=4, MPP_MODE=5, MAP_MODE=6, MP_MODE=7
var is_adhoc_rpt=<% getIndex("networkType_rpt");%>; //INFRASTRUCTURE=0, ADHOC=1


var warn_msg1='WPS was disabled automatically because wireless mode setting could not be supported. ' +
				'You need go to Wireless/Basic page to modify settings to enable WPS.';
var warn_msg2='WPS was disabled automatically because Radius Authentication could not be supported. ' +
				'You need go to Wireless/Security page to modify settings to enable WPS.';
var warn_msg3="PIN number was generated. You have to click \'Apply\' button to make change effectively.";
var disable_all=0;
var disable_rpt_all=0;

function initial(){
	show_banner(1);
	
	show_menu(5,1,2);
		
	show_footer();
}
function triggerPBCClicked()
{
	showLoading();
  	return true;
}

function triggerPINClicked()
{
	showLoading();	
	return true;
}

function resetUnCfgClicked()
{
	document.formWsc.action_mode.value = "Restart_WLAN";	//2011.05.10 Jerry
	document.formWsc.elements["resetUnCfg"].value = 1;
	showLoading();	//2011.05.10 Jerry
	document.forms["formWsc"].submit();	
}

function resetRptUnCfgClicked()
{
	document.formWsc.elements["resetRptUnCfg"].value = 1;
	document.forms["formWsc"].submit();	
}

function compute_pin_checksum(val)
{
	var accum = 0;	
	var code = parseInt(val)*10;

	accum += 3 * (parseInt(code / 10000000) % 10); 
	accum += 1 * (parseInt(code / 1000000) % 10); 
	accum += 3 * (parseInt(code / 100000) % 10); 
	accum += 1 * (parseInt(code / 10000) % 10);
	accum += 3 * (parseInt(code / 1000) % 10);
	accum += 1 * (parseInt(code / 100) % 10);
	accum += 3 * (parseInt(code / 10) % 10); 
	accum += 1 * (parseInt(code / 1) % 10);	
	var digit = (parseInt(accum) % 10);
	return ((10 - digit) % 10);
}

function validate_pin_code(code)
{
	var accum=0;

	accum += 3 * (parseInt(code / 10000000) % 10); 
	accum += 1 * (parseInt(code / 1000000) % 10); 
	accum += 3 * (parseInt(code / 100000) % 10); 
	accum += 1 * (parseInt(code / 10000) % 10);
	accum += 3 * (parseInt(code / 1000) % 10);
	accum += 1 * (parseInt(code / 100) % 10);
	accum += 3 * (parseInt(code / 10) % 10); 
	accum += 1 * (parseInt(code / 1) % 10);
	return (0 == (accum % 10));	
}

function check_pin_code(str)
{
	var i;
	var code_len;
		
	code_len = str.length;
	if (code_len != 8 && code_len != 4)
		return 1;

	for (i=0; i<code_len; i++) {
		if ((str.charAt(i) < '0') || (str.charAt(i) > '9'))
			return 2;
	}

	if (code_len == 8) {
		var code = parseInt(str, 10);
		if (!validate_pin_code(code))
			return 3;
		else
			return 0;
	}
	else
		return 0;
}

function setPinClicked()
{
	var ret;
	ret = check_pin_code(document.formWsc.peerPin.value);
	if (ret == 1) {
		alert("<#JS_InvalidPIN#>");
		document.formWsc.peerPin.focus();	
		return false;
	}
	else if (ret == 2) {
		alert("<#JS_InvalidPIN#>");
		document.formWsc.peerPin.focus();		
		return false;
	}
	else if (ret == 3) {
		if ( !confirm("<#JS_InvalidPIN#>") ) {
			document.formWsc.peerPin.focus();
			return false;
  		}
	}
	document.formWsc.setPIN.value = "1";
	showLoading();
	document.formWsc.submit();
}

function checkWPSstate(form, isClientChk, isRptChk)
{
	if (disable_all) {
		disableCheckBox(form.elements["disableWPS"]);
		disableButton(form.elements["save"]);
	}
	if(isClientChk)
	{
		if (disable_all || form.elements["disableWPS"][1].checked) { 	
			disableTextField(form.elements["peerPin"]);
			disableButton(form.elements["btnSetPIN"]);	 	
			disableButton(form.elements["triggerPBC"]);
			disableButton(form.elements["resetUnConfiguredBtn"]);
		}
		else {
			enableTextField(form.elements["peerPin"]);
			enableButton(form.elements["btnSetPIN"]);		
			enableButton(form.elements["triggerPBC"]);
			
			if (isConfig==1)
				enableButton(form.elements['resetUnConfiguredBtn']);
			else
				disableButton(form.elements['resetUnConfiguredBtn']);
					
		}
	}
	if(isClient == 1 && isRptChk)
	{
		if (disable_rpt_all || form.elements["disableWPS"][1].checked) 
		{
			disableButton(form.elements["triggerRptPIN"]);	 	
			disableButton(form.elements["triggerRptPBC"]);
			disableButton(form.elements["resetRptUnConfiguredBtn"]);
			
		}
		else 
		{
			enableButton(form.elements["triggerRptPIN"]);		
			enableButton(form.elements["triggerRptPBC"]);
	     
			if (isRptConfig==1) 
				enableButton(form.elements['resetRptUnConfiguredBtn']);
			else
				disableButton(form.elements['resetRptUnConfiguredBtn']);	
		}
		
		disableRadioGroup(form.elements["configVxd"]);
	}
	disableRadioGroup(form.elements["config"]);
	return true;
}

function saveChangesWPS(form)
{
	document.formWsc.action_mode.value = "Restart_WLAN";
	showLoading();
   	return true;
}

function Load_Setting()
{
	
	if(isConfig == 1)
		document.formWsc.elements["config"][0].checked = true;
	else
		document.formWsc.elements["config"][1].checked = true;

		

}
</script>
</head>

<body onload="initial();Load_Setting();" onunLoad="disable_auto_hint(13, 0);return unload_body();">
<div id="TopBanner"></div>

<div id="Loading" class="popup_bg"></div>

<iframe name="hidden_frame" id="hidden_frame" src="" width="0" height="0" frameborder="0"></iframe>

<table class="content" align="center" cellpadding="0" cellspacing="0">
	<tr>
		<td width="23">&nbsp;</td>		
		<td valign="top" width="202">
		<div  id="mainMenu"></div>
		<div  id="subMenu"></div>	
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
		<td><#menu5_1#> - <#t2WPS#></td>
	</tr>
	</thead>
	<tbody>
	<tr>
		<td bgcolor="#FFFFFF"><#WLANConfig11b_display6_sectiondesc#></td>
	</tr>
	</tbody>	
	<tr>
	  <td bgcolor="#FFFFFF">
		<table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3"  class="FormTable">

<form action="/start_apply.htm" method=POST name="formWsc" target="hidden_frame">
<input type="hidden" name="current_page" value="wlwps.asp">
<input type="hidden" value="formWsc" name="typeForm">
<input type="hidden" name="action_mode" value="">
<input type="hidden" name="flag" value="nodetect">
<input type="hidden" name="preferred_lang" id="preferred_lang" value="<% getInfo("preferred_lang"); %>">	<!--2011.04.14 Jerry-->
<input type="hidden" name="setPIN" value="">

<script>
	if (mode == 0 || mode == 3) //0:AP 3:AP+WDS
	    	disable_all = check_wps_enc(encrypt, enable1x, wpa_auth);
	else
		disable_all = check_wps_wlanmode(mode, is_adhoc);
		
		var isRptClient = !isClient;  
	if (mode_rpt == 0 || mode_rpt == 3) //0:AP 3:AP+WDS
	    	disable_rpt_all = check_wps_enc(encrypt_rpt, enable1x_rpt, wpa_auth_rpt);
	else
		disable_rpt_all = check_wps_wlanmode(mode_rpt, is_adhoc_rpt);
</script>

<tr style="display:none">
  <th width="30%"><a class="hintstyle" href="javascript:void(0);" onClick="openHint(13,1);"><#WLANConfig11b_x_WPS_itemname#></a></th>
  <td>
<script>
	var disableWPS_tmp = <% getIndex("wscDisable"); %>;
	var disableWPS_ON = "";
	var disableWPS_OFF = "";
	if(disableWPS_tmp)
		disableWPS_ON = "checked";
	else
		disableWPS_OFF = "checked";
	document.write("<input type=\"radio\" name=\"disableWPS\" class=\"input\" value=\"OFF\" ONCLICK=\"checkWPSstate(document.formWsc, 1, 1)\" " + disableWPS_OFF + "><#checkbox_Yes#>\n");
	document.write("<input type=\"radio\" name=\"disableWPS\" class=\"input\" value=\"ON\" ONCLICK=\"checkWPSstate(document.formWsc, 1, 1)\" " + disableWPS_ON + "><#checkbox_No#>\n");
</script>
  </td>
</tr>

<tr align="right" style="display:none">
  <td colspan="2">
	<input type="submit" value="<#CTL_apply#>" name="save" class="button" onClick="return saveChangesWPS(document.formWsc)">
  </td>
</tr>

<tr>
  <th width="30%"><#WLANConfig11b_x_WPSStatus_itemname#></th>  
  <td>
	<input type="radio" name="config" class="button" value="on" ><#WLANConfig11b_x_WPS_Configured#>&nbsp;&nbsp;
	<input type="radio" name="config" class="button" value="off"><#WLANConfig11b_x_WPS_UnConfigured#>
  </td>  
</tr>

<tr>
  <td width="30%">&nbsp;</td> 
  <td>
  	<input type="hidden" value="0" name="resetUnCfg">
  	<input type="button" value="<#CTL_Reset_OOB#>" name="resetUnConfiguredBtn" class="button" onClick="return resetUnCfgClicked()">
  </td>  
</tr>

<tr>
  <!--<th width="30%">Self-PIN Number:</th>-->
  <th><a class="hintstyle" href="javascript:void(0);" onclick="openHint(13,4);"><#WLANConfig11b_x_DevicePIN_itemname#></a></th>
  <td><% getInfo("wscLoocalPin");%></td>
</tr>

<tr>
  <th width="30%"><#WLANConfig11b_x_WPS_PBC#></th> 
  <td>
	<input type="submit" value="<#WLANConfig11b_x_WPS_Start_PBC#>" name="triggerPBC" class="button" onClick="return triggerPBCClicked()">
  </td>
</tr>

<tr>
  <!--<th width="30%">Client PIN Number:</th>-->
  <th><a class="hintstyle" href="javascript:void(0);" onclick="openHint(13,3);"><#WLANConfig11b_x_WPSPIN_itemname#></a></th>
  <td>
	<input type="text" name="peerPin" class="input" size="12" maxlength="10" value="">
	<input type="button" value="<#WLANConfig11b_x_WPS_Start_PIN#>" name="btnSetPIN" class="button" onClick="setPinClicked();">
  </td>
</tr>

<script>
   checkWPSstate(document.formWsc, 1, 0);
</script>

<script>
 	if (disable_all) {
		 document.write("<tr><td colspan=\"2\" height=\"55\"><font size=2><em>");
	   	if (disable_all == 1)     
   			document.write(warn_msg1);
	   	else
	   		document.write(warn_msg2);
		document.write("</td></tr>"); 	   	
 	}
</script>

</table></td></tr>

</table>		
</td>
</form>
	  <!--==============Beginning of hint content=============-->	
          <td id="help_td" style="width:15px;" valign="top">
<form name="hint_form"></form>
            <div id="helpicon" onClick="openHint(0,0);" title="<#Help_button_default_hint#>">
            	<img src="images/help.gif"/>
            </div>
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
