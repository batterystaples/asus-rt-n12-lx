<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<html xmlns:v>
<head>
<meta http-equiv="X-UA-Compatible" content="IE=EmulateIE7"/>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<script type="text/javascript" src="/jquery.js"></script>
<meta HTTP-EQUIV="Pragma" CONTENT="no-cache">
<meta HTTP-EQUIV="Expires" CONTENT="-1">
<link rel="shortcut icon" href="images/favicon.png">
<link rel="icon" href="images/favicon.png">
<meta http-equiv="X-UA-Compatible" content="IE=EmulateIE7"/>
<title>ASUS Wireless Router <#Web_Title#> - <#menu5_3_2#></title>
<link rel="stylesheet" type="text/css" href="/index_style.css"> 
<link rel="stylesheet" type="text/css" href="/form_style.css">
<script type="text/javascript" src="/state.js"></script>
<script type="text/javascript" src="/help.js"></script>
<script type="text/javascript" src="/general.js"></script>
<script type="text/javascript" src="/popup.js"></script>
<script type="text/javascript" src="/detect.js"></script>
<script type="text/javascript" src="util_gw.js"> </script>
<script type="text/javascript" src="util_qos.js"> </script>

<script>
function initial(){
	show_banner(1);
	show_menu(5,3,2);
	show_footer();
}
function checkClientRange(start,end)
{
  var start_d, end_d;
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

function addRuleClick()
{
	if (!document.formQosAdd.enabled[0].checked)
	{
		showLoading();	//2011.03.28 Jerry
	  	return true;
	}

	if (!document.formQosAdd.automaticUplinkSpeed[0].checked && (document.formQosAdd.manualUplinkSpeed.value=="" || document.formQosAdd.manualUplinkSpeed.value < 100)) {
		alert("<#IPQOS_warning1#>");
		document.formQosAdd.manualUplinkSpeed.focus();
		return false;
  	}
  
	if (!document.formQosAdd.automaticDownlinkSpeed[0].checked && (document.formQosAdd.manualDownlinkSpeed.value=="" || document.formQosAdd.manualDownlinkSpeed.value<100)) {
		alert("<#IPQOS_warning2#>");
		document.formQosAdd.manualDownlinkSpeed.focus();
		return false;
  	}


	if (document.formQosAdd.ipStart.value=="" && document.formQosAdd.ipEnd.value=="" &&
  	document.formQosAdd.mac.value=="" &&
	document.formQosAdd.bandwidth.value=="" && document.formQosAdd.bandwidth_downlink.value=="" && 
		document.formQosAdd.comment.value=="")
	{
		showLoading();	//2011.03.28 Jerry
		return true;
	}

	if (document.formQosAdd.addressType[0].checked==true) {
    
		if ( checkIpAddr(document.formQosAdd.ipStart, 'Invalid IP address') == false )
	    		return false;
		if ( checkIpAddr(document.formQosAdd.ipEnd, 'Invalid IP address') == false )
	    		return false;

        	if ( !checkClientRange(document.formQosAdd.ipStart.value,document.formQosAdd.ipEnd.value) ) {
			alert("<#IPQOS_warning3#>\n<#JS_validip2#>");
			document.formQosAdd.ipStart.focus();
			return false;
        	}

		var LAN_IP = ipv4_to_unsigned_integer("<% getInfo("ip"); %>");
		var LAN_MASK = ipv4_to_unsigned_integer("<% getInfo("mask"); %>");			

		var tarIp = ipv4_to_unsigned_integer(document.formQosAdd.ipStart.value);

		if ((tarIp & LAN_MASK) != (LAN_IP & LAN_MASK))
		{
			alert("<#IPQOS_warning4#>");
			return false;
		}
		tarIp = ipv4_to_unsigned_integer(document.formQosAdd.ipEnd.value);

		if ((tarIp & LAN_MASK) != (LAN_IP & LAN_MASK))
		{
			alert("<#IPQOS_warning5#>");
			return false;
		}
		
	}
  	else {
		var str = document.formQosAdd.mac.value;
	  	if ( str.length < 12) {
			alert('<#JS_validmac#>');
			document.formQosAdd.mac.focus();
			return false;
	  	}

	  	for (var i=0; i<str.length; i++) {
	    		if ( (str.charAt(i) >= '0' && str.charAt(i) <= '9') ||
			(str.charAt(i) >= 'a' && str.charAt(i) <= 'f') ||
			(str.charAt(i) >= 'A' && str.charAt(i) <= 'F') )
				continue;

			alert('<#JS_validmac#>');
			document.formQosAdd.mac.focus();
			return false;
	  	}
  	}
  	if ( (document.formQosAdd.bandwidth.value == "" || document.formQosAdd.bandwidth.value == 0)
   	&& (document.formQosAdd.bandwidth_downlink.value == "" || document.formQosAdd.bandwidth_downlink.value == 0) ) {
	alert('<#JS_fieldblank#>');
		document.formQosAdd.bandwidth.focus();
		return false;
  	}
  
  	if (document.formQosAdd.bandwidth.value!="") {
  		if ( validateKey( document.formQosAdd.bandwidth.value ) == 0 ) {
			alert("<#IPQOS_warning6#>");
			document.formQosAdd.bandwidth.focus();
			return false;
  		}
   	}
   
   	if (document.formQosAdd.bandwidth_downlink.value!="") {
  		if ( validateKey( document.formQosAdd.bandwidth_downlink.value ) == 0 ) {
			alert("<#IPQOS_warning6#>");
			document.formQosAdd.bandwidth_downlink.focus();
			return false;
  		}
   	}
/*Edison 2011.4.20*/
	var entryNum = <% getIndex("qosRuleNum"); %>;
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
  	else
	{
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

function disableQosDelButton()
{
	disableButton(document.formQosDel.deleteSel);
}

function ipAddrClicked()
{
 	enableTextField(document.formQosAdd.ipStart);
 	enableTextField(document.formQosAdd.ipEnd);
	disableTextField(document.formQosAdd.mac);
}

function macAddrClicked()
{
 	disableTextField(document.formQosAdd.ipStart);
 	disableTextField(document.formQosAdd.ipEnd);
	enableTextField(document.formQosAdd.mac);
}
	
function updateQosState()
{
  if (document.formQosAdd.enabled[0].checked) {  	
 	enableTextField(document.formQosAdd.automaticUplinkSpeed);
 	enableTextField(document.formQosAdd.automaticDownlinkSpeed);
 	enableTextField(document.formQosAdd.addressType[0]);
 	enableTextField(document.formQosAdd.addressType[1]);
	enableTextField(document.formQosAdd.mode);
	enableTextField(document.formQosAdd.bandwidth);
	enableTextField(document.formQosAdd.bandwidth_downlink);
	enableTextField(document.formQosAdd.comment);
	
	updateLinkState();
	
	if (document.formQosAdd.addressType[0].checked==true)
		ipAddrClicked();
	else
		macAddrClicked();
  }
  else {
 	disableTextField(document.formQosAdd.automaticUplinkSpeed);
 	disableTextField(document.formQosAdd.automaticDownlinkSpeed);
 	disableTextField(document.formQosAdd.manualUplinkSpeed);
 	disableTextField(document.formQosAdd.manualDownlinkSpeed);
 	disableTextField(document.formQosAdd.addressType[0]);
 	disableTextField(document.formQosAdd.addressType[1]);
 	disableTextField(document.formQosAdd.ipStart);
 	disableTextField(document.formQosAdd.ipEnd);
	disableTextField(document.formQosAdd.mac);
	disableTextField(document.formQosAdd.mode);
	disableTextField(document.formQosAdd.bandwidth);
	disableTextField(document.formQosAdd.bandwidth_downlink);
	disableTextField(document.formQosAdd.comment);
  }
}

function updateLinkState()
{
  if (document.formQosAdd.automaticUplinkSpeed[0].checked) {
 	disableTextField(document.formQosAdd.manualUplinkSpeed);
  }
  else {
 	enableTextField(document.formQosAdd.manualUplinkSpeed);
  }
  
  if (document.formQosAdd.automaticDownlinkSpeed[0].checked) {
 	disableTextField(document.formQosAdd.manualDownlinkSpeed);
  }
  else {
 	enableTextField(document.formQosAdd.manualDownlinkSpeed);
  }
}

</script>
</head>

<body onLoad="initial();" onunLoad="return unload_body();">

<div id="TopBanner"></div>

<div id="Loading" class="popup_bg"></div>

<iframe name="hidden_frame" id="hidden_frame" src="" width="0" height="0" frameborder="0"></iframe>

<table class="content" align="center" cellpadding="0" cellspacing="0">
	<tr>
		<td width="23">&nbsp;</td>		
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
			<table width="500" border="0" align="center" cellpadding="4" cellspacing="0" class="FormTitle" table>
				<thead>
				<tr>
					<td><#BM_title_User#></td>
				</tr>
				</thead>
				
				<tbody>
				<tr>
					<td bgcolor="#FFFFFF"><#IPQOS_sectiondesc#></td>
				</tr>
				</tbody>
				
				<tr>
					<td bgcolor="#FFFFFF">
						<table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable">

<form action="/start_apply.htm" method=POST name="formQosAdd" target="hidden_frame">
<input type="hidden" name="current_page" value="ip_qos.asp">
<input type="hidden" value="formIpQoS" name="typeForm">
<input type="hidden" value="/ip_qos.asp" name="submit-url">
<input type="hidden" name="action_mode" value="Restart_QoS">	<!--2011.03.28 Jerry-->
<input type="hidden" name="flag" value="nodetect">	<!--2011.03.28 Jerry-->
<input type="hidden" name="preferred_lang" id="preferred_lang" value="<% getInfo("preferred_lang"); %>">	<!--2011.04.14 Jerry-->

<tr>
  <th width="40%"><#IPQOS_Enable#></th>
  <td colspan="2">
<script>
	var qosEnabled_tmp = <% getIndex("qosEnabled"); %>;
	var qosEnabled_ON = "";
	var qosEnabled_OFF = "";
	if(qosEnabled_tmp)
		qosEnabled_ON = "checked";
	else
		qosEnabled_OFF = "checked";
	document.write("<input type=\"radio\" name=\"enabled\" value=\"ON\" " + qosEnabled_ON + " ONCLICK=updateQosState()><#checkbox_Yes#>\n");
	document.write("<input type=\"radio\" name=\"enabled\" value=\"OFF\" " + qosEnabled_OFF + " ONCLICK=updateQosState()><#checkbox_No#>\n");
</script>
  </td>
</tr>

<tr style="display:none;">
  <th><#IPQOS_Automatic_Uplink_Speed#></th>
  <td colspan="2">
<script>
	var qosAutoUplinkSpeed_tmp = <% getIndex("qosAutoUplinkSpeed"); %>;
	var qosAutoUplinkSpeed_ON = "";
	var qosAutoUplinkSpeed_OFF = "";
	if(qosAutoUplinkSpeed_tmp)
		qosAutoUplinkSpeed_ON = "checked";
	else
		qosAutoUplinkSpeed_OFF = "checked";
	document.write("<input type=\"radio\" name=\"automaticUplinkSpeed\" value=\"ON\" " + qosAutoUplinkSpeed_ON + " ONCLICK=updateLinkState()><#checkbox_Yes#>\n");
	document.write("<input type=\"radio\" name=\"automaticUplinkSpeed\" value=\"OFF\" " + qosAutoUplinkSpeed_OFF + " ONCLICK=updateLinkState()><#checkbox_No#>\n");
</script>
 </td></tr>

<tr>
  <th><#IPQOS_Manual_Uplink_Speed#></th>
  <td>
	<input type="text" name="manualUplinkSpeed" class="input" size="8" maxlength="8" value="<% getInfo("qosManualUplinkSpeed"); %>">
  </td>
</tr>

<tr style="display:none;">
  <th><#IPQOS_Automatic_Downlink_Speed#></th>
  <td colspan="2">
<script>
	var qosAutoDownlinkSpeed_tmp = <% getIndex("qosAutoDownlinkSpeed"); %>;
	var qosAutoDownlinkSpeed_ON = "";
	var qosAutoDownlinkSpeed_OFF = "";
	if(qosAutoDownlinkSpeed_tmp)
		qosAutoDownlinkSpeed_ON = "checked";
	else
		qosAutoDownlinkSpeed_OFF = "checked";
	document.write("<input type=\"radio\" name=\"automaticDownlinkSpeed\" value=\"ON\" " + qosAutoDownlinkSpeed_ON + " ONCLICK=updateLinkState()><#checkbox_Yes#>\n");
	document.write("<input type=\"radio\" name=\"automaticDownlinkSpeed\" value=\"OFF\" " + qosAutoDownlinkSpeed_OFF + " ONCLICK=updateLinkState()><#checkbox_No#>\n");
</script>
  </td>
</tr>

<tr>
  <th><#IPQOS_Manual_Downlink_Speed#></th>
  <td>
	<input type="text" name="manualDownlinkSpeed" class="input" size="8" maxlength="8" value="<% getInfo("qosManualDownlinkSpeed"); %>">
  </td>
</tr>

</table>
</td></tr>

<tr>
<td bgcolor="#FFFFFF">
<table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable">

<thead>
<tr>
  <td colspan="2"><#IPQOS_QoS_Rule#></td>
</tr>
</thead>

<tr>
  <th  width="40%"><#IPQOS_Address_Type#></th>
  <td>
      <input type="radio" name="addressType" value="0" checked ONCLICK=ipAddrClicked()>IP&nbsp;&nbsp;
      <input type="radio" name="addressType" value="1" ONCLICK=macAddrClicked()>MAC
  </td>
</tr>

<tr>
  <th width="30%"><a class="hintstyle" href="javascript:void(0);" onClick="openHint(18,3);"><#IPQOS_Source_IP_Address#></a></th>
  <td>
	<input type="text" name="ipStart" class="input" size="12" maxlength="15" value=""><b>-</b>
      	<input type="text" name="ipEnd" class="input" size="12" maxlength="15" value="">
  </td>
</tr>

<tr>
  <th><#IPQOS_MacAddress#></th>
  <td>
	<input type="text" name="mac" class="input" size="12" maxlength="12">
  </td>
</tr>
    
<tr>
  <th><#IPQOS_Mode#></th>
  <td>
	<select size="1" name="mode" class="input">
      		<option selected value="1"><#IPQOS_Guaranteed_minimum_bandwidth#></option>
      		<option value="2"><#IPQOS_Restricted_maximum_bandwidth#></option>
      	</select>
  </td>
</tr>
  
<tr>
  <th><#IPQOS_Uplink_Bandwidth#></th>
  <td>
	<input type="text" name="bandwidth" class="input" size="8">
  </td>
</tr>
	
<tr>
  <th><#IPQOS_Downlink Bandwidth#></th>
  <td>
	<input type="text" name="bandwidth_downlink" class="input" size="8">
  </td>
</tr>
	
<tr style="display:none;">
  <th>Comment:</th>
  <td>
	<input type="text" name="comment" class="input" size="10" maxlength="15">
  </td>
</tr>

<tr>
  <td colspan="2" align="right">
	<input type="submit" value="<#CTL_apply#>" class="button" name="addQos" class="button" onClick="return addRuleClick()">
  </td>
</tr>

  <script> updateQosState(); </script>
</form>
</table>
</td></tr>


<form action="/start_apply.htm" method=POST name="formQosDel" target="hidden_frame">
<input type="hidden" name="current_page" value="ip_qos.asp">
<input type="hidden" value="formIpQoS" name="typeForm">
<input type="hidden" value="/ip_qos.asp" name="submit-url">
<input type="hidden" name="action_mode" value="Restart_QoS">	<!--2011.03.28 Jerry-->
<input type="hidden" name="flag" value="nodetect">	<!--2011.03.28 Jerry-->

<tr>
<td bgcolor="#FFFFFF">
<table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable">
<thead>
<tr>
  <td colspan="6"><#BM_UserList_title#></td>
</tr>
</thead>
<tr>
	<td align=center width=\"10%%\" bgcolor=\"#808080\"><#LANHostConfig_x_Select_itemname#></td>
      	<td align=center width=\"15%%\" bgcolor=\"#808080\"><#BM_UserList2#></td>
      	<td align=center width=\"15%%\" bgcolor=\"#808080\"><#LANHostConfig_ManualMac_itemname#></td>
      	<td align=center width=\"10%%\" bgcolor=\"#808080\"><#IPQOS_Mode_itemname#></td>
      	<td align=center width=\"25%%\" bgcolor=\"#808080\"><#IPQOS_Uplink_Bandwidth1#></td>
      	<td align=center width=\"25%%\" bgcolor=\"#808080\"><#IPQOS_Downlink_Bandwidth1#></td>
</tr>
  <% ipQosList(); %>
<tr>
  <td colspan="6" align="right">
	<input type="submit" value="<#CTL_del#>" name="deleteSel" class="button" onClick="return deleteClick()">
  </td>
</tr>
<script>
	var entryNum = <% getIndex("qosRuleNum"); %>;
	if ( entryNum == 0 )
      	  	disableQosDelButton();
</script>
</form>
</table>
</td></tr>

</table>
</td>

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

