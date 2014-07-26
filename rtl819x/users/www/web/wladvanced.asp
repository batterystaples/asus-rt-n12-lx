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
<title>ASUS Wireless Router <#Web_Title#> - <#menu5_1_6#></title>
<link rel="stylesheet" type="text/css" href="index_style.css"> 
<link rel="stylesheet" type="text/css" href="form_style.css">
<script type="text/javascript" src="/state.js"></script>
<script type="text/javascript" src="/general.js"></script>
<script type="text/javascript" src="/help.js"></script>
<script type="text/javascript" src="/popup.js"></script>
<script type="text/javascript" src="/detect.js"></script>
<script type="text/javascript" src="util_gw.js"> </script>
<script>
var band2G5GSupport=<% getIndex("Band2G5GSupport"); %> ;

function initial()
{
	show_banner(1);
	show_menu(5,1,3);		
	show_footer();
}
function validateNum(str)
{
  for (var i=0; i<str.length; i++) {
   	if ( !(str.charAt(i) >='0' && str.charAt(i) <= '9')) {
		alert("Invalid value. It should be in decimal number (0-9).");
		return false;
  	}
  }
  return true;
}
function saveChanges()
{
	if ( validateNum(document.advanceSetup.fragThreshold.value) == 0 ) {
  		document.advanceSetup.fragThreshold.focus();
		return false;
	}
  	num = parseInt(document.advanceSetup.fragThreshold.value);
	if (document.advanceSetup.fragThreshold.value == "" || num < 256 || num > 2346) {
  		alert('<#JS_validrange#> 256 <#JS_validrange_to#> 2346');
  		document.advanceSetup.fragThreshold.focus();
		return false;
  	}

	if ( validateNum(document.advanceSetup.rtsThreshold.value) == 0 ) {
  		document.advanceSetup.rtsThreshold.focus();
		return false;
	}
  	num = parseInt(document.advanceSetup.rtsThreshold.value);
	if (document.advanceSetup.rtsThreshold.value=="" || num > 2347) {
  		alert('<#JS_validrange#> 0 <#JS_validrange_to#> 2347');
  		document.advanceSetup.rtsThreshold.focus();
		return false;
	}

	if ( validateNum(document.advanceSetup.beaconInterval.value) == 0 ) {
  		document.advanceSetup.beaconInterval.focus();
		return false;
	}
  	num = parseInt(document.advanceSetup.beaconInterval.value);
	if (document.advanceSetup.beaconInterval.value=="" || num < 20 || num > 1024) {
  		alert('<#JS_validrange#> 20 <#JS_validrange_to#> 1024');
  		document.advanceSetup.beaconInterval.focus();
		return false;
	}
	showLoading();	//2011.03.28 Jerry
	return true;
}

function wlan_adv_switch()
{
	var wlanband_tmp = <% getIndex("band"); %>;	
	var wlanband = "";
	if(wlanband_tmp < 9)
		wlanband = "0";

	var checkid_aggregation;
 	var checkid_shortgi;
 	var wlan_xTxR="<% getInfo("wlan_xTxR"); %>";
 	
 	checkid_aggregation=document.getElementById("Aggregation");
 	checkid_shortgi=document.getElementById("ShortGi");
	
 	if(wlan_xTxR == "1*1")
 	{
 		document.advanceSetup.tx_stbc[0].checked= false;
 		document.advanceSetup.tx_stbc[1].checked= true;
 		document.advanceSetup.tx_stbc[0].disabled =true;
		document.advanceSetup.tx_stbc[1].disabled =true;
 	}
 	else if(wlan_xTxR == "0*0")
 	{
 		document.getElementById("stbctransmit").style.display = "none";
 	}
 	
	if(band2G5GSupport == 2) //2:5g
 	{
 		document.getElementById("preambleType").style.display = "none"; 
 	}
 	else
 	{
 		document.getElementById("preambleType").style.display = "";	
 	}
}
function onClick_func(enable)
{
	if(enable)
		enableRadioGroup(document.advanceSetup.sideBand0);
	else
		disableRadioGroup(document.advanceSetup.sideBand0);
	
}
</script>

<body onload="initial();wlan_adv_switch();" onunLoad="disable_auto_hint(3, 16);return unload_body();">
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
	<div id="tabMenu" class="submenuBlock"></div>
		<br />
		<!--===================================Beginning of Main Content===========================================-->
<table width="98%" border="0" align="center" cellpadding="0" cellspacing="0">
	<tr>
		<td valign="top" >
		
<table width="98%" border="0" align="center" cellpadding="5" cellspacing="0" class="FormTitle" table>
	<thead>
	<tr>
		<td><#menu5_1#> - <#menu5_1_6#></td>
	</tr>
	</thead>
	<tbody>
	<tr>
		<td bgcolor="#FFFFFF"><#WLANConfig11b_display5_sectiondesc#></td>
	</tr>
	</tbody>	
	<tr>
	  <td bgcolor="#FFFFFF">
		<table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3"  class="FormTable" id="WAdvTable">

<!--form action="form.cgi" method=POST name="advanceSetup"-->
<form action="/start_apply.htm" method=POST name="advanceSetup" target="hidden_frame">
<input type="hidden" name="current_page" value="wladvanced.asp">
<input type="hidden" value="formAdvanceSetup" name="typeForm">
<input type="hidden" value="/wladvanced.asp" name="submit-url">
<input type="hidden" name="action_mode" value="Restart_WLAN">	<!--2011.03.28 Jerry-->
<input type="hidden" name="flag" value="nodetect">	<!--2011.03.28 Jerry-->
<input type="hidden" name="preferred_lang" id="preferred_lang" value="<% getInfo("preferred_lang"); %>">	<!--2011.04.14 Jerry-->

<tr>
  <th><a class="hintstyle" href="javascript:void(0);" onClick="openHint(3, 1);"><#WLANConfig11b_x_RadioEnable_itemname#></a></th>
  <td>
<script>
	var radio_tmp = <% getIndex("wlanDisabled"); %>;
	var radio_ON = "";
	var radio_OFF = "";
	if(radio_tmp == 0)
		radio_ON = "checked";
	else
		radio_OFF = "checked";
	document.write("<input type=\"radio\" value=\"ON\" name=\"wlanDisabled<% getIndex("wlan_idx"); %>\" " + radio_ON + "><#checkbox_Yes#>\n");
	document.write("<input type=\"radio\" value=\"OFF\" name=\"wlanDisabled<% getIndex("wlan_idx"); %>\" " + radio_OFF + "><#checkbox_No#>\n");
</script>
  </td>
</tr>

<tr>
  <th><a class="hintstyle" href="javascript:void(0);" onClick="openHint(3, 9);"><#WLANConfig11b_x_Frag_itemname#></a></th>
  <td>
	<input type="text" name="fragThreshold" class="input" size="10" maxlength="4" value=<% getInfo("fragThreshold"); %>>(256-2346)
  </td>
</tr>

<tr>
  <th><a class="hintstyle" href="javascript:void(0);" onClick="openHint(3, 10);"><#WLANConfig11b_x_RTS_itemname#></a></th>
  <td>
	<input type="text" name="rtsThreshold" class="input" size="10" maxlength="4" value=<% getInfo("rtsThreshold"); %>>(0-2347)
  </td>
</tr>

<tr>
  <th><a class="hintstyle" href="javascript:void(0);" onClick="openHint(3, 12);"><#WLANConfig11b_x_Beacon_itemname#></a></th>
  <td>
	<input type="text" name="beaconInterval" class="input" size="10" maxlength="4" value=<% getInfo("beaconInterval"); %>> (20-1024 ms)
  </td>
</tr>

<tr id="preambleType" style="display:">
  <th><#WLANConfig11b_x_Preamble_type#></th>
  <td>
<script>
	var preamble_tmp = <% getIndex("preamble"); %>;
	var preamble_short = "";
	var preamble_long = "";
	if(preamble_tmp == 0)
		preamble_long = "checked";
	else
		preamble_short = "checked";
	document.write("<input type=\"radio\" value=\"long\" name=\"preamble\" " + preamble_long + "><#WLANConfig11b_x_Long_Preamble#>&nbsp;&nbsp;\n");
	document.write("<input type=\"radio\" name=\"preamble\" value=\"short\" " + preamble_short + "><#WLANConfig11b_x_Short_Preamble#>\n");
</script>
  </td>
</tr>
    
<tr>
  <th><#WLANConfig11b_x_IAPP#></th>
  <td>
<script>	
	var iappDisabled_tmp = <% getIndex("iappDisabled"); %>;
	var iappDisabled_yes = "";
	var iappDisabled_no = "";
	if(iappDisabled_tmp == 0)
		iappDisabled_yes = "checked";
	else
		iappDisabled_no = "checked";
	document.write("<input type=\"radio\" name=\"iapp\" value=\"yes\" " + iappDisabled_yes + "><#WLANConfig11b_WirelessCtrl_button1name#>&nbsp;&nbsp;\n");
	document.write("<input type=\"radio\" name=\"iapp\" value=\"no\" " + iappDisabled_no + "><#WLANConfig11b_WirelessCtrl_buttonname#>\n");
</script>
  </td>
</tr>

<tr>
  <th><#WLANConfig11b_x_Protection#></th>
  <td>
<script>	
	var protectionDisabled_tmp = <% getIndex("protectionDisabled"); %>;
	var protectionDisabled_yes = "";
	var protectionDisabled_no = "";
	if(protectionDisabled_tmp == 0)
		protectionDisabled_yes = "checked";
	else
		protectionDisabled_no = "checked";
	document.write("<input type=\"radio\" name=\"11g_protection\" value=\"yes\" " + protectionDisabled_yes + "><#WLANConfig11b_WirelessCtrl_button1name#>&nbsp;&nbsp;\n");
	document.write("<input type=\"radio\" name=\"11g_protection\" value=\"no\" " + protectionDisabled_no + "><#WLANConfig11b_WirelessCtrl_buttonname#>\n");
</script>
  </td>
</tr>
    
<tr id="Aggregation" style="display:">
  <th><#WLANConfig11b_x_Aggregation#></th>
  <td>
<script>	
	var aggregation_tmp = <% getIndex("aggregation"); %>;
	var aggregation_enable = "";
	var aggregation_disable = "";
	if(aggregation_tmp != 0)
		aggregation_enable = "checked";
	else
		aggregation_disable = "checked";
	document.write("<input type=\"radio\" name=\"aggregation\" value=\"enable\" " + aggregation_enable + "><#WLANConfig11b_WirelessCtrl_button1name#>&nbsp;&nbsp;\n");
	document.write("<input type=\"radio\" name=\"aggregation\" value=\"disable\" " + aggregation_disable + "><#WLANConfig11b_WirelessCtrl_buttonname#>\n");
</script>
  </td>
</tr>

<tr id="ShortGi" style="display:">
  <th><#WLANConfig11b_x_Short_GI#></th>
  <td>
<script>	
	var shortGIEnabled_tmp = <% getIndex("shortGIEnabled"); %>;
	var shortGIEnabled_on = "";
	var shortGIEnabled_off = "";
	if(shortGIEnabled_tmp == 1)
		shortGIEnabled_on = "checked";
	else
		shortGIEnabled_off = "checked";
	document.write("<input type=\"radio\" name=\"shortGI0\" value=\"on\" " + shortGIEnabled_on + "><#WLANConfig11b_WirelessCtrl_button1name#>&nbsp;&nbsp;\n");
	document.write("<input type=\"radio\" name=\"shortGI0\" value=\"off\" " + shortGIEnabled_off + "><#WLANConfig11b_WirelessCtrl_buttonname#>\n");
</script>
  </td>
</tr> 

<tr id="blockrelay" style="display:">
  <th><#WLANConfig11b_x_Partition#></th>
  <td>
<script>	
	var block_relay_tmp = <% getIndex("block_relay"); %>;
	var block_relay_enable = "";
	var block_relay_disable = "";
	if(block_relay_tmp == 1)
		block_relay_enable = "checked";
	else
		block_relay_disable = "checked";
	document.write("<input type=\"radio\" name=\"block_relay\" value=\"enable\" " + block_relay_enable + "><#WLANConfig11b_WirelessCtrl_button1name#>&nbsp;&nbsp;\n");
	document.write("<input type=\"radio\" name=\"block_relay\" value=\"disable\" " + block_relay_disable + "><#WLANConfig11b_WirelessCtrl_buttonname#>\n");
</script>
  </td>
</tr> 

<tr id="stbctransmit" style="display:">
  <th><#WLANConfig11b_x_STBC#></th>
  <td>
<script>	
	var tx_stbc_tmp = <% getIndex("tx_stbc"); %>;
	var tx_stbc_enable = "";
	var tx_stbc_disable = "";
	if(tx_stbc_tmp == 1)
		tx_stbc_enable = "checked";
	else
		tx_stbc_disable = "checked";
	document.write("<input type=\"radio\" name=\"tx_stbc\" value=\"enable\" " + tx_stbc_enable + "><#WLANConfig11b_WirelessCtrl_button1name#>&nbsp;&nbsp;\n");
	document.write("<input type=\"radio\" name=\"tx_stbc\" value=\"disable\" " + tx_stbc_disable + "><#WLANConfig11b_WirelessCtrl_buttonname#>\n");
</script>
  </td>
</tr> 

<tr>
  <th><#WLANConfig11b_x_RF_Power#></th>
  <td>

<script>	
	var RFPower_tmp = <% getIndex("RFPower"); %>;
	var RFPower_0 = "";
	var RFPower_1 = "";
	var RFPower_2 = "";
	var RFPower_3 = "";
	var RFPower_4 = "";
	if(RFPower_tmp == 0)
		RFPower_0 = "checked";
	if(RFPower_tmp == 1)
		RFPower_1 = "checked";
	if(RFPower_tmp == 2)
		RFPower_2 = "checked";
	if(RFPower_tmp == 3)
		RFPower_3 = "checked";
	if(RFPower_tmp == 4)
		RFPower_4 = "checked";
	document.write("<input type=\"radio\" name=\"RFPower\" value=\"0\" " + RFPower_0 + ">100%&nbsp;&nbsp;\n");
	document.write("<input type=\"radio\" name=\"RFPower\" value=\"1\" " + RFPower_1 + ">70%&nbsp;&nbsp;\n");
	document.write("<input type=\"radio\" name=\"RFPower\" value=\"2\" " + RFPower_2 + ">50%&nbsp;&nbsp;\n");
	document.write("<input type=\"radio\" name=\"RFPower\" value=\"3\" " + RFPower_3 + ">35%&nbsp;&nbsp;\n");
	document.write("<input type=\"radio\" name=\"RFPower\" value=\"4\" " + RFPower_4 + ">15%\n");
</script>
  </td>
</tr>

<tr>
  <td colspan="2" align="right">
	<input type="submit" value="<#CTL_apply#>" name="save" class="button" onClick="return saveChanges()">
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
	  <div id="helpicon" onClick="openHint(0, 0);" title="<#Help_button_default_hint#>">
		<img src="images/help.gif">
	  </div>
	  
	  <div id="hintofPM" style="display:none;">
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

