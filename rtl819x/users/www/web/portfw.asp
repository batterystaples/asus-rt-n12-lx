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
<title>ASUS Wireless Router <#Web_Title#> - <#menu5_5_2#></title>
<link rel="stylesheet" type="text/css" href="index_style.css"> 
<link rel="stylesheet" type="text/css" href="form_style.css">
<script language="JavaScript" type="text/javascript" src="/state.js"></script>
<script language="JavaScript" type="text/javascript" src="/popup.js"></script>
<script type="text/javascript" language="JavaScript" src="/help.js"></script>
<script language="JavaScript" type="text/javascript" src="/general.js"></script>
<script language="JavaScript" type="text/javascript" src="/detect.js"></script>
<meta http-equiv="Content-Type" content="text/html">
<script type="text/javascript" src="util_gw.js"> </script>
<script>
function initial(){
	show_banner(1);
	show_menu(5,3,3);
	show_footer();
}
function addClick()
{
	if (!document.formPortFwAdd.enabled[0].checked){
		showLoading();	//2011.03.28 Jerry
  		return true;
	}
	
	if (document.formPortFwAdd.ip.value=="" && document.formPortFwAdd.fromPort.value=="" &&
	document.formPortFwAdd.toPort.value=="" && document.formPortFwAdd.comment.value=="" ){
		showLoading();	//2011.03.28 Jerry
		return true;
	}
	if ( checkIpAddr(document.formPortFwAdd.ip, 'Invalid IP address') == false )
	    	return false;

	if (document.formPortFwAdd.fromPort.value=="") {
		alert('<#JS_fieldblank#><#BM_alert_port3#>');
		document.formPortFwAdd.fromPort.focus();
		return false;
  	}
	if ( validateKey( document.formPortFwAdd.fromPort.value ) == 0 ) {
		alert('<#JS_validport#>');
		document.formPortFwAdd.fromPort.focus();
		return false;
	}
	d1 = getDigit(document.formPortFwAdd.fromPort.value, 1);
	if (d1 > 65535 || d1 < 1) {
		alert('<#BM_alert_port3#>');
		document.formPortFwAdd.fromPort.focus();
		return false;
  	}
	if (document.formPortFwAdd.toPort.value!="") {
		if ( validateKey( document.formPortFwAdd.toPort.value ) == 0 ) {
			alert('<#JS_validport#>');
			document.formPortFwAdd.toPort.focus();
			return false;
  		}
		d2 = getDigit(document.formPortFwAdd.toPort.value, 1);
 		if (d2 > 65535 || d2 < 1) {
			alert('<#BM_alert_port3#>');
			document.formPortFwAdd.toPort.focus();
			return false;
  		}
		if (d1 > d2 ) {
			alert("<#PORT_warning#>");
			document.formPortFwAdd.fromPort.focus();
			return false;
		}
  	}
/*Edison 2011.4.20*/
	var entryNum = <% getIndex("portFwNum"); %>;
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
	if ( !cconfirm("<#Delete_confirm1#>") ) {
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
	disableButton(document.formPortFwDel.deleteSelPortFw);
}

function updateState()
{
  if (document.formPortFwAdd.enabled[0].checked) {
 	enableTextField(document.formPortFwAdd.ip);
	enableTextField(document.formPortFwAdd.protocol);
	enableTextField(document.formPortFwAdd.fromPort);
	enableTextField(document.formPortFwAdd.toPort);
  }
  else {
 	disableTextField(document.formPortFwAdd.ip);
	disableTextField(document.formPortFwAdd.protocol);
	disableTextField(document.formPortFwAdd.fromPort);
	disableTextField(document.formPortFwAdd.toPort);
  }
}

</script>
</head>

<body onload="initial();" onunLoad="disable_auto_hint(9, 2);return unload_body();">
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
		
<table width="98%" border="0" align="center" cellpadding="5" cellspacing="0" class="FormTitle" table>
	<thead>
	<tr>
		<td><#t1NAT#> - <#menu5_3_4#></td>
	</tr>
	</thead>
	<tbody>
	<tr>
		<td bgcolor="#FFFFFF"><#IPConnection_VServerEnable_sectiondesc#></td>
	</tr>
	</tbody>
	<tr>
	  <td bgcolor="#FFFFFF"><table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3"  class="FormTable">

<form action="/start_apply.htm" method=POST name="formPortFwAdd" target="hidden_frame">
<input type="hidden" name="current_page" value="portfw.asp">
<input type="hidden" value="formPortFw" name="typeForm">
<input type="hidden" value="/portfw.asp" name="submit-url">
<input type="hidden" name="action_mode" value="Restart_Rirewall">	<!--2011.03.28 Jerry-->
<input type="hidden" name="flag" value="nodetect">	<!--2011.03.28 Jerry-->
<input type="hidden" name="preferred_lang" id="preferred_lang" value="<% getInfo("preferred_lang"); %>">	<!--2011.04.14 Jerry-->

<tr>
  <th width="40%"><#IPConnection_VServerEnable_itemname#></th>
  <td>
<script>
	var portFwEnabled_tmp = <% getIndex("portFwEnabled"); %>;
	var portFwEnabled_ON = "";
	var portFwEnabled_OFF = "";
	if(portFwEnabled_tmp)
		portFwEnabled_ON = "checked";
	else
		portFwEnabled_OFF = "checked";
	document.write("<input type=\"radio\" name=\"enabled\" value=\"ON\" " + portFwEnabled_ON + " ONCLICK=updateState()><#checkbox_Yes#>\n");
	document.write("<input type=\"radio\" name=\"enabled\" value=\"OFF\" " + portFwEnabled_OFF + " ONCLICK=updateState()><#checkbox_No#>\n");	
</script>
  </td>
</tr>

<tr>
  <th><#IPConnection_VServerIP_itemname1#></th>
  <td>
	<input type="text" name="ip" class="input" size="10" maxlength="15">
  </td>
</tr>

<tr>
  <th><#IPConnection_VServerProto_itemname1#></th>
  <td>
	<select name="protocol">
    		<option select value="0">Both</option>
    		<option value="1">TCP</option>
    		<option value="2">UDP</option>
  	</select>
  </td>
</tr>

<tr>
  <th><#IPConnection_VServerPort_itemname1#></th>
  <td>
	<input type="text" name="fromPort" class="input" size="3"><b>-</b>
      	<input type="text" name="toPort" class="input" size="3">
  </td>
</tr>

<tr>
  <td colspan="2" align="right">
  	<input type="submit" value="<#CTL_apply#>" class="button" name="addPortFw" onClick="return addClick()">
  </td>
</tr>
  <script> updateState(); </script>
</form>
</table>
</td></tr>


<tr>
	  <td bgcolor="#FFFFFF"><table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3"  class="FormTable">

<form action="/start_apply.htm" method=POST name="formPortFwDel" target="hidden_frame">
<input type="hidden" name="current_page" value="portfw.asp">
<input type="hidden" value="formPortFw" name="typeForm">
<input type="hidden" value="/portfw.asp" name="submit-url">
<input type="hidden" name="action_mode" value="Restart_Rirewall">	<!--2011.03.28 Jerry-->
<input type="hidden" name="flag" value="nodetect">	<!--2011.03.28 Jerry-->

<thead>
<tr>
  <td colspan="4"><#IPConnection_VSList_title#></td>
</tr>
</thead>
<tr>
	<td align=center width=\"20%%\" bgcolor=\"#808080\"><#LANHostConfig_x_Select_itemname#></td>
      	<td align=center width=\"30%%\" bgcolor=\"#808080\"><#IPConnection_VServerIP_itemname#></td>
      	<td align=center width=\"25%%\" bgcolor=\"#808080\"><#IPConnection_VServerProto_itemname#></td>
      	<td align=center width=\"25%%\" bgcolor=\"#808080\"><#IPConnection_VServerPort_itemname#></td>
</tr>
  <% portFwList(); %>

<tr>
  <td colspan="4" align="right">
	<input type="submit" value="<#CTL_del#>" name="deleteSelPortFw" class="button" onClick="return deleteClick()">
  </td>
</tr>

</table>
 <script>
	var entryNum = <% getIndex("portFwNum"); %>;
	if(entryNum == 0)
		disableDelButton();
 </script>
</form>

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

