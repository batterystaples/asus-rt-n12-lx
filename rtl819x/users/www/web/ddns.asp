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
<title>ASUS Wireless Router <#Web_Title#> - <#menu5_3_6#></title>
<link rel="stylesheet" type="text/css" href="index_style.css"> 
<link rel="stylesheet" type="text/css" href="form_style.css">
<script language="JavaScript" type="text/javascript" src="/state.js"></script>
<script language="JavaScript" type="text/javascript" src="/general.js"></script>
<script language="JavaScript" type="text/javascript" src="/popup.js"></script>
<script type="text/javascript" language="JavaScript" src="/help.js"></script>
<script type="text/javascript" language="JavaScript" src="/detect.js"></script>
</head>
<script>
function initial() {
	show_banner(1);
	show_menu(5,3,5);
	show_footer();
}
function disableButton (button,val) {
  if (document.all || document.getElementById)
    button.disabled = val;
  else if (button) {
    button.oldOnClick = button.onclick;
    button.onclick = null;
    button.oldValue = button.value;
    button.value = 'DISABLED';
  }
}

function disableDdnsButton(val)
{
	disableButton(document.ddns.ddnsType, val);
	disableButton(document.ddns.ddnsDomainName, val);
	disableButton(document.ddns.ddnsUser, val);
	disableButton(document.ddns.ddnsPassword, val);

}

function updateState()
{
	if(document.ddns.ddnsEnabled[0].checked)
		disableDdnsButton(false);
	else
		disableDdnsButton(true);
}

function ddns_saveChanges()
{
	form = document.ddns ;
	if(form.ddnsEnabled[0].checked){
		if(form.ddnsDomainName.value == ""){
			alert("<#LANHostConfig_x_DDNS_alarm_14#>");
			form.ddnsDomainName.value = form.ddnsDomainName.defaultValue;
			form.ddnsDomainName.focus();
			return false ;
		}
		if(form.ddnsUser.value == ""){
			alert("<#QKSet_account_nameblank#>");
			form.ddnsUser.value = form.ddnsUser.defaultValue;
			form.ddnsUser.focus();
			return false ;
		}
		if(form.ddnsPassword.value == ""){
			alert("<#File_Pop_content_alert_desc6#>");
			form.ddnsPassword.value = form.ddnsPassword.defaultValue;
			form.ddnsPassword.focus();
			return false ;
		}
	}
	showLoading();	//2011.03.28 Jerry
	return true;
}
</script>

<body onload="initial();" onunLoad="return unload_body();">

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
		<td><#menu5_3#> - <#menu5_3_6#></td>
	</tr>
	</thead>
	<tbody>
	<tr>
	  <td bgcolor="#FFFFFF"><#LANHostConfig_x_DDNSEnable_sectiondesc#></td>
	  </tr>
	<tr>
		<td bgcolor="#FFFFFF"><table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3"  class="FormTable">


<!--form action="form.cgi" method=POST name="ddns"-->
<form action="/start_apply.htm" method=POST name="ddns" target="hidden_frame">
<input type="hidden" name="current_page" value="ddns.asp">
<input type="hidden" value="formDdns" name="typeForm">
<input type="hidden" value="/ddns.asp" name="submit-url">
<input type="hidden" name="action_mode" value="Reinit">	<!--2011.03.28 Jerry-->
<input type="hidden" name="flag" value="nodetect">	<!--2011.03.28 Jerry-->
<input type="hidden" name="preferred_lang" id="preferred_lang" value="<% getInfo("preferred_lang"); %>">	<!--2011.04.14 Jerry-->

<!--<table border="0" width=600>-->
<tr>
  <th width="40%"><#LANHostConfig_x_DDNSEnable_itemname#></th>
  <td colspan="2">
<script>
	var ddnsEnabled_tmp = <% getIndex("ddnsEnabled"); %>;
	var ddnsEnabled_ON = "";
	var ddnsEnabled_OFF = "";
	if(ddnsEnabled_tmp)
		ddnsEnabled_ON = "checked";
	else
		ddnsEnabled_OFF = "checked";
	document.write("<input type=\"radio\" name=\"ddnsEnabled\" value=\"ON\" " + ddnsEnabled_ON + " ONCLICK=updateState()><#checkbox_Yes#>\n");
	document.write("<input type=\"radio\" name=\"ddnsEnabled\" value=\"OFF\" " + ddnsEnabled_OFF + " ONCLICK=updateState()><#checkbox_No#>\n");
</script>
  </td>
</tr>

<tr>
  <!--<th>Service Provider:</th>-->
  <th><#LANHostConfig_x_DDNSServer_itemname#></th>
  <td>
	<select name="ddnsType">
<script>
	var ddnsType_tmp = <% getIndex("ddnsType"); %>;
	var ddnsType_DynDNS = "";
	var ddnsType_TZO = "";
	var ddnsType_zoneedit = "";
	var ddnsType_asus_ddns = "";
	switch(ddnsType_tmp){
		case 0:
			ddnsType_DynDNS = "selected";
			break;
		case 1:
			ddnsType_TZO = "selected";
			break;
		case 2:
			ddnsType_zoneedit = "selected";
			break;
	}
	document.write("<option value=0 " + ddnsType_DynDNS + ">WWW.DYNDNS.ORG</option>\n");
	document.write("<option value=1 " + ddnsType_TZO + ">WWW.TZO.COM</option>\n");
	document.write("<option value=2 " + ddnsType_zoneedit + ">WWW.ZONEEDIT.COM</option>\n");
</script>
	</select>
  </td>
</tr>

<tr>
  <th><#DDNS_Domain_Name#></th>
  <td>
 	<input type="text" name="ddnsDomainName" class="input" size="20" maxlength="50" value=<% getInfo("ddnsDomainName"); %>>
  </td>
</tr>

<tr>
  <!--<th>User Name/Email:</th>-->
  <th><#LANHostConfig_x_DDNSUserName_itemname#></th>
  <td>
	<input type="text" name="ddnsUser" class="input" size="20" maxlength="50" value="<% getInfo("ddnsUser"); %>">
  </td>
</tr>
	
<tr>
  <!--<th>Password/Key:</th>-->
  <th><#LANHostConfig_x_DDNSPassword_itemname#></th>
  <td>
	<input type="password" name="ddnsPassword" class="input" size="20" maxlength="30" value="<% getInfo("ddnsPassword"); %>">
  </td>
</tr>

<tr>
  <td colspan="2" align="right">
  	<input type="submit" value="<#CTL_apply#>" class="button" name="apply" onClick="return ddns_saveChanges()">
  </td>
</tr>
</table>
  
<script>
	updateState();
</script>

</form>

</td></tr>
</table>
</td>
</form>

	<td id="help_td" style="width:15px;" valign="top">
		  
	  <div id="helpicon" onClick="openHint(0,0);" title="<#Help_button_default_hint#>"><img src="images/help.gif" /></div>
	  <div id="hintofPM" style="display:none;">
<form name="hint_form"></form>
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
	  </div><!--End of hintofPM-->
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
