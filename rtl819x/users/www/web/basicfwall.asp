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
<title>ASUS Wireless Router <#Web_Title#> - <#menu5_5_1#></title>
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
	show_menu(5,4,1);	
	show_footer();
	enable_auto_hint(8, 6);
}

function applyRule(){
	if(validForm()){
		showLoading();
		document.form.submit();
	}
}

function validForm(){
	if(!validate_range(document.form.webWanAccessPort, 1024, 65535))
		return false;
	
	return true;
}

function updatefwallState()
{
	if(document.form.firewallEnabled[0].checked){
		document.getElementById('wanwebenable').style.display = "";
		document.getElementById('webwanport').style.display = "";
		document.getElementById('ping').style.display = "";
	}else{
		document.getElementById('wanwebenable').style.display = "none";
		document.getElementById('webwanport').style.display = "none";
		document.getElementById('ping').style.display = "none";
	}
}
</script>
</head>

<body onload="initial();" onunLoad="disable_auto_hint(8, 6);return unload_body();">
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
		
<table width="500" border="0" align="center" cellpadding="5" cellspacing="0" class="FormTitle">
	<thead>
	<tr>
		<td><#menu5_5#> - <#menu5_5_1#></td>
	</tr>
	</thead>
	<tbody>
	<tr>
	  <td bgcolor="#FFFFFF"><#FirewallConfig_display2_sectiondesc#></td>
	  </tr>
	</tbody>
	<tr>
	  <td bgcolor="#FFFFFF">		
		<table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable">



<form action="/start_apply.htm" method=POST name="form" target="hidden_frame">
<input type="hidden" name="current_page" value="basicfwall.asp">
<input type="hidden" value="formBasicFwallSetup" name="typeForm">
<input type="hidden" value="/basicfwall.asp" name="submit-url">
<input type="hidden" name="action_mode" value="Restart_Rirewall">	<!--2011.03.28 Jerry-->
<input type="hidden" name="flag" value="nodetect">	<!--2011.03.28 Jerry-->
<input type="hidden" name="preferred_lang" id="preferred_lang" value="<% getInfo("preferred_lang"); %>">	<!--2011.04.14 Jerry-->
<tr>
  <th align="right"><a class="hintstyle" href="javascript:void(0);" onClick="openHint(8,6);"><#FirewallConfig_FirewallEnable_itemname#></a></th>
  <td>
<script>
	var firewallEnabled_tmp = <% getIndex("firewallEnabled"); %>;
	var firewallEnabled_ON = "";
	var firewallEnabled_OFF = "";
	if(firewallEnabled_tmp)
		firewallEnabled_ON = "checked";
	else
		firewallEnabled_OFF = "checked";
	document.write("<input type=\"radio\" name=\"firewallEnabled\" value=\"ON\" " + firewallEnabled_ON + " ONCLICK=updatefwallState()><#checkbox_Yes#>");
	document.write("<input type=\"radio\" name=\"firewallEnabled\" value=\"OFF\" " + firewallEnabled_OFF + " ONCLICK=updatefwallState()><#checkbox_No#>");
</script>
  </td>
</tr>
<tr>
  <th align="right"><a class="hintstyle" href="javascript:void(0);" onClick="openHint(8,7);"><#FirewallConfig_DoSEnable_itemname#></a></th>
  <td>
<script>
	var dosEnabled_tmp = <% getIndex("dosEnabled"); %>;
	var dosEnabled_ON = "";
	var dosEnabled_OFF = "";
	if(dosEnabled_tmp)
		dosEnabled_ON = "checked";
	else
		dosEnabled_OFF = "checked";
	document.write("<input type=\"radio\" name=\"dosEnabled\" value=\"ON\" " + dosEnabled_ON + "><#checkbox_Yes#>");
	document.write("<input type=\"radio\" name=\"dosEnabled\" value=\"OFF\" " + dosEnabled_OFF + "><#checkbox_No#>");	
</script>
  </td>
</tr>


<tr id="wanwebenable">
  <th align="right"><a class="hintstyle" href="javascript:void(0);" onClick="openHint(8,2);"><#FirewallConfig_x_WanWebEnable_itemname#></a></th>
  <td>
<script>
	var webWanAccess_tmp = <% getIndex("webWanAccess"); %>;
	var webWanAccess_ON = "";
	var webWanAccess_OFF = "";
	if(webWanAccess_tmp)
		webWanAccess_ON = "checked";
	else
		webWanAccess_OFF = "checked";
	document.write("<input type=\"radio\" name=\"webWanAccess\" value=\"ON\" " + webWanAccess_ON + "><#checkbox_Yes#>");
	document.write("<input type=\"radio\" name=\"webWanAccess\" value=\"OFF\" " + webWanAccess_OFF + "><#checkbox_No#>");
</script>
  </td>
</tr>

<tr id="webwanport">
  <th><a class="hintstyle" href="javascript:void(0);" onClick="openHint(8,3);"><#FirewallConfig_x_WanWebPort_itemname#></a></th>
  <td>
	<input type="text" name="webWanAccessPort" class="input" size="10" maxlength="10" value=<% getInfo("webWanAccessPort"); %>>
  </td>
</tr>

<tr id="ping">
  <th align="right"><a class="hintstyle" href="javascript:void(0);" onClick="openHint(8,5);"><#FirewallConfig_x_WanPingEnable_itemname#></a></th>
  <td>
<script>
	var pingWanAccess_tmp = <% getIndex("pingWanAccess"); %>;
	var pingWanAccess_ON = "";
	var pingWanAccess_OFF = "";
	if(pingWanAccess_tmp)
		pingWanAccess_ON = "checked";
	else
		pingWanAccess_OFF = "checked";
	document.write("<input type=\"radio\" name=\"pingWanAccess\" value=\"ON\" " + pingWanAccess_ON + "><#checkbox_Yes#>");
	document.write("<input type=\"radio\" name=\"pingWanAccess\" value=\"OFF\" " + pingWanAccess_OFF + "><#checkbox_No#>");
</script>
  </td>
</tr>

<tr>
  <td colspan="2" align="right">
	<input name="button" type="button" class="button" onclick="applyRule();" value="<#CTL_apply#>"/>
  </td>
</tr>    

</table>
</td></tr>

</table>
</td>
</form>

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

