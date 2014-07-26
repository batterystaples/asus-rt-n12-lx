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
<title>ASUS Wireless Router <#Web_Title#> - <#menu5_1_5#></title>
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
function initial(){
	show_banner(1);
	show_menu(5,1,3);
	show_footer();
}

function applyRule(){
	if(validForm()){
		showLoading();		
		document.form.submit();
	}
}

function validForm(){
	if(!validate_ipaddr(document.form.radiusIP<% getIndex("wlan_idx"); %>, 'wl_radius_ipaddr'))
		return false;
	
	if(!validate_range(document.form.radiusPort<% getIndex("wlan_idx"); %>, 0, 65535))
		return false;
	
	if(!validate_string(document.form.radiusPass<% getIndex("wlan_idx"); %>))
		return false;
	
	return true;
}
</script>
</head>

<body onload="initial();" onunLoad="disable_auto_hint(13, 0);return unload_body();">
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
		
<table width="98%" border="0" align="center" cellpadding="5" cellspacing="0" class="FormTitle" table>
	<thead>
	<tr>
		<td><#menu5_1#> - <#t2RADIUS#></td>
	</tr>
	</thead>
	<tbody>
	<tr>
		<td bgcolor="#FFFFFF"><#WLANAuthentication11a_display1_sectiondesc#></td>
	</tr>
	</tbody>	
	<tr>
	  <td bgcolor="#FFFFFF">
		<table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3"  class="FormTable">

<form action="form.cgi" method=POST name="form" target="hidden_frame">

<tr>
  <!--<th width="30%">RADIUS&nbsp;Server&nbsp;IP&nbsp;Address:</th>-->
  <th><a class="hintstyle" href="javascript:void(0);"  onClick="openHint(2,1);"><#WLANAuthentication11a_ExAuthDBIPAddr_itemname#></a></th>
  <td>
	<input id="radius_ip" name="radiusIP<% getIndex("wlan_idx"); %>" class="input" size="16" maxlength="15" value="">
  </td>
</tr>

<tr>
  <!--<th width="30%">RADIUS&nbsp;Server&nbsp;Port:</th>-->
  <th><a class="hintstyle" href="javascript:void(0);" onClick="openHint(2,2);"><#WLANAuthentication11a_ExAuthDBPortNumber_itemname#></a></th>
  <td>
	<input type="text" id="radius_port" name="radiusPort<% getIndex("wlan_idx"); %>" class="input" size="5" maxlength="5" value="1812">
  </td>
</tr>

<tr>
  <!--<th width="30%">RADIUS&nbsp;Server&nbsp;Password:</th>-->
  <th><a class="hintstyle" href="javascript:void(0);" onClick="openHint(2,3);"><#WLANAuthentication11a_ExAuthDBPassword_itemname#></a></th>
  <td>
	<input type="password" id="radius_pass" name="radiusPass<% getIndex("wlan_idx"); %>" size="32" maxlength="64" value="">
  </td>
</tr>

<tr align="right">
  <td colspan="2">
	<input type="hidden" value="/wlsecurity.asp" name="submit-url">
	<input type="button" value="<#CTL_apply#>" name="save" class="button" onClick="applyRule();">
  </td>
</tr>
</table>

</form>

</td></tr>
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
