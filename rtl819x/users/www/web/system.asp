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
<title>ASUS Wireless Router <#Web_Title#> - <#menu5_6_2#></title>
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
	show_menu(5,5,2);	
	show_footer();
}

function applyRule(){
	if(validForm()){
		showLoading();
		 var selectmenu = document.getElementById("timeZone");
		 var AllTZ=selectmenu.options[selectmenu.selectedIndex].text;
		document.form.NTP_SYSTIMEZONE.value=AllTZ.substr(1,9);
		document.form.submit();
	}
}

function validForm(){
	if(!validate_string(document.form.newpass) || !validate_string(document.form.confpass))
		return false;
	
	if(document.form.newpass.value != document.form.confpass.value){
		showtext($("alert_msg"),"*<#File_Pop_content_alert_desc7#>");
		
		document.form.newpass.focus();
		document.form.newpass.select();
		
		return false;
	}
	
	if(document.form.newpass.value.length > 0)
		alert("<#File_Pop_content_alert_desc10#>");
	
	return true;
}

</script>
</head>

<body onload="initial();" onunLoad="disable_auto_hint(11, 3);return unload_body();">
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
		<td><#menu5_6#> - <#menu5_6_2#></td>
	</tr>
	</thead>
	<tbody>
	<tr>
		<td bgcolor="#FFFFFF"></td>
	</tr>
	</tbody>

<form action="/start_apply.htm" method=POST name="form" target="hidden_frame">
<input type="hidden" name="current_page" value="system.asp">
<input type="hidden" value="formSystemSetup" name="typeForm">
<input type="hidden" value="/system.asp" name="submit-url">
<input type="hidden" name="action_mode" value="Restart_MISC">
<input type="hidden" name="flag" value="nodetect">
<input type="hidden" name="preferred_lang" id="preferred_lang" value="<% getInfo("preferred_lang"); %>">	<!--2011.04.14 Jerry-->
<input type="hidden" name="NTP_SYSTIMEZONE" id="NTP_SYSTIMEZONE"> <!--2011.05.05 Emily-->

<!--Change System's password-->
	<tr>
	  <td bgcolor="#FFFFFF">
	  <table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3"  class="FormTable">
<thead>
  <tr>
  <td colspan="2"><#PASS_changepasswd#></td>
  </tr>
</thead>

<tr>
  <!--<th>New Password:</th>-->
  <th width="40%"><a class="hintstyle" href="javascript:void(0);" onClick="openHint(11,4)"><#PASS_new#></th>
  <td>
	<input type="password" name="newpass" class="input" size="20" maxlength="16">
  </td>
</tr>

<tr>
  <!--<th>Confirmed Password:</th>-->
  <th valign="top"><a class="hintstyle" href="javascript:void(0);" onClick="openHint(11,4)"><#PASS_retype#></th>
  <td>
	<input type="password" name="confpass" class="input" size="20" maxlength="16"><br/><span id="alert_msg"></span>
  </td>
</tr>

</table>
</td></tr>

<!--Miscellaneous-->
<tr>
	  <td bgcolor="#FFFFFF">
      <table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3"  class="FormTable">
      	<thead>
	  	<tr>
          <td colspan="2"><#t2Misc#></td>
        </tr>
    	</thead>

<tr>
  <!--<th>Log Server IP Address:</th>-->
  <th width="40%"><a class="hintstyle"  href="javascript:void(0);" onClick="openHint(11,1)"><#LANHostConfig_x_ServerLogEnable_itemname#></a></th>
  <td>
	<input type="text" name="logServer" class="input" value="<% getInfo("rtLogServer"); %>" size="13" maxlength="16">
  </td>
</tr>

<tr>
  <!--<th width="40%">Time Zone Select:</th>-->
  <th width="40%"><a class="hintstyle"  href="javascript:void(0);" onClick="openHint(11,2)"><#LANHostConfig_x_TimeZone_itemname#></a></th>
  <td>
	<select name="timeZone" id="timeZone" class="input">
<script>
      	var i;
       	for(i=0;i<ntp_zone_array.length;i++){
		if (i == ntp_zone_index)
			document.write('<option value="',ntp_zone_array[i].value,'" selected>',ntp_zone_array[i].name,'</option>');
		else
			document.write('<option value="',ntp_zone_array[i].value,'">',ntp_zone_array[i].name,'</option>');
	}
</script>
	</select>
  </td>
</tr>

<tr>
  <!--<th>NTP server:</th>-->
  <th><a class="hintstyle"  href="javascript:void(0);" onClick="openHint(11,3)"><#LANHostConfig_x_NTPServer1_itemname#></a></th>
  <td>
	<input type="text" name="ntpServerIp" class="input" size="20" maxlength="50" value=<% getInfo("ntpServerIp2"); %>>
  </td>
</tr>

<tr>
  <td colspan="2" align="right">
	<input type="button" value="<#CTL_apply#>" name="save" class="button" onclick="applyRule();">
  </td>
</tr>

<script>
		setTimeZone(document.form.timeZone, "<% getInfo("ntpTimeZone"); %>");
</script>

</table>

</td></tr>
</table></td>
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


