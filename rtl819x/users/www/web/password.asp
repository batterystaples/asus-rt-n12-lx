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
<SCRIPT>
function initial(){
	show_banner(1);
	show_menu(5,5,2);	
	show_footer();
}
function includeSpace(str)
{
  for (var i=0; i<str.length; i++) {
  	if ( str.charAt(i) == ' ' ) {
	  return true;
	}
  }
  return false;
}

function saveChanges()
{
   if ( document.form.username.value.length == 0 ) {
	if ( !confirm('User account is empty.\nDo you want to disable the password protection?') ) {
		document.form.username.focus();
		return false;
  	}
	else
		return true;
  }

   if ( document.form.newpass.value != document.form.confpass.value) {
	alert('Password is not matched. Please type the same password between \'new\' and \'confirmed\' box.');
	document.form.newpass.focus();
	return false;
  }

  if ( document.form.username.value.length > 0 &&
  		document.form.newpass.value.length == 0 ) {
	alert('Password cannot be empty. Please try it again.');
	document.form.newpass.focus();
	return false;
  }

  if ( includeSpace(document.form.username.value)) {
	alert('Cannot accept space character in user name. Please try it again.');
	document.form.username.focus();
	return false;
  }

  if ( includeSpace(document.form.newpass.value)) {
	alert('Cannot accept space character in password. Please try it again.');
	document.form.newpass.focus();
	return false;
  }

  return true;
}

function checkEmpty(field){
	if(field.value.length == 0){
		alert(field.name + " field can't be empty\n");
		field.value = field.defaultValue;
		field.focus();
		return false;
	}
	else
		return true;
}
function checkNumber(field){
    str =field.value ;
    for (var i=0; i<str.length; i++) {
    	if ( (str.charAt(i) >= '0' && str.charAt(i) <= '9'))
                        continue;
	field.value = field.defaultValue;
        alert("Invalid " +field.name + " Number. It should be in  number (0-9).");
        return false;
    }	
	return true;
}
function saveChanges(form){
	var Month_num;
	var Day_num;
	var Hour_num;
	var Min_num;
	var Sec_num;
	if((checkEmpty(form.year)& checkEmpty(form.month) & checkEmpty(form.hour)
	 & checkEmpty(form.day) &checkEmpty(form.minute) & checkEmpty(form.second))== false)
	 	return false;

	if((checkNumber(form.year)& checkNumber(form.month) & checkNumber(form.hour)
	 & checkNumber(form.day) &checkNumber(form.minute) & checkNumber(form.second))== false)
	 	return false;
	if(form.month.value == '0'){
		form.month.value = form.month.defaultValue;
        	alert("Invalid month Number. It should be in  number (1-9).");
		return false;
	}
	Month_num =parseInt(form.month.value, 10);
	Day_num =parseInt(form.day.value, 10);
	Hour_num =parseInt(form.hour.value, 10);
	Min_num =parseInt(form.minute.value, 10);
	Sec_num =parseInt(form.second.value, 10);
	if((Month_num<=0) || (Month_num > 12) || (Day_num <= 0) || (Day_num > 31) || (Hour_num < 0)  || (Hour_num > 23) || (Min_num < 0) || (Min_num > 59) || (Sec_num < 0) || (Sec_num > 59)){
			alert("Invalid Time value!");
		return false;
	}
	if (form.enabled.checked) {
		if(form.ntpServerId[1].checked == true){ 
			if(form.ntpServerIp2.value != ""){
				if ( checkIpAddr(form.ntpServerIp2, 'Invalid IP address') == false )
			    	return false;
			}
			else{
				//form.ntpServerIp2.value = "0.0.0.0" ;	
				alert("Invalid NTP Server IP address! It can not be empty.");
				return false; 
			}
		}
	}	
	return true;
}

</SCRIPT>
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
		<td bgcolor="#FFFFFF"><!--This page is used to set the account to access the web server of Access Point.
 Empty user name and password will disable the protection.--></td>
	</tr>
	</tbody>

<form action="form.cgi" method=POST name="form">
<input type="hidden" value="formSystemSetup" name="typeForm">
<input type="hidden" value="/password.asp" name="submit-url">

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
	<input type="password" name="newpass" class="input" size="20" maxlength="30">
  </td>
</tr>

<tr>
  <!--<th>Confirmed Password:</th>-->
  <th valign="top"><a class="hintstyle" href="javascript:void(0);" onClick="openHint(11,4)"><#PASS_retype#></th>
  <td>
	<input type="password" name="confpass" class="input" size="20" maxlength="30">
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
  <!--<th width="40%">Time Zone Select:</th>-->
  <th width="40%"><a class="hintstyle"  href="javascript:void(0);" onClick="openHint(11,2)"><#LANHostConfig_x_TimeZone_itemname#></a></th>
  <td>
	<select name="timeZone" class="input">
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
	<input type="text" name="ntpServerIp2" class="input" size="15" maxlength="15" value=<% getInfo("ntpServerIp2"); %>>
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


