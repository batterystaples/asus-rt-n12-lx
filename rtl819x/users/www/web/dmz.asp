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
<title>ASUS Wireless Router <#Web_Title#> - <#menu5_3_5#></title>
<link rel="stylesheet" type="text/css" href="index_style.css"> 
<link rel="stylesheet" type="text/css" href="form_style.css">
<script language="JavaScript" type="text/javascript" src="/state.js"></script>
<script language="JavaScript" type="text/javascript" src="/general.js"></script>
<script language="JavaScript" type="text/javascript" src="/popup.js"></script>
<script type="text/javascript" language="JavaScript" src="/help.js"></script>
<script type="text/javascript" language="JavaScript" src="/detect.js"></script>
<script type="text/javascript" src="util_gw.js"> </script>
<script>
function initial()
{
	show_banner(1); 
	show_menu(5,3,4);
	show_footer();
}

function updateState()
{
	if (document.form.enabled[0].checked)
	 	enableTextField(document.form.ip);
	else {
		document.form.ip.value = "";
 		disableTextField(document.form.ip);
	}
}

function applyRule(){
	if(validForm()){
		showLoading();
		document.form.submit();
	}
}

function validForm(){
	if(!validate_ipaddr(document.form.ip, 'ip'))
		return false;
	return true;
}
</script>
</head>

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
		
<table width="530" border="0" align="center" cellpadding="5" cellspacing="0" class="FormTitle" table>
	<thead>
	<tr>
		<td><#t1NAT#> - <#menu5_3_5#></td>
	</tr>
	</thead>
	<tbody>
	<tr>
	  <td bgcolor="#FFFFFF"><#IPConnection_ExposedIP_sectiondesc#></td>
	  </tr>
	<tr>
		<td bgcolor="#FFFFFF"><table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3"  class="FormTable">

<form action="/start_apply.htm" method=POST name="form" target="hidden_frame">
<input type="hidden" name="current_page" value="dmz.asp">
<input type="hidden" value="formDMZ" name="typeForm">
<input type="hidden" value="save" name="save">
<input type="hidden" value="/dmz.asp" name="submit-url">
<input type="hidden" name="action_mode" value="Restart_Rirewall">	<!--2011.03.28 Jerry-->
<input type="hidden" name="flag" value="nodetect">	<!--2011.03.28 Jerry-->
<input type="hidden" name="preferred_lang" id="preferred_lang" value="<% getInfo("preferred_lang"); %>">	<!--2011.04.14 Jerry-->

<tr>
  <th width="40%"><#DMZ_Enable#></th>
  <td>
<script>
	var dmzEnabled_tmp = <% getIndex("dmzEnabled"); %>;
	var dmzEnabled_ON = "";
	var dmzEnabled_OFF = "";
	if(dmzEnabled_tmp)
		dmzEnabled_ON = "checked";
	else
		dmzEnabled_OFF = "checked";
	document.write("<input type=\"radio\" value=\"ON\" name=\"enabled\" " + dmzEnabled_ON + " onclick=\"updateState()\"><#checkbox_Yes#>");
	document.write("<input type=\"radio\" value=\"OFF\" name=\"enabled\" " + dmzEnabled_OFF + " onclick=\"updateState()\"><#checkbox_No#>");			
</script>
  </td>
</tr>

<tr>
  <!--<th>DMZ Host IP Address:</th>-->
  <th width="40%"><#IPConnection_ExposedIP_itemname#></th>
  <td>
	<input type="text" name="ip" class="input" size="15" maxlength="15" value=<% getInfo("dmzHost"); %> >
  </td>
</tr>

<tr>
  <td colspan="2" align="right">
	<input type="button" value="<#CTL_apply#>" class="button" name="apply" onClick="applyRule()">
  </td>
</tr>
     <script> updateState(); </script>
</form>
</table>


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
