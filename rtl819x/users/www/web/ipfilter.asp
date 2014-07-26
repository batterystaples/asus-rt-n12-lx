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
<title>ASUS Wireless Router <#Web_Title#> - <#menu5_3_3#></title>
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
	show_menu(5,4,5);
	show_footer();
}
function addClick()
{
	if (!document.formFilterAdd.enabled[0].checked)
	{
		showLoading();	//2011.03.28 Jerry
		return true;
	}

	if (document.formFilterAdd.ip.value=="" && document.formFilterAdd.comment.value=="" )
		return true;

	if ( checkIpAddr(document.formFilterAdd.ip, 'Invalid IP address') == false )
		return false;
/*Edison 2011.4.20*/
	var entryNum = <% getIndex("ipFilterNum"); %>;
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


function disableDelButton()
{
	disableButton(document.formFilterDel.deleteSelFilterIp);
}

function updateState()
{
  if (document.formFilterAdd.enabled[0].checked) {
 	enableTextField(document.formFilterAdd.ip);
	enableTextField(document.formFilterAdd.protocol);
  }
  else {
 	disableTextField(document.formFilterAdd.ip);
  	disableTextField(document.formFilterAdd.protocol);
  }
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
		
<table width="500" border="0" align="center" cellpadding="5" cellspacing="0" class="FormTitle" table>
	<thead>
	<tr>
		<td><#menu5_5#> - <#IPFILTER_menu#></td>
	</tr>
	</thead>
	<tbody>
	<tr>
		<td bgcolor="#FFFFFF"><#IPFILTER_sectiondesc#></td>
	</tr>
	</tbody>	
	<tr>
	  <td bgcolor="#FFFFFF">
	  <table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3"  class="FormTable">

<form action="/start_apply.htm" method=POST name="formFilterAdd" target="hidden_frame">
<input type="hidden" name="current_page" value="ipfilter.asp">
<input type="hidden" value="formFilter" name="typeForm">
<input type="hidden" value="/ipfilter.asp" name="submit-url">
<input type="hidden" name="action_mode" value="Restart_Rirewall">	<!--2011.03.28 Jerry-->
<input type="hidden" name="flag" value="nodetect">	<!--2011.03.28 Jerry-->
<input type="hidden" name="preferred_lang" id="preferred_lang" value="<% getInfo("preferred_lang"); %>">	<!--2011.04.14 Jerry-->

<tr>
  <th width="40%"><#IPFILTER_Enable#></th>
  <td>
<script>
	var ipFilterEnabled_tmp = <% getIndex("ipFilterEnabled"); %>;
	var ipFilterEnabled_ON = "";
	var ipFilterEnabled_OFF = "";
	if(ipFilterEnabled_tmp)
		ipFilterEnabled_ON = "checked";
	else
		ipFilterEnabled_OFF = "checked";
	document.write("<input type=\"radio\" name=\"enabled\" value=\"ON\" " + ipFilterEnabled_ON + " ONCLICK=updateState()><#checkbox_Yes#>\n");
	document.write("<input type=\"radio\" name=\"enabled\" value=\"OFF\" " + ipFilterEnabled_OFF + " ONCLICK=updateState()><#checkbox_No#>\n");	
</script>
  </td>
</tr>

<tr>
    <th><#IPConnection_VServerIP_itemname1#></th>
    <td>
	<input type="text" value="<% getInfo("ipfilter_lanip"); %>" name="ip" class="input" size="10" maxlength="15">
    </td>
</tr>

<tr>
    <th><#IPConnection_VServerProto_itemname1#></th>
    <td>
	<select name="protocol">
    		<option select value="0" class="input">Both</option>
    		<option value="1">TCP</option>
    		<option value="2">UDP</option>
    		</select>
    </td>
</tr>

<tr>
    <td colspan="2" align="right">
    	<input type="submit" value="<#CTL_apply#>" class="button" name="addFilterIp" onClick="return addClick()">&nbsp;&nbsp;
    </td>
</tr>
  <script> updateState(); </script>
</form>
</table>
</td></tr>

<tr>
	  <td bgcolor="#FFFFFF">
	  <table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3"  class="FormTable">
<form action="/start_apply.htm" method=POST name="formFilterDel" target="hidden_frame">
<input type="hidden" name="current_page" value="ipfilter.asp">
<input type="hidden" value="formFilter" name="typeForm">
<input type="hidden" value="/ipfilter.asp" name="submit-url">
<input type="hidden" name="action_mode" value="Restart_Rirewall">	<!--2011.03.28 Jerry-->
<input type="hidden" name="flag" value="nodetect">	<!--2011.03.28 Jerry-->
<input type="hidden" name="preferred_lang" id="preferred_lang" value="<% getInfo("preferred_lang"); %>">	<!--2011.04.14 Jerry-->

<thead>
<tr>
  <td colspan="3"><#FirewallConfig_LWFilterList_groupitemdesc#></td>
</tr>
</thead>
<tr>
	<td align=center width=\"25%%\" bgcolor=\"#808080\"><#LANHostConfig_x_Select_itemname#></td>
      	<td align=center width=\"40%%\" bgcolor=\"#808080\"><#IPConnection_VServerIP_itemname#></td>
      	<td align=center width=\"35%%\" bgcolor=\"#808080\"><#FirewallConfig_LanWanProFlag_itemname#></td>
</tr>
  <% ipFilterList(); %>

<tr>
  <td colspan="3" align="right">
	<input type="submit" value="<#CTL_del#>" name="deleteSelFilterIp" class="button" onClick="return deleteClick()">
  </td>
</tr>

</table>
 <script>
	var entryNum = <% getIndex("ipFilterNum"); %>;
	if ( entryNum == 0 )
		disableDelButton();
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
<!--</blockquote>-->
<div id="footer"></div>
</body>
</html>
