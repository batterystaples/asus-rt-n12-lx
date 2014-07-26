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
	show_menu(5,4,2);
	show_footer();
}

function addClick()
{
	if (!document.formFilterAdd.enabled[0].checked)
	{
		showLoading();	//2011.03.28 Jerry
		return true;
	}
	var str = document.formFilterAdd.url.value;
	for (var i=0; i<str.length; i++) {
     		if ( str.charAt(i) == ';')
     		{
     			//alert("Error character: \";\"");
			alert("<#URLFILTER_Error#>");
			return false;
     		}
	}
			
	if (document.formFilterAdd.url.value=="")
	{
		showLoading();	//2011.03.28 Jerry
		return true;
	}
/*Edison 2011.4.20*/
	var entryNum = <% getIndex("urlFilterNum"); %>;
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
	disableButton(document.formFilterDel.deleteSelFilterUrl);
}

function updateState()
{
  if (document.formFilterAdd.enabled[0].checked)
 	enableTextField(document.formFilterAdd.url);  
  else
 	disableTextField(document.formFilterAdd.url); 
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
		
<table width="500" border="0" align="center" cellpadding="5" cellspacing="0" class="FormTitle" table>
	<thead>
	<tr>
		<td><#menu5_5#> - <#menu5_5_2#></td>
	</tr>
	</thead>
	<tbody>
	<tr>
		<td bgcolor="#FFFFFF"><#FirewallConfig_UrlFilterEnable_sectiondesc#></td>
	</tr>
	</tbody>

	<tr>
	  <td bgcolor="#FFFFFF"><table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3"  class="FormTable">

<!--form action="form.cgi" method=POST name="formFilterAdd"-->
<form action="/start_apply.htm" method=POST name="formFilterAdd" target="hidden_frame">
<input type="hidden" name="current_page" value="urlfilter.asp">
<input type="hidden" value="formFilter" name="typeForm">
<input type="hidden" value="/urlfilter.asp" name="submit-url">
<input type="hidden" name="action_mode" value="Restart_Rirewall">	<!--2011.03.28 Jerry-->
<input type="hidden" name="flag" value="nodetect">	<!--2011.03.28 Jerry-->
<input type="hidden" name="preferred_lang" id="preferred_lang" value="<% getInfo("preferred_lang"); %>">	<!--2011.04.14 Jerry-->

<tr>
  <th width="40%"><#FirewallConfig_UrlFilterEnable_itemname1#></th>
  <td>
<script>
	var urlFilterEnabled_tmp = <% getIndex("urlFilterEnabled"); %>;
	var urlFilterEnabled_ON = "";
	var urlFilterEnabled_OFF = "";
	if(urlFilterEnabled_tmp)
		urlFilterEnabled_ON = "checked";
	else
		urlFilterEnabled_OFF = "checked";
	document.write("<input type=\"radio\" name=\"enabled\" value=\"ON\" " + urlFilterEnabled_ON + " ONCLICK=updateState()><#checkbox_Yes#>\n");
	document.write("<input type=\"radio\" name=\"enabled\" value=\"OFF\" " + urlFilterEnabled_OFF + " ONCLICK=updateState()><#checkbox_No#>\n");	
</script>
  </td>
</tr>

<tr>
     <th><#FirewallConfig_UrlList_groupitemdesc1#>
     <td><input type="text" name="url" size="30" maxlength="30"></td>
</tr>

<tr>
     <td colspan="2" align="right">
     <input type="submit" value="<#CTL_apply#>" class="button" name="addFilterUrl" onClick="return addClick()">
     </td>
</tr>
  <script> updateState(); </script>
</form>
</table>
</td></tr>

<form action="/start_apply.htm" method=POST name="formFilterDel" target="hidden_frame">
<input type="hidden" name="current_page" value="urlfilter.asp">
<input type="hidden" value="formFilter" name="typeForm">
<input type="hidden" value="/urlfilter.asp" name="submit-url">
<input type="hidden" name="action_mode" value="Restart_Rirewall">	<!--2011.03.28 Jerry-->
<input type="hidden" name="flag" value="nodetect">	<!--2011.03.28 Jerry-->
<input type="hidden" name="preferred_lang" id="preferred_lang" value="<% getInfo("preferred_lang"); %>">	<!--2011.04.14 Jerry-->

<tr><td bgcolor="#FFFFFF">
  <table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable">
<thead>
<tr>
  <td colspan="2"><#URLFILTER_Table#></td>
</tr>
</thead>
<tr>
	<td align=center width=\"30%%\" bgcolor=\"#808080\"><#LANHostConfig_x_Select_itemname#></td>
      	<td align=center width=\"70%%\" bgcolor=\"#808080\"><#FirewallConfig_UrlList_groupitemdesc#></td>
</tr>
  <% urlFilterList(); %>                                                                                  

<tr>
  <td colspan="2" align="right">
	<input type="submit" value="<#CTL_del#>" name="deleteSelFilterUrl" class="button" onClick="return deleteClick()">
  </td>
</tr>
  </table>

 <script>
	var entryNum = <% getIndex("urlFilterNum"); %>;
   	if ( entryNum == 0 )
      	  	disableDelButton();
 </script>
</td></tr>
</form>


<!--</td></tr>-->
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
