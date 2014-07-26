<html>
<! Copyright (c) Realtek Semiconductor Corp., 2003. All Rights Reserved. ->
<head>
<meta http-equiv="X-UA-Compatible" content="IE=EmulateIE7"/>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta HTTP-EQUIV="Pragma" CONTENT="no-cache">
<meta HTTP-EQUIV="Expires" CONTENT="-1">
<link rel="shortcut icon" href="images/favicon.png">
<link rel="icon" href="images/favicon.png">

<title>ASUS Wireless Router <#Web_Title#> - <#menu5_1_4#></title>
<link rel="stylesheet" type="text/css" href="index_style.css"> 
<link rel="stylesheet" type="text/css" href="form_style.css">
<script language="JavaScript" type="text/javascript" src="/state.js"></script>
<script language="JavaScript" type="text/javascript" src="/help.js"></script>
<script language="JavaScript" type="text/javascript" src="/general.js"></script>
<script language="JavaScript" type="text/javascript" src="/popup.js"></script>
<script language="JavaScript" type="text/javascript" src="/detect.js"></script>
<script type="text/javascript" src="util_gw.js"> </script>
<script>
function initial(){
	show_banner(1);
	show_menu(5,1,4);
	
	show_footer();	
}
function addClick()
{
  var str = document.formWlAcAdd.mac.value;

  if (document.formWlAcAdd.wlanAcEnabled.selectedIndex == 0)
	return true;

  if ( str.length == 0)
  	return true;

  if ( str.length < 12) {
	alert("Input MAC address is not complete. It should be 12 digits in hex.");
	document.formWlAcAdd.mac.focus();
	return false;
  }

  for (var i=0; i<str.length; i++) {
    if ( (str.charAt(i) >= '0' && str.charAt(i) <= '9') ||
			(str.charAt(i) >= 'a' && str.charAt(i) <= 'f') ||
			(str.charAt(i) >= 'A' && str.charAt(i) <= 'F') )
			continue;

	alert("Invalid MAC address. It should be in hex number (0-9 or a-f).");
	document.formWlAcAdd.mac.focus();
	return false;
  }
  return true;
}


function deleteClick()
{
  acl_num = <% getIndex("wlanAcNum"); %> ;
  delNum = 0 ;
  for(i=1 ; i <= acl_num ; i++){
  	if(document.formWlAcDel.elements["select"+i].checked)
  		delNum ++ ;
  }
  if(document.formWlAcAdd.wlanAcEnabled.selectedIndex==1 && delNum==acl_num){
		if ( !confirm('Delete the all entries will cause all client cannot connect to AP.  Sure?') )
			return false;
   }
  else if ( !confirm('Do you really want to delete the selected entry?') ) {
	return false;
  }
  else
	return true;
}

function deleteAllClick()
{
   if(document.formWlAcAdd.wlanAcEnabled.selectedIndex==1){
		if ( !confirm('Delete the all entries will cause all client cannot connect to AP.  Sure?') )
			return false;
   }else if ( !confirm('Do you really want to delete the all entries?') ) {
	return false;
  }
  else
	return true;
}
function disableDelButton()
{
	disableButton(document.formWlAcDel.deleteSelFilterMac);
	disableButton(document.formWlAcDel.deleteAllFilterMac);
}

function enableAc()
{
  enableTextField(document.formWlAcAdd.mac);
  enableTextField(document.formWlAcAdd.comment);
}

function disableAc()
{
  disableTextField(document.formWlAcAdd.mac);
  disableTextField(document.formWlAcAdd.comment);
}

function updateState(filed)
{
  wlanDisabled = <% getIndex("wlanDisabled"); %> ;
  wlanMode = <% getIndex("wlanMode"); %>;
  var wlanState="<%getScheduleInfo("wlan_state");%>";
  if(wlanDisabled || wlanMode == 1 || wlanMode ==2 || wlanState=='Disabled'){
	disableDelButton();
	disableButton(document.formWlAcDel.reset);
	disableButton(document.formWlAcAdd.reset);
	disableButton(document.formWlAcAdd.addFilterMac);
  	disableTextField(document.formWlAcAdd.wlanAcEnabled);
  	disableAc();
  } 
  else{
  if (filed.selectedIndex > 0)
 	enableAc();
  else
  	disableAc();
  }

}

function resetForm()
{
	document.formWlAcAdd.wlanAcEnabled.selectedIndex = <% getIndex("wlanAcEnabled"); %> ;
	document.formWlAcAdd.mac.value="";
	document.formWlAcAdd.comment.value="";
	
}

</script>
</head>
<body onload="initial();">
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
		
<table width="500" border="0" align="center" cellpadding="5" cellspacing="0" class="FormTitle" table>
	<thead>
	<tr>
		<td><#menu5_1#> - <#menu5_1_4#> (5GHz)</td>
	</tr>
	</thead>
	<tbody>
	<tr>
		<td bgcolor="#FFFFFF">If you choose 'Allowed Listed', only those clients whose wireless MAC addresses are in the access control list will be able to connect to your Access Point. When 'Deny Listed' is selected, these wireless clients on the list will not be able to connect the Access Point.</td>
	</tr>
	</tbody>	
	<tr>
	  <td bgcolor="#FFFFFF">
		<table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3"  class="FormTable">

<form action=/goform/formWlAc method=POST name="formWlAcAdd">
<tr>
   	<th>Wireless Access Control Mode:</th>
	<td>
	<select size="1" name="wlanAcEnabled" onChange="updateState(this)">
          <option value="0" >Disable</option>
          <option value="1" selected >Allow Listed</option>
          <option value="2" >Deny Listed</option>
        </select>
	</td>
	<script>
	document.formWlAcAdd.wlanAcEnabled.selectedIndex = <% getIndex("wlanAcEnabled"); %> ;
	</script>
</tr>
<tr>
     <th>MAC Address:</th>
     <td><input type="text" name="mac" size="15" maxlength="12"></td>
</tr>
<tr>
     <th>Comment:</th>
     <td><input type="text" name="comment" size="16" maxlength="20"></td>
</tr>
<tr align="right"><td colspan="2">
     	<input type="submit" value="<#CTL_apply#>" class="button" name="addFilterMac" onClick="return addClick()">
        <input type="button" value="Reset" name="reset" class="button" onClick="resetForm();">
        <input type="hidden" value="/wlactrl.asp" name="submit-url">
</td></tr>
  </form>
</table>
<br>
<form action=/goform/formWlAc method=POST name="formWlAcDel">
  <table border="0" width=440>
  <tr><font size=2><b>Current Access Control List:</b></font></tr>
  <% wlAcList(); %>
  </table>
  <br>
  <input type="submit" value="Delete Selected" name="deleteSelFilterMac" onClick="return deleteClick()">&nbsp;&nbsp;
  <input type="submit" value="Delete All" name="deleteAllFilterMac" onClick="return deleteAllClick()">&nbsp;&nbsp;&nbsp;
  <input type="reset" value="Reset" name="reset">
  <input type="hidden" value="/wlactrl.asp" name="submit-url">
 <script>
	var entryNum = <% getIndex("wlanAcNum"); %>;
	if ( entryNum == 0 )
      	  	disableDelButton();
	updateState(document.formWlAcAdd.wlanAcEnabled);
 </script>
</form>

</td></tr>
</table>
</td>

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

<!--</blockquote>-->
<div id="footer"></div>
</body>
</html>
