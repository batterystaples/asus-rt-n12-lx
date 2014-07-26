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
<title>ASUS Wireless Router <#Web_Title#> - <#menu5_6_1_title#></title>
<link rel="stylesheet" type="text/css" href="index_style.css"> 
<link rel="stylesheet" type="text/css" href="form_style.css">
<link rel="stylesheet" type="text/css" href="usp_style.css">
<link rel="stylesheet" type="text/css" href="other.css">
<script language="JavaScript" type="text/javascript" src="/state.js"></script>
<script language="JavaScript" type="text/javascript" src="/jquery.js"></script>
<script language="JavaScript" type="text/javascript" src="/general.js"></script>
<script language="JavaScript" type="text/javascript" src="/popup.js"></script>
<script type="text/javascript" language="JavaScript" src="/help.js"></script>
<script type="text/javascript" language="JavaScript" src="/detect.js"></script>
<script type="text/javascript" src="util_gw.js"> </script>
<script>
wan_route_x = '';
wan_nat_x = '';
wan_proto = '';

var sw_mode = <% getIndex("opMode"); %> ;
function initial(){
	show_banner(1);
	show_menu(5,5,1);
	show_footer();
	setScenerion(sw_mode);
}

function saveMode(){
	
	if(document.form.sw_mode[0].checked == true && sw_mode == 0){
		alert("<#Web_Title#> <#op_already_configured#>");
		return false;
	}
	
	if(document.form.sw_mode[1].checked == true && sw_mode == 1){
		alert("<#Web_Title#> <#op_already_configured#>");
		return false;
	}
	
	if(document.form.sw_mode[0].checked == true){
		document.form.flag.value = 'nodetect';
		document.form.action="/start_apply.htm";
		document.form.target="hidden_frame";
		document.form.current_page.value = "opmode.asp";
		document.form.typeForm.value = "formOpMode";
		document.form.action_mode.value = "Reinit";
		showLoading();	//2011.04.21 Jerry
	}
	else if(document.form.sw_mode[1].checked == true){
		document.form.flag.value = 'adv_ap_mode';
	}
	
	document.form.submit();
}

var $j = jQuery.noConflict();
var id_WANunplungHint;

function setScenerion(mode){
	if(mode == '0'){
		$j("#Senario").css("background","url(/images/gw.gif) no-repeat");
		$j("#radio2").hide();
		$j("#Internet_span").hide();
		$j("#ap-line").css("display", "none");
		$j("#AP").html("<#Internet#>");
		$j("#mode_desc").html("<#OP_GW_desc1#><#OP_GW_desc2#>");
		$j("#nextButton").attr("value","<#CTL_next#>");
	}
	else if(mode == '1'){
		$j("#Senario").css("background", "url(/images/ap.gif) no-repeat");
		$j("#radio2").css("display", "none");
		$j("#Internet_span").css("display", "block");
		$j("#ap-line").css("display", "none");
		$j("#AP").html("<#Device_type_02_RT#>");
		$j("#mode_desc").html("<#OP_AP_desc1#><#OP_AP_desc2#>");
		$j("#nextButton").attr("value","<#CTL_next#>");
		$j("#Unplug-hint").css("display", "none");
	}
}
</script>

<body onload="initial();" onunLoad="disable_auto_hint(11, 3);return unload_body();">
<div id="TopBanner"></div>
<div id="hiddenMask" class="popup_bg">
	<table cellpadding="5" cellspacing="0" id="dr_sweet_advise" class="dr_sweet_advise" align="center">
		<tr>
		<td>
			<div class="drword" id="drword" style="height:110px;"><#Main_alert_proceeding_desc4#> <#Main_alert_proceeding_desc1#>...
				<br/>
				<br/>
	    </div>
		  <div class="drImg"><img src="images/DrsurfImg.gif"></div>
			<div style="height:70px;"></div>
		</td>
		</tr>
	</table>
<!--[if lte IE 6.5]><iframe class="hackiframe"></iframe><![endif]-->
</div>

<div id="Loading" class="popup_bg"></div>

<form action="/QIS_wizard.htm" method=POST name="form">
<input type="hidden" name="current_page" value="">
<input type="hidden" value="" name="typeForm">
<input type="hidden" name="action_mode" value="">
<input type="hidden" name="flag" value="">
<input type="hidden" name="preferred_lang" id="preferred_lang" value="<% getInfo("preferred_lang"); %>">	<!--2011.04.14 Jerry-->
<input type="hidden" name="lan_ipaddr" value="<% getInfo("ip-gw"); %>">

<iframe name="hidden_frame" id="hidden_frame" src="" width="0" height="0" frameborder="0"></iframe>
<table class="content" align="center" cellpadding="0" cellspacing="0">
  <tr>
	<td width="23">&nbsp;</td>
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
		
<table width="95%" border="0" align="center" cellpadding="5" cellspacing="0" class="FormTitle">
	<thead>
	<tr>
		<td><#t1SYS#> - <#t2OP#></td>
	</tr>
	</thead>

	<tr>
	  <td bgcolor="#C0DAE4">
	<fieldset style="width:95%; margin:0 auto; padding-bottom:3px;">
	<legend>
		<span style="font-size:13px; font-weight:bold;">

<script>
	var opMode_GW = "";
	var opMode_AP = "";
	if(sw_mode == 0)	//GW
		opMode_GW = "checked";
	else	//AP
		opMode_AP = "checked";
	document.write("<input type=\"radio\" name=\"sw_mode\" class=\"input\" value=\"0\" onclick=\"setScenerion(0);\" " + opMode_GW + "><#OP_GW_item#>\n");
	document.write("<input type=\"radio\" name=\"sw_mode\" class=\"input\" value=\"1\" onclick=\"setScenerion(1);\" " + opMode_AP + "><#OP_AP_item#>\n");
</script>
		</span>
	</legend>
	<div id="mode_desc" style="position:relative;display:block; height:60px;z-index:90;">
		<#OP_GW_desc1#>
	</div>
		<br/><br/>
	<div id="Senario">
		<span style="margin:140px 0px 0px 140px;"><#Web_Title#></span>
		<span id="AP" style="margin:120px 0px 0px 355px;"><#Device_type_03_AP#></span>
		<span id="Internet_span" style="margin:70px 0px 0px 405px;"><#Internet#></span>
		<span style="margin:220px 0px 0px 40px;"><#Wireless_Clients#></span>
		<span style="margin:220px 0px 0px 360px;"><#Wired_Clients#></span>
		<div id="ap-line" style="border:0px solid #333;margin:77px 0px 0px 245px;width:133px; height:41px; position:absolute; background:url(/images/wanlink.gif) no-repeat;"></div>
		<div id="Unplug-hint" style="border:2px solid red; background-color:#FFF; padding:3px;margin:0px 0px 0px 150px;width:250px; position:absolute; display:block; display:none;"><#web_redirect_suggestion1#></div>
	</div>	
	</fieldset>
	  </td>
	</tr>
	<tr>
		<td align="right" bgColor="#C0DAE4">
			<input name="button" type="button" class="button" onClick="saveMode();" value="<#CTL_onlysave#>">
		</td>
	</tr>
</table>
</td>
		<td id="help_td" style="width:15px;display:none;" valign="top">
			<div id="helpicon" onClick="openHint(0,0);" title="<#Help_button_default_hint#>"><img src="images/help.gif" /></div>
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
	  	</div><!--End of hintofPM--> 
		 </td>
		</tr>
      </table>
		<!--===================================Ending of Main Content===========================================-->
	</td>
    <td width="10" align="center" valign="top">&nbsp;</td>
	</tr>
</table>
</form>
<form name="hint_form"></form>
<div id="footer"></div>


</body>
</html>
