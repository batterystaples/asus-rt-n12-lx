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
<title>ASUS Wireless Router <#Web_Title#> - <#menu5_1_1#></title>
<link rel="stylesheet" type="text/css" href="index_style.css"> 
<link rel="stylesheet" type="text/css" href="form_style.css">
<link rel="stylesheet" type="text/css" href="usp_style.css">
<link href="other.css"  rel="stylesheet" type="text/css">
<script type="text/javascript" src="/state.js"></script>
<script type="text/javascript" src="/help.js"></script>
<script type="text/javascript" src="/general.js"></script>
<script type="text/javascript" src="/popup.js"></script>
<script type="text/javascript" src="/md5.js"></script>
<script type="text/javascript" src="/detect.js"></script>
<script type="text/javascript" src="util_gw.js"> </script>
<script>
var wlan_channel=new Array();
var wlan_txrate=new Array();
var regDomain=new Array();
var defaultChan=new Array();
var lastBand=new Array();
var usedBand=new Array();
var RFType=new Array();
var APMode=new Array();
var bandIdx=new Array();
var bandIdxAP=new Array();
var bandIdxClient=new Array();
var startChanIdx=new Array();
var disableSSID=new Array();
var networkType=new Array();
var wlan_idx= <% getIndex("wlan_idx"); %> ;
var opmode=<% getIndex("opMode"); %> ;
var WiFiTest=<% getIndex("WiFiTest"); %> ;
var ssid_2g="<% getIndex("2G_ssid"); %>";
var ssid_5g="<% getIndex("5G_ssid"); %>";
lastBand[wlan_idx] = 0;
bandIdxAP[wlan_idx] = -1;
bandIdxClient[wlan_idx] = -1;
startChanIdx[wlan_idx] = 0;
disableSSID[wlan_idx] = 0;
networkType[wlan_idx] = <% getIndex("networkType"); %>;
var enc_method=new Array();
enc_method[wlan_idx] = <% getIndex("encrypt"); %>;
var change_wpa_enc = 0;
var wep_warning_flag = 0;

function initial(){
	show_banner(1);
	show_menu(5,1,1);
	show_footer();

  document.form.ssid<% getIndex("wlan_idx"); %>.value = decodeURIComponent(document.form.rt_ssid2.value);
}

function updateState(form, wlan_id)
{
  updateIputState(form, wlan_id);
}

function updateMode_basic(form, wlan_id)
{
	var mode_selected=0;
	var Type_selected=0;
	updateMode(form, wlan_id);
	Type_selected = document.form.elements["type"+wlan_id].selectedIndex;
  	mode_selected=document.form.elements["mode"+wlan_id].selectedIndex;
  	var chan_number_idx=form.elements["chan"+wlan_id].selectedIndex;
	var chan_number= form.elements["chan"+wlan_id].options[chan_number_idx].value;	
  	if(mode_selected ==1){
		if(Type_selected == 0){
			disableTextField(document.form.elements["controlsideband"+wlan_id]);
			disableTextField(document.form.elements["channelbound"+wlan_id]);
		}else{
			enableTextField(document.form.elements["channelbound"+wlan_id]);
			index_channelbound=document.form.elements["channelbound"+wlan_id].selectedIndex;
		if(index_channelbound ==0)
			disableTextField(document.form.elements["controlsideband"+wlan_id]);	
		else{
			if(chan_number != 0)
				enableTextField(document.form.elements["controlsideband"+wlan_id]);
			else
				disableTextField(document.form.elements["controlsideband"+wlan_id]);
		}
		}
	}else{
		enableTextField(document.form.elements["channelbound"+wlan_id]);
			index_channelbound=document.form.elements["channelbound"+wlan_id].selectedIndex;
		if(index_channelbound ==0)
			disableTextField(document.form.elements["controlsideband"+wlan_id]);	
		else{
			if(chan_number != 0)
				enableTextField(document.form.elements["controlsideband"+wlan_id]);
	 		else
				disableTextField(document.form.elements["controlsideband"+wlan_id]);
		}
}
	
	if( mode_selected == 5 )	//6 should be MESH mode
		disableTextField(document.form.elements["ssid<% getIndex("wlan_idx"); %>"]);

}

function updateType_basic(form, wlan_id)
{
	updateType(form, wlan_id);
	
}
function Set_SSIDbyBand(form, wlan_id, band, index)
{
	var selectText=band.options[index].text.substr(0,1);
	if(selectText == '5')
		form.elements["ssid"+wlan_idx].value = ssid_5g;
	else if(selectText == '2')
		form.elements["ssid"+wlan_idx].value = ssid_2g;
}
function Set_onChangeBand(form, wlan_id, band, index){
	var band;
	var auto;
	var txrate;
	var value;
	
	var checkid_wmm1 = document.getElementById("wlan_wmm");
	var checkid_wmm2 = document.form.wlanwmm<% getIndex("wlan_idx"); %>;
	var checkid_bound=document.getElementById("channel_bounding");
	var checkid_sideband = document.getElementById("control_sideband");
	var wmm_value = <% getIndex("wmmEnabled"); %>;	
	var mode_selected=0;
	var Type_selected=0;
	var index_channelbound=0;
	if(wmm_value==0)
		document.form.elements["wlanwmm<% getIndex("wlan_idx"); %>"].selectedIndex=0;
	else
		document.form.elements["wlanwmm<% getIndex("wlan_idx"); %>"].selectedIndex=1;
	value =band.options[index].value;
	if(value ==9 || value ==10 || value ==7 || value ==11){
		checkid_bound.style.display = "";
		checkid_sideband.style.display = "";
		document.form.elements["wlanwmm<% getIndex("wlan_idx"); %>"].selectedIndex = 1;
	 	checkid_wmm2.disabled = true;
	}else{
		checkid_bound.style.display = "none";
		checkid_sideband.style.display = "none";
		checkid_wmm2.disabled = false;
	}
	
	var txrate_idx=form.elements["txRate"+wlan_idx].selectedIndex;
	var wlan_txrate_value= form.elements["txRate"+wlan_idx].options[txrate_idx].value;
	wlan_txrate[wlan_idx] = wlan_txrate_value;
	document.form.elements["txRate<% getIndex("wlan_idx"); %>"].length=0;
	showtxrate_updated(document.form, value, wlan_idx, <% getIndex("rf_used"); %>);	
	
	updateChan_channebound(form, wlan_id);
	Type_selected = document.form.elements["type"+wlan_id].selectedIndex;
  	mode_selected=document.form.elements["mode"+wlan_id].selectedIndex;
  	//if client and infrastructure mode
  	if(mode_selected ==1){
		if(Type_selected == 0){
			disableTextField(document.form.elements["controlsideband"+wlan_id]);
			disableTextField(document.form.elements["channelbound"+wlan_id]);
		}else{
			enableTextField(document.form.elements["channelbound"+wlan_id]);
			index_channelbound=document.form.elements["channelbound"+wlan_id].selectedIndex;
		if(index_channelbound ==0)
			disableTextField(document.form.elements["controlsideband"+wlan_id]);	
		else
			enableTextField(document.form.elements["controlsideband"+wlan_id]);
		}
	}else{
		enableTextField(document.form.elements["channelbound"+wlan_id]);
			index_channelbound=document.form.elements["channelbound"+wlan_id].selectedIndex;
		if(index_channelbound ==0)
			disableTextField(document.form.elements["controlsideband"+wlan_id]);	
		else
			enableTextField(document.form.elements["controlsideband"+wlan_id]);
	}	
	var chan_number_idx=form.elements["chan"+wlan_id].selectedIndex;
	var chan_number= form.elements["chan"+wlan_id].options[chan_number_idx].value;	
	if(chan_number == 0)
		disableTextField(document.form.elements["controlsideband"+wlan_id]);	
	else{
		if(document.form.elements["channelbound"+wlan_id].selectedIndex == "0")
		disableTextField(document.form.elements["controlsideband"+wlan_id]);	
 		else
			enableTextField(document.form.elements["controlsideband"+wlan_id]);		
	}
}

function LoadSetting()
 {
 	var form = document.form;
	var wlanband_tmp = <% getIndex("band"); %>;
	var wlanband = ""
	if(wlanband_tmp < 7)
		wlanband = "0";

 	var checkid_bound;
 	var checkid_sideband;
 	var checkid_wmm1 = document.getElementById("wlan_wmm");
	var checkid_wmm2 = document.form.wlanwmm<% getIndex("wlan_idx"); %>;
 	var mode_index = document.form.elements["mode<% getIndex("wlan_idx"); %>"].selectedIndex;
 	var nettype_index = document.form.elements["type<% getIndex("wlan_idx"); %>"].selectedIndex;
 	var checkid_bound=document.getElementById("channel_bounding");
	var checkid_sideband=document.getElementById("control_sideband");

 	var checkid_authMode=document.getElementById("authMode_asus");
	var checkid_crypto_asus=document.getElementById("crypto_asus");
	var checkid_wpaPsk_asus=document.getElementById("wpaPsk_asus");
	var checkid_keyLength_asus=document.getElementById("keyLength_asus");
	var checkid_rt_key_asus=document.getElementById("rt_key_asus");
	var checkid_wepKey_asus=document.getElementById("wepKey_asus");
	var checkid_rt_key2_asus=document.getElementById("rt_key2_asus");
	var checkid_rt_key3_asus=document.getElementById("rt_key3_asus");
	var checkid_rt_key4_asus=document.getElementById("rt_key4_asus");
	var checkid_rt_phrase_x_asus=document.getElementById("rt_phrase_x_asus");
	var checkid_radiusIP_asus=document.getElementById("radiusIP_asus");
	var checkid_radiusPort_asus=document.getElementById("radiusPort_asus");
	var checkid_radius_Pass_asus=document.getElementById("radiusPass_asus");
	if(checkid_authMode.value=="disabled")
	{
	checkid_crypto_asus.style.display = "none";
	checkid_wpaPsk_asus.style.display = "none";
	checkid_keyLength_asus.style.display = "none";
	checkid_rt_key_asus.style.display = "none";
	checkid_wepKey_asus.style.display = "none";
	checkid_rt_key2_asus.style.display = "none";
	checkid_rt_key3_asus.style.display = "none";
	checkid_rt_key4_asus.style.display = "none";
	checkid_rt_phrase_x_asus.style.display = "none";
	checkid_radiusIP_asus.style.display = "none";
	checkid_radiusPort_asus.style.display = "none";
	checkid_radius_Pass_asus.style.display = "none";

	}
	else if(checkid_authMode.value=="wpa"||checkid_authMode.value=="wpa2"||checkid_authMode.value=="radius")
	{
		checkid_crypto_asus.style.display = "none";
		checkid_wpaPsk_asus.style.display = "none";
		checkid_keyLength_asus.style.display = "none";
		checkid_rt_key_asus.style.display = "none";
		checkid_wepKey_asus.style.display = "none";
		checkid_rt_key2_asus.style.display = "none";
		checkid_rt_key3_asus.style.display = "none";
		checkid_rt_key4_asus.style.display = "none";
		checkid_rt_phrase_x_asus.style.display = "none";
		checkid_radiusIP_asus.style.display = "";
		checkid_radiusPort_asus.style.display = "";
		checkid_radius_Pass_asus.style.display = "";
	}
	else if(checkid_authMode.value == "open"||checkid_authMode.value=="shared") {	//Open system 
		checkid_crypto_asus.style.display = "none";
		checkid_wpaPsk_asus.style.display = "none";
		checkid_keyLength_asus.style.display = "";
		checkid_rt_key_asus.style.display = "";
		checkid_wepKey_asus.style.display = "";
		checkid_rt_key2_asus.style.display = "";
		checkid_rt_key3_asus.style.display = "";
		checkid_rt_key4_asus.style.display = "";
		checkid_rt_phrase_x_asus.style.display = "";
		checkid_radiusIP_asus.style.display = "none";
		checkid_radiusPort_asus.style.display = "none";
		checkid_radius_Pass_asus.style.display = "none";
	}
	else if(checkid_authMode.value == "psk"||checkid_authMode.value == "psk2"||checkid_authMode.value == "pskauto") {
		checkid_crypto_asus.style.display = "";
		checkid_wpaPsk_asus.style.display = "";
		checkid_keyLength_asus.style.display = "none";
		checkid_rt_key_asus.style.display = "none";
		checkid_wepKey_asus.style.display = "none";
		checkid_rt_key2_asus.style.display = "none";
		checkid_rt_key3_asus.style.display = "none";
		checkid_rt_key4_asus.style.display = "none";
		checkid_rt_phrase_x_asus.style.display = "none";
		checkid_radiusIP_asus.style.display = "none";
		checkid_radiusPort_asus.style.display = "none";
		checkid_radius_Pass_asus.style.display = "none";
	}

	var wmm_value = <% getIndex("wmmEnabled"); %>;
	if(wmm_value==0)
		document.form.elements["wlanwmm<% getIndex("wlan_idx"); %>"].selectedIndex=0;
	else
		document.form.elements["wlanwmm<% getIndex("wlan_idx"); %>"].selectedIndex=1;
 	if(wlanband == "0"){
 		checkid_bound.style.display = "none";
 		checkid_sideband.style.display = "none";
	 	checkid_wmm2.disabled = false;
 	}else{
 		checkid_bound.style.display = "";
 		checkid_sideband.style.display = "";
		document.form.elements["wlanwmm<% getIndex("wlan_idx"); %>"].selectedIndex = 1;
	 	checkid_wmm2.disabled = true;
 	}

	var init_bound = "";
	var init_bound_tmp = <% getIndex("ChannelBonding"); %>;
	if(init_bound_tmp == 0)
		init_bound = "0";

	var init_sideband = "";
	var init_sideband_tmp = <% getIndex("ControlSideBand"); %>;
	if(init_sideband_tmp == 0)
		init_sideband = "0";
 
 	if(init_bound=="0")
		document.form.elements["channelbound<% getIndex("wlan_idx"); %>"].selectedIndex=0;
 	else
		document.form.elements["channelbound<% getIndex("wlan_idx"); %>"].selectedIndex=1;
 		
 	if(init_sideband=="0")
		document.form.elements["controlsideband<% getIndex("wlan_idx"); %>"].selectedIndex=0;
 	else
		document.form.elements["controlsideband<% getIndex("wlan_idx"); %>"].selectedIndex=1;
 	if(init_bound == "0")
		disableTextField(document.form.elements["controlsideband<% getIndex("wlan_idx"); %>"]);
		
	//if client and infrastructure mode
	if(mode_index==1){
	 	if(nettype_index ==0){
			disableTextField(document.form.elements["controlsideband<% getIndex("wlan_idx"); %>"]);
			disableTextField(document.form.elements["channelbound<% getIndex("wlan_idx"); %>"]);
	 	}
	}

	if( mode_index == 5 )
		disableTextField(document.form.elements["ssid<% getIndex("wlan_idx"); %>"]);

	var hiddenSSID_value = <% getIndex("hiddenSSID"); %>;
	if(hiddenSSID_value==0)
		document.form.hiddenSSID<% getIndex("wlan_idx"); %>[1].checked = true;//Added by Jerry
	else
		document.form.hiddenSSID<% getIndex("wlan_idx"); %>[0].checked = true;//Added by Jerry
	updateChan_channebound(document.form, wlan_idx);	

	var chan_number_idx=form.elements["chan"+wlan_idx].selectedIndex;
	var chan_number= form.elements["chan"+wlan_idx].options[chan_number_idx].value;
	
	wlan_channel[wlan_idx] = chan_number;
	
	var txrate_idx=form.elements["txRate"+wlan_idx].selectedIndex;
	var wlan_txrate_value= form.elements["txRate"+wlan_idx].options[txrate_idx].value;
	wlan_txrate[wlan_idx] = wlan_txrate_value;
	if(chan_number == 0)	
		disableTextField(document.form.elements["controlsideband<% getIndex("wlan_idx"); %>"]);
		
	var isPocketRouter="<% getInfo("isPocketRouter"); %>"*1;
	var pocketRouter_Mode="<% getInfo("pocketRouter_Mode"); %>"*1;
	if(pocketRouter_Mode == 1) //1:bridge and client mode
		disableTextField(document.form.elements["mode"+wlan_idx]);
      				
}

function LoadSecuritySetting()
{
	var mode = <% getVirtualIndex("encrypt", 0); %>;	//ENCRYPT_DISABLED=0, ENCRYPT_WEP=1, ENCRYPT_WPA=2, ENCRYPT_WPA2=4, ENCRYPT_WPA2_MIXED=6 ,ENCRYPT_WAPI=7
	var enable_1x="<% getVirtualIndex("enable1X", 0); %>";
	var wlan_auth = <% getVirtualIndex("authType", 0); %>;	//AUTH_OPEN=0, AUTH_SHARED, AUTH_BOTH
	var wpa_auth = <% getVirtualIndex("wpaAuth", 0); %>;	//WPA_AUTH_AUTO=1, WPA_AUTH_PSK=2
	var wapi_auth="<% getVirtualIndex("wapiAuth", 0); %>";
	var wepmode = <% getVirtualIndex("wep", 0); %>;	//WEP_DISABLED=0, WEP64=1, WEP128=2
	var wep_key_fmt = <% getVirtualIndex("keyType", 0); %>;
	var wpa_cipher = <% getVirtualIndex("wpaCipher", 0); %>;	//WPA_CIPHER_TKIP=1, WPA_CIPHER_AES=2, WPA_CIPHER_MIXED=3
	var wpa2_cipher = <% getVirtualIndex("wpa2Cipher", 0); %>;	//WPA_CIPHER_TKIP=1, WPA_CIPHER_AES=2, WPA_CIPHER_MIXED=3
	var psk_fmt="<% getVirtualIndex("pskFormat", 0); %>";
	var wapi_psk_fmt="<% getVirtualIndex("wapiPskFormat", 0); %>";
	var tmp_eap_type="<% getVirtualIndex("eapType", 0); %>";
	var tmp_eap_inside_type="<% getVirtualIndex("eapInsideType", 0); %>";
	
	document.form.radiusIP<% getIndex("wlan_idx"); %>.value="<%getVirtualInfo("rsIp", 0);%>";
	document.form.radiusPort<% getIndex("wlan_idx"); %>.value="<%getVirtualInfo("rsPort", 0);%>";
	document.form.radiusPass<% getIndex("wlan_idx"); %>.value="<%getVirtualInfo("rsPassword", 0);%>";
	document.form.rt_key.selectedIndex= <% getVirtualIndex("defaultKeyId", 0); %>;
	if(mode == 0)	//Disabled
		document.form.authMode<% getIndex("wlan_idx"); %>.selectedIndex = 0;

	if(mode == 1)	//WEP
	{
		if(enable_1x=="1")
			document.form.authMode<% getIndex("wlan_idx"); %>.selectedIndex = 7;
		else if(wlan_auth == 1)	//Shared key
			document.form.authMode<% getIndex("wlan_idx"); %>.selectedIndex = 1;
		else if(wlan_auth == 0)	//Open system
			document.form.authMode<% getIndex("wlan_idx"); %>.selectedIndex = 0;
		
		if(wlan_auth == 0 || wlan_auth == 1)
			document.form.keyLength<% getIndex("wlan_idx"); %>.selectedIndex = wepmode;
	}
	else if(mode == 2)	//WPA
	{
		if(wpa_auth == 2) {	//PSK
			if(wpa_cipher == 1)	//TKIP
				document.form.authMode<% getIndex("wlan_idx"); %>.selectedIndex = 2;
		}
		if(wpa_auth == 1)	//Enterprise (RADIUS)
			document.form.authMode<% getIndex("wlan_idx"); %>.selectedIndex = 5;
	}
	else if(mode == 4)	//WPA2
	{
		if(wpa_auth == 2)	//PSK
			document.form.authMode<% getIndex("wlan_idx"); %>.selectedIndex = 3;
		if(wpa_auth == 1)	//Enterprise (RADIUS)
			document.form.authMode<% getIndex("wlan_idx"); %>.selectedIndex = 6;
	}

	if(mode == 6)	//WPA-Mixed
	{
		document.form.authMode<% getIndex("wlan_idx"); %>.selectedIndex = 4;
		change_wpa_enc = 1;
	}
	
	change_auth(document.form.authMode<% getIndex("wlan_idx"); %>);
	automode_hint();
	wep_warning_flag = 1;
}
function change_auth(o)
{
 	var checkid_bound=document.getElementById("channel_bounding");
	var checkid_sideband=document.getElementById("control_sideband");

 	var checkid_authMode=document.getElementById("authMode_asus");
	var checkid_crypto_asus=document.getElementById("crypto_asus");
	var checkid_wpaPsk_asus=document.getElementById("wpaPsk_asus");
	var checkid_keyLength_asus=document.getElementById("keyLength_asus");
	var checkid_rt_key_asus=document.getElementById("rt_key_asus");
	var checkid_wepKey_asus=document.getElementById("wepKey_asus");
	var checkid_rt_key2_asus=document.getElementById("rt_key2_asus");
	var checkid_rt_key3_asus=document.getElementById("rt_key3_asus");
	var checkid_rt_key4_asus=document.getElementById("rt_key4_asus");
	var checkid_rt_phrase_x_asus=document.getElementById("rt_phrase_x_asus");
	var checkid_radiusIP_asus=document.getElementById("radiusIP_asus");
	var checkid_radiusPort_asus=document.getElementById("radiusPort_asus");
	var checkid_radius_Pass_asus=document.getElementById("radiusPass_asus");
	
	var tF = document.form;
	tF.rt_phrase_x.value="<%getVirtualInfo("asusphrase", 0);%>";

	if(o.value == "open") {	//Open system 
		var length = tF.elements["keyLength"+<% getIndex("wlan_idx");%>].options.length;
		if(length==2)
		{
			tF.elements["keyLength"+<% getIndex("wlan_idx");%>].remove(0);
			tF.elements["keyLength"+<% getIndex("wlan_idx");%>].remove(1);
			tF.elements["keyLength"+<% getIndex("wlan_idx");%>].options[0]=new Option("None",0,false,false);
			tF.elements["keyLength"+<% getIndex("wlan_idx");%>].options[1]=new Option("WEP-64bits",1,false,false);
			tF.elements["keyLength"+<% getIndex("wlan_idx");%>].options[2]=new Option("WEP-128bits",2,false,false);
		}

		checkid_crypto_asus.style.display = "none";
		checkid_wpaPsk_asus.style.display = "none";
		checkid_keyLength_asus.style.display = "";
		checkid_rt_key_asus.style.display = "";
		checkid_wepKey_asus.style.display = "";
		checkid_rt_key2_asus.style.display = "";
		checkid_rt_key3_asus.style.display = "";
		checkid_rt_key4_asus.style.display = "";
		checkid_rt_phrase_x_asus.style.display = "";
		checkid_radiusIP_asus.style.display = "none";
		checkid_radiusPort_asus.style.display = "none";
		checkid_radius_Pass_asus.style.display = "none";
		
		tF.wpaPsk<% getIndex("wlan_idx"); %>.value = "";
		tF.rt_phrase_x.value="<%getVirtualInfo("asusphrase", 0);%>";
		change_wep();
		if(wep_warning_flag == 1)
			alert("<#WEP_warning#>");
	}
	else if(o.value == "shared") {	// Shared key
		if(document.form.band<% getIndex("wlan_idx"); %>.value == "7") {	//TKIP limitation in n mode.
			alert("<#WLANConfig11n_nmode_limition_hint#>");
			document.form.authMode<% getIndex("wlan_idx"); %>.selectedIndex = 3;
			change_auth(document.form.authMode<% getIndex("wlan_idx"); %>);
			return;
		}
		var length = tF.elements["keyLength"+<% getIndex("wlan_idx");%>].options.length;
		if(length==3)
			tF.elements["keyLength"+<% getIndex("wlan_idx");%>].remove(0);

		checkid_crypto_asus.style.display = "none";
		checkid_wpaPsk_asus.style.display = "none";
		checkid_keyLength_asus.style.display = "";
		checkid_rt_key_asus.style.display = "";
		checkid_wepKey_asus.style.display = "";
		checkid_rt_key2_asus.style.display = "";
		checkid_rt_key3_asus.style.display = "";
		checkid_rt_key4_asus.style.display = "";
		checkid_rt_phrase_x_asus.style.display = "";
		checkid_radiusIP_asus.style.display = "none";
		checkid_radiusPort_asus.style.display = "none";
		checkid_radius_Pass_asus.style.display = "none";

		tF.wpaPsk<% getIndex("wlan_idx"); %>.value = "";
		tF.wepKey<% getIndex("wlan_idx"); %>.value = "";
		tF.rt_phrase_x.value="<%getVirtualInfo("asusphrase", 0);%>";
		change_wep();
		tF.wepKey<% getIndex("wlan_idx"); %>.focus();
		if(wep_warning_flag == 1)
			alert("<#WEP_warning#>");
	}
	else if(o.value == "psk"||o.value == "psk2"||o.value == "pskauto") {	//WPA-Personal, WPA2-Personal, WPA-Auto-Personal
		var length = tF.elements["crypto<% getIndex("wlan_idx");%>"].options.length;
		tF.elements["crypto<% getIndex("wlan_idx");%>"].remove(0);
		tF.elements["crypto<% getIndex("wlan_idx");%>"].remove(1);
		if(o.value == "psk")
			tF.elements["crypto<% getIndex("wlan_idx");%>"].options[0]=new Option("TKIP","tkip",false,false);
		if(o.value == "psk2")
			tF.elements["crypto<% getIndex("wlan_idx");%>"].options[0]=new Option("AES","aes",false,false);
		if(o.value == "pskauto") {
			tF.elements["crypto<% getIndex("wlan_idx");%>"].options[0]=new Option("AES","aes",false,false);
			tF.elements["crypto<% getIndex("wlan_idx");%>"].options[1]=new Option("TKIP+AES","tkip+aes",false,false);
			if(change_wpa_enc)
			{
				var wpa_cipher = <% getVirtualIndex("wpaCipher", 0); %>;	//WPA_CIPHER_TKIP=1, WPA_CIPHER_AES=2, WPA_CIPHER_MIXED=3
				tF.elements["crypto<% getIndex("wlan_idx");%>"].selectedIndex = wpa_cipher - 2;
				change_wpa_enc = 0;
			}
		}
		
		checkid_crypto_asus.style.display = "";
		checkid_wpaPsk_asus.style.display = "";
		checkid_keyLength_asus.style.display = "none";
		checkid_rt_key_asus.style.display = "none";
		checkid_wepKey_asus.style.display = "none";
		checkid_rt_key2_asus.style.display = "none";
		checkid_rt_key3_asus.style.display = "none";
		checkid_rt_key4_asus.style.display = "none";
		checkid_rt_phrase_x_asus.style.display = "none";
		checkid_radiusIP_asus.style.display = "none";
		checkid_radiusPort_asus.style.display = "none";
		checkid_radius_Pass_asus.style.display = "none";

		tF.wpaPsk<% getIndex("wlan_idx"); %>.value = decodeURIComponent("<% apmib_char_to_ascii("WLANConfig11b", "pskValue"); %>");
		tF.keyLength<% getIndex("wlan_idx"); %>.selectedIndex = 0;
		tF.wepKey<% getIndex("wlan_idx"); %>.value = "";
		change_key_des();
		tF.wpaPsk<% getIndex("wlan_idx"); %>.focus();

		if(o.value == "psk") {
			tF.elements["crypto<% getIndex("wlan_idx");%>"].options[0]=new Option("TKIP","tkip",false,false);
			if(document.form.band<% getIndex("wlan_idx"); %>.value == "7") {	//TKIP limitation in n mode.
				alert("<#WLANConfig11n_nmode_limition_hint#>");
				document.form.authMode<% getIndex("wlan_idx"); %>.selectedIndex = 3;
				change_auth(document.form.authMode<% getIndex("wlan_idx"); %>);
			}
		}
	}
	else if(o.value == "wpa" || o.value == "wpa2") {
		tF.elements["crypto"+<% getIndex("wlan_idx");%>].remove(0);
		tF.elements["crypto"+<% getIndex("wlan_idx");%>].remove(1);		
		if(o.value == "wpa")
			tF.elements["crypto"+<% getIndex("wlan_idx");%>].options[0]=new Option("TKIP","tkip",false,false);
		if(o.value == "wpa2")
			tF.elements["crypto"+<% getIndex("wlan_idx");%>].options[0]=new Option("AES","aes",false,false);
			
		checkid_crypto_asus.style.display = "";
		checkid_wpaPsk_asus.style.display = "none";
		checkid_keyLength_asus.style.display = "none";
		checkid_rt_key_asus.style.display = "none";
		checkid_wepKey_asus.style.display = "none";
		checkid_rt_key2_asus.style.display = "none";
		checkid_rt_key3_asus.style.display = "none";
		checkid_rt_key4_asus.style.display = "none";
		checkid_rt_phrase_x_asus.style.display = "none";
		checkid_radiusIP_asus.style.display = "";
		checkid_radiusPort_asus.style.display = "";
		checkid_radius_Pass_asus.style.display = "";
		
		tF.wpaPsk<% getIndex("wlan_idx"); %>.value = decodeURIComponent("<% apmib_char_to_ascii("WLANConfig11b", "pskValue"); %>");
		tF.radiusIP<% getIndex("wlan_idx"); %>.value="<%getVirtualInfo("rsIp", 0);%>";
		tF.radiusPort<% getIndex("wlan_idx"); %>.value="<%getVirtualInfo("rsPort", 0);%>";
		tF.radiusPass<% getIndex("wlan_idx"); %>.value="<%getVirtualInfo("rsPassword", 0);%>";
		tF.keyLength<% getIndex("wlan_idx"); %>.selectedIndex = 0;
		tF.wepKey<% getIndex("wlan_idx"); %>.value = "";
		change_key_des();

		if(o.value == "wpa") {
			tF.elements["crypto"+<% getIndex("wlan_idx");%>].options[0]=new Option("TKIP","tkip",false,false);
			if(document.form.band<% getIndex("wlan_idx"); %>.value == "7") {	//TKIP limitation in n mode.
				alert("<#WLANConfig11n_nmode_limition_hint#>");
				document.form.authMode<% getIndex("wlan_idx"); %>.selectedIndex = 6;
				change_auth(document.form.authMode<% getIndex("wlan_idx"); %>);
			}
		}
	}
	else if(o.value == "radius") {	
		checkid_crypto_asus.style.display = "none";
		checkid_wpaPsk_asus.style.display = "none";
		checkid_keyLength_asus.style.display = "none";
		checkid_rt_key_asus.style.display = "none";
		checkid_wepKey_asus.style.display = "none";
		checkid_rt_key2_asus.style.display = "none";
		checkid_rt_key3_asus.style.display = "none";
		checkid_rt_key4_asus.style.display = "none";
		checkid_rt_phrase_x_asus.style.display = "none";
		checkid_radiusIP_asus.style.display = "";
		checkid_radiusPort_asus.style.display = "";
		checkid_radius_Pass_asus.style.display = "";
		
		tF.radiusIP<% getIndex("wlan_idx"); %>.value="<%getVirtualInfo("rsIp", 0);%>";
		tF.radiusPort<% getIndex("wlan_idx"); %>.value="<%getVirtualInfo("rsPort", 0);%>";
		tF.radiusPass<% getIndex("wlan_idx"); %>.value="<%getVirtualInfo("rsPassword", 0);%>";
		tF.wpaPsk<% getIndex("wlan_idx"); %>.value = decodeURIComponent("<% apmib_char_to_ascii("WLANConfig11b", "pskValue"); %>");
		tF.keyLength<% getIndex("wlan_idx"); %>.selectedIndex = 0;
		tF.wepKey<% getIndex("wlan_idx"); %>.value = "";
		change_key_des();

		if(document.form.band<% getIndex("wlan_idx"); %>.value == "7") {	//WEP limitation in n mode.
			alert("<#WLANConfig11n_nmode_limition_hint#>");
			document.form.authMode<% getIndex("wlan_idx"); %>.selectedIndex = 6;
			change_auth(document.form.authMode<% getIndex("wlan_idx"); %>);
		}
	}
	//Lucifer
	automode_hint();
}

function change_wep()
{
	var wepmode = <% getVirtualIndex("wep", 0); %>;//WEP_DISABLED=0, WEP64=1, WEP128=2

	if(wepmode==1)
	{
		document.form.wepKey<% getIndex("wlan_idx"); %>.value= decodeURIComponent("<% getVirtualIndex("wep64Key1", 0); %>");
		document.form.rt_key2.value= decodeURIComponent("<% getVirtualIndex("wep64Key2", 0); %>");
		document.form.rt_key3.value= decodeURIComponent("<% getVirtualIndex("wep64Key3", 0); %>");
		document.form.rt_key4.value= decodeURIComponent("<% getVirtualIndex("wep64Key4", 0); %>");
	}
	else if(wepmode==2)
	{
		document.form.wepKey<% getIndex("wlan_idx"); %>.value= decodeURIComponent("<% getVirtualIndex("wep128Key1", 0); %>");
		document.form.rt_key2.value= decodeURIComponent("<% getVirtualIndex("wep128Key2", 0); %>");
		document.form.rt_key3.value= decodeURIComponent("<% getVirtualIndex("wep128Key3", 0); %>");
		document.form.rt_key4.value= decodeURIComponent("<% getVirtualIndex("wep128Key4", 0); %>");
	}
	if(document.form.keyLength<% getIndex("wlan_idx"); %>.value  == "0")
	{
		disableTextField(document.form.rt_key);
		disableTextField(document.form.wepKey<% getIndex("wlan_idx"); %>);
		disableTextField(document.form.rt_key2);
		disableTextField(document.form.rt_key3);
		disableTextField(document.form.rt_key4);
		disableTextField(document.form.rt_phrase_x);
	}
	else
	{
		enableTextField(document.form.rt_key);
		enableTextField(document.form.wepKey<% getIndex("wlan_idx"); %>);
		enableTextField(document.form.rt_key2);
		enableTextField(document.form.rt_key3);
		enableTextField(document.form.rt_key4);
		enableTextField(document.form.rt_phrase_x);
	}
	change_key_des();

	if(document.form.band<% getIndex("wlan_idx"); %>.value == "7" && (document.form.keyLength<% getIndex("wlan_idx"); %>.value == 1 || document.form.keyLength<% getIndex("wlan_idx"); %>.value == 2)) {	//TKIP limitation in n mode.
		alert("<#WLANConfig11n_nmode_limition_hint#>");
		document.form.authMode<% getIndex("wlan_idx"); %>.selectedIndex = 3;
		change_auth(document.form.authMode<% getIndex("wlan_idx"); %>);
	}
}

function change_key_des(){
	var objs = getElementsByName_iefix("span", "key_des");
	var wep_type = document.form.keyLength<% getIndex("wlan_idx"); %>.value;
	var str = "";

	if(wep_type == "1")
		str = "(<#WLANConfig11b_WEPKey_itemtype1#>)";
	else if(wep_type == "2")
		str = "(<#WLANConfig11b_WEPKey_itemtype2#>)";

	for(var i = 0; i < objs.length; ++i)
		showtext(objs[i], str);
}

function change_wepKey(o){
	var wep = document.form.keyLength<% getIndex("wlan_idx"); %>.value;
	if(wep == "1"){
		if(o.value.length > 10)
			o.value = o.value.substring(0, 10);
	}
	else if(wep == "2"){
		if(o.value.length > 26)
			o.value = o.value.substring(0, 26);
	}
	return true;
}

function applyRule(){
	var auth_mode = document.form.authMode<% getIndex("wlan_idx"); %>.value;
	
	if(document.form.wpaPsk<% getIndex("wlan_idx"); %>.value == "Please type Password")
		document.form.wpaPsk<% getIndex("wlan_idx"); %>.value = "";
	 
	if( validForm() && saveChanges_basic(document.form, wlan_idx) && ValidateSecurity() ){
	  document.form.rt_ssid2.value = encodeURIComponent(document.form.ssid<% getIndex("wlan_idx"); %>.value);
		showLoading();	
		document.form.submit();
	}
}
function validate_wlphrase(s, v, obj){
	if(!validate_string(obj)){
		//is_wlphrase(s, v, obj);
		return(false);
	}
	
	return true;
}
function validForm(){
	var auth_mode = document.form.authMode<% getIndex("wlan_idx"); %>.value;
	
	if(!validate_string_ssid(document.form.ssid<% getIndex("wlan_idx"); %>))
		return false;
	
			
	if(auth_mode == "psk" || auth_mode=="psk2" || auth_mode=='pskauto'){ //2008.08.04 lock modified
		if(!validate_psk(document.form.wpaPsk<% getIndex("wlan_idx"); %>))
			return false;
	}
	else if (auth_mode == "open" || auth_mode == "shared") {
		if(!validate_wlphrase('WLANConfig11b', 'wl_phrase_x', document.form.rt_phrase_x))
			return false;
		if(document.form.rt_key.value == "1") {
			if(!validate_wlkey(document.form.wepKey<% getIndex("wlan_idx"); %>))
				return false;
		}
		else if (document.form.rt_key.value == "2") {
			if(!validate_wlkey(document.form.rt_key2))
				return false;
		}
		else if (document.form.rt_key.value == "3") {
			if(!validate_wlkey(document.form.rt_key3))
				return false;
		}
		else if (document.form.rt_key.value == "4") {
			if(!validate_wlkey(document.form.rt_key4))
				return false;
		}	
	}
	return true;
}

function validate_wlkey(key_obj){
	var wep_type = document.form.keyLength<% getIndex("wlan_idx"); %>.value;
	var iscurrect = true;
	var str = "<#JS_wepkey#>";
	if(wep_type == "0")
		iscurrect = true;	// do nothing
	else if(wep_type == "1")
	{
		if(key_obj.value.length == 5 && validate_string(key_obj))
		{
			document.form.format<% getIndex("wlan_idx"); %>.value = 1;
			iscurrect = true;
		}
		else if(key_obj.value.length == 10 && validate_hex(key_obj))
		{
			document.form.format<% getIndex("wlan_idx"); %>.value = 2;
			iscurrect = true;
		}
		else
		{
			str += "(<#WLANConfig11b_WEPKey_itemtype1#>)";
			iscurrect = false;
		}
	}
	else if(wep_type == "2")
		{
		if(key_obj.value.length == 13 && validate_string(key_obj))
		{
			document.form.format<% getIndex("wlan_idx"); %>.value = 1;
			iscurrect = true;
		}
		else if(key_obj.value.length == 26 && validate_hex(key_obj))
		{
			document.form.format<% getIndex("wlan_idx"); %>.value = 2;
			iscurrect = true;
		}
		else
		{
			str += "(<#WLANConfig11b_WEPKey_itemtype2#>)";
			iscurrect = false;
		}
	}
	else
	{
		alert("<#ALERT_OF_ERROR_System0#>");
		iscurrect = false;
	}
	
	if(iscurrect == false)
	{
		alert(str);
		key_obj.focus();
		key_obj.select();
	}
	return iscurrect;
}

function ValidateSecurity()
{
	var tF= document.form;//document.forms[0];
	var enc_mode = tF.authMode<% getIndex("wlan_idx"); %>.value;

	tF.use1x<% getIndex("wlan_idx"); %>.value = "OFF";

	if(tF.authMode<% getIndex("wlan_idx"); %>.value == "open" || tF.authMode<% getIndex("wlan_idx"); %>.value == "shared")
		tF.authType.value = tF.authMode<% getIndex("wlan_idx"); %>.value;
	
	if(tF.authMode<% getIndex("wlan_idx"); %>.selectedIndex == 0)	//WEP(open)
	{
		if(tF.keyLength<% getIndex("wlan_idx"); %>.selectedIndex == 0)
			tF.method<% getIndex("wlan_idx"); %>.value = 0;
		else
			tF.method<% getIndex("wlan_idx"); %>.value = 1;
	}
	if(tF.authMode<% getIndex("wlan_idx"); %>.selectedIndex == 1)	//WEP(shared)
		tF.method<% getIndex("wlan_idx"); %>.value = 1;
	else if(tF.authMode<% getIndex("wlan_idx"); %>.selectedIndex == 2 || tF.authMode<% getIndex("wlan_idx"); %>.selectedIndex == 5)	//WPA(personal, enterprise)
		tF.method<% getIndex("wlan_idx"); %>.value = 2;
	else if(tF.authMode<% getIndex("wlan_idx"); %>.selectedIndex == 3 || tF.authMode<% getIndex("wlan_idx"); %>.selectedIndex == 6)	//WPA2(personal, enterprise)
		tF.method<% getIndex("wlan_idx"); %>.value = 4;
	else if(tF.authMode<% getIndex("wlan_idx"); %>.selectedIndex == 4)	//WPA-Auto-Personal
		tF.method<% getIndex("wlan_idx"); %>.value = 6;
	else if(tF.authMode<% getIndex("wlan_idx"); %>.selectedIndex == 7)
		tF.method<% getIndex("wlan_idx"); %>.value = 13;//Lucifer
	
	if(tF.keyLength<% getIndex("wlan_idx"); %>.selectedIndex == 0)
		tF.wepKeyLen<% getIndex("wlan_idx"); %>.value = "wep64";
	else if(tF.keyLength<% getIndex("wlan_idx"); %>.selectedIndex == 1)
		tF.wepKeyLen<% getIndex("wlan_idx"); %>.value = "wep128";	

	tF.length<% getIndex("wlan_idx"); %>.value = tF.keyLength<% getIndex("wlan_idx"); %>.value;
	tF.key<% getIndex("wlan_idx"); %>.value = tF.wepKey<% getIndex("wlan_idx"); %>.value;

	if(tF.authMode<% getIndex("wlan_idx"); %>.selectedIndex == 2 || tF.authMode<% getIndex("wlan_idx"); %>.selectedIndex == 3  || tF.authMode<% getIndex("wlan_idx"); %>.selectedIndex == 4)	//PSK
		tF.wpaAuth<% getIndex("wlan_idx"); %>.value = "psk";
	
	if(tF.authMode<% getIndex("wlan_idx"); %>.selectedIndex == 5 || tF.authMode<% getIndex("wlan_idx"); %>.selectedIndex == 6)	//EAP
		tF.wpaAuth<% getIndex("wlan_idx"); %>.value = "eap";
	
	if(tF.authMode<% getIndex("wlan_idx"); %>.selectedIndex == 2 || tF.authMode<% getIndex("wlan_idx"); %>.selectedIndex == 5)	//WPA only
		tF.ciphersuite<% getIndex("wlan_idx"); %>.value = tF.crypto<% getIndex("wlan_idx"); %>.value;
	if(tF.authMode<% getIndex("wlan_idx"); %>.selectedIndex == 4) {	//WPA-auto
		tF.ciphersuite<% getIndex("wlan_idx"); %>.value = tF.crypto<% getIndex("wlan_idx"); %>.value;
		tF.wpa2ciphersuite<% getIndex("wlan_idx"); %>.value = tF.crypto<% getIndex("wlan_idx"); %>.value;
	}
	if(tF.authMode<% getIndex("wlan_idx"); %>.selectedIndex == 3 || tF.authMode<% getIndex("wlan_idx"); %>.selectedIndex == 6)	//WPA2 only
		tF.wpa2ciphersuite<% getIndex("wlan_idx"); %>.value = tF.crypto<% getIndex("wlan_idx"); %>.value;
	if(tF.authMode<% getIndex("wlan_idx"); %>.selectedIndex == 7)	//WPA2 only
		tF.use1x<% getIndex("wlan_idx"); %>.value = "ON";
	else
		tF.use1x<% getIndex("wlan_idx"); %>.value = "OFF";
	
	tF.pskValue<% getIndex("wlan_idx"); %>.value = tF.wpaPsk<% getIndex("wlan_idx"); %>.value;

	tF.wapiAuth<% getIndex("wlan_idx"); %>[0].checked = false;
	tF.wapiAuth<% getIndex("wlan_idx"); %>[1].checked = false;	

	tF.wlan_ssid_id.value = tF.SSID_Setting.value;
	tF.wlan_ssid.value= tF.SSID_Setting.value;

	tF.defaultTxKeyId<% getIndex("wlan_idx"); %>.value=tF.rt_key.value;
	tF.key1<% getIndex("wlan_idx"); %>.value=tF.wepKey<% getIndex("wlan_idx"); %>.value;
	tF.key2<% getIndex("wlan_idx"); %>.value=tF.rt_key2.value;
	tF.key3<% getIndex("wlan_idx"); %>.value=tF.rt_key3.value;
	tF.key4<% getIndex("wlan_idx"); %>.value=tF.rt_key4.value;
	tF.asus_phrase<% getIndex("wlan_idx"); %>.value=tF.rt_phrase_x.value;


	saveChanges_wpa(document.form, <% getIndex("wlan_idx"); %>);//Lucifer
	return true;
}

</SCRIPT>
</head>

<body onload="initial();LoadSetting();LoadSecuritySetting();" onunLoad="disable_auto_hint(0, 11);return unload_body();">
<div id="TopBanner"></div>

<div id="Loading" class="popup_bg"></div>
<div id="hiddenMask" class="popup_bg">
	<table cellpadding="5" cellspacing="0" id="dr_sweet_advise" class="dr_sweet_advise" align="center">
		<tr>
		<td>
			<div class="drword" id="drword"><#Main_alert_proceeding_desc4#> <#Main_alert_proceeding_desc1#>...
				<br/>
				<br/>
		    </div>
		  <div class="drImg"><img src="images/DrsurfImg.gif"></div>
			<div style="height:70px; "></div>
		</td>
		</tr>
	</table>
<!--[if lte IE 6.5]><iframe class="hackiframe"></iframe><![endif]-->
</div>

<iframe name="hidden_frame" id="hidden_frame" width="0" height="0" frameborder="0"></iframe>

<table class="content" align="center" cellpadding="0" cellspacing="0">
  <tr>
	<td width="23">&nbsp;</td>
	
	<!--=====Beginning of Main Menu=====-->
	<td valign="top" width="202">
	  <div id="mainMenu"></div>
	  <div id="subMenu"></div>
	</td>
	
	<td height="430" valign="top">
	  <div id="tabMenu" class="submenuBlock"></div><br>

<!--===================================Beginning of Main Content===========================================-->
<table width="98%" border="0" align="center" cellpadding="0" cellspacing="0">
  <tr>
	<td align="left" valign="top" >
	  <table width="98%" border="0" cellpadding="5" cellspacing="0" class="FormTitle">
		<thead>
		<tr>
		  <td><#menu5_1#> - <#menu5_1_1#></td>
		</tr>
		</thead>	
		
		<tbody>
		<tr>
		  <td bgcolor="#FFFFFF">

<form action="/start_apply.htm" method=POST name="form" target="hidden_frame">
<!-- for WPS -->

<input type="hidden" name="current_page" value="wlbasic.asp">
<input type="hidden" value="formWlEncrypt" name="typeForm">
<input type="hidden" name="action_mode" value="Restart_WLAN">	<!--2011.04.27 Jerry-->
<input type="hidden" name="flag" value="nodetect">	<!--2011.04.27 Jerry-->
<INPUT type=hidden name=wps_clear_configure_by_reg<% getIndex("wlan_idx"); %> value=0>
<INPUT type=hidden name=Band2G5GSupport value=<% getIndex("Band2G5GSupport"); %>>
<INPUT type=hidden name=wlBandMode value=<% getIndex("wlanBand2G5GSelect"); %>>
<input type="hidden" name="SSID_Setting" value="0">
<input type="hidden" id="wlan_ssid" name="wlan_ssid" value="">
<input type="hidden" id="wlan_ssid_id" name="wlan_ssid_id" value="">        
<input type="hidden" id="wlan_security_mode" name="method<% getIndex("wlan_idx"); %>" value="">
<input type="hidden" id="wlan_authtype" name="authType" value="">
<input type="hidden" id="wlan_wepkeylength" name="wepKeyLen<% getIndex("wlan_idx"); %>" value="">
<input type="hidden" id="wlan_wepkeyfmt" name="wlan_wepkeyfmt" value="">
<input type="hidden" id="wlan_wepdefaultkey" name="wlan_wepdefaultkey" value="">
<input type="hidden" id="wlan_wepkey" name="wlan_wepkey" value="">

<input type="hidden" id="wepEnabled" name="wepEnabled<% getIndex("wlan_idx"); %>" value="ON">
<input type="hidden" id="length" name="length<% getIndex("wlan_idx"); %>" value="">
<input type="hidden" id="format" name="format<% getIndex("wlan_idx"); %>" value="">
<input type="hidden" id="key" name="key<% getIndex("wlan_idx"); %>" value="">
<input type="hidden" id="wlan_wpa_psk_fmt" name="pskFormat<% getIndex("wlan_idx"); %>" value="0">
<input type="hidden" id="wlan_wpa_psk" name="pskValue<% getIndex("wlan_idx"); %>" value="">
<input type="hidden" id="wlan_wpa_preAuth" name="preAuth<% getIndex("wlan_idx"); %>" value="">
<input type="hidden" id="wlan_ieee8021x" name="use1x<% getIndex("wlan_idx"); %>" value="">

<input type="hidden" id="eap_type" name="eapType<% getIndex("wlan_idx"); %>" value="">
<input type="hidden" id="eap_inside_type" name="eapInsideType<% getIndex("wlan_idx"); %>" value="">
<input type="hidden" id="eap_user_id" name="eapUserId<% getIndex("wlan_idx"); %>" value="">
<input type="hidden" id="radius_user_name" name="radiusUserName<% getIndex("wlan_idx"); %>" value="">
<input type="hidden" id="radius_user_pass" name="radiusUserPass<% getIndex("wlan_idx"); %>" value="">
<input type="hidden" id="radius_user_cert_pass" name="radiusUserCertPass<% getIndex("wlan_idx"); %>" value="">

<input type="hidden" id="wlan_wapi_psk_fmt" name="wapiPskFormat<% getIndex("wlan_idx"); %>" value="">
<input type="hidden" id="wlan_wapi_psk" name="wapiPskValue<% getIndex("wlan_idx"); %>" value="">
<input type="hidden" id="wlan_as_server_ip" name="wapiASIP<% getIndex("wlan_idx"); %>" value="">
<input type="hidden" name="preferred_lang" id="preferred_lang" value="<% getInfo("preferred_lang"); %>">	<!--2011.04.14 Jerry-->

 <input type="hidden" name="rt_ssid2" value="<% apmib_char_to_ascii("WLANConfig11b", "ssid"); %>">
<input type="hidden"  name="auth_Type" value="">
<input type="hidden"  name="wpaAuth<% getIndex("wlan_idx"); %>" value="">

<input type="hidden" name="defaultTxKeyId<% getIndex("wlan_idx"); %>" value="">

<input type="hidden" name="key1<% getIndex("wlan_idx"); %>" value="">

<input type="hidden" name="key2<% getIndex("wlan_idx"); %>" value="">

<input type="hidden" name="key3<% getIndex("wlan_idx"); %>" value="">

<input type="hidden" name="key4<% getIndex("wlan_idx"); %>" value="">

<input type="hidden" name="asus_phrase<% getIndex("wlan_idx"); %>" value="">

<input type="hidden" name="ciphersuite<% getIndex("wlan_idx"); %>" value="">
<input type="hidden" name="wpa2ciphersuite<% getIndex("wlan_idx"); %>" value="">


<table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable" id="WLgeneral">

<tr>
  <!--<th>SSID:</th>-->
  <th width="50%"><a class="hintstyle" href="javascript:void(0);" onClick="openHint(0, 1);"><#WLANConfig11b_SSID_itemname#></a></th>
  <td>
	<input type="text" name="ssid<% getIndex("wlan_idx"); %>" class="input" size="32" maxlength="32" value="<% getInfo("ssid"); %>" onkeypress="return is_string(this)" >
  </td>
</tr>

<tr>
  <!--<th>Broadcast SSID:</th>-->
  <th><a class="hintstyle"  href="javascript:void(0);" onClick="openHint(0, 2);"><#WLANConfig11b_x_BlockBCSSID_itemname#></a></th>
  <td>
	<input type="radio" value="1" name="hiddenSSID<% getIndex("wlan_idx"); %>" class="input" onClick=""><#checkbox_Yes#>
	<input type="radio" value="0" name="hiddenSSID<% getIndex("wlan_idx"); %>" class="input" onClick=""><#checkbox_No#>
  </td>
</tr>

<tr>
  <!--<th>Band:</th>-->
  <th><a class="hintstyle" href="javascript:void(0);" onClick="openHint(0, 4);"><#WLANConfig11b_x_Mode11g_itemname#></a></th>
  <td>
	<select size="1" name="band<% getIndex("wlan_idx"); %>" class="input" onChange="nmode_limitation(); updateBand(document.form, wlan_idx); Set_onChangeBand(document.form, wlan_idx, document.form.band<% getIndex("wlan_idx"); %>, document.form.band<% getIndex("wlan_idx"); %>.selectedIndex); Set_SSIDbyBand(document.form, wlan_idx,document.form.band<% getIndex("wlan_idx"); %>, document.form.band<% getIndex("wlan_idx"); %>.selectedIndex); automode_hint();">

<script>
	RFType[wlan_idx] = <% getIndex("RFType"); %>;
	APMode[wlan_idx] = <% getIndex("wlanMode"); %>;
   	val = <% getIndex("band"); %>;
	if (val > 0)
		val = val-1;
    	bandIdx[wlan_idx] = val;
		bandIdxAP[wlan_idx]=bandIdx[wlan_idx];
		bandIdxClient[wlan_idx]=bandIdx[wlan_idx];
	showBand(document.form, wlan_idx);
</script>

	</select>
	<span id="band_hint" style="display:none"><#WLANConfig11n_automode_limition_hint#></span>
  </td>
</tr>

<!--display:none-->
<tr style="display:none">
  <th>Mode:</th>
  <td>
	<select size="1" name="mode<% getIndex("wlan_idx"); %>" class="input" onChange="updateMode_basic(document.form, wlan_idx)">		
	<%  getModeCombobox(); %>   
	</select>
  </td>
</tr>

<tr style="display:none">
  <th>Network Type:</th>
  <td>
	<select size="1" name="type<% getIndex("wlan_idx"); %>" class="input" onChange="updateType_basic(document.form, wlan_idx)">
<script>
	val = <% getIndex("networkType"); %>;
   	if ( val == 0 ) {
      		document.write("<option selected value=\"0\">Infrastructure </option>");
   	  	document.write("<option value=\"1\">Ad hoc</option>");
      	}

	if ( val == 1 ) {
     	  	document.write("<option value=\"0\">Infrastructure </option>");
   	  	document.write("<option selected value=\"1\">Ad hoc</option>");
      	}
</script>
	</select>
  </td>
</tr>

<tr id="channel_bounding" style="display:none">
  <!--<th>Channel Width:</th>-->
  <th><a class="hintstyle" href="javascript:void(0);" onClick="openHint(0, 14);"><#WLANConfig11b_ChannelBW_itemname#></a></th>
  <td>
	<select size="1" name="channelbound<% getIndex("wlan_idx"); %>" class="input" onChange="update_controlsideband(document.form, wlan_idx)">
     		<option value="0">20MHz</option>
		<option value="1">20/40MHz</option>
	</select>
  </td>
</tr>
<tr>
  <!--<th>Channel Number:</th>-->
  <th><a id="wl_channel_select" class="hintstyle" href="javascript:void(0);" onClick="openHint(0, 3);"><#WLANConfig11b_Channel_itemname#></a></th>
  <td>
	<select size="1" name="chan<% getIndex("wlan_idx"); %>" class="input" onChange="updateChan_selectedIndex(document.form, wlan_idx);"></select>
  </td>

</tr>

<tr id="control_sideband" style="display:none" >
  <th><a id="sideband_select" class="hintstyle" href="javascript:void(0);" onClick="openHint(0, 15);"><#WLANConfig11b_EChannel_itemname#></a></th>
  <td>
	<select size="1" name="controlsideband<% getIndex("wlan_idx"); %>" class="input">
		<option value="1">Auto</option>
	 </select>
	 <SCRIPT>
	//mars add{
	regDomain[wlan_idx] = <% getIndex("regDomain"); %>;
  	defaultChan[wlan_idx] = <% getIndex("channel"); %>;
	wlan_channel[wlan_idx] = <% getIndex("channel"); %>;
	updateChan(document.form, wlan_idx);//mars add}
	insertExtChannelOption(document.form, wlan_idx);
	//Lucifer
    </SCRIPT>
  </td>
</tr>

<tr id="wlan_wmm" style="display:none">
  <th>WMM:</th>
  <td>
	<select size="1" name="wlanwmm<% getIndex("wlan_idx"); %>" class="input" onChange="">
		<option value="0">Disabled</option>
		<option value="1">Enabled</option>
	 </select>
  </td>
</tr>

<tr style="display:none">
  <th>Data Rate:</th>
  <td>
	<select size="1" name="txRate<% getIndex("wlan_idx"); %>" class="input" onChange="checkTurboState()">
<script>
	band = <% getIndex("band"); %>
	auto= <% getIndex("rateAdaptiveEnabled"); %>;
 	txrate = <% getIndex("fixTxRate"); %>;
     	rf_num = <% getIndex("rf_used"); %>;
	
	var rate_mask = [15,1,1,1,1,2,2,2,2,2,2,2,2,4,4,4,4,4,4,4,4,8,8,8,8,8,8,8,8];
	var rate_name=["Auto","1M","2M","5.5M","11M","6M","9M","12M","18M","24M","36M","48M","54M", "MCS0", "MCS1",
		"MCS2", "MCS3", "MCS4", "MCS5", "MCS6", "MCS7", "MCS8", "MCS9", "MCS10", "MCS11", "MCS12", "MCS13", "MCS14", "MCS15"];
	var mask=0;
	var defidx=0;
	var idx, i, rate;
	
	if (auto)
		txrate=0;
	if (band & 1)
		mask |= 1;
	if ((band&2) || (band&4))
		mask |= 2;
	if (band & 8) {
		if (rf_num == 2)
			mask |= 12;	
		else
			mask |= 4;
	}	
	for (idx=0, i=0; i<=28; i++) {
		if (rate_mask[i] & mask) {
			if (i == 0)
				rate = 0;
			else
				rate = (1 << (i-1));
			if (txrate == rate)
				defidx = idx;
			document.write('<option value="' + i + '">' + rate_name[i] + '\n');
			idx++;
		}
	}
	document.form.elements["txRate"+ <% getIndex("wlan_idx"); %>].selectedIndex=defidx;
</script>
	</select>
  </td>
</tr>

<tr style="display:none">
  <td colspan="2">
<script>
	var wlanMacClone_wlan_idx = <% getIndex("wlan_idx"); %>;
	var wlanMacClone_tmp = <% getIndex("wlanMacClone"); %>;
	var wlanMacClone_checked = "";
	if(wlanMacClone_tmp)
		wlanMacClone_checked = "checked"; 
	document.write("<input type=\"checkbox\" name=\"wlanMacClone" + wlanMacClone_wlan_idx + "\" value=\"ON\" " + wlanMacClone_checked + ">&nbsp;&nbsp; Enable Mac Clone (Single Ethernet Client)");
</script>
  </td>
</tr>

<tr style="display:none">
  <td colspan="2">SSID of Extended Interface:&nbsp;&nbsp;
  	<input type="text" name="repeaterSSID<% getIndex("wlan_idx"); %>" size="33" maxlength="32" value="<% getInfo("repeaterSSID"); %>">
  </td>
</tr>


<tr>
  <th><a class="hintstyle" href="javascript:void(0);" onClick="openHint(0, 5);"><#WLANConfig11b_AuthenticationMethod_itemname#></a></th>
  <td>
	<select id="authMode_asus" name="authMode<% getIndex("wlan_idx"); %>" class="input" onChange="return change_auth(this);">
		<option value="open">Open System</option>
		<option value="shared">Shared Key</option>
		<option value="psk">WPA-Personal</option>
		<option value="psk2">WPA2-Personal</option>
		<option value="pskauto">WPA-Auto-Personal</option>
		<option value="wpa">WPA-Enterprise</option>
		<option value="wpa2">WPA2-Enterprise</option>
		<option value="radius">Radius with 802.1x</option>
	</select>
  </td>
</tr>

<tr id="crypto_asus" style="display:none">
  <th><a class="hintstyle" href="javascript:void(0);" onClick="openHint(0, 6);"><#WLANConfig11b_WPAType_itemname#></a></th>
  <td>
	<select name="crypto<% getIndex("wlan_idx"); %>" class="input" onChange="automode_hint();"> <!-- define in general.js, plz grep "TKIP" -->
		<option value="aes">AES</option>
		<option value="tkip+aes">TKIP+AES</option>
	</select>
  </td>
</tr>
			  
<tr id="wpaPsk_asus" style="display:none">
  <th><a class="hintstyle" href="javascript:void(0);" onClick="openHint(0, 7);"><#WLANConfig11b_x_PSKKey_itemname#></a></th>
  <td>
	<input type="text" name="wpaPsk<% getIndex("wlan_idx"); %>" maxlength="64" class="input" size="32" value="">
  </td>
</tr>
			  		  
<tr id="keyLength_asus" style="display:none">
  <th><a class="hintstyle" href="javascript:void(0);" onClick="openHint(0, 9);"><#WLANConfig11b_WEPType_itemname#></a></th>
  <td>
	<select name="keyLength<% getIndex("wlan_idx"); %>" class="input" onChange="change_wep();automode_hint();">
		<option value="0">None</option>
		<option value="1">WEP-64bits</option>
		<option value="2">WEP-128bits</option>
	</select>
  <br>
  <span name="key_des"></span>
  </td>
</tr>

<!--key index-->
<tr id="rt_key_asus" style="display:none">
	<th><a class="hintstyle" href="javascript:void(0);" onClick="openHint(0, 10);"><#WLANConfig11b_WEPDefaultKey_itemname#></a></th>
	<td>
		<select name="rt_key" class="input"  onChange="return change_common(this, 'WLANConfig11b', 'rt_key');">
		<option value="1">1</option>
		<option value="2">2</option>
		<option value="3">3</option>
		<option value="4">4</option>
		</select>
	</td>
</tr>

<!--wep key-->
<tr id="wepKey_asus" style="display:none">
  <th><a class="hintstyle" href="javascript:void(0);" onClick="openHint(0, 18);"><#WLANConfig11b_WEPKey1_itemname#></th>
  <td>
	<input type="text" id="key" name="wepKey<% getIndex("wlan_idx"); %>" class="input" maxlength="32" size="34" value="" onKeyUp="return change_wepKey(this);">
  </td>
</tr>

<tr id="rt_key2_asus" style="display:none">
  <th><a class="hintstyle" href="javascript:void(0);" onClick="openHint(0, 18);"><#WLANConfig11b_WEPKey2_itemname#></th>
  <td>
	<input type="text" name="rt_key2" id="rt_key2" maxlength="32" class="input" size="34" value="" onKeyUp="return change_wepKey(this);">
  </td>
</tr>
			  
<tr id="rt_key3_asus" style="display:none">
  <th><a class="hintstyle" href="javascript:void(0);" onClick="openHint(0, 18);"><#WLANConfig11b_WEPKey3_itemname#></th>
  <td>
	<input type="text" name="rt_key3" id="rt_key3" maxlength="32" class="input" size="34" value="" onKeyUp="return change_wepKey(this);">
  </td>
</tr>
			  
<tr id="rt_key4_asus" style="display:none">
  <th><a class="hintstyle" href="javascript:void(0);" onClick="openHint(0, 18);"><#WLANConfig11b_WEPKey4_itemname#></th>
  <td>
	<input type="text" name="rt_key4" id="rt_key4" maxlength="32" class="input" size="34" value="" onKeyUp="return change_wepKey(this);">
  </td>
</tr>

<!--asus passphrase-->
<tr id="rt_phrase_x_asus" style="display:none">
  <th><a class="hintstyle" href="javascript:void(0);" onClick="openHint(0, 8);"><#WLANConfig11b_x_Phrase_itemname#></a></th>
  <td>
	<input type="text" name="rt_phrase_x" maxlength="64" class="input" size="32" value="" onKeyUp="return is_wlphrase('WLANConfig11b', 'rt_phrase_x', this);">
  </td>
</tr>

<!--radius setting-->
<tr id="radiusIP_asus" style="display:none">
  <th><a class="hintstyle" href="javascript:void(0);"  onClick="openHint(2,1);"><#WLANAuthentication11a_ExAuthDBIPAddr_itemname#></a></th>
  <td>
	<input id="radius_ip" name="radiusIP<% getIndex("wlan_idx"); %>" class="input" size="16" maxlength="15" value="">
  </td>
</tr>

<tr id="radiusPort_asus" style="display:none">
  <th><a class="hintstyle" href="javascript:void(0);" onClick="openHint(2,2);"><#WLANAuthentication11a_ExAuthDBPortNumber_itemname#></a></th>
  <td>
	<input type="text" id="radius_port" name="radiusPort<% getIndex("wlan_idx"); %>" class="input" size="5" maxlength="5" value="1812">
  </td>
</tr>

<tr id="radiusPass_asus" style="display:none">
  <th><a class="hintstyle" href="javascript:void(0);" onClick="openHint(2,3);"><#WLANAuthentication11a_ExAuthDBPassword_itemname#></a></th>
  <td>
	<input type="password" id="radius_pass" name="radiusPass<% getIndex("wlan_idx"); %>" size="32" maxlength="64" value="">
  </td>
</tr>

<tr id="wapi_auth" style="display:none">
<td>
<input name="wapiAuth<% getIndex("wlan_idx"); %>" type="radio" value="eap" >PSK
<input name="wapiAuth<% getIndex("wlan_idx"); %>" type="radio" value="psk">Pre-Shared&nbsp;Key
</td>
</tr>

<tr align="right">
  <td colspan="2">
	<input type="hidden" value="/wlbasic.asp" name="submit-url">
	<input type="button" value="<#CTL_apply#>" name="save" class="button" onClick="applyRule();">
	<input type="hidden" name="basicrates<% getIndex("wlan_idx"); %>" value=0>
	<input type="hidden" name="operrates<% getIndex("wlan_idx"); %>" value=0>
  </td>
</tr>
  </table>

<script>
   	usedBand[wlan_idx] = <% getIndex("band"); %>;

   	updateState(document.form, wlan_idx);
	var mssid_num = <% getIndex("wlan_mssid_num"); %>;
	if(mssid_num == 0)
		disableButton(document.form.elements["multipleAP<% getIndex("wlan_idx"); %>"]);	
</script>

</form>

</td></tr>
		</tbody>
  </table>
</td>

	<!--==============Beginning of hint content=============-->
	<td id="help_td" style="width:15px;" valign="top">
<form name="hint_form"></form>
	  <div id="helpicon" onClick="openHint(0, 0);" title="<#Help_button_default_hint#>">
		<img src="images/help.gif">
	  </div>
	  
	  <div id="hintofPM" style="display:none;">
		<table width="100%" cellpadding="0" cellspacing="1" class="Help" bgcolor="#999999">
		  <thead>
		  <tr>
			<td>
			  <div id="helpname" class="AiHintTitle"></div>
			  <a href="javascript:closeHint();"><img src="images/button-close.gif" class="closebutton" /></a>
			</td>
		  </tr>
		  </thead>
		  
		  <tbody>
		  <tr>
			<td valign="top">
			  <div id="hint_body" class="hint_body2"></div>
			  <iframe id="statusframe" name="statusframe" class="statusframe" src="" frameborder="0"></iframe>
			</td>
		  </tr>
		  </tbody>
		</table>
	  </div>
	</td>
	<!--==============Ending of hint content=============-->
  </tr>
</table>
<!--===================================Ending of Main Content===========================================-->

	</td>
	
	<td width="10" align="center" valign="top"></td>
  </tr>
</table>

<div id="footer"></div>
</body>
</html>
