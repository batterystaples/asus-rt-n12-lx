/*==============================================================================*/
/*   wlbasic.asp and wizard-wlan1.asp  tcpiplan.asp*/

// for WPS ---------------------------------------------------->>
var wps_warn1='The SSID had been configured by WPS. Any change of the setting ' +
				'may cause stations to be disconnected. ' + 
				'Are you sure you want to continue with the new setting?';
var wps_warn2='AP Mode had been configured by WPS. Any change of the setting ' +
				'may cause stations to be disconnected. ' + 
				'Are you sure you want to continue with the new setting?';
var wps_warn3='The security setting had been configured by WPS. Any change of the setting ' +
				'may cause stations to be disconnected. ' + 
				'Are you sure you want to continue with the new setting?';
var wps_warn4='The WPA Enterprise Authentication cannot be supported by WPS. ' +
				'Use this configuration will cause WPS be disabled. ' + 
				'Are you sure you want to continue with the new setting?';
var wps_warn5='The 802.1x Authentication cannot be supported by WPS. ' +
				'Use this configuration will cause WPS be disabled. ' + 
				'Are you sure you want to continue with the new setting?';
var wps_warn6='WDS mode cannot be supported by WPS. ' +
				'Use this configuration will cause WPS be disabled. ' + 
				'Are you sure you want to continue with the new setting?';
var wps_warn7='Adhoc Client mode cannot be supported by WPS. ' +
				'Use this configuration will cause WPS be disabled. ' + 
				'Are you sure you want to continue with the new setting?';
var encrypt_11n = 'Invalid Encryption Mode! WPA or WPA2, Cipher suite AES should be used for 802.11n band.';
var encrypt_basic = 'The Encryption Mode is not suitable for 802.11n band, please modify wlan encrypt setting, or it will not work properly.';
var encrypt_confirm='Are you sure you want to continue with this encrypt mode for 11n band? It may not get good performance while the user is using wlan network!';
var wps_wep_key_old;

function check_wps_enc(enc, radius, auth)
{
	if (enc == 0 || enc == 1) {
		if (radius != 0)
			return 2;
	}		
	else {
		if (auth & 1)
			return 2;
	}
	return 0;
}

function check_wps_wlanmode(mo, type)
{
	if (mo == 2) {
		return 1;
	}
	if (mo == 1 && type != 0) {
		return 1;
	}
	return 0;
}
//<<----------------------------------------------- for WPS
function disableDNSinput()
{
   disableTextField(document.tcpip.dns1);
   disableTextField(document.tcpip.dns2);
   disableTextField(document.tcpip.dns3);
}

function enableDNSinput()
{
   enableTextField(document.tcpip.dns1);
   enableTextField(document.tcpip.dns2);
   enableTextField(document.tcpip.dns3);
}

function autoDNSclicked()
{
  disableDNSinput();
}

function manualDNSclicked()
{
  enableDNSinput();
}



function skip () { this.blur(); }
function disableTextField (field) {
  if (document.all || document.getElementById)
    field.disabled = true;
  else {
    field.oldOnFocus = field.onfocus;
    field.onfocus = skip;
  }
}

function enableTextField (field) {
  if (document.all || document.getElementById)
    field.disabled = false;
  else {
    field.onfocus = field.oldOnFocus;
  }
}

function verifyBrowser() {
	var ms = navigator.appVersion.indexOf("MSIE");
	ie4 = (ms>0) && (parseInt(navigator.appVersion.substring(ms+5, ms+6)) >= 4);
	var ns = navigator.appName.indexOf("Netscape");
	ns= (ns>=0) && (parseInt(navigator.appVersion.substring(0,1))>=4);
	if (ie4)
		return "ie4";
	else
		if(ns)
			return "ns";
		else
			return false;
}

function saveChanges_basic(form, wlan_id)
{	
  mode =form.elements["mode"+wlan_id] ;

  ssid =form.elements["ssid"+wlan_id] ;			//mode.selectedIndex=4 means AP+MESH
  // P2P_SUPPORT
  if ( (mode.selectedIndex==0 || mode.selectedIndex==3 ) && ssid.value=="") {
	//alert('SSID cannot be empty');
	alert( '<#JS_fieldblank#>');
	ssid.value = ssid.defaultValue;
	ssid.focus();
	return false;
   }

	var idx_value= form.elements["band"+wlan_id].selectedIndex;
	var band_value= form.elements["band"+wlan_id].options[idx_value].value;
	var band = parseInt(band_value, 10) + 1;

	var wlBandMode =form.elements["wlBandMode"].value ;
		
	if(wlBandMode == 3) // 3:BANDMODESIGNLE
	{
		var selectText=form.elements["band"+wlan_id].options[idx_value].text.substr(0,1);
		
		if(selectText=='2') //match '2'
			form.elements["Band2G5GSupport"].value = 1;//1:PHYBAND_2G
		else
			form.elements["Band2G5GSupport"].value = 2;//2:PHYBAND_5G										
	}

	basicRate=0;
	operRate=0;
	if (band & 1) {
		basicRate|=0xf;
		operRate|=0xf;		
	}
	if ( (band & 2) || (band & 4) ) {
		operRate|=0xff0;
		if (!(band & 1)) {
			if (WiFiTest)
				basicRate=0x15f;
			else
				basicRate=0x1f0;
		}			
	}
	if (band & 8) {
		if (!(band & 3))
			operRate|=0xfff;	
		if (band & 1)
			basicRate=0xf;
		else if (band & 2)			
			basicRate=0x1f0;
		else
			basicRate=0xf;
	}
	
	operRate|=basicRate;
	if (band && band != usedBand[wlan_id]) {
		form.elements["basicrates"+wlan_id].value = basicRate;
		form.elements["operrates"+wlan_id].value = operRate;
	}
	else {
		form.elements["basicrates"+wlan_id].value = 0;
		form.elements["operrates"+wlan_id].value = 0;
	}

   return true;
}
/*==============================================================================*/
function show_div(show,id) {
	if(show)
		document.getElementById(id).style.display = "";
    	else	    
    		document.getElementById(id).style.display = "none";
}

/*   tcpipwan.asp */
/*-- keith: add l2tp support. 20080515  */
function wanShowDiv(pptp_bool, dns_bool, dnsMode_bool, pppoe_bool, static_bool, l2tp_bool, USB3G_bool)
{
 	show_div(pptp_bool,"pptp_div");
  	show_div(dns_bool,"dns_div");
  	show_div(dnsMode_bool,"dnsMode_div");
  	show_div(pppoe_bool,"pppoe_div");
	show_div(static_bool,"static_div"); 
	show_div(l2tp_bool,"l2tp_div"); /*-- keith: add l2tp support. 20080515  */
    show_div(USB3G_bool, "USB3G_div"  );

  	if (pptp_bool==0 && pppoe_bool==0 && static_bool==0 && dns_bool && l2tp_bool==0 && USB3G_bool==0) /*-- keith: add l2tp support. 20080515  */
  	  	show_div(1,"dhcp_div");  	
  	else
  		show_div(0,"dhcp_div");  
}

function saveChanges_wan(form)
{
  var wanType = form.wanType.selectedIndex ;
  if ( wanType == 0 ){ //static IP
	  if ( checkIpAddr(form.wan_ip, 'Invalid IP address') == false )
	    return false;
  	  if (checkIPMask(form.wan_mask) == false)
  		return false ;

	  if ( form.wan_ip.value == form.wan_gateway.value ){
		alert("<#IPConnection_warning_WANIPEQUALGatewayIP#>");
	      return false;
	  }

	  if (form.wan_gateway.value!="" && form.wan_gateway.value!="0.0.0.0") {

	    if ( checkIpAddr(form.wan_gateway, 'Invalid default gateway address') == false )
	      return false;
	    if ( !checkSubnet(form.wan_ip.value,form.wan_mask.value,form.wan_gateway.value)) {
		alert(form.wan_gateway.value + '<#JS_validip#>');
	      form.wan_gateway.value = form.wan_gateway.defaultValue;
	      form.wan_gateway.focus();
	      return false;
	    }
	  }
	  else
	      form.wan_gateway.value = '0.0.0.0';  

	  if (form.fixedIpMtuSize != null){
	     d2 = getDigit(form.fixedIpMtuSize.value, 1);
	     if ( validateKey(form.fixedIpMtuSize.value) == 0 ||
			(d2 > 1500 || d2 < 1400) ) {
			alert('<#JS_validrange#> 1400 <#JS_validrange_to#> 1500');
			form.fixedIpMtuSize.value = form.fixedIpMtuSize.defaultValue;
			form.fixedIpMtuSize.focus();
			return false;
	     }
	  }    
  }
  else if ( wanType == 1){ //dhcp wanType
  	  if (form.dhcpMtuSize != null){
	     d2 = getDigit(form.dhcpMtuSize.value, 1);
	     if ( validateKey(form.dhcpMtuSize.value) == 0 ||
			(d2 > 1492 || d2 < 1400) ) {
			alert('<#JS_validrange#> 1400 <#JS_validrange_to#> 1492');
			form.dhcpMtuSize.value = form.dhcpMtuSize.defaultValue;
			form.dhcpMtuSize.focus();
			return false;
	     }
	  } 
  }
  else if ( wanType == 2){ //pppoe wanType
	   if (form.pppUserName.value=="") {
		  alert('<#JS_fieldblank#>');
		  form.pppUserName.value = form.pppUserName.defaultValue;
		  form.pppUserName.focus();
		  return false;
	   }
	   if (form.pppPassword.value=="") {
		  alert('<#JS_fieldblank#>');
		  form.pppPassword.value = form.pppPassword.defaultValue;
		  form.pppPassword.focus();
		  return false;
	   }
	   if ( form.pppConnectType != null){
	     if ( form.pppConnectType.selectedIndex == 1 ) {
		d1 = getDigit(form.pppIdleTime.value, 1);
		if ( validateKey(form.pppIdleTime.value) == 0 ||
			(d1 > 1000 || d1 < 1) ) {
			alert('<#JS_validrange#> 1 <#JS_validrange_to#> 1000');
			form.pppIdleTime.focus();
			return false;
		}
	     }
	   } 
           
           if ( form.pppMtuSize != null){
	     d2 = getDigit(form.pppMtuSize.value, 1);
	     if ( validateKey(form.pppMtuSize.value) == 0 ||
			(d2 > 1492 || d2 < 1360) ) {
			alert('<#JS_validrange#> 1360 <#JS_validrange_to#> 1492');
			form.pppMtuSize.value = form.pppMtuSize.defaultValue;
			form.pppMtuSize.focus();
			return false;
	     }
	   }  // if (pppMtuSize !=null)
  }
  else if ( wanType == 3){ //pptp wanType
	if(!form.wan_pptp_use_dynamic_carrier_radio[0].checked == true)
	{
	  if ( checkIpAddr(form.pptpIpAddr, 'Invalid IP address') == false )
	    return false;
	  if (checkIPMask(form.pptpSubnetMask) == false)
  			return false ;

	  if ( checkIpAddr(form.pptpServerIpAddr, 'Invalid server IP address') == false )
	      return false;

	  if ( !checkSubnet(form.pptpIpAddr.value,form.pptpSubnetMask.value,form.pptpDefGw.value)) {
	      alert(form.pptpDefGw.value + '<#JS_validip#>');
	      form.pptpDefGw.value = form.pptpDefGw.defaultValue;
	      form.pptpDefGw.focus();
	      return false;
	  }
	}
	  if ( checkIpAddr(form.pptpServerIpAddr, 'Invalid server IP address') == false )
	      return false;

	  if (form.pptpUserName.value=="") {
		  alert('<#JS_fieldblank#>');
		  form.pptpUserName.value = form.pptpUserName.defaultValue;
		  form.pptpUserName.focus();
		  return false;
	  }
	  if (form.pptpPassword.value=="") {
		  alert('<#JS_fieldblank#>');
		  form.pptpPassword.value = form.pptpPassword.defaultValue;
		  form.pptpPassword.focus();
		  return false;
	  }
	   if ( form.pptpConnectType != null){
			     if ( form.pptpConnectType.selectedIndex == 1 ) {
				d1 = getDigit(form.pptpIdleTime.value, 1);
				if ( validateKey(form.pptpIdleTime.value) == 0 ||
					(d1 > 1000 || d1 < 1) ) {
					alert('<#JS_validrange#> 1 <#JS_validrange_to#> 1000');
					form.pptpIdleTime.focus();
					return false;
				}
			     }
	   }
	  if ( form.pptpMtuSize != null){
	  	d2 = getDigit(form.pptpMtuSize.value, 1);
	   	if ( validateKey(form.pptpMtuSize.value) == 0 ||
			(d2 > 1460 || d2 < 1400) ) {
			alert('<#JS_validrange#> 1400 <#JS_validrange_to#> 1460');
			form.pptpMtuSize.value = form.pptpMtuSize.defaultValue;
			form.pptpMtuSize.focus();
			return false;
	   	}
	  } 
   } 
   /*-- keith: add l2tp support. 20080515  */
   else if ( wanType == 4){ //l2tp wanType
	if(!form.wan_l2tp_use_dynamic_carrier_radio[0].checked == true)
	{
	  if ( checkIpAddr(form.l2tpIpAddr, 'Invalid IP address') == false )
	    return false;
	  if (checkIPMask(form.l2tpSubnetMask) == false)
  			return false ;

	  if ( !checkSubnet(form.l2tpIpAddr.value,form.l2tpSubnetMask.value,form.l2tpDefGw.value)) {
	      alert(form.l2tpDefGw.value + '<#JS_validip#>');
	      form.l2tpDefGw.value = form.l2tpDefGw.defaultValue;
	      form.l2tpDefGw.focus();
	      return false;
	  }
	}
	  if ( checkIpAddr(form.l2tpServerIpAddr, 'Invalid server IP address') == false )
	      return false;

	  if (form.l2tpUserName.value=="") {
		  alert('<#JS_fieldblank#>');
		  form.l2tpUserName.value = form.l2tpUserName.defaultValue;
		  form.l2tpUserName.focus();
		  return false;
	  }
	  if (form.l2tpPassword.value=="") {
		  alert('<#JS_fieldblank#>');
		  form.l2tpPassword.value = form.l2tpPassword.defaultValue;
		  form.l2tpPassword.focus();
		  return false;
	  }
	   if ( form.l2tpConnectType != null){
	     if ( form.l2tpConnectType.selectedIndex == 1 ) {
				d1 = getDigit(form.l2tpIdleTime.value, 1);
				if ( validateKey(form.l2tpIdleTime.value) == 0 ||
					(d1 > 1000 || d1 < 1) ) {
					alert('<#JS_validrange#> 1 <#JS_validrange_to#> 1000');
					form.l2tpIdleTime.focus();
					return false;
				}
	     }
	   } 
	  if ( form.l2tpMtuSize != null){
	  	d2 = getDigit(form.l2tpMtuSize.value, 1);
	   	if ( validateKey(form.l2tpMtuSize.value) == 0 ||
			(d2 > 1460 || d2 < 1400) ) {
			alert('<#JS_validrange#> 1400 <#JS_validrange_to#> 1460');
			form.l2tpMtuSize.value = form.l2tpMtuSize.defaultValue;
			form.l2tpMtuSize.focus();
			return false;
	   	}
	  } 
   }
// --------------- USB3G wanType ---------------
   else if ( wanType == 5){
        if (form.USB3G_APN.value=="") {
	    alert('<#JS_fieldblank#>');
            form.USB3G_APN.value = form.USB3G_APN.defaultValue;
            form.USB3G_APN.focus();
            return false;
        }

        if (form.USB3G_DIALNUM.value=="") {
	    alert('<#JS_fieldblank#>');
            form.USB3G_DIALNUM.value = form.USB3G_DIALNUM.defaultValue;
            form.USB3G_DIALNUM.focus();
            return false;
        }

        if ( form.USB3GConnectType != null){
            if ( form.USB3GConnectType.selectedIndex == 1 ) {
                d1 = getDigit(form.USB3GIdleTime.value, 1);
                if ( validateKey(form.USB3GIdleTime.value) == 0 || (d1 > 1000 || d1 < 1) ) {
		    alert('<#JS_validrange#> 1 <#JS_validrange_to#> 1000');
                    form.USB3GIdleTime.focus();
                    return false;
                }
            }
        }
        if ( form.USB3GMtuSize != null){
            d2 = getDigit(form.USB3GMtuSize.value, 1);
            if ( validateKey(form.USB3GMtuSize.value) == 0 || (d2 > 1490 || d2 < 1420) ) {
		alert('<#JS_validrange#> 1420 <#JS_validrange_to#> 1490');
                form.USB3GMtuSize.value = form.USB3GMtuSize.defaultValue;
                form.USB3GMtuSize.focus();
			return false;
	   	}
	  } 
   } 

   if( wanType != 0 ) { // not static IP
	   group = form.dnsMode;
	   for (var r = 0; r < group.length; r++)
		  if (group[r].checked)
		    break;

	   if (r == 1) {
	      if (form.dns1.value==""){
			alert('<#JS_fieldblank#>');
	      		return false;
		}	
	      if (form.dns1.value!="0.0.0.0") {
		  if ( checkIpAddr(form.dns1, 'Invalid DNS1 address') == false )
		     return false;
	      }		
	      if (form.dns2 != null){
	      	if (form.dns2.value=="")
			form.dns2.value="0.0.0.0";
	      	if (form.dns2.value!="0.0.0.0") {
		 if ( checkIpAddr(form.dns2, 'Invalid DNS2 address') == false )
		     return false;
	      	}			
	      }//dns2 != null
	      if (form.dns3 != null){	
	      	if (form.dns3.value=="")
			form.dns3.value="0.0.0.0";
	      	if (form.dns3.value!="0.0.0.0") {
		  if ( checkIpAddr(form.dns3, 'Invalid DNS3 address') == false )
		     return false;
	      	}			
	      }// dns3 != null
	   }
   }
   else{
	  if (form.dns1.value==""){
		alert('<#JS_fieldblank#>');
	      	return false;
	  }
	  if (form.dns1.value!="0.0.0.0") {
	     if ( checkIpAddr(form.dns1, 'Invalid DNS1 address') == false )
	       return false;
	  }
	  	    
	  if (form.dns2 != null){  
	  	if (form.dns2.value=="")
	    		form.dns2.value="0.0.0.0";
	  	if (form.dns2.value!="0.0.0.0") {
	    		if ( checkIpAddr(form.dns2, 'Invalid DNS2 address') == false )
	      			return false;
	  	}	    		
	  }
	  if (form.dns3 != null){
	  	if (form.dns3.value=="")
	    		form.dns3.value="0.0.0.0";
	  	if (form.dns3.value!="0.0.0.0") {
	    		if ( checkIpAddr(form.dns3, 'Invalid DNS3 address') == false )
	      			return false;
	  	}	    		
	  } 
   }
   if (form.wan_macAddr != null){
   	if (form.wan_macAddr.value == "")
		form.wan_macAddr.value = "000000000000";
	var str = form.wan_macAddr.value;
   	if ( str.length < 12) {
		alert('<#JS_validmac#>');
		form.wan_macAddr.value = form.wan_macAddr.defaultValue;
		form.wan_macAddr.focus();
		return false;
  	}
   	for (var i=0; i<str.length; i++) {
     		if ( (str.charAt(i) >= '0' && str.charAt(i) <= '9') ||
			(str.charAt(i) >= 'a' && str.charAt(i) <= 'f') ||
			(str.charAt(i) >= 'A' && str.charAt(i) <= 'F') )
			continue;
		alert('<#JS_validmac#>');
		form.wan_macAddr.value = form.wan_macAddr.defaultValue;
		form.wan_macAddr.focus();
		return false;
   	}  	
   }

   return true;
}
/*==============================================================================*/
/*   wlbasic.asp */
function enableWLAN(form, wlan_id)
{
	var idx_value= form.elements["band"+wlan_id].selectedIndex;
	var band_value= form.elements["band"+wlan_id].options[idx_value].value;
	var chan_boundIdx = form.elements["channelbound"+wlan_id].selectedIndex;	
	var mode_idx = form.elements["mode"+wlan_id].selectedIndex; 
	var mode_value =form.elements["mode"+wlan_id].options[mode_idx].value; 	
	
	if(form.elements["multipleAP"+wlan_id] != null) { // for multiple ap
		if (mode_value == 0 || mode_value == 3)
			enableButton(form.elements["multipleAP"+wlan_id]);
		else
			disableButton(form.elements["multipleAP"+wlan_id]);
	}
	
  if (mode_value !=1) {	//mode != client
  	disableTextField(form.elements["type"+wlan_id]); //network type
  	if(form.elements["showMac"+wlan_id]!= null) {
		// mode ==AP or AP+WDS or MPP+AP or MAP
  		if (mode_value ==0 || mode_value ==3 || mode_value ==4 || mode_value ==6){	
  			enableButton(form.elements["showMac"+wlan_id]);
			
			// plus note, just AP or AP+WDS need Multi-AP,under MPP+AP or MAP mode disable multi-AP
			if (mode_value ==0 || mode_value ==3)	
			if(form ==document.wlanSetup){  	
				if(form.elements["multipleAP"+wlan_id] != null)
					enableButton(form.elements["multipleAP"+wlan_id]);
			}		
  		}else{
  			disableButton(form.elements["showMac"+wlan_id]);
  			if(form ==document.wlanSetup){  	
				if(form.elements["multipleAP"+wlan_id] != null)
					disableButton(form.elements["multipleAP"+wlan_id]);
			}	
  		}
  	}
  	enableTextField(form.elements["chan"+wlan_id]);
  }
  else {	// mode == client
    	if (disableSSID[wlan_id])
  		disableTextField(form.elements["type"+wlan_id]);
  	else
   		enableTextField(form.elements["type"+wlan_id]);   	   	
    	
   	if(form.elements["showMac"+wlan_id] != null)
		disableButton(form.elements["showMac"+wlan_id]);
	if(form ==document.wlanSetup){  	
		if(form.elements["multipleAP"+wlan_id] != null)
			disableButton(form.elements["multipleAP"+wlan_id]);
	}	
	if (form.elements["type"+wlan_id].selectedIndex==0) {
		disableTextField(form.elements["chan"+wlan_id]);
	}
	else {
		enableTextField(form.elements["chan"+wlan_id]);
	}

  }
  if (disableSSID[wlan_id]){
	disableTextField(form.elements["ssid"+wlan_id]);
 	disableTextField(form.elements["mode"+wlan_id]);  	
  }
  else {
  	if (mode_value !=2)
  		enableTextField(form.elements["ssid"+wlan_id]);
  	else
  		disableTextField(form.elements["ssid"+wlan_id]);
  		
  	enableTextField(form.elements["mode"+wlan_id]); 
  }  
  enableTextField(form.elements["band"+wlan_id]);

  if(form.elements["mode"+wlan_id].selectedIndex == 1 && opmode != 2) // client mode but not wisp
  	enableCheckBox(form.elements["wlanMacClone"+wlan_id]);
  else
  	disableCheckBox(form.elements["wlanMacClone"+wlan_id]);
  	
	if(band_value == 9 || band_value ==10 || band_value==7 || band_value==11){
	  	enableTextField(form.elements["channelbound"+wlan_id]);
	  
	  	
	  	if(chan_boundIdx == 1)
	  		enableTextField(form.elements["controlsideband"+wlan_id]);
	  	else 	
	  		 disableTextField(form.elements["controlsideband"+wlan_id]);
	 }
	if(form ==document.wlanSetup){  	
		enableTextField(form.elements["txRate"+wlan_id]);	
  		enableTextField(form.elements["hiddenSSID"+wlan_id]);	
	}
}
function disableWLAN(form, wlan_id)
{
  disableTextField(form.elements["mode"+wlan_id]);
  disableTextField(form.elements["band"+wlan_id]);
  disableTextField(form.elements["type"+wlan_id]); 
  disableTextField(form.elements["ssid"+wlan_id]);
  disableTextField(form.elements["chan"+wlan_id]);
  disableTextField(form.elements["channelbound"+wlan_id]);
  disableTextField(form.elements["controlsideband"+wlan_id]);
if(form == document.wlanSetup){  
  disableTextField(form.elements["hiddenSSID"+wlan_id]);
  disableTextField(form.elements["txRate"+wlan_id]);
  disableButton(form.elements["multipleAP"+wlan_id]);
}  
  disableCheckBox(form.elements["wlanMacClone"+wlan_id]);

  if(form.elements["showMac"+wlan_id]!= null)
  	disableButton(form.elements["showMac"+wlan_id]);
}
function updateIputState(form, wlan_id)
{

}

function disableButton (button) {
  //if (verifyBrowser() == "ns")
  //	return;
  if (document.all || document.getElementById)
    button.disabled = true;
  else if (button) {
    button.oldOnClick = button.onclick;
    button.onclick = null;
    button.oldValue = button.value;
    button.value = 'DISABLED';
  }
}

function enableButton (button) {
  //if (verifyBrowser() == "ns")
  //	return;
  if (document.all || document.getElementById)
    button.disabled = false;
  else if (button) {
    button.onclick = button.oldOnClick;
    button.value = button.oldValue;
  }
}

function showChannel5G(form, wlan_id)
{
	var sideBand=form.elements["controlsideband"+wlan_id].value;
	form.elements["chan"+wlan_id].length=startChanIdx[wlan_id];
	if (startChanIdx[wlan_id] == 0)
		defChanIdx=0;
	else
		defChanIdx=1;

	if (0 && startChanIdx[wlan_id]==0) { // no auto selection
		form.elements["chan"+wlan_id].options[0] = new Option("Auto", 0, false, false);
		if (0 == defaultChan[wlan_id]) {
			form.elements["chan"+wlan_id].selectedIndex = 0;
			defChanIdx = 0;
		}
		startChanIdx[wlan_id]++;		
	}
	if (regDomain[wlan_id]==6) {	// MKK
		for (idx=startChanIdx[wlan_id], chan=34; chan<=64; idx++, chan+=2) {
			if ((chan==50) || (chan==54) || (chan==58) || (chan==62)) {
				idx--;
				continue;
			}
			form.elements["chan"+wlan_id].options[idx] = new Option(chan, chan, false, false);
			if (chan == defaultChan[wlan_id]) {
				form.elements["chan"+wlan_id].selectedIndex = idx;
				defChanIdx=idx;
			}
		}
	}
	else {
		var bound = form.elements["channelbound"+wlan_id].selectedIndex;
		var inc_scale;
		if (bound == 0) //20MHz
		{
			inc_scale = 4;
			chan_str = 36;
			chan_end = 64;
		}	
		else //40MHz
		{ 
			inc_scale = 8;
			if(sideBand == 0) // upper
			{
				chan_str = 40;
				chan_end = 64;
			}
			else // lower
			{
				chan_str = 36;
				chan_end = 60;
			}
		}
			
		for (idx=startChanIdx[wlan_id], chan=chan_str; chan<=chan_end; idx++, chan+=inc_scale) {
			form.elements["chan"+wlan_id].options[idx] = new Option(chan, chan, false, false);
			if (chan == defaultChan[wlan_id]) {
				form.elements["chan"+wlan_id].selectedIndex = idx;
				defChanIdx=idx;
			}
		}
		if (RFType[wlan_id] == 9) {			
			// ETSI, SPAIN, FRANCE, ISRAEL
			if ((regDomain[wlan_id] == 1) || ((regDomain[wlan_id] >= 3) && (regDomain[wlan_id] <= 5)) || (regDomain[wlan_id] == 7)) 
			{
				if (bound == 0) {		//20MHz
					inc_scale = 4;
					chan_str = 100;
					chan_end = 140;
				}	else {
					inc_scale = 8;
					if(sideBand == 0) // upper
					{
						chan_str = 104;
						chan_end = 136;
					}
					else // lower
					{
						chan_str = 100;
						chan_end = 132;
					}
				}		
				for (chan=chan_str; chan<=chan_end; idx++, chan+=inc_scale) {
					form.elements["chan"+wlan_id].options[idx] = new Option(chan, chan, false, false);
					if (chan == defaultChan[wlan_id]) {
						form.elements["chan"+wlan_id].selectedIndex = idx;
						defChanIdx=idx;
					}
				}
			}
			
			// FCC, IC
			if ((regDomain[wlan_id] == 1) || (regDomain[wlan_id] == 2)) {
				if (bound == 0) {		//20MHz
					inc_scale = 4;
					chan_str = 149;
					chan_end = 165;
				}	else {
					inc_scale = 8;
					if(sideBand == 0) // upper
					{
						chan_str = 153;
						chan_end = 165;
					}
					else // lower
					{
						chan_str = 149;
						chan_end = 161;
					}
				}					
				for (chan=chan_str; chan<=chan_end; idx++, chan+=inc_scale) {
					form.elements["chan"+wlan_id].options[idx] = new Option(chan, chan, false, false);
					if (chan == defaultChan[wlan_id]) {
						form.elements["chan"+wlan_id].selectedIndex = idx;
						defChanIdx=idx;
					}
				}
			}			
			// MKK3
			if (regDomain[wlan_id] == 10) {
				for (chan=183; chan<=190; idx++, chan+=1) {
					form.elements["chan"+wlan_id].options[idx] = new Option(chan, chan, false, false);
					if (chan == defaultChan[wlan_id]) {
						form.elements["chan"+wlan_id].selectedIndex = idx;
						defChanIdx=idx;
					}
				}
				for (chan=192; chan<=196; idx++, chan+=2) {
					form.elements["chan"+wlan_id].options[idx] = new Option(chan, chan, false, false);
					if (chan == defaultChan[wlan_id]) {
						form.elements["chan"+wlan_id].selectedIndex = idx;
						defChanIdx=idx;
					}
				}
				for (chan=207; chan<=212; idx++, chan+=1) {
					form.elements["chan"+wlan_id].options[idx] = new Option(chan, chan, false, false);
					if (chan == defaultChan[wlan_id]) {
						form.elements["chan"+wlan_id].selectedIndex = idx;
						defChanIdx=idx;
					}
				}
				for (chan=214; chan<=216; idx++, chan+=2) {
					form.elements["chan"+wlan_id].options[idx] = new Option(chan, chan, false, false);
					if (chan == defaultChan[wlan_id]) {
						form.elements["chan"+wlan_id].selectedIndex = idx;
						defChanIdx=idx;
					}
				}
			}
		}
	}
	form.elements["chan"+wlan_id].length = idx;
	if (defChanIdx==0)
		form.elements["chan"+wlan_id].selectedIndex = 0;
}


function showChannel2G(form, wlan_id, bound_40, band_value)
{
	var start = 1;	//Modified by Jerry
	var end = 14;	//Modified by Jerry
	if (regDomain[wlan_id]==1 || regDomain[wlan_id]==2) {
		start = 1;
		end = 11;
	}
	if (regDomain[wlan_id]==3) {
		start = 1;
		end = 13;
	}
	if (regDomain[wlan_id]==4) {
		start = 10;
		end = 11;
	}
	if (regDomain[wlan_id]==5) {
		start = 10;
		end = 13;
	}
	if (regDomain[wlan_id]==6) {
		start = 1;
		end = 14;
	}

	defChanIdx=0;
	form.elements["chan"+wlan_id].length=0;

	idx=0;
	form.elements["chan"+wlan_id].options[0] = new Option("Auto", 0, false, false);
	
	if(wlan_channel[wlan_id] ==0){
		form.elements["chan"+wlan_id].selectedIndex = 0;
		defChanIdx = 0;
	}

	idx++;	
	for (chan=start; chan<=end; chan++, idx++) {
		form.elements["chan"+wlan_id].options[idx] = new Option(chan, chan, false, false);
		if(chan == wlan_channel[wlan_id]){
			form.elements["chan"+wlan_id].selectedIndex = idx;
			defChanIdx = idx;
		}
	}
	form.elements["chan"+wlan_id].length=idx;
	startChanIdx[wlan_id] = idx;
}
function updateChan_channebound(form, wlan_id)
{
	var idx_value= form.elements["band"+wlan_id].selectedIndex;
	var band_value= form.elements["band"+wlan_id].options[idx_value].value;
	var bound = form.elements["channelbound"+wlan_id].selectedIndex;
	var adjust_chan;
	var Band2G5GSupport=form.elements["Band2G5GSupport"].value;
	
	if(form.name == "wizard")
	{
		switch(wlan_id)
		{
			case 0:
				if(form.elements["wlan1_phyband"].value == "5GHz")
					Band2G5GSupport = 2;
				else
					Band2G5GSupport = 1;
				break;
				
			case 1:
				if(form.elements["wlan2_phyband"].value == "5GHz")
					Band2G5GSupport = 2;
				else
					Band2G5GSupport = 1;
				break;
			
		}
		
	}
		
	if(band_value ==3 || band_value ==11){
		currentBand = 2;
	}
	else if(band_value ==0 || band_value ==1 || band_value ==2 || band_value == 9 || band_value ==10){
		currentBand = 1;
	}
	else if(band_value == 4 || band_value==5 || band_value==6){
		currentBand = 3;
	}
	else if(band_value == 7) //7:n
	{
		if(Band2G5GSupport == 1) //1:2g
			currentBand = 1;
		else
			currentBand = 2;
	}
	if(band_value==9 || band_value==10 || band_value ==7){	
		if(bound ==0)
			adjust_chan=0;
		if(bound ==1)
			adjust_chan=1;	
	}else
		adjust_chan=0;	  
    
	if (currentBand == 3) {
		showChannel2G(form, wlan_id, adjust_chan, band_value);
		showChannel5G(form, wlan_id);
	}
  
  	if (currentBand == 2) {
		startChanIdx[wlan_id]=0;
		showChannel5G(form, wlan_id);
	}
	
  	if (currentBand == 1)
		showChannel2G(form, wlan_id, adjust_chan, band_value);
 	
 	if(band_value==9 || band_value==10 || band_value ==7 || band_value ==11){
	  	if(form.elements["chan"+wlan_id].value == 0){ // 0:auto	  
	  		disableTextField(form.elements["controlsideband"+wlan_id]);	
		}
	}
}

function updateChan(form, wlan_id)
{
	var idx_value= form.elements["band"+wlan_id].selectedIndex;
	var band_value= form.elements["band"+wlan_id].options[idx_value].value;
	var Band2G5GSupport=form.elements["Band2G5GSupport"].value;
	
	if(form.name == "wizard")
	{
		switch(wlan_id)
		{
			case 0:
				if(form.elements["wlan1_phyband"].value == "5GHz")
					Band2G5GSupport = 2;
				else
					Band2G5GSupport = 1;
				break;
				
			case 1:
				if(form.elements["wlan2_phyband"].value == "5GHz")
					Band2G5GSupport = 2;
				else
					Band2G5GSupport = 1;
				break;
			
		}
		
	}	

	if(band_value ==3|| band_value ==11 || (band_value ==7 && Band2G5GSupport == 2)){ // 3:5g_a 11:5g_an 7:n 2:PHYBAND_5G
		currentBand = 2;
	}
	else if(band_value ==0 || band_value ==1 || band_value ==2 || band_value == 9 || band_value ==10 || (band_value ==7 && Band2G5GSupport == 1)){
		currentBand = 1;
	}else if(band_value == 4 || band_value==5 || band_value==6){
		currentBand = 3;
	}

  if (lastBand[wlan_id] != currentBand) {
  	lastBand[wlan_id] = currentBand;
	if (currentBand == 3) {
		showChannel2G(form, wlan_id, 0, band_value);
		showChannel5G(form, wlan_id);
	}
	
  if (currentBand == 2) {
		startChanIdx[wlan_id]=0;
		showChannel5G(form, wlan_id);
	}
	
  	if (currentBand == 1)
		showChannel2G(form, wlan_id, 0, band_value);
  }
  	if(band_value==9 || band_value==10 || band_value ==7 || band_value ==11){
	  	if(form.elements["chan"+wlan_id].value ==0){ // 0:auto
	  		disableTextField(form.elements["controlsideband"+wlan_id]);	
		}
	}
}

function showBand_MultipleAP(form, wlan_id, band_root, index_id)
{
  var idx=0;
  var band_value=bandIdx[wlan_id];
  if(band_root ==0){
	form.elements["wl_band_ssid"+index_id].options[idx++] = new Option("2.4 GHz (B)", "0", false, false);
}else if(band_root ==1){
	form.elements["wl_band_ssid"+index_id].options[idx++] = new Option("2.4 GHz (G)", "1", false, false);
}else if(band_root ==2){
	form.elements["wl_band_ssid"+index_id].options[idx++] = new Option("2.4 GHz (B)", "0", false, false);
	form.elements["wl_band_ssid"+index_id].options[idx++] = new Option("2.4 GHz (G)", "1", false, false);	
 	form.elements["wl_band_ssid"+index_id].options[idx++] = new Option("2.4 GHz (B+G)", "2", false, false);
}else if(band_root ==9){
	form.elements["wl_band_ssid"+index_id].options[idx++] = new Option("2.4 GHz (G)", "1", false, false);	
	form.elements["wl_band_ssid"+index_id].options[idx++] = new Option("2.4 GHz (G+N)", "9", false, false);
}else if(band_root ==10){
	form.elements["wl_band_ssid"+index_id].options[idx++] = new Option("2.4 GHz (B)", "0", false, false);
	form.elements["wl_band_ssid"+index_id].options[idx++] = new Option("2.4 GHz (G)", "1", false, false);	
 	form.elements["wl_band_ssid"+index_id].options[idx++] = new Option("2.4 GHz (B+G)", "2", false, false);
 	form.elements["wl_band_ssid"+index_id].options[idx++] = new Option("2.4 GHz (G+N)", "9", false, false);
 	form.elements["wl_band_ssid"+index_id].options[idx++] = new Option("2.4 GHz (B+G+N)", "10", false, false);
}
 
form.elements["wl_band_ssid"+index_id].selectedIndex = 0;
 form.elements["wl_band_ssid"+index_id].length = idx;
}


function showBandAP(form, wlan_id)
{
  var idx=0;
  var band_value=bandIdx[wlan_id];
	var Band2G5GSupport=form.elements["Band2G5GSupport"].value;
	var wlBandMode=form.elements["wlBandMode"].value;
	var i;

if(form.name == "wizard")
{
	switch(wlan_id)
	{
		case 0:
			if(form.elements["wlan1_phyband"].value == "5GHz")
				Band2G5GSupport = 2;
			else
				Band2G5GSupport = 1;
			break;
	
		case 1:
			if(form.elements["wlan2_phyband"].value == "5GHz")
				Band2G5GSupport = 2;
			else
				Band2G5GSupport = 1;
			break;
		
	}

}
	
	if(Band2G5GSupport == 2 || wlBandMode == 3) // 2:PHYBAND_5G 3:BANDMODESIGNLE
	{
		form.elements["band"+wlan_id].options[idx++] = new Option("5 GHz (A)", "3", false, false);
		form.elements["band"+wlan_id].options[idx++] = new Option("5 GHz (N)", "7", false, false);
		form.elements["band"+wlan_id].options[idx++] = new Option("5 GHz (A+N)", "11", false, false);
	}

//mars add{
	if(Band2G5GSupport == 1 || wlBandMode == 3) // 1:PHYBAND_2G 3:BANDMODESIGNLE
	{
		form.elements["band"+wlan_id].options[idx++] = new Option("Auto", "10", false, false);//B+G+N
		form.elements["band"+wlan_id].options[idx++] = new Option("b/g Mixed", "2", false, false);//b+g
		form.elements["band"+wlan_id].options[idx++] = new Option("n Only", "7", false, false); //n
		form.elements["band"+wlan_id].options[idx++] = new Option("g Only", "1", false, false);//g
		form.elements["band"+wlan_id].options[idx++] = new Option("b Only", "0", false, false);//b
	}
//mars add}


	for(i=0 ; i<idx ; i++)
	{
		if(form.elements["band"+wlan_id].options[i].value == band_value)
		{			
			if(band_value == 7 && wlBandMode == 3)// 2g and 5g has the same band value in N.
			{
				var selectText=form.elements["band"+wlan_id].options[i].text.substr(0,1);
				
				if( (Band2G5GSupport == 2 && selectText == '5') //2:PHYBAND_5G
				||	(Band2G5GSupport == 1 && selectText == '2') //1:PHYBAND_2G
				) 
				{
					form.elements["band"+wlan_id].selectedIndex = i;
					break;					
				}			
			}
			else
			{	
				form.elements["band"+wlan_id].selectedIndex = i;
				break;
			}
		}				
	}	

 form.elements["band"+wlan_id].length = idx;
}
        
     
function showBandClient(form, wlan_id)
{
  var idx=0;
   var band_value=bandIdx[wlan_id];
var Band2G5GSupport=form.elements["Band2G5GSupport"].value;
	var wlBandMode=form.elements["wlBandMode"].value;
	var i;

if(form.name == "wizard")
	{
		switch(wlan_id)
		{
			case 0:
				if(form.elements["wlan1_phyband"].value == "5GHz")
					Band2G5GSupport = 2;
				else
					Band2G5GSupport = 1;
				break;
				
			case 1:
				if(form.elements["wlan2_phyband"].value == "5GHz")
					Band2G5GSupport = 2;
				else
					Band2G5GSupport = 1;
				break;
			
		}
		
	}
	
	if(Band2G5GSupport == 2 || wlBandMode == 3) // 2:PHYBAND_5G 3:BANDMODESIGNLE
	{
		form.elements["band"+wlan_id].options[idx++] = new Option("5 GHz (A)", "3", false, false);
		form.elements["band"+wlan_id].options[idx++] = new Option("5 GHz (N)", "7", false, false);
		form.elements["band"+wlan_id].options[idx++] = new Option("5 GHz (A+N)", "11", false, false);
	}

//mars add{
	if(Band2G5GSupport == 1 || wlBandMode == 3) // 1:PHYBAND_2G 3:BANDMODESIGNLE
	{
		 form.elements["band"+wlan_id].options[idx++] = new Option("Auto", "10", false, false);//B+G+N
		 form.elements["band"+wlan_id].options[idx++] = new Option("b/g Mixed", "2", false, false);//b+g
		 form.elements["band"+wlan_id].options[idx++] = new Option("n Only", "7", false, false); //n
		 form.elements["band"+wlan_id].options[idx++] = new Option("g Only", "1", false, false);//g
		 form.elements["band"+wlan_id].options[idx++] = new Option("b Only", "0", false, false);//b
	}
//mars add}

	for(i=0 ; i<idx ; i++)
	{
		if(form.elements["band"+wlan_id].options[i].value == band_value)
		{
			if(band_value == 7 && wlBandMode == 3)// 2g and 5g has the same band value in N.
			{
				var selectText=form.elements["band"+wlan_id].options[i].text.substr(0,1);
				
				if( (Band2G5GSupport == 2 && selectText == '5') //2:PHYBAND_5G
				||	(Band2G5GSupport == 1 && selectText == '2') //1:PHYBAND_2G
				) 
				{
			form.elements["band"+wlan_id].selectedIndex = i;
			break;
		}				
	}	
			else
			{	
				form.elements["band"+wlan_id].selectedIndex = i;
				break;
			}
		}				
	}	

 form.elements["band"+wlan_id].length = idx;
}

function showBand(form, wlan_id)
{
  if (APMode[wlan_id] != 1)
	showBandAP(form, wlan_id);
  else
 	showBandClient(form, wlan_id);
}
function get_by_id(id){
	with(document){
	return getElementById(id);
	}
}
function get_by_name(name){
	with(document){
	return getElementsByName(name);
	}
}
function updateMode(form, wlan_id)
{
	var chan_boundid;
	var controlsidebandid;
	var wlan_wmm1;
	var wlan_wmm2;
	var networktype;
	var mode_idx =form.elements["mode"+wlan_id].selectedIndex;
	var mode_value = form.elements["mode"+wlan_id].options[mode_idx].value; 
	var idx_value= form.elements["band"+wlan_id].selectedIndex;
	var band_value= form.elements["band"+wlan_id].options[idx_value].value;
	if (form.elements["mode"+wlan_id].selectedIndex != 1) {
  		if (APMode[wlan_id] == 1) {
			if (bandIdxAP[wlan_id] < 0){
				bandIdx[wlan_id]=2;	// set B+G as default
			}else{
				bandIdx[wlan_id]=bandIdxAP[wlan_id];
			}
		}  
	}else {
	  	if (APMode[wlan_id] != 1) {
			if (bandIdxClient[wlan_id] < 0) {
	 			if (RFType[wlan_id] == 10)
					bandIdx[wlan_id]=2;	// set B+G as default
				else
					bandIdx[wlan_id]=6;	// set A+B+G as default
			}
			else{
				bandIdx[wlan_id]=bandIdxClient[wlan_id];
			}
		}	
	}
	APMode[wlan_id] =form.elements["mode"+wlan_id].selectedIndex;
	showBand(form, wlan_id);
  	if(form == document.wlanSetup){
  		wlan_wmm1 = form.elements["wlanwmm"+wlan_id];
  		wlan_wmm2 =  get_by_id("wlan_wmm");
	}

	networktype = form.elements["type"+wlan_id];
	if(mode_value !=1) {
		networktype.disabled = true;
	}else {
		networktype.selectedIndex = networkType[wlan_id];
		networktype.disabled = false;		
	}
	
 	chan_boundid = get_by_id("channel_bounding");
  	controlsidebandid = get_by_id("control_sideband");  
  	
	if(bandIdx[wlan_id] == 9 || bandIdx[wlan_id] == 10 ||  bandIdx[wlan_id] == 7 || bandIdx[wlan_id] == 11){
		chan_boundid.style.display = "";
	 	controlsidebandid.style.display = "";
		 if(form == document.wlanSetup){
			wlan_wmm1.disabled = true;
		}
	}else{
		chan_boundid.style.display = "none";
		controlsidebandid.style.display = "none";
	 	 if(form == document.wlanSetup){
	 		wlan_wmm1.disabled = false;
	 	}
	 }
	  updateIputState(form, wlan_id);
	 if(form==document.wizard){
		var chan_number_idx=form.elements["chan"+wlan_id].selectedIndex;
		var chan_number= form.elements["chan"+wlan_id].options[chan_number_idx].value;	
		if(chan_number == 0)
			disableTextField(form.elements["controlsideband"+wlan_id]);	
		else{
			if(form.elements["channelbound"+wlan_id].selectedIndex == "0")
	 			disableTextField(form.elements["controlsideband"+wlan_id]);	
	 		else
				enableTextField(form.elements["controlsideband"+wlan_id]);		
		}
	}
}

function updateBand(form, wlan_id)
{
	var band_index= form.elements["band"+wlan_id].selectedIndex;
	var band_value= form.elements["band"+wlan_id].options[band_index].value;
  if (APMode[wlan_id] != 1){
	bandIdxAP[wlan_id] = band_value;
  }else{
	bandIdxClient[wlan_id] =band_value;
  }	

  updateChan(form, wlan_id);
  
}

function updateType(form, wlan_id)
{
	var mode_selected=0;
	var Type_selected=0;
	var index_channelbound=0;
  updateChan(form, wlan_id);
  updateIputState(form, wlan_id);
  Type_selected = form.elements["type"+wlan_id].selectedIndex;
  mode_selected=form.elements["mode"+wlan_id].selectedIndex;
  //if client and infrastructure mode
  	if(mode_selected ==1){
		if(Type_selected == 0){
			disableTextField(form.elements["controlsideband"+wlan_id]);
			disableTextField(form.elements["channelbound"+wlan_id]);
		}else{
			enableTextField(form.elements["channelbound"+wlan_id]);
			index_channelbound=form.elements["channelbound"+wlan_id].selectedIndex;
		if(index_channelbound ==0)
			disableTextField(form.elements["controlsideband"+wlan_id]);	
		else
			enableTextField(form.elements["controlsideband"+wlan_id]);
		}
	}
	
		var chan_number_idx=form.elements["chan"+wlan_id].selectedIndex;
		var chan_number= form.elements["chan"+wlan_id].options[chan_number_idx].value;	
		if(chan_number == 0)
			disableTextField(form.elements["controlsideband"+wlan_id]);	
		else{
			if(form.elements["channelbound"+wlan_id].selectedIndex == "0")
	 			disableTextField(form.elements["controlsideband"+wlan_id]);	
	 		else
				enableTextField(form.elements["controlsideband"+wlan_id]);		
		}
}

/*==============================================================================*/
/*   wlwpa.asp */
function disableRadioGroup (radioArrOrButton)
{
  if (radioArrOrButton.type && radioArrOrButton.type == "radio") {
 	var radioButton = radioArrOrButton;
 	var radioArray = radioButton.form[radioButton.name];
  }
  else
 	var radioArray = radioArrOrButton;
 	radioArray.disabled = true;
 	for (var b = 0; b < radioArray.length; b++) {
 	if (radioArray[b].checked) {
 		radioArray.checkedElement = radioArray[b];
 		break;
	}
  }
  for (var b = 0; b < radioArray.length; b++) {
 	radioArray[b].disabled = true;
 	radioArray[b].checkedElement = radioArray.checkedElement;
  }
}

function enableRadioGroup (radioArrOrButton)
{
  if (radioArrOrButton.type && radioArrOrButton.type == "radio") {
 	var radioButton = radioArrOrButton;
 	var radioArray = radioButton.form[radioButton.name];
  }
  else
 	var radioArray = radioArrOrButton;

  radioArray.disabled = false;
  radioArray.checkedElement = null;
  for (var b = 0; b < radioArray.length; b++) {
 	radioArray[b].disabled = false;
 	radioArray[b].checkedElement = null;
  }
}

function preserve () { this.checked = this.storeChecked; }
function disableCheckBox (checkBox) {
  if (!checkBox.disabled) {
    checkBox.disabled = true;
    if (!document.all && !document.getElementById) {
      checkBox.storeChecked = checkBox.checked;
      checkBox.oldOnClick = checkBox.onclick;
      checkBox.onclick = preserve;
    }
  }
}

function enableCheckBox (checkBox)
{
  if (checkBox.disabled) {
    checkBox.disabled = false;
    if (!document.all && !document.getElementById)
      checkBox.onclick = checkBox.oldOnClick;
  }
}
function openWindow(url, windowName, wide, high) {
	if (document.all)
		var xMax = screen.width, yMax = screen.height;
	else if (document.layers)
		var xMax = window.outerWidth, yMax = window.outerHeight;
	else
	   var xMax = 640, yMax=500;
	var xOffset = (xMax - wide)/2;
	var yOffset = (yMax - high)/3;

	var settings = 'width='+wide+',height='+high+',screenX='+xOffset+',screenY='+yOffset+',top='+yOffset+',left='+xOffset+', resizable=yes, toolbar=no,location=no,directories=no,status=no,menubar=no,scrollbars=yes';
	window.open( url, windowName, settings );
}
function validateKey(str)
{
   for (var i=0; i<str.length; i++) {
    if ( (str.charAt(i) >= '0' && str.charAt(i) <= '9') ||
    		(str.charAt(i) == '.' ) )
			continue;
	return 0;
  }
  return 1;
}

function getDigit(str, num)
{
  i=1;
  if ( num != 1 ) {
  	while (i!=num && str.length!=0) {
		if ( str.charAt(0) == '.' ) {
			i++;
		}
		str = str.substring(1);
  	}
  	if ( i!=num )
  		return -1;
  }
  for (i=0; i<str.length; i++) {
  	if ( str.charAt(i) == '.' ) {
		str = str.substring(0, i);
		break;
	}
  }
  if ( str.length == 0)
  	return -1;
  d = parseInt(str, 10);
  return d;
}

function checkDigitRange(str, num, min, max)
{
  d = getDigit(str,num);
  if ( d > max || d < min )
      	return false;
  return true;
}


function check_wpa_psk(form, wlan_id)
{
	var str = form.elements["pskValue"+wlan_id].value;
	if (form.elements["pskFormat"+wlan_id].selectedIndex==1) {
		if (str.length != 64) {
			alert("<#UTIL_GW_error1#>");
			form.elements["pskValue"+wlan_id].focus();
			return false;
		}
		takedef = 0;
		if (defPskFormat[wlan_id] == 1 && defPskLen[wlan_id] == 64) {
			for (var i=0; i<64; i++) {
    				if ( str.charAt(i) != '*')
					break;
			}
			if (i == 64 )
				takedef = 1;
  		}
		if (takedef == 0) {
			for (var i=0; i<str.length; i++) {
    				if ( (str.charAt(i) >= '0' && str.charAt(i) <= '9') ||
					(str.charAt(i) >= 'a' && str.charAt(i) <= 'f') ||
					(str.charAt(i) >= 'A' && str.charAt(i) <= 'F') )
					continue;
				alert("<#UTIL_GW_error2#>");
				form.elements["pskValue"+wlan_id].focus();
				return false;
  			}
		}
	}
	else {
		if (str.length < 8) {
			alert("<#UTIL_GW_error1#>");
			form.elements["pskValue"+wlan_id].focus();
			return false;
		}
		if (str.length > 63) {
			alert("<#UTIL_GW_error1#>");
			form.elements["pskValue"+wlan_id].focus();
			return false;
		}
	}
  
  return true;
}

function saveChanges_wpa(form, wlan_id)
{
  method = form.elements["method"+wlan_id] ;
  wpaAuth= form.elements["wpaAuth"+wlan_id] ;

  if (method.selectedIndex>=2 && (wpaAuth.value == "psk" || wpaAuth[1].checked))
	return check_wpa_psk(form, wlan_id);	
 
    if (form.elements["use1x"+wlan_id].value != "OFF" && form.elements["radiusPort"+wlan_id].disabled == false ) {
	if (form.elements["radiusPort"+wlan_id].value=="") {
		alert('<#JS_fieldblank#><#BM_alert_port3#>');
		form.elements["radiusPort"+wlan_id].focus();
		return false;
  	}
	if (validateKey(form.elements["radiusPort"+wlan_id].value)==0) {
		alert('<#JS_validport#><#BM_alert_port3#>');
		form.elements["radiusPort"+wlan_id].focus();
		return false;
	}
        port = parseInt(form.elements["radiusPort"+wlan_id].value, 10);

 	if (port > 65535 || port < 1) {
		alert('<#JS_validport#><#BM_alert_port3#>');
		form.elements["radiusPort"+wlan_id].focus();
		return false;
  	}

	if ( checkIpAddr(form.elements["radiusIP"+wlan_id], 'Invalid RADIUS Server IP address') == false )
	    return false;
   } 
   	
   
   
   return true;
}
/*==============================================================================*/
/*   tcpiplan.asp  */
function checkMask(str, num)
{
  d = getDigit(str,num);
  if( !(d==0 || d==128 || d==192 || d==224 || d==240 || d==248 || d==252 || d==254 || d==255 ))
  	return false;
  return true;
}


function checkSubnet(ip, mask, client)
{
  ip_d = getDigit(ip, 1);
  mask_d = getDigit(mask, 1);
  client_d = getDigit(client, 1);
  if ( (ip_d & mask_d) != (client_d & mask_d ) )
	return false;

  ip_d = getDigit(ip, 2);
  mask_d = getDigit(mask, 2);
  client_d = getDigit(client, 2);
  if ( (ip_d & mask_d) != (client_d & mask_d ) )
	return false;

  ip_d = getDigit(ip, 3);
  mask_d = getDigit(mask, 3);
  client_d = getDigit(client, 3);
  if ( (ip_d & mask_d) != (client_d & mask_d ) )
	return false;

  ip_d = getDigit(ip, 4);
  mask_d = getDigit(mask, 4);
  client_d = getDigit(client, 4);
  if ( (ip_d & mask_d) != (client_d & mask_d ) )
	return false;

  return true;
}
function checkIPMask(field)
{

  if (field.value=="") {
	alert(field.value + '<#JS_fieldblank#>');
	field.value = field.defaultValue;
	field.focus();
	return false;
  }
  if ( validateKey( field.value ) == 0 ) {
	alert(field.value + '<#JS_validip#>');
      	field.value = field.defaultValue;
	field.focus();
	return false;
  }
  if ( !checkMask(field.value,1) ) {
	alert(field.value + '<#JS_validip#>');
	field.value = field.defaultValue;
	field.focus();
	return false;
  }

  if ( !checkMask(field.value,2) ) {
	alert(field.value + '<#JS_validip#>');
	field.value = field.defaultValue;
	field.focus();
	return false;
  }
  if ( !checkMask(field.value,3) ) {
	alert(field.value + '<#JS_validip#>');
	field.value = field.defaultValue;
	field.focus();
	return false;
  }
  if ( !checkMask(field.value,4) ) {
	alert(field.value + '<#JS_validip#>');
	field.value = field.defaultValue;
	field.focus();
	return false;
  }
}  
function checkIpAddr(field, msg)
{
  if (field.value=="") {
	alert(field.value + '<#JS_fieldblank#>');
	field.value = field.defaultValue;
	field.focus();
	return false;
  }
   if ( validateKey(field.value) == 0) {
	alert(field.value + '<#JS_validip#>');
      field.value = field.defaultValue;
      field.focus();
      return false;
   }
   if ( !checkDigitRange(field.value,1,0,255) ) {
	alert(field.value + '<#JS_validip#>');
      field.value = field.defaultValue;
      field.focus();
      return false;
   }
   if ( !checkDigitRange(field.value,2,0,255) ) {
	alert(field.value + '<#JS_validip#>');
      field.value = field.defaultValue;
      field.focus();
      return false;
   }
   if ( !checkDigitRange(field.value,3,0,255) ) {
	alert(field.value + '<#JS_validip#>');
      field.value = field.defaultValue;
      field.focus();
      return false;
   }
   if ( !checkDigitRange(field.value,4,1,254) ) {
	alert(field.value + '<#JS_validip#>');
      field.value = field.defaultValue;
      field.focus();
      return false;
   }
   return true;
}


/////////////////////////////////////////////////////////////////////////////
/*wlwep.asp*/
function validateKey_wep(form, idx, str, len, wlan_id)
{
 if (idx >= 0) {

  if (str.length ==0)
  	return 1;

  if ( str.length != len) {
  	idx++;
	alert('Invalid length of Key ' + idx + ' value. It should be ' + len + ' characters.');
	return 0;
  }
  }
  else {
	if ( str.length != len) {
		alert('Invalid length of WEP Key value. It should be ' + len + ' characters.');
		return 0;
  	}
  }
  if ( str == "*****" ||
       str == "**********" ||
       str == "*************" ||
       str == "**************************" )
       return 1;

  if (form.elements["format"+wlan_id].selectedIndex==0)
       return 1;

  for (var i=0; i<str.length; i++) {
    if ( (str.charAt(i) >= '0' && str.charAt(i) <= '9') ||
			(str.charAt(i) >= 'a' && str.charAt(i) <= 'f') ||
			(str.charAt(i) >= 'A' && str.charAt(i) <= 'F') )
			continue;

	alert("Invalid key value. It should be in hex number (0-9 or a-f).");
	return 0;
  }

  return 1;
}

function setDefaultWEPKeyValue(form, wlan_id)
{
  if (form.elements["length"+wlan_id].selectedIndex == 0) {
	if ( form.elements["format"+wlan_id].selectedIndex == 0) {
		form.elements["key"+wlan_id].maxLength = 5;
		form.elements["key"+wlan_id].value = "*****";
	}
	else {
		form.elements["key"+wlan_id].maxLength = 10;
		form.elements["key"+wlan_id].value = "**********";

	}
  }
  else {
  	if ( form.elements["format"+wlan_id].selectedIndex == 0) {
		form.elements["key"+wlan_id].maxLength = 13;
		form.elements["key"+wlan_id].value = "*************";

	}
	else {
		form.elements["key"+wlan_id].maxLength = 26;
		form.elements["key"+wlan_id].value ="**************************";
	}
  }
  
}
function saveChanges_wepkey(form, wlan_id)
{
  var keyLen;
  if (form.elements["length"+wlan_id].selectedIndex == 0) {
  	if ( form.elements["format"+wlan_id].selectedIndex == 0)
		keyLen = 5;
	else
		keyLen = 10;
  }
  else {
  	if ( form.elements["format"+wlan_id].selectedIndex == 0)
		keyLen = 13;
	else
		keyLen = 26;
  }

  if (validateKey_wep(form, 0,form.elements["key"+wlan_id].value, keyLen, wlan_id)==0) {
	form.elements["key"+wlan_id].focus();
	return false;
  }

  return true;
}

function setDefaultKeyValue(form, wlan_id)
{
  if (form.elements["length"+wlan_id].selectedIndex == 0) {
	if ( form.elements["format"+wlan_id].selectedIndex == 0) {
		form.elements["key"+wlan_id].maxLength = 5;
		form.elements["key"+wlan_id].value = "*****";	
	}
	else {
		form.elements["key"+wlan_id].maxLength = 10;
		form.elements["key"+wlan_id].value = "**********";
	}
  }
  else {
  	if ( form.elements["format"+wlan_id].selectedIndex == 0) {
		form.elements["key"+wlan_id].maxLength = 13;		
		form.elements["key"+wlan_id].value = "*************";
	}
	else {
		form.elements["key"+wlan_id].maxLength = 26;
		form.elements["key"+wlan_id].value ="**************************";	
	}
  }
  
}


function saveChanges_wep(form, wlan_id)
{
  var keyLen;
  if (form.elements["length"+wlan_id].selectedIndex == 0) {
  	if ( form.elements["format"+wlan_id].selectedIndex == 0)
		keyLen = 5;
	else
		keyLen = 10;
  }
  else {
  	if ( form.elements["format"+wlan_id].selectedIndex == 0)
		keyLen = 13;
	else
		keyLen = 26;
  }

  if (validateKey_wep(form, 0,form.elements["key"+wlan_id].value, keyLen, wlan_id)==0) {
	form.elements["key"+wlan_id].focus();
	return false;
  }

  return true;
}



function lengthClick(form, wlan_id)
{
  updateFormat(form, wlan_id);
}

///////////////////////////////////////////////////////////////////////
//ntp.asp and wizard-ntp.asp
var ntp_zone_index=4;

function ntp_entry(name, value) { 
	this.name = name ;
	this.value = value ;
} 

var ntp_zone_array=new Array(65);
ntp_zone_array[0]=new ntp_entry("(GMT-12:00)Eniwetok, Kwajalein","12 1");
ntp_zone_array[1]=new ntp_entry("(GMT-11:00)Midway Island, Samoa","11 1");
ntp_zone_array[2]=new ntp_entry("(GMT-10:00)Hawaii", "10 1");
ntp_zone_array[3]=new ntp_entry("(GMT-09:00)Alaska", "9 1");
ntp_zone_array[4]=new ntp_entry("(GMT-08:00)Pacific Time (US & Canada); Tijuana", "8 1");
ntp_zone_array[5]=new ntp_entry("(GMT-07:00)Arizona", "7 1");
ntp_zone_array[6]=new ntp_entry("(GMT-07:00)Mountain Time (US & Canada)", "7 2");
ntp_zone_array[7]=new ntp_entry("(GMT-06:00)Central Time (US & Canada)", "6 1");
ntp_zone_array[8]=new ntp_entry("(GMT-06:00)Mexico City, Tegucigalpa", "6 2");
ntp_zone_array[9]=new ntp_entry("(GMT-06:00)Saskatchewan", "6 3");
ntp_zone_array[10]=new ntp_entry("(GMT-05:00)Bogota, Lima, Quito", "5 1");
ntp_zone_array[11]=new ntp_entry("(GMT-05:00)Eastern Time (US & Canada)", "5 2");
ntp_zone_array[12]=new ntp_entry("(GMT-05:00)Indiana (East)", "5 3");
ntp_zone_array[13]=new ntp_entry("(GMT-04:00)Atlantic Time (Canada)", "4 1");
ntp_zone_array[14]=new ntp_entry("(GMT-04:00)Caracas, La Paz", "4 2");
ntp_zone_array[15]=new ntp_entry("(GMT-04:00)Santiago", "4 3");
ntp_zone_array[16]=new ntp_entry("(GMT-03:30)Newfoundland", "3 1");
ntp_zone_array[17]=new ntp_entry("(GMT-03:00)Brasilia", "3 2");
ntp_zone_array[18]=new ntp_entry("(GMT-03:00)Buenos Aires, Georgetown", "3 3");
ntp_zone_array[19]=new ntp_entry("(GMT-02:00)Mid-Atlantic", "2 1");
ntp_zone_array[20]=new ntp_entry("(GMT-01:00)Azores, Cape Verde Is.", "1 1");
ntp_zone_array[21]=new ntp_entry("(GMT)Casablanca, Monrovia", "0 1");
ntp_zone_array[22]=new ntp_entry("(GMT)Greenwich Mean Time: Dublin, Edinburgh, Lisbon, London", "0 2");
ntp_zone_array[23]=new ntp_entry("(GMT+01:00)Amsterdam, Berlin, Bern, Rome, Stockholm, Vienna", "-1 1");
ntp_zone_array[24]=new ntp_entry("(GMT+01:00)Belgrade, Bratislava, Budapest, Ljubljana, Prague", "-1 2");
ntp_zone_array[25]=new ntp_entry("(GMT+01:00)Barcelona, Madrid", "-1 3");
ntp_zone_array[26]=new ntp_entry("(GMT+01:00)Brussels, Copenhagen, Madrid, Paris, Vilnius", "-1 4");
ntp_zone_array[27]=new ntp_entry("(GMT+01:00)Paris", "-1 5");
ntp_zone_array[28]=new ntp_entry("(GMT+01:00)Sarajevo, Skopje, Sofija, Warsaw, Zagreb", "-1 6");
ntp_zone_array[29]=new ntp_entry("(GMT+02:00)Athens, Istanbul, Minsk", "-2 1");
ntp_zone_array[30]=new ntp_entry("(GMT+02:00)Bucharest", "-2 2");
ntp_zone_array[31]=new ntp_entry("(GMT+02:00)Cairo", "-2 3");
ntp_zone_array[32]=new ntp_entry("(GMT+02:00)Harare, Pretoria", "-2 4");
ntp_zone_array[33]=new ntp_entry("(GMT+02:00)Helsinki, Riga, Tallinn", "-2 5");
ntp_zone_array[34]=new ntp_entry("(GMT+02:00)Jerusalem", "-2 6");
ntp_zone_array[35]=new ntp_entry("(GMT+03:00)Baghdad, Kuwait, Riyadh", "-3 1");
ntp_zone_array[36]=new ntp_entry("(GMT+03:00)Moscow, St. Petersburg, Volgograd", "-3 2");
ntp_zone_array[37]=new ntp_entry("(GMT+03:00)Mairobi", "-3 3");
ntp_zone_array[38]=new ntp_entry("(GMT+03:30)Tehran", "-3 4");
ntp_zone_array[39]=new ntp_entry("(GMT+04:00)Abu Dhabi, Muscat", "-4 1");
ntp_zone_array[40]=new ntp_entry("(GMT+04:00)Baku, Tbilisi", "-4 2");
ntp_zone_array[41]=new ntp_entry("(GMT+04:30)Kabul", "-4 3");
ntp_zone_array[42]=new ntp_entry("(GMT+05:00)Ekaterinburg", "-5 1");
ntp_zone_array[43]=new ntp_entry("(GMT+05:00)Islamabad, Karachi, Tashkent", "-5 2");
ntp_zone_array[44]=new ntp_entry("(GMT+05:30)Bombay, Calcutta, Madras, New Delhi", "-5 3");
ntp_zone_array[45]=new ntp_entry("(GMT+06:00)Astana, Almaty, Dhaka", "-6 1");
ntp_zone_array[46]=new ntp_entry("(GMT+06:00)Colombo", "-6 2");
ntp_zone_array[47]=new ntp_entry("(GMT+07:00)Bangkok, Hanoi, Jakarta", "-7 1");
ntp_zone_array[48]=new ntp_entry("(GMT+08:00)Beijing, Chongqing, Hong Kong, Urumqi", "-8 1");
ntp_zone_array[49]=new ntp_entry("(GMT+08:00)Perth", "-8 2");
ntp_zone_array[50]=new ntp_entry("(GMT+08:00)Singapore", "-8 3");
ntp_zone_array[51]=new ntp_entry("(GMT+08:00)Taipei", "-8 4");
ntp_zone_array[52]=new ntp_entry("(GMT+09:00)Osaka, Sapporo, Tokyo", "-9 1");
ntp_zone_array[53]=new ntp_entry("(GMT+09:00)Seoul", "-9 2");
ntp_zone_array[54]=new ntp_entry("(GMT+09:00)Yakutsk", "-9 3");
ntp_zone_array[55]=new ntp_entry("(GMT+09:30)Adelaide", "-9 4");
ntp_zone_array[56]=new ntp_entry("(GMT+09:30)Darwin", "-9 5");
ntp_zone_array[57]=new ntp_entry("(GMT+10:00)Brisbane", "-10 1");
ntp_zone_array[58]=new ntp_entry("(GMT+10:00)Canberra, Melbourne, Sydney", "-10 2");
ntp_zone_array[59]=new ntp_entry("(GMT+10:00)Guam, Port Moresby", "-10 3");
ntp_zone_array[60]=new ntp_entry("(GMT+10:00)Hobart", "-10 4");
ntp_zone_array[61]=new ntp_entry("(GMT+10:00)Vladivostok", "-10 5");
ntp_zone_array[62]=new ntp_entry("(GMT+11:00)Magadan, Solomon Is., New Caledonia", "-11 1");
ntp_zone_array[63]=new ntp_entry("(GMT+12:00)Auckland, Wllington", "-12 1");
ntp_zone_array[64]=new ntp_entry("(GMT+12:00)Fiji, Kamchatka, Marshall Is.", "-12 2");

function setTimeZone(field, value){
    field.selectedIndex = 4 ;
    for(i=0 ;i < field.options.length ; i++){
    	if(field.options[i].value == value){
		field.options[i].selected = true;
		break;
}
}

}

function setNtpServer(field, ntpServer){
    field.selectedIndex = 0 ;
    for(i=0 ;i < field.options.length ; i++){
    	if(field.options[i].value == ntpServer){
		field.options[i].selected = true;
		break;
	}
    }
}
function updateState_ntp(form)
{
	if(form.enabled.checked){
		enableTextField(form.timeZone);
		enableTextField(form.ntpServerIp1);
		enableCheckBox (form.dlenabled);
		if(form.ntpServerIp2 != null)
			enableTextField(form.ntpServerIp2);
	}
	else{
		disableTextField(form.timeZone);
		disableTextField(form.ntpServerIp1);
		disableCheckBox (form.dlenabled);
		if(form.ntpServerIp2 != null)
			disableTextField(form.ntpServerIp2);
	}
}

function saveChanges_ntp(form)
{
	if(form.ntpServerIp2.value != ""){
		if ( checkIpAddr(form.ntpServerIp2, 'Invalid IP address') == false )
		    return false;
	}
	else
		form.ntpServerIp2.value = "0.0.0.0" ;
	return true;
}
function getRefToDivNest(divID, oDoc) 
{
  if( !oDoc ) { oDoc = document; }
  if( document.layers ) {
	if( oDoc.layers[divID] ) { return oDoc.layers[divID]; } else {
	for( var x = 0, y; !y && x < oDoc.layers.length; x++ ) {
		y = getRefToDivNest(divID,oDoc.layers[x].document); }
	return y; } }
  if( document.getElementById ) { return document.getElementById(divID); }
  if( document.all ) { return document.all[divID]; }
  return document[divID];
}

function progressBar( oBt, oBc, oBg, oBa, oWi, oHi, oDr ) 
{
  MWJ_progBar++; this.id = 'MWJ_progBar' + MWJ_progBar; this.dir = oDr; this.width = oWi; this.height = oHi; this.amt = 0;
  //write the bar as a layer in an ilayer in two tables giving the border
  document.write( '<span id = "progress_div" class = "off" > <table border="0" cellspacing="0" cellpadding="'+oBt+'">'+
	'<tr><td>Please wait...</td></tr><tr><td bgcolor="'+oBc+'">'+
		'<table border="0" cellspacing="0" cellpadding="0"><tr><td height="'+oHi+'" width="'+oWi+'" bgcolor="'+oBg+'">' );
  if( document.layers ) {
	document.write( '<ilayer height="'+oHi+'" width="'+oWi+'"><layer bgcolor="'+oBa+'" name="MWJ_progBar'+MWJ_progBar+'"></layer></ilayer>' );
  } else {
	document.write( '<div style="position:relative;top:0px;left:0px;height:'+oHi+'px;width:'+oWi+';">'+
			'<div style="position:absolute;top:0px;left:0px;height:0px;width:0;font-size:1px;background-color:'+oBa+';" id="MWJ_progBar'+MWJ_progBar+'"></div></div>' );
  }
  document.write( '</td></tr></table></td></tr></table></span>\n' );
  this.setBar = resetBar; //doing this inline causes unexpected bugs in early NS4
  this.setCol = setColour;
}

function resetBar( a, b ) 
{
  //work out the required size and use various methods to enforce it
  this.amt = ( typeof( b ) == 'undefined' ) ? a : b ? ( this.amt + a ) : ( this.amt - a );
  if( isNaN( this.amt ) ) { this.amt = 0; } if( this.amt > 1 ) { this.amt = 1; } if( this.amt < 0 ) { this.amt = 0; }
  var theWidth = Math.round( this.width * ( ( this.dir % 2 ) ? this.amt : 1 ) );
  var theHeight = Math.round( this.height * ( ( this.dir % 2 ) ? 1 : this.amt ) );
  var theDiv = getRefToDivNest( this.id ); if( !theDiv ) { window.status = 'Progress: ' + Math.round( 100 * this.amt ) + '%'; return; }
  if( theDiv.style ) { theDiv = theDiv.style; theDiv.clip = 'rect(0px '+theWidth+'px '+theHeight+'px 0px)'; }
  var oPix = document.childNodes ? 'px' : 0;
  theDiv.width = theWidth + oPix; theDiv.pixelWidth = theWidth; theDiv.height = theHeight + oPix; theDiv.pixelHeight = theHeight;
  if( theDiv.resizeTo ) { theDiv.resizeTo( theWidth, theHeight ); }
  theDiv.left = ( ( this.dir != 3 ) ? 0 : this.width - theWidth ) + oPix; theDiv.top = ( ( this.dir != 4 ) ? 0 : this.height - theHeight ) + oPix;
}

function setColour( a ) 
{
  //change all the different colour styles
  var theDiv = getRefToDivNest( this.id ); if( theDiv.style ) { theDiv = theDiv.style; }
  theDiv.bgColor = a; theDiv.backgroundColor = a; theDiv.background = a;
}

function showtxrate_updated(form, band, wlan_id, rf_num)
{
  var idx=0;
  var i;
  var txrate_str;
 
 form.elements["txRate"+wlan_id].options[idx++] = new Option("Auto", "0", false, false);
 
 if(band == 0 || band ==2 || band ==10){
 form.elements["txRate"+wlan_id].options[idx++] = new Option("1M", "1", false, false);
 form.elements["txRate"+wlan_id].options[idx++] = new Option("2M", "2", false, false);
 form.elements["txRate"+wlan_id].options[idx++] = new Option("5.5M", "3", false, false);
 form.elements["txRate"+wlan_id].options[idx++] = new Option("11M", "4", false, false);
}
 if(band ==9 || band ==10 || band ==1 || band ==2 || band == 11){
 form.elements["txRate"+wlan_id].options[idx++] = new Option("6M", "5", false, false);
 form.elements["txRate"+wlan_id].options[idx++] = new Option("9M", "6", false, false);
 form.elements["txRate"+wlan_id].options[idx++] = new Option("12M", "7", false, false);
 form.elements["txRate"+wlan_id].options[idx++] = new Option("18M", "8", false, false);
 form.elements["txRate"+wlan_id].options[idx++] = new Option("24M", "9", false, false);
 form.elements["txRate"+wlan_id].options[idx++] = new Option("36M", "10", false, false);
 form.elements["txRate"+wlan_id].options[idx++] = new Option("48M", "11", false, false);
 form.elements["txRate"+wlan_id].options[idx++] = new Option("54M", "12", false, false);
}
 if(band ==9 || band ==10 || band == 7 || band == 11){
 form.elements["txRate"+wlan_id].options[idx++] = new Option("MCS0", "13", false, false);
 form.elements["txRate"+wlan_id].options[idx++] = new Option("MCS1", "14", false, false);
 form.elements["txRate"+wlan_id].options[idx++] = new Option("MCS2", "15", false, false);
 form.elements["txRate"+wlan_id].options[idx++] = new Option("MCS3", "16", false, false);
 form.elements["txRate"+wlan_id].options[idx++] = new Option("MCS4", "17", false, false);
 form.elements["txRate"+wlan_id].options[idx++] = new Option("MCS5", "18", false, false);
 form.elements["txRate"+wlan_id].options[idx++] = new Option("MCS6", "19", false, false); 
 form.elements["txRate"+wlan_id].options[idx++] = new Option("MCS7", "20", false, false);
 if (rf_num >=2) {
	 form.elements["txRate"+wlan_id].options[idx++] = new Option("MCS8", "21", false, false);
	 form.elements["txRate"+wlan_id].options[idx++] = new Option("MCS9", "22", false, false);
	 form.elements["txRate"+wlan_id].options[idx++] = new Option("MCS10", "23", false, false);
	 form.elements["txRate"+wlan_id].options[idx++] = new Option("MCS11", "24", false, false);
	 form.elements["txRate"+wlan_id].options[idx++] = new Option("MCS12", "25", false, false);
	 form.elements["txRate"+wlan_id].options[idx++] = new Option("MCS13", "26", false, false);
	 form.elements["txRate"+wlan_id].options[idx++] = new Option("MCS14", "27", false, false);
	 form.elements["txRate"+wlan_id].options[idx++] = new Option("MCS15", "28", false, false);
 }
}
 form.elements["txRate"+wlan_id].length = idx;
 
 for (i=0; i<idx; i++) {
 	txrate_str = form.elements["txRate"+wlan_id].options[i].value;
 if(wlan_txrate[wlan_id]  == txrate_str)
 	form.elements["txRate"+wlan_id].selectedIndex = i;
 }


}
var MultiLanguage = 0;
function mavis_write(string_name)
{
	document.write(eval("string_name[" + MultiLanguage + "]"));
}

function update_controlsideband(form, wlan_id)
{
	var index=form.elements["channelbound"+wlan_id].selectedIndex;
	
	if(index ==0)
		disableTextField(form.elements["controlsideband"+wlan_id]);	
	else {
		enableTextField(form.elements["controlsideband"+wlan_id]);
		updateChan_selectedIndex(form, wlan_id);
	}
	updateChan_channebound(form, wlan_id);
	var chan_number_idx=form.elements["chan"+wlan_id].selectedIndex;
	var chan_number_value=form.elements["chan"+wlan_id].value;	
	
	if(chan_number_idx==0 && chan_number_value==0)
		disableTextField(form.elements["controlsideband"+wlan_id]);	

}

function insertExtChannelOption(form,wlan_id)
{
	var wmode = form.elements["band"+wlan_id].value;
	var CurrentCh = form.elements["chan"+wlan_id].value;
	var option_length = form.elements["chan"+wlan_id].options.length;
	var end_channel_num = 1;
	if (regDomain[wlan_id]==1 || regDomain[wlan_id]==2) //start = 1; end = 11;
		end_channel_num = 7;
	if (regDomain[wlan_id]==3)	//start = 1; end = 13;
		end_channel_num = 9;
	if (regDomain[wlan_id]==6)	//start = 1; end = 14;
		end_channel_num = 10;

	var x =form.elements["controlsideband"+wlan_id];
	var length = form.elements["controlsideband"+wlan_id].options.length;
	if (length > 1)
	{
		x.selectedIndex = 1;
		x.remove(x.selectedIndex);
	}
	if ((CurrentCh >=1) && (CurrentCh <= 4))
	{
		x.options[0].text = 1*CurrentCh + 4;
		x.options[0].value = 0;	//2011.05.05 Jerry
	}
	else if ((CurrentCh >= 5) && (CurrentCh <= end_channel_num))
	{
		x.options[0].text = 1*CurrentCh - 4;
		x.options[0].value = 0;
		CurrentCh = 1*CurrentCh;
		CurrentCh += 4;
		form.elements["controlsideband"+wlan_id].options[1]=new Option(CurrentCh);
		form.elements["controlsideband"+wlan_id].options[1].value=1;
	}
	else if (CurrentCh > end_channel_num)
	{
		x.options[0].text = 1*CurrentCh - 4;
		x.options[0].value = 0;
	}
	else
	{
		x.options[0].text = "Auto";
		x.options[0].value = "1";
	}
}

function updateChan_selectedIndex(form, wlan_id)
{
	var chan_number_idx=form.elements["chan"+wlan_id].selectedIndex;
	var chan_number= form.elements["chan"+wlan_id].options[chan_number_idx].value;
	wlan_channel[wlan_id] = chan_number;
	if(chan_number == 0)
		disableTextField(form.elements["controlsideband"+wlan_id]);	
	else{
		if(form.elements["channelbound"+wlan_id].selectedIndex == "0")
 			disableTextField(form.elements["controlsideband"+wlan_id]);	
 		else
			{
			enableTextField(form.elements["controlsideband"+wlan_id]);
			insertExtChannelOption(form,wlan_id);
			}
		}
	
}

function is_wlphrase(s, v, o){
	var pseed = new Array;
	var wep_key = new Array(5);
	var randNumber;

		wepType = document.form.keyLength<% getIndex("wlan_idx"); %>.value;
		wepKey1 = document.form.wepKey<% getIndex("wlan_idx"); %>;
		wepKey2 = document.form.rt_key2;
		wepKey3 = document.form.rt_key3;
		wepKey4 = document.form.rt_key4;
	
		phrase = o.value;
	if(wepType == "1"){
		for(var i = 0; i < phrase.length; i++){
			pseed[i%4] ^= phrase.charCodeAt(i);
		}
		
		randNumber = pseed[0] | (pseed[1]<<8) | (pseed[2]<<16) | (pseed[3]<<24);
		for(var j = 0; j < 5; j++){
			randNumber = ((randNumber*0x343fd)%0x1000000);
			randNumber = ((randNumber+0x269ec3)%0x1000000);
			wep_key[j] = ((randNumber>>16)&0xff);
		}
		
		wepKey1.value = binl2hex_c(wep_key);
		for(var j = 0; j < 5; j++){
			randNumber = ((randNumber * 0x343fd) % 0x1000000);
			randNumber = ((randNumber + 0x269ec3) % 0x1000000);
			wep_key[j] = ((randNumber>>16) & 0xff);
		}
		
		wepKey2.value = binl2hex_c(wep_key);
		for(var j = 0; j < 5; j++){
			randNumber = ((randNumber * 0x343fd) % 0x1000000);
			randNumber = ((randNumber + 0x269ec3) % 0x1000000);
			wep_key[j] = ((randNumber>>16) & 0xff);
		}
		
		wepKey3.value = binl2hex_c(wep_key);
		for(var j = 0; j < 5; j++){
			randNumber = ((randNumber * 0x343fd) % 0x1000000);
			randNumber = ((randNumber + 0x269ec3) % 0x1000000);
			wep_key[j] = ((randNumber>>16) & 0xff);
		}
		
		wepKey4.value = binl2hex_c(wep_key);
	}
	else if(wepType == "2" || wepType == "3"){
		password = "";
		
		if(phrase.length > 0){
			for(var i = 0; i < 64; i++){
				ch = phrase.charAt(i%phrase.length);
				password = password+ch;
			}
		}
		password = calcMD5(password);
		if(wepType == "2"){
			wepKey1.value = password.substr(0, 26);
		}
		else{
			wepKey1.value = password.substr(0, 32);
		}
		wepKey2.value = wepKey1.value;
		wepKey3.value = wepKey1.value;
		wepKey4.value = wepKey1.value;
	}
	return true;
}

function change_common(o, s, v){
	var selected_key;
	if(v == "rt_key"){ /* Handle AuthenticationMethod Change */
		if(o.value==1)
		selected_key = eval("document.form.wepKey<% getIndex("wlan_idx"); %>");
		else
		selected_key = eval("document.form.rt_key"+o.value);
		selected_key.focus();
		selected_key.select();
	}
	return true;
}

function automode_hint(){ //For 54Mbps limitation in auto mode + WEP/TKIP.
	if(document.form.band<% getIndex("wlan_idx"); %>.value == "10" && 
	   (document.form.keyLength<% getIndex("wlan_idx"); %>.value == 1 || 
	    document.form.keyLength<% getIndex("wlan_idx"); %>.value == 2 || 
	    document.form.authMode<% getIndex("wlan_idx"); %>.value == "radius" ||
	    ((document.form.authMode<% getIndex("wlan_idx"); %>.value == "psk" || document.form.authMode<% getIndex("wlan_idx"); %>.value == "wpa" || document.form.authMode<% getIndex("wlan_idx"); %>.value == "pskauto") && document.form.crypto<% getIndex("wlan_idx"); %>.value.indexOf("tkip") == 0) 
	   )
	  ){
		$("band_hint").style.display = "block";
	}
	else{
		$("band_hint").style.display = "none";
	}	
}

function nmode_limitation(){ //For TKIP limitation in n mode.
	if(document.form.band<% getIndex("wlan_idx"); %>.value == "7"){
		if(document.form.authMode<% getIndex("wlan_idx"); %>.selectedIndex == 0 && (document.form.keyLength<% getIndex("wlan_idx"); %>.selectedIndex == "1" || document.form.keyLength<% getIndex("wlan_idx"); %>.selectedIndex == "2")){
			alert("<#WLANConfig11n_nmode_limition_hint#>");
			document.form.authMode<% getIndex("wlan_idx"); %>.selectedIndex = 3;
		}
		else if(document.form.authMode<% getIndex("wlan_idx"); %>.selectedIndex == 1){
			alert("<#WLANConfig11n_nmode_limition_hint#>");
			document.form.authMode<% getIndex("wlan_idx"); %>.selectedIndex = 3;
		}
		else if(document.form.authMode<% getIndex("wlan_idx"); %>.selectedIndex == 2){
			alert("<#WLANConfig11n_nmode_limition_hint#>");
			document.form.authMode<% getIndex("wlan_idx"); %>.selectedIndex = 3;
		}
		else if(document.form.authMode<% getIndex("wlan_idx"); %>.selectedIndex == 5){
			alert("<#WLANConfig11n_nmode_limition_hint#>");
			document.form.authMode<% getIndex("wlan_idx"); %>.selectedIndex = 6;
		}
		wep_warning_flag = 0;
		change_auth(document.form.authMode<% getIndex("wlan_idx"); %>);
		wep_warning_flag = 1;
	}
}

