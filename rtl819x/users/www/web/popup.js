// JavaScript Document
var winH,winW;
		
function winW_H(){
	if(parseInt(navigator.appVersion) > 3){
		winW = document.documentElement.scrollWidth;
		if(document.documentElement.clientHeight > document.documentElement.scrollHeight)
			winH = document.documentElement.clientHeight;
		else
			winH = document.documentElement.scrollHeight;
	}
} 

function LoadingTime(seconds, flag){
	showtext($("proceeding_main_txt"), "<#Main_alert_proceeding_desc1#>...");
	$("Loading").style.visibility = "visible";
	
	y = y+progress;
	if(typeof(seconds) == "number" && seconds >= 0){
		if(seconds != 0){
			showtext($("proceeding_main_txt"), "<#Main_alert_proceeding_desc4#>");
			showtext($("proceeding_txt"), Math.round(y)+"% <#Main_alert_proceeding_desc1#>");
			--seconds;
			setTimeout("LoadingTime("+seconds+", '"+flag+"');", 1000);
		}
		else{
			showtext($("proceeding_main_txt"), translate("<#Main_alert_proceeding_desc3#>"));
			showtext($("proceeding_txt"), "");
			y = 0;
			
			if(flag != "waiting")
				setTimeout("hideLoading();",1000);			
		}
	}
}
function LoadingProgress(seconds){
	$("LoadingBar").style.visibility = "visible";
	
	y = y + progress;
	if(typeof(seconds) == "number" && seconds >= 0){
		if(seconds != 0){
			$("proceeding_img").style.width = Math.round(y) + "%";
			$("proceeding_img_text").innerHTML = Math.round(y) + "%";
			--seconds;
			setTimeout("LoadingProgress("+seconds+");", 1000);
		}
		else{
			$("proceeding_img_text").innerHTML = "<#Main_alert_proceeding_desc3#>";
			y = 0;
			setTimeout("hideLoadingBar();",1000);
			location.href = "index.asp";
		}
	}
}
//--------Edison 2011.4.25
function maxfilter(entryNum,Max_Filter_Num){
	if (entryNum + 1 > Max_Filter_Num){
		alert("<#JS_itemlimit1#> "+ Max_Filter_Num +"<#JS_itemlimit2#>");
		return true;
	}
	return false;
}
//-----------------------
function showLoading(seconds, flag){
	disableCheckChangedStatus();
	
	if(location.pathname.indexOf("QIS_wizard.htm") < 0)
		hideHint();
	clearHintTimeout();
	
	htmlbodyforIE = document.getElementsByTagName("html");  //this both for IE&FF, use "html" but not "body" because <!DOCTYPE html PUBLIC.......>
	htmlbodyforIE[0].style.overflow = "hidden";	  //hidden the Y-scrollbar for preventing from user scroll it.
	
	winW_H();
	var blockmarginTop;
	var sheight = document.documentElement.scrollHeight;
	var cheight = document.documentElement.clientHeight

	blockmarginTop = (navigator.userAgent.indexOf("Safari")>=0)?(sheight-cheight<=0)?200:sheight-cheight+200:document.documentElement.scrollTop+200;
	
	//Lock modified it for Safari4 display issue.
	$("loadingBlock").style.marginTop = blockmarginTop+"px";
	$("Loading").style.width = winW+"px";
	$("Loading").style.height = winH+"px";
	
	loadingSeconds = seconds;
	progress = 100/loadingSeconds;
	y = 0;
	
	LoadingTime(seconds, flag);
}

function dr_advise(){
	disableCheckChangedStatus();
	
	clearHintTimeout();
	
	htmlbodyforIE = document.getElementsByTagName("html");  //this both for IE&FF, use "html" but not "body" because <!DOCTYPE html PUBLIC.......>
	htmlbodyforIE[0].style.overflow = "hidden";	  //hidden the Y-scrollbar for preventing from user scroll it.
	
	winW_H();
	var blockmarginTop;
	blockmarginTop = document.documentElement.scrollTop + 200;	
	$("dr_sweet_advise").style.marginTop = blockmarginTop+"px"
	$("hiddenMask").style.width = winW+"px";
	$("hiddenMask").style.height = winH+"px";	
	$("hiddenMask").style.visibility = "visible";
}

function showLoadingBar(seconds){
	disableCheckChangedStatus();
	
	if(location.pathname.indexOf("QIS_wizard.htm") < 0)
		hideHint();
	clearHintTimeout();
	
	htmlbodyforIE = document.getElementsByTagName("html");  //this both for IE&FF, use "html" but not "body" because <!DOCTYPE html PUBLIC.......>
	htmlbodyforIE[0].style.overflow = "hidden";	  //hidden the Y-scrollbar for preventing from user scroll it.
	
	winW_H();

	//2011.04.14 Jerry {
	var blockmarginTop;
	var sheight = document.documentElement.scrollHeight;
	var cheight = document.documentElement.clientHeight

	blockmarginTop = (navigator.userAgent.indexOf("Safari")>=0)?(sheight-cheight<=0)?200:sheight-cheight+200:document.documentElement.scrollTop+200;
	
	//Lock modified it for Safari4 display issue.
	$("loadingBarBlock").style.marginTop = blockmarginTop+"px";
	$("LoadingBar").style.width = winW+"px";
	$("LoadingBar").style.height = winH+"px";
	
	loadingSeconds = seconds;
	progress = 100/loadingSeconds;
	y = 0;
	
	LoadingProgress(seconds);
	//2011.04.14 Jerry }
}

function hideLoadingBar(){
	enableCheckChangedStatus();
	$("LoadingBar").style.visibility = "hidden";
}

function hideLoading(flag){
	if(flag != "noDrSurf")
		enableCheckChangedStatus();
	
	$("Loading").style.visibility = "hidden";
}             

function simpleSSID(obj){
	var SSID = document.loginform.wl_ssid.value;
	
	if(SSID.length < 16)
		showtext(obj, SSID);
	else{
		obj.title = SSID;
		showtext(obj, SSID.substring(0, 16)+"...");
	}
}
