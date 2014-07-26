<html>
<head>
<title><#ZVMODELVZ#> Web Manager</title>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<link rel="stylesheet" type="text/css" href="/form_style.css" media="screen"></link>
<script language="javascript">

</script>
</head>  

<body>
<input type="hidden" name="enable" value="">

<table class="formTable"  width="600" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3">
	<thead>
	<tr>
		<th>Firmware Version</th>
		<td><% getInfo("fw_Version_Rd"); %></td>
	</tr>
	<tr>
		<th>BootLoader Version</th>
		<td><% getInfo("Get_BootLoaderVersion"); %></td>
	</tr>
	</thead>
</table>	

</form>
</body>
</html>
