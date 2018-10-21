const fs = remote.require("fs")
const md5File = require('md5-file')

setTimeout(function(){
	let user = require("os").userInfo().username;
	let version = md5File.sync("/home/" + user + "/.raiden/version")
	try {
		let newVersion = md5File.sync("version")
    	fs.statSync("/home/" + user + "/.raiden");
    	document.getElementById('unistall-container').innerHTML += "<button style = \"top:490px;left:165px;position:absolute\"type=\"button\" class=\"btn btn-primary standardImg\" onclick=\"confirmUninstallation()\">Uninstall</button>"
		document.getElementById("version").innerHTML = "Version " + fs.readFileSync("version");
		if(version !== newVersion) {
			document.getElementById('install').innerHTML = "Upgrade to " + fs.readFileSync("version");
			document.getElementById('install').setAttribute( "onClick", "confirmUpgrade()" );
		} else {
			document.getElementById('install').innerHTML = "Reinstall";
			document.getElementById('install').setAttribute( "onClick", "confirmReinstallation()" );
		}
		
  	} catch(e) {

  }

}, 150)
