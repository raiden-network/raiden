const { exec } = require('child_process');
const {ipcRenderer} = require('electron');
const Worker = require('webworker-threads').Worker;
const remote = require('electron').remote;
const fs = remote.require("fs")
const Web3 = require("web3")
const mainnet = []
//Confirm the installation
function confirmInstallation() {
	window.location = "pages/installation.html"
}
//Confirm the installation
function confirmUninstallation() {
	window.location = "pages/uninstallation.html"
}
// Confirm the reinstallation
function confirmReinstallation() {
	window.location = "pages/reinstallation.html"
}
// Confirm the upgrade
function confirmUpgrade() {
	try {
		let user = require("os").userInfo().username;
		let oldVersion = fs.readFileSync('/home/' + user + '/.raiden/version').toString();
		let newVersion = fs.readFileSync('./version').toString();
		if(mainnet.includes(newVersion) && !mainnet.includes(oldVersion)){
			alert("detected different network between, " + oldVersion + "(ropsten) and " + newVersion + "(mainnet), therefore you may need to fill the installation form");
			confirmReinstallation();
		} else if(!mainnet.includes(newVersion) && mainnet.includes(oldVersion)){
			alert("detected different network between, " + oldVersion + "(mainnet) and " + newVersion + "(ropsten), therefore you need to fill the installation form");
			confirmReinstallation();
		} else {
		document.body.innerHTML = "<img src = './loading.gif' >";
		ipcRenderer.send('load');
		let thread = new Worker(function(){

				var initiation = new Date().getTime();
    			while ((new Date().getTime() - initiation) < 500);
				postMessage(":-)");
			

		})
			thread.onmessage = function(event) {
			system("cp raiden-cli ~/.raiden/raiden-cli")
			system("cp version ~/.raiden/version")
			GenerateLauncher();
			window.location = "pages/success2.html"
		}

	};
	} catch(e) {
		alert(e.message);
	}
}
// Kill the proccess
function end() {
		const Window = remote.getCurrentWindow();
      	Window.close();
		process.exit(1)
}
// Safe System call
function safeSystem(cmd) {
	const { exec } = require('child_process');
	exec(cmd, (err, stdout, stderr) => {
	  if (err) {
	    alert( err.message )
	    end()
	  }
	});
}
// Standard system call
function system(cmd) {
	const { exec } = require('child_process');
	exec(cmd, (err, stdout, stderr) => {
	  if (err) {
	    alert( err.message )
	    end()
	  }
	});
}

// Append to file
function append(path, value) {
  var data = fs.readFileSync(path, 'utf-8');
  var newValue = data + value;
  fs.writeFile(path, newValue, 'utf-8');
}
// Get Desktop Ubuntu
function getDesktop() {
	let user = require("os").userInfo().username;
	const { exec } = require('child_process');
	let ret;

	return ret;
}
// Generate Launcher
function GenerateLauncher() {
	exec("xdg-user-dir DESKTOP", (err, stdout, stderr) => {
	  if (err) {
	    alert( err.message )
	    end()
	  }
	  let desktop = stdout;
	  desktop = desktop.substring(0, desktop.length-1);
	  let launcher = desktop + "/Raiden";
	  exec("cp -a Raiden -b " + launcher, (err, stdout, stderr) => {});
  	  system("chmod a+x " + launcher);
  });

}
// Generate raiden-quick and raiden-cli
function generateScripts(keystore, infura, network ) {
		let user = require("os").userInfo().username;
		let infuraUrl = "https://" + network + ".infura.io/" + infura;
		let keyPath = "/home/" + user + "/.raiden/keys";
		let dataPath = "/home/" + user + "/.raiden/data";
		let jsonPath = keyPath + "/key0.json";
		let raiden_quickPath = "/home/" + user +"/.raiden/raiden-quick";
		GenerateLauncher();
		system("mkdir /home/" + user + "/.raiden");
		system("mkdir " + dataPath);
		system("mkdir " + keyPath);
		system("cp " + keystore + " " + jsonPath);
		system("> " + raiden_quickPath);
		system("cp raiden-cli ~/.raiden/")
		system("cp version ~/.raiden/")
	  	append(raiden_quickPath, "# /bin/env bash\n")
	  	let raiden_quickContent = "/home/$USER/.raiden/raiden-cli --keystore-path /home/$USER/.raiden/keys --datadir /home/$USER/.raiden/data --eth-rpc-endpoint " + infuraUrl + "\n"
	  	append(raiden_quickPath, raiden_quickContent)
	  	system("chmod a+x " + raiden_quickPath);
}
// Setup bash(Modify $PATH properly)
function setupBash() {
	let user = require("os").userInfo().username;
	if ((fs.readFileSync("/home/" + user + "/.bashrc")).indexOf("export PATH=/home/$USER/.raiden:$PATH") === -1)
		append("/home/" + user + "/.bashrc", "\n export PATH=/home/$USER/.raiden:$PATH")
}
// Start Installation Process
function StartInstallation() {
	try {
		if( document.getElementById('keystore').files[document.getElementById('keystore').files.length-1] === undefined ){
			alert('You need a valid json keystore')
			return;
		}
		let keystore = document.getElementById('keystore').files[document.getElementById('keystore').files.length-1].path
		let keystoreValue = fs.readFileSync(document.getElementById('keystore').files[document.getElementById('keystore').files.length-1].path)
		let infura = document.getElementById('infura').value;
		let network = document.getElementById('network').value;
		if( !checkJson(keystoreValue) ) return;
		document.body.innerHTML = "<img src = '../loading.gif' >";
		ipcRenderer.send('load');
		let thread = new Worker(function(){

				var initiation = new Date().getTime();
    			while ((new Date().getTime() - initiation) < 500);
				postMessage(":-)");
			

		})
		thread.onmessage = function(event) {
		  generateScripts(keystore, infura, network)
		  setupBash();
		  ipcRenderer.send('default');
		  window.location = "./success.html"
		};
	} catch(e) {
		alert(e.message);
	}
}
// Start Reinstallation Process
function StartReinstallation() {
	try {
		if( document.getElementById('keystore').files[document.getElementById('keystore').files.length-1] === undefined ){
			alert('You need a valid json keystore')
			return;
		}
		let keystore = document.getElementById('keystore').files[document.getElementById('keystore').files.length-1].path
		let keystoreValue = fs.readFileSync(document.getElementById('keystore').files[document.getElementById('keystore').files.length-1].path)
		let infura = document.getElementById('infura').value;
		let network = document.getElementById('network').value;
		if( !checkJson(keystoreValue) ) return;
		document.body.innerHTML = "<img src = '../loading.gif' >";
		ipcRenderer.send('load');
		let thread = new Worker(function(){

				var initiation = new Date().getTime();
    			while ((new Date().getTime() - initiation) < 500);
				postMessage(":-)");
			

		})
		thread.onmessage = function(event) {
		  system("rm ~/.raiden -rf")
		  generateScripts(keystore, infura, network)
		  setupBash();
		  ipcRenderer.send('default');
		  window.location = "./success.html"
		};
	} catch(e) {
		alert(e.message);
	}
}
// Start Uninstallation Process
function StartUninstallation() {
	try {
		document.body.innerHTML = "<img src = '../loading.gif' >";
		ipcRenderer.send('load');
		let thread = new Worker(function(){

				var initiation = new Date().getTime();
    			while ((new Date().getTime() - initiation) < 500);
				postMessage(":-)");
			

		})
		thread.onmessage = function(event) {
		  system("rm ~/.raiden -rf")
		  window.location = "./success1.html"
		};
	} catch(e) {
		alert(e.message);
	}
}
// check if the json is a keystore
function checkJson(stringifiedJson) {
	try {
		let key = JSON.parse(stringifiedJson)
		if(key.address === undefined)
			throw 'Not a valid json'
		return 1;	
	}catch(e) {
		alert("Not a valid json");
		return 0;
	}

}
// Open the browser in a given link
function navigate(link) {
	exec('firefox ' + link, (err, stdout, stderr) => {
	  if (err) {
	    alert("Firefox not installed on this system")
	  }
	});
}
