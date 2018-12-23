/*
The following Script contains every information
needed information to establish connection with raiden node.
it also include the node ethereum address.

MIT License

Copyright (c) 2018 Giulio rebuffo

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

*/
const XMLHttpRequest = require("xmlhttprequest").XMLHttpRequest;
// this functions helps me in doing a simple request to query the node address
const getNodeAddress = function (url) {
	// make request
	let request = new XMLHttpRequest();
	request.open('GET', url + '/api/1/address', false);
	// Send request
	request.send(null);
	if (request.responseText === undefined) {
		throw JSON.stringify(request.statusText);
	}
	let parsed = JSON.parse(request.responseText);
	return parsed.our_address;
}

function Provider (url) {
	/**
	 * Should be used to check if the raiden node is online
	 *
	 * @method isConnected
	 * @return {Boolean} whatever the node is connected
	*/
	this.isConnected = function() {
			// make test request
			let request = new XMLHttpRequest();
			request.open('GET', this.url + '/api/1/address', false);
			// Send request
			request.send(null);
			if (request.status === 200 ) return true
			else return false;
	}
	/**
	 * Should be used to change provider
	 *
	 * @method setProvider
	 * @param {String} new url
	 * @return {Boolean} whatever the node is connected
	*/
	this.setProvider = function(url) {
			this.url = url;
			try {
				// Update node address
				this.address = getNodeAddress(this.url);
			} catch(e) {
				this.address = e.toString(this.url);
			}
	}
	// Set the initial provider of the raiden node
	this.setProvider(url);

}



module.exports = Provider;
