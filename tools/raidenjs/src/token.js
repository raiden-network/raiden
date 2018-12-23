/*
The following Script contains all the possible interaction with token networks in the raiden node
TODO: Converting automatically token address recognized as non EIP55 in EIP55 address.

MIT License

Copyright (c) 2018 Giulio rebuffo

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

*/
const Web3 = require("web3")
const HTTPRequest = require("./httpRequest.js")
const AsyncHTTPRequest = require("./AsyncHttpRequest.js")

function Token (url) {
	this.url = url;
}
/**
 * Should be used to deploy a new to token network
 *
 * @method newTokenNetwork
 * @param {String} token address
 * @return {String} address of the token network
 */
Token.prototype.newTokenNetwork = function (token) {
	let checksum = Web3.utils.toChecksumAddress(token);

	console.log(this.url + '/api/1/tokens/' + checksum)
	let res = HTTPRequest(this.url + '/api/1/tokens/' + checksum, 'PUT');
	switch (res.status) {
		case 402:
			throw '402: Insufficient ETH to pay for the gas of the register on-chain transaction';
		case 404:
			throw '404: Not a valid EIP55 encoded address or method disabled';
		case 409:
			throw 'The token was already registered before, or The registering transaction failed.';
		case 501:
			throw 'Method disabled';
	}

	return res.message.token_network_address;
}
/**
 * Should be used to deploy a new to token network asyncronously
 *
 * @method newTokenNetworkAsync
 * @param {String} token address
 * @param {Function} the asyncronous callback
 * @return {XMLHttpRequest} the http request
 */
Token.prototype.newTokenNetworkAsync = function (token, callback) {
	let checksum = Web3.utils.toChecksumAddress(token);
	return AsyncHTTPRequest(this.url + '/api/1/tokens/' + checksum, 'PUT', null,callback)
}
/**
 * Should be used to query all the registred token addresses
 *
 * @method getRegisteredTokens
 * @return {Array} the list of the addresses
 */
Token.prototype.getRegisteredTokens = function () {
	let res = HTTPRequest(this.url + '/api/1/tokens', 'GET')

	if (res.status !== 200) {
		throw res.status + ': Raiden internal error';
	}

	return res.message;
}
/**
 * Should be used to query all the registred token addresses asyncronously
 *
 * @method getRegisteredTokensAsync
 * @param {Function} the asyncronous callback
 * @return {XMLHttpRequest} the http request
 */
Token.prototype.getRegisteredTokensAsync = function ( callback ) {
	return AsyncHTTPRequest(this.url + '/api/1/tokens', 'GET', null,callback)
}
/**
 * Should be used to query all joined token networks
 *
 * @method getRegisteredTokens
 * @return {Array} the list of the token networks
 */
Token.prototype.getJoinedTokenNetworks = function () {
	let res = HTTPRequest(this.url + '/api/1/connections', 'GET')

	if (res.status !== 200) {
		throw res.status + ': Raiden internal error';
	}

	return res.message;
}
/**
 * Should be used to query all joined token networks asyncronously
 *
 * @method getRegisteredTokensAsync
 * @param {Function} the asyncronous callback
 * @return {XMLHttpRequest} the http request
 */
Token.prototype.getJoinedTokenNetworksAsync = function (callback) {
	return AsyncHTTPRequest(this.url + '/api/1/connections', 'GET', null,callback)
}
/**
 * Should be used to join a token network
 *
 * @method joinTokenNetwork
 * @param {String} token address
 * @param {Number} the initial amount of funds to deposit in the token address
 * @param {Function} the asyncronous callback
 * @return {XMLHttpRequest} the http request
 */
Token.prototype.joinTokenNetwork = function(token, funds, callback) {
	let checksum = Web3.utils.toChecksumAddress(token);
	return AsyncHTTPRequest(this.url + '/api/1/connections/' + checksum, 'PUT', {
		"funds": funds
	},callback)
}
/**
 * Should be used to leave a token network
 *
 * @method leaveTokenNetwork
 * @param {String} token address
 * @param {Number} the initial amount of funds to deposit in the token address
 * @param {Function} the asyncronous callback
 * @return {XMLHttpRequest} the http request
 */
Token.prototype.leaveTokenNetwork = function (token, callback) {
	let checksum = Web3.utils.toChecksumAddress(token);
	let req = AsyncHTTPRequest(this.url + '/api/1/connections/' + checksum, 'DELETE', null,callback)
	setTimeout(function() {  
		if(req.readyState === 4) return;
		req.abort() 
		throw "The token network can't be closed due to timeout";
	}, 1000);
	return req;
}
/**
 * Should be used to initialize a payment
 *
 * @method initPayment
 * @param {Object} transaction object
 * @param {Function} the asyncronous callback
 * @return {XMLHttpRequest} the http request
 */
Token.prototype.initPayment = function(tx, callback) {
	tx.to = Web3.utils.toChecksumAddress(tx.to);
	tx.token = Web3.utils.toChecksumAddress(tx.token);
	return AsyncHTTPRequest(this.url + '/api/1/payments/' + tx.token + '/' + tx.to, 'POST', {
		"amount": tx.value
	}, callback)
}

module.exports = Token;
