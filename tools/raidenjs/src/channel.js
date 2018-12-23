/*
The following Script contains all the possible interaction with channels in the raiden node

MIT License

Copyright (c) 2018 Giulio rebuffo

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

*/
const Web3 = require("web3")
const HTTPRequest = require("./httpRequest.js")
const AsyncHTTPRequest = require("./AsyncHttpRequest.js")

function Channel (url) {
	this.url = url;
}
/**
 * Should be used to get all unsetteled channels
 *
 * @method getChannels
 * @return {Array} the list of all the channels
 */
Channel.prototype.getChannels = function () {
	let res = HTTPRequest(this.url + '/api/1/channels', 'GET')

	if (res.status !== 200) {
		throw res.status + ': Raiden internal error';
	}

	return res.message;
}
/**
 * Should be used to get all unsetteled channels for a given token
 *
 * @method getChannelsForToken
 * @param {String} token address
 * @return {Array} list of channels
 */
Channel.prototype.getChannelsForToken = function (token) {
	let checksum = Web3.utils.toChecksumAddress(token);
	let res = HTTPRequest(this.url + '/api/1/channels/' + checksum, 'GET')

	if (res.status !== 200) {
		throw res.status + ': Raiden internal error';
	}

	return res.message;
}
/**
 * Should be used to get all unsetteled channels asyncronously
 *
 * @method getChannelsAsync
 * @param {Function} the asyncronous callback
 * @return {XMLHttpRequest} the http request
 */
Channel.prototype.getChannelsAsync = function (callback) {
	return AsyncHTTPRequest(this.url + '/api/1/channels', 'GET', null, callback)
}
/**
 * Should be used to get all unsetteled channels for a given token ayncronously
 *
 * @method getChannelsForTokenAsync
 * @param {String} token address
 * @param {Function} the asyncronous callback
 * @return {XMLHttpRequest} the http request
 */
Channel.prototype.getChannelsForTokenAsync = function (token, callback) {
	let checksum = Web3.utils.toChecksumAddress(token);
	return AsyncHTTPRequest(this.url + '/api/1/channels/' + checksum, 'GET', null, callback)
}
/**
 * Should be used to get a specific unsettled channel
 *
 * @method getChannel
 * @param {String} token address
 * @param {String} partner address
 * @return {Object} the channel
 */
Channel.prototype.getChannel = function (token, partner) {
	let checksum_token = Web3.utils.toChecksumAddress(token);
	let checksum_partner = Web3.utils.toChecksumAddress(partner);
	let res = HTTPRequest(this.url + '/api/1/channels/' + checksum_token + '/' + checksum_partner, 'GET')
	if (res.status !== 200) {
		throw res.message.errors;
	}

	return res.message;
}
/**
 * Should be used to get a specific channel asyncronously
 *
 * @method getChannelAsync
 * @param {String} token address
 * @param {String} partner address
 * @param {Function} the asyncronous callback
 * @return {XMLHttpRequest} the http request
 */
Channel.prototype.getChannelAsync = function (token, partner, callback) {
	let checksum_token = Web3.utils.toChecksumAddress(token);
	let checksum_partner = Web3.utils.toChecksumAddress(partner);
	return AsyncHTTPRequest(this.url + '/api/1/channels/' + checksum_token + '/' + checksum_partner, 'GET', null,callback)
}
/**
 * Should be used to get all the address which have unsettled channels with the node address
 *
 * @method getPartners
 * @param {String} token address
 * @param {Function} the asyncronous callback
 * @return {Array} the list of addresses
 */
Channel.prototype.getPartners = function(token) {
	let checksum = Web3.utils.toChecksumAddress(token);
	let res = HTTPRequest(this.url + '/api/1/tokens/' + checksum + '/partners', 'GET')

	switch (res.status) {
		case 404:
			throw '404: Token Address not found or given token is not a valid EIP-55 Encoded Ethereum address';
		case 500:
			throw 'Internal Error';
	}

	return res.message;
}
/**
 * Should be used to get all the address which have unsettled channels with the node address asyncroously
 *
 * @method getPartnersAsync
 * @param {String} token address
 * @param {Function} the asyncronous callback
 * @return {XMLHttpRequest} the http request
 */
Channel.prototype.getPartnersAsync = function(token, callback) {
	let checksum = Web3.utils.toChecksumAddress(token);
	return AsyncHTTPRequest(this.url + '/api/1/tokens/' + checksum + '/partners', 'GET', null ,callback);
}
/**
 * Should be used to open a new channel
 *
 * @method openChannel
 * @param {String} token address
 * @param {String} token address
 * @param {Number} total amount of token for initial deposit
 * @param {Number} number of block before automatic settle
 * @param {Function} the asyncronous callback
 * @return {XMLHttpRequest} the http request
 */
Channel.prototype.openChannel = function(partner, token, deposit, settle_timeout, callback) {
	let checksum_partner = Web3.utils.toChecksumAddress(partner);
	let checksum_token = Web3.utils.toChecksumAddress(token);
	return AsyncHTTPRequest(this.url + '/api/1/channels', 'PUT', {
		    "partner_address": checksum_partner,
			"token_address": checksum_token,
			"total_deposit": deposit,
			"settle_timeout": settle_timeout
	} ,callback);
}
/**
 * Should be used to close a specific channel
 *
 * @method closeChannel
 * @param {String} token address
 * @param {String} partner address
 * @param {Function} the asyncronous callback
 * @return {XMLHttpRequest} the http request
 */
Channel.prototype.closeChannel = function(token, partner, callback) {
	let checksum_partner = Web3.utils.toChecksumAddress(partner);
	let checksum_token = Web3.utils.toChecksumAddress(token);
	let req =  AsyncHTTPRequest(this.url + '/api/1/channels/' + checksum_token + "/" + checksum_partner, 'PATCH', { "state": "closed" } ,callback);
	// if we do not abort the request will be alive while the partner doesn't close it as well
	setTimeout(function(){ req.abort() }, 3000);
	return req;
}
/**
 * Should be used to deposit tokens into a channel
 *
 * @method deposit
 * @param {String} token address
 * @param {String} partner address
 * @param {Number} the amount of token to deposit
 * @param {Function} the asyncronous callback
 * @return {XMLHttpRequest} the http request
 */
Channel.prototype.deposit = function(token, partner, amount ,callback) {
	let checksum_partner = Web3.utils.toChecksumAddress(partner);
	let checksum_token = Web3.utils.toChecksumAddress(token);
	let channel = this.getChannel(token, partner);
	let req =  AsyncHTTPRequest(this.url + '/api/1/channels/' + checksum_token + "/" + checksum_partner, 'PATCH', { 
		"total_deposit": channel.total_deposit + amount 
	} ,callback);
	// if we do not abort the request will be alive while the partner doesn't close it as well
	return req;
}
// IMPORTANT: these functions will count just the unsettled channels in which the given node is involved
module.exports = Channel;
