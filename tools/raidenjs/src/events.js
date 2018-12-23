/*
The following Script contains all the methods to get blockchain and raiden event for a given raiden node

MIT License

Copyright (c) 2018 Giulio rebuffo

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

*/
const Web3 = require("web3")
const HTTPRequest = require("./httpRequest.js")
const AsyncHTTPRequest = require("./AsyncHttpRequest.js")

function Events (url) {
	this.url = url;
}
/**
 * Should be used to get all TokenNetwork Creation events in Ethereum
 *
 * @method getTokenNetworksCreationEvents
 * @return {Array} the list of all the events
 */
Events.prototype.getTokenNetworksCreationEvents = function () {
	let res = HTTPRequest(this.url + '/api/1/_debug/blockchain_events/network', 'GET')

	if (res.status !== 200) {
		throw JSON.stringify(res.message);
	}

	return res.message;
}
/**
 * Should be used to get all TokenNetwork Creation events in Ethereum asyncronously
 *
 * @method getTokenNetworksCreationEvents
 * @param {Function} the asyncronous callback
 * @return {XMLHttpRequest} the http request
 */
Events.prototype.getTokenNetworksCreationEventsAsync = function (callback) {
	return AsyncHTTPRequest(this.url + '/api/1/_debug/blockchain_events/network', 'GET', null,callback)
}
/**
 * Should be used to get all events of a specific token network
 *
 * @method getTokenNetworkEvents
 * @param {String} token address
 * @return {Array} the list of all the events
 */
Events.prototype.getTokenNetworkEvents = function (token) {
	let token_checksum = Web3.utils.toChecksumAddress(token);
	let res;
	res = HTTPRequest(this.url + '/api/1/_debug/blockchain_events/tokens/' + token_checksum, 'GET')

    
	if (res.status !== 200) {
		throw JSON.stringify(res.message);
	}

	return res.message;
}
/**
 * Should be used to get all events of channels that uses a given token address
 *
 * @method getChannelsEvents
 * @param {String} token address
 * @param {String} Optional: the partner of the channel
 * @return {Array} the list of all the events
 */
Events.prototype.getChannelsEvents = function (token, partner) {
	let token_checksum = Web3.utils.toChecksumAddress(token);
	let res;
	if (partner) {
		let partner_checksum = Web3.utils.toChecksumAddress(partner);
		res = HTTPRequest(this.url + '/api/1/_debug/blockchain_events/payment_networks/' + token_checksum + '/channels/' + partner_checksum, 'GET')
	} else {
		res = HTTPRequest(this.url + '/api/1/_debug/blockchain_events/payment_networks/' + token_checksum + '/channels', 'GET')
	}
    
    
	if (res.status !== 200) {
		throw JSON.stringify(res.message);
	}
    
	return res.message;
}
/**
 * Should be used to get the payment history of a given channel
 *
 * @method getPaymentEventHistory
 * @param {String} token address
 * @param {String} Optional: the partner of the channel
 * @return {Array} the list of all the events
 */
Events.prototype.getPaymentEventHistory = function (token, partner) {
	let token_checksum = Web3.utils.toChecksumAddress(token);
	let partner_checksum = Web3.utils.toChecksumAddress(partner);
	let res = HTTPRequest(this.url + '/api/1/payments/' + token_checksum + '/' + partner_checksum, 'GET')
    
	if (res.status !== 200) {
		throw JSON.stringify(res.message);
	}
    
	return res.message;
}
/**
 * Should be used to get all raiden internal events
 *
 * @method getInternalEvents
 * @return {Array} the list of all the events
 */
Events.prototype.getInternalEvents = function () {
	let res = HTTPRequest(this.url + '/api/1/_debug/raiden_events', 'GET')
    
	if (res.status !== 200) {
		throw JSON.stringify(res.message);
	}
    
	return res.message;
}
// IMPORTANT: these functions will count just the unsettled channels in which the given node is involved
module.exports = Events;