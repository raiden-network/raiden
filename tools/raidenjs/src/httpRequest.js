/*
The following Script contains a simplified method that helps with interactions in raiden node

MIT License

Copyright (c) 2018 Giulio rebuffo

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

*/
const XMLHttpRequest = require("xmlhttprequest").XMLHttpRequest;
// Simplify request to Raiden node
const HTTPRequest = (url, method) => {
	// make request
	let request = new XMLHttpRequest();
	request.open(method, url, false);
	// Send request
	request.send(null);
	let parsed;

	if (request.responseText === undefined) {
		parsed = null;
	} else {
		parsed = JSON.parse(request.responseText);
	}

	return {
		"message" : parsed,
		"status" : request.status
		}
}

module.exports = HTTPRequest;
