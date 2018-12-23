const Provider = require('./provider.js')
const Token = require('./token.js');
const Channel = require('./channel.js');
const Events = require('./events.js');

function Raiden (url) {
	Provider.call(this, url);
	this.token = new Token(this.url);
	this.channel = new Channel(this.url);
	this.events = new Events(this.url);
}

module.exports = Raiden;