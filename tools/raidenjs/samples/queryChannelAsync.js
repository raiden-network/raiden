const Raiden = require('../index.js')

let raiden = new Raiden("http://localhost:5001")
raiden.channel.getChannelAsync("0xc778417E063141139Fce010982780140Aa0cD5Ab", "YOUR PARTNER" , (value, error) => {
	if(error) throw error.toString()
	console.log(value)
})
