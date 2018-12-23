const Raiden = require('../index.js')

let raiden = new Raiden("http://localhost:5001")
raiden.channel.getChannelsAsync((value, error) => {
	if(error) throw error.toString()
	console.log(value)
})
