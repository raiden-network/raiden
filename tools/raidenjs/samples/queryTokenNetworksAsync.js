const Raiden = require('../index.js')

let raiden = new Raiden("http://localhost:5001")
raiden.token.getJoinedTokenNetworksAsync((value, error) => {
	if(error) throw error
	console.log(value)
})
