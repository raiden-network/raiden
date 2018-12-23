const Raiden = require('../index.js')
const tx = {
	to: "0x61C808D82A3Ac53231750daDc13c777b59310bD9",
	value: 500,
	token: "0xc778417E063141139Fce010982780140Aa0cD5Ab",
}

let raiden = new Raiden("http://localhost:5001")
raiden.token.initPayment(tx , (value, error) => {
	if(error) throw error.toString()
	console.log(value)
})
