const Raiden = require('../index.js')

let raiden = new Raiden("http://localhost:5001")
let partners = raiden.getPartners("0xc778417E063141139Fce010982780140Aa0cD5Ab")
console.log(partners);