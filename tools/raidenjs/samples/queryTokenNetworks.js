const Raiden = require('../index.js')

let raiden = new Raiden("http://localhost:5001")
console.log(raiden.token.getJoinedTokenNetworks());
