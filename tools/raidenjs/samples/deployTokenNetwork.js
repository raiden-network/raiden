const Raiden = require('../index.js')

let raiden = new Raiden("http://localhost:5001")
let token_network = raiden.token.newTokenNetwork("0x49ca7c2dabc2112a3d3b703493904fa96b67eec6")
console.log(token_network);
