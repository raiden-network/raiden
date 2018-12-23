const Raiden = require('../index.js')

let raiden = new Raiden("http://localhost:5001")
raiden.setProvider("http://localhost:9090")
console.log(raiden.url);
