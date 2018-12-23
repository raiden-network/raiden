const Raiden = require('../index.js')

let raiden = new Raiden("http://localhost:5001")
let channels = raiden.channel.getChannels()
console.log(channels);