const Raiden = require('../index.js')

let raiden = new Raiden("http://localhost:5001")
// You can also specify a partner in the second argument if you want a more accurate research
let events = raiden.events.getChannelsEvents("0xc778417E063141139Fce010982780140Aa0cD5Ab")
console.log(events);