const Raiden = require('../index.js')

let raiden = new Raiden("http://localhost:5001")
let events = raiden.events.getTokenNetworksCreationEvents()
console.log(events);