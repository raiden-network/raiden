module.exports = {
    build: {
        "index.html": "index.html",
        "app.js": [
            "javascripts/app.js"
            ],
        "app.css": [
            "stylesheets/app.css"
            ],
        "images/": "images/"
    },
    deploy: [
        "ChannelManagerContract",
        "ChannelManagerLibrary",
        "EndpointRegistry",
        "HumanStandardToken",
        "NettingChannelContract",
        "NettingChannelLibrary",
        "Registry",
        "Standard_Token",
        "StandardToken",
        "Token"
        ],
    rpc: {
        from: "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a",
        host: "localhost",
        port: 8545
    }
};
