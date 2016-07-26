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
        "Dcdr",
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
        host: "localhost",
        port: 8545
    }
};
