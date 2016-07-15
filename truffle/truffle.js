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
        "ChannelManagerLibrary",
        "Dcdr",
        "EndpointRegistry",
        "HumanStandardToken",
        "NettingChannelLibrary",
        "Registry",
        "Standard_Token",
        "StandardToken",
        "Token"
        ],
    rpc: {
        host: "localhost",
        port: 8101,
        from: "329482da2a2c7b2412589d85312765f32514dd59"
    }
};
