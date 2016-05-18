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
      "slice.sol",

      "HumanStandardTokenFactory.sol",
      "HumanStandardToken.sol",
      "SampleRecipient.sol",
      "Standard_Token.sol",
      "StandardToken.sol",
      "Token.sol"
      ],
  rpc: {
    host: "localhost",
    port: 4000
  }
};
