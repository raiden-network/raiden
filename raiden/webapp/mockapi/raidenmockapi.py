#!flask/bin/python
from flask import Flask, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)
channels = [
    {
        "channel_address": "0x2a65aca4d5fc5b5c859090a6c34d164135398226",
        "partner_address": "0x9d80d905bc1e106d5bd0637c12b893c5ab60cb41",
        "token_address": "0x6266e28f62a851295a4afb9e3ceac754853b5a62",
        "balance": 500,
        "state": "open",
        "settle_timeout": 100
    },
    {
        "channel_address": "0x89dcbca4d5fc5b5c859090a6c34d164135398236",
        "partner_address": "0xbcadef1867123721cdcd7869ab12383467bffa23",
        "token_address": "0x6266e28f62a851295a4afb9e3ceac754853b5a62",
        "balance": 1000,
        "state": "open",
        "settle_timeout": 100
    },
    {
        "channel_address": "0x9ff56aca4d5fc5b5c859090a6c34d164135398246",
        "partner_address": "0xdfab2f1867123721bdbd2950ab12383467bffa235",
        "token_address": "0x6266e28f62a851295a4afb9e3ceac754853b5a62",
        "balance": 2000,
        "state": "open",
        "settle_timeout": 100
    }
]


assets = [
    {"address": "0x6266e28f62a851295a4afb9e3ceac754853b5a62"},
    {"address": "0xbad3562ffc159d295a4afb9e3ceac754853b5a62"},
    {"address": "0x78ac32bfa09845cc43abcdef785effee976efe54"}
]


events = [
    {
        "partner": "0x9d80d905bc1e106d5bd0637c12b893c5ab60cb41",
        "asset": "0x6266e28f62a851295a4afb9e3ceac754853b5a62",
        "status": "opened",
        "block": 89675,
        "timestamp": 1484638939

    },
    {
        "partner": "0xbcadef1867123721cdcd7869ab12383467bffa23",
        "asset": "0x6266e28f62a851295a4afb9e3ceac754853b5a62",
        "status": "settled",
        "block": 98765,
        "timestamp": 1484563339
    },
    {
        "partner": "0xdfab2f1867123721bdbd2950ab12383467bffa235",
        "asset": "0x6266e28f62a851295a4afb9e3ceac754853b5a62",
        "status": "closed",
        "block": 102865,
        "timestamp": 1484484139
    }
]


@app.route('/api/<version>/channels/', methods=['GET'])
def get_channels(version):
    return jsonify(channels)


@app.route('/api/<version>/tokens/', methods=['GET'])
def get_assets(version):
    return jsonify(assets)


@app.route('/api/<version>/events/', methods=['GET'])
def get_events(version):
    return jsonify(events)


if __name__ == '__main__':
    app.run(debug=True)
