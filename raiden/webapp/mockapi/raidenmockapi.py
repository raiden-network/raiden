#!flask/bin/python
from flask import Flask, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)
channels = [
    {
        "partner": "0x9d80d905bc1e106d5bd0637c12b893c5ab60cb41",
        "asset": "0x6266e28f62a851295a4afb9e3ceac754853b5a62",
        "deposit": 500,
        "status": "opened"
    },
    {
        "partner": "0xbcadef1867123721cdcd7869ab12383467bffa23",
        "asset": "0x6266e28f62a851295a4afb9e3ceac754853b5a62",
        "deposit": 1000,
        "status": "settled"
    },
    {
        "partner": "0xdfab2f1867123721bdbd2950ab12383467bffa235",
        "asset": "0x6266e28f62a851295a4afb9e3ceac754853b5a62",
        "deposit": 2000,
        "status": "closed"
    }
  ]


assets = ["0x6266e28f62a851295a4afb9e3ceac754853b5a62",
          "0xbad3562ffc159d295a4afb9e3ceac754853b5a62",
          "0x78ac32bfa09845cc43abcdef785effee976efe54"
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

@app.route('/raiden/api/channels', methods=['GET'])
def get_channels():
    return jsonify(channels)


@app.route('/raiden/api/assets', methods=['GET'])
def get_assets():
    return jsonify({'assets': assets})


@app.route('/raiden/api/events', methods=['GET'])
def get_events():
    return jsonify({'events': events})




if __name__ == '__main__':
    app.run(debug=True)