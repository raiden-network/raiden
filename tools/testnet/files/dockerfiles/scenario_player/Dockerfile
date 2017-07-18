FROM brainbot/raiden

MAINTAINER Ulrich Petri <ulrich@brainbot.com>

ADD scenario_player.py /usr/local/bin/transfer_generator.py
ADD scenario-testnet-token.yml /usr/share

ENTRYPOINT ["/usr/local/bin/transfer_generator.py"]
