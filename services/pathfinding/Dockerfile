FROM python:3.6

LABEL Name=pathfinding-service-dev Version=0.0.1 Author="Paul Lange"
EXPOSE 6000

WORKDIR /pfs
ADD . /pfs

RUN python3 -m pip install -r requirements.txt
RUN python3 setup.py develop
CMD ["python3", "-m", "pathfinder.cli"]
