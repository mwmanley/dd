#!/bin/bash

ID=$(date +%Y%M%d)

docker build -t log${ID} .

./make_logs.py --logfile /tmp/access.log &

docker run -v /tmp/access.log:/var/log/access.log --name logtest log${ID}
docker attach logtest
docker stop logtest
docker rm logtest

# docker rmi log${ID_HASH}
