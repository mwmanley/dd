FROM python:2.7

RUN touch /var/log/access.log # since the program will read this by default
WORKDIR /usr/src
ADD . /usr/src
ENTRYPOINT ["python", "parse_logs.py"]
