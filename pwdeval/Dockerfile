FROM ubuntu:latest

RUN \
  apt-get update && \
  apt-get -y install john john-data && \
  apt-get -y install ophcrack && \
  mkdir -p /pwdeval

WORKDIR /pwdeval
CMD /bin/bash
