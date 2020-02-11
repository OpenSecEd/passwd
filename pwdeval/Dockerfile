FROM ubuntu:latest

RUN \
  apt-get update && \
  apt-get -y install john john-data && \
  apt-get -y install ophcrack && \
  mkdir -p /pwdeval

RUN \
  apt-get -y install curl unzip && \
  cd /tmp && \
  curl -o rainbowcrack.zip https://project-rainbowcrack.com/rainbowcrack-1.7-linux64.zip && \
  unzip rainbowcrack.zip && \
  cd rainbowcrack-1.7-linux64 && \
  install -D -m0755 rtsort rtmerge rtgen rtc2rt rt2rtc rcrack /usr/local/bin && \
  install -D -m0644 alglib0.so charset.txt /usr/local/bin

WORKDIR /pwdeval
CMD /bin/bash
