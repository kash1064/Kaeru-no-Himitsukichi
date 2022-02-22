FROM ubuntu:20.04
ENV TZ=Asia/Tokyo

RUN mkdir -p /app/pack
RUN mkdir -p /app/blog
ENV HOME=/app/
WORKDIR $HOME/pack

RUN apt update && apt upgrade -y
RUN apt install tzdata -y
RUN apt install curl git wget -y
RUN apt install nodejs npm -y
RUN npm install n -g
RUN n stable

RUN apt purge -y nodejs npm
RUN apt autoremove -y

RUN node -v
RUN npm install -g gatsby-cli
RUN npm install gh-pages --save-dev

WORKDIR $HOME/blog
EXPOSE 8000