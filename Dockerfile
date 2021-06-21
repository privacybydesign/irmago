FROM buildpack-deps:buster as build

WORKDIR /build
RUN wget https://gitlab.science.ru.nl/irma/github-mirrors/irmago/-/jobs/artifacts/master/download?job=binaries -O artifact.zip -q
RUN unzip -j artifact.zip

FROM golang:1.16-alpine

COPY --from=build /build/irma-master-linux-amd64 /usr/local/bin/irma

EXPOSE 8088

CMD [ "irma", "server"]
