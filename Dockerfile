# Use variable base image, such that we can also build for other base images, like alpine.
ARG BASE_IMAGE=debian:stable-slim

FROM golang:1 as build

# Set build environment
ENV CGO_ENABLED=0

# Build irma CLI tool
COPY . /irmago
WORKDIR /irmago
RUN go build -a -ldflags '-extldflags "-static"' -o "/bin/irma" ./irma

FROM $BASE_IMAGE

# The amazonlinux image does not include adduser, so we have to install this first.
RUN if grep -q -E 'Amazon Linux' /etc/os-release; then yum install -y shadow-utils; fi

# Add application user
RUN adduser --disabled-password --gecos '' irma || adduser irma

# The debian image does not include ca-certificates, so we have to install this first.
RUN if which apt-get &> /dev/null; then apt-get update && apt-get install -y ca-certificates; fi

COPY --from=build /bin/irma /usr/local/bin/irma

# Switch to application user
USER irma

# Include schemes in the Docker image to speed up the start-up time.
RUN irma scheme download

ENTRYPOINT ["irma"]
