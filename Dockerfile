FROM golang:1-alpine as build

# Set build environment
ENV CGO_ENABLED=0

# Build irma CLI tool
COPY . /irmago
WORKDIR /irmago
RUN go build -buildvcs=false -a -ldflags '-extldflags "-static"' -o "/bin/irma" ./irma

# Create application user
RUN adduser -D -u 1000 -g irma irma

# Start building the final image
FROM scratch

# Copy binary from build stage
COPY --from=build /bin/irma /bin/irma

# Add TLS root certificates
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

# Ensure the application user and group is set
COPY --from=build /etc/passwd /etc/passwd
COPY --from=build /etc/group /etc/group
COPY --from=build --chown=irma:irma /home/irma/ /home/irma/

# Switch to application user
USER irma

# Include schemes as assets in the Docker image to speed up the start-up time
RUN ["/bin/irma", "scheme", "download", "--use-schemes-assets-path"]

ENTRYPOINT ["/bin/irma"]
