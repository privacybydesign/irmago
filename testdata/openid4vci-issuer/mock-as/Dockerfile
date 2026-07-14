FROM golang:1.24-alpine AS build
WORKDIR /src
COPY main.go .
RUN CGO_ENABLED=0 go build -o /mock-as main.go

FROM alpine:3.21
COPY --from=build /mock-as /mock-as
ENTRYPOINT ["/mock-as"]
