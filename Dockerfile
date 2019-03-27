FROM golang:1.12 as builder

ENV DEP_VERSION 0.5.1
ENV SRC_PATH /go/src/github.com/nuts-foundation/nuts-proxy
ENV EXECUTABLE_NAME nuts-service-proxy

RUN curl -fsSL -o /usr/local/bin/dep https://github.com/golang/dep/releases/download/v$DEP_VERSION/dep-linux-amd64 && chmod +x /usr/local/bin/dep

RUN mkdir -p $SRC_PATH
WORKDIR $SRC_PATH

COPY Gopkg.toml Gopkg.lock main.go ./
RUN dep ensure --vendor-only
COPY cmd ./cmd

RUN CGO_ENABLED=0 go build -o /$EXECUTABLE_NAME main.go

FROM scratch
COPY --from=builder /$EXECUTABLE_NAME .
ENTRYPOINT ["./nuts-service-proxy", "serve", "-p", "3000"]
