FROM golang:1.22 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go install ./cmd/guardagent

FROM gcr.io/distroless/static:nonroot
COPY --from=build /go/bin/guardagent /usr/bin/guardagent
EXPOSE 8080 9090
USER nonroot
ENTRYPOINT ["/usr/bin/guardagent"]
