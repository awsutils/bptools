FROM alpine:3 AS certs
RUN apk --no-cache add ca-certificates

FROM scratch
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
ARG TARGETARCH
COPY bptools-linux-${TARGETARCH} /bptools
ENTRYPOINT ["/bptools"]
