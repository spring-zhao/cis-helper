FROM registry.corp.kuaishou.com/ksbase/build/golang/centos7-golang:1.24-alpine

WORKDIR /app

COPY bin/ /app/bin/

ENV CIS_HELPER_TLS_MODE=mtls

CMD ["/app/bin/https-server"]
