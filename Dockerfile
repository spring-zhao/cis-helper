FROM registry.corp.kuaishou.com/ksbase/build/golang/centos7-golang:1.24-alpine

# RUN rm -rf /usr/local/sbin/kcsize /usr/local/bin/kcsize \
#     && mkdir -p /usr/local/bin /usr/local/sbin \
#     && wget -O /usr/local/bin/kcsize http://bs3-hb1.internal/image-kcsize/kcsize \
#     && chmod a+x /usr/local/bin/kcsize \
#     && ln -s /usr/local/bin/kcsize /usr/local/sbin/kcsize

# get kcsize
RUN rm -rf /usr/local/bin/kcsize \
    && wget -O /usr/local/bin/kcsize http://bs3-hb1.internal/image-kcsize/kcsize \
    && chmod a+x /usr/local/bin/kcsize

WORKDIR /app

COPY bin/ /app/bin/

ENV CIS_HELPER_TLS_MODE=mtls

CMD ["/usr/local/bin/kcsize", "api"]
