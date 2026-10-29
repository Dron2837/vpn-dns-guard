FROM alpine:3.20
RUN apk add --no-cache iproute2 iptables bind-tools
COPY fixture-entry.sh /fixture-entry.sh
ENTRYPOINT ["/bin/sh", "/fixture-entry.sh"]
