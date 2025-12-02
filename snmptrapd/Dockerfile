FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    snmptrapd \
    snmp \
    snmp-mibs-downloader \
    && rm -rf /var/lib/apt/lists/*

RUN sed -i 's/mibs :/# mibs :/g' /etc/snmp/snmp.conf

COPY snmptrapd.conf /etc/snmp/snmptrapd.conf
COPY start.sh /start.sh
RUN chmod +x /start.sh

EXPOSE 162/udp

CMD ["/start.sh"]
