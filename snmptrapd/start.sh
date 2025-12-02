#!/bin/bash
exec snmptrapd -f -Lo -c /etc/snmp/snmptrapd.conf 0.0.0.0:162
