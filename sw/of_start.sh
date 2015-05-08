#!/bin/bash

# Execute this shell on your home directory as a super user

# 1. Download OpenFlow bitfile
# 2. Start ofdatapath with indicating interfaces
# 3. Start ofprotocol

nf_download -r openflow/hw-lib/nf2/openflow_switch.bit
openflow/udatapath/ofdatapath punix:/var/run/test -i nf2c0,nf2c1,nf2c2,nf2c3 &
openflow/secchan/ofprotocol unix:/var/run/test tcp:$1 --out-of-band &
