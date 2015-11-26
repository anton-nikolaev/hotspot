#!/bin/sh
ngctl mkpeer ipfw: nat 60 out
ngctl name ipfw:60 nat
ngctl connect ipfw: nat: 61 in
ngctl msg nat: setaliasaddr 192.168.9.9
