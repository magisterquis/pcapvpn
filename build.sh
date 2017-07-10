#!/bin/sh

set -e
set -x

cc -O2 --pedantic -Wall -o pcapvpn pcapvpn.c -lpcap -lpthread -static
