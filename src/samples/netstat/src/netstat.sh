#!/bin/sh

while [ 1 ]; do
	LANG=en; netstat -atn | telnet localhost 9000; sleep 1;
done

# EOF
