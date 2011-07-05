#!/bin/sh

while [ 1 ]; do
	(sleep 2; LANG=en; netstat -atn | sed -e 's/[^0-9a-zA-Z. :\*]//g') | telnet ::1 9100 >/dev/null
	sleep 1
done

# EOF
