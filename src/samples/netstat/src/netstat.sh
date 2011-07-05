#!/bin/sh

impl="sh ./netstat_impl.sh"
nohup $impl >&- 2>&- <&- & 
[ $? -ne 0 ] && echo NG || echo OK
