#!/bin/bash
if [ ! -p fifo ]
then
	null
else
	mkfifo fifo	
fi

xterm  ./server -v 4433 & 
xterm -e ./mitm -v 4432 4433 > fifo &
sleep 1
xterm -e ./client -v 4423 < fifo &
