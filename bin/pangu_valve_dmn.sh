#!/bin/bash
while [ 1 ];
do
	count=`ls -l core.* |wc -l`
	echo $count
	if [ $count -lt 3 ]
	then
		echo "set unlimited"
		ulimit -c unlimited
	else
		ulimit -c 0
	fi

	./pangu_valve  >> /dev/null
	retval=$?
	if [ $retval == 10 ]; then
		echo program receives full, restart at `date +"%w %Y/%m/%d, %H:%M:%S"` >> RESTART.log
	elif [ $retval == 20 ]; then
		echo program already running, restart at `date +"%w %Y/%m/%d, %H:%M:%S"` >> RESTART.log
	else
		echo program crashed, restart at `date +"%w %Y/%m/%d, %H:%M:%S"` >> RESTART.log
	fi
	sleep 30
done

