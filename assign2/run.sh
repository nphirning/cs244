#! /bin/sh


	cat ./sites.csv | while read line
	do
		sudo python3 ./icw-test.py $line >> "./results/$line.txt"
	done
	#python3 ./data-count.py > "./summary.txt"

