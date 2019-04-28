#! /bin/sh
for i in {1..5}
do
	cat ./sites.csv | while read line
	do
		sudo python3 ./icw-test.py $line >> "./results2/$line.txt"
	done
done
