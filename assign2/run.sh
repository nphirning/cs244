#! /bin/sh
cat ./sites.csv | while read line
do
	sudo python3 ./icw-test.py $line
done
