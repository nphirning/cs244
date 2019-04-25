#! /bin/sh
cat ./sites.csv | while read line
do
	sudo python ./icw-test.py $line
done
