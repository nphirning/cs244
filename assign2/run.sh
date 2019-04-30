#! /bin/sh

rm -rf results
mkdir results
for i in {1..5}
do
	cat ./sites.csv | while read line
	do
		sudo python3 ./icw-test.py $line >> "./results/$line.txt"
	done
done
python3 ./data-count.py > "./summary.txt"
