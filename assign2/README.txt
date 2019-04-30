"sites.csv" contains a list of the 1000 most popular sites according to Amazon's Alexa
ranking. "icw-test.py" contains a python script to measure the initial congestion
window of a given site passed in as the script's first and only argument. 

We also have a file "HTTPsites.csv" consisting of the 4500 most popular sites
according to Amazon's Alexa ranking which do not respond to port 443, which we
did not use to generate our results and which appeared to generate similar
behavior. 

We have a single dependency on scapy, which can be installed by running
"pip3 install -r requirements.txt" in the assign2 directory. Scripts should
be run using Python3. 

Replicating our results can be done by running "run.sh" with root privileges, which
will run icw-test.py on each site listed in sites.csv, storing the result of each
computation in the site's corresponding file in the "results" folder. It will then
run "data-count.py", a python script to summarize the results data in a format
similar to figures 2 and 3 in [Padhyre, Floyd 01] with identical semantics. 