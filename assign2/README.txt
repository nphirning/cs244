"sites.csv" contains a list of the 1000 most popular sites according to Amazon's Alexa
ranking. "icw-test.py" contains a python script to measure the initial congestion
window of a given site passed in as the script's first and only argument. 

Replicating our results can be done by running "run.sh" with root privileges, which
will run icw-test.py on each site listed in sites.csv, storing the result of each
computation in the site's corresponding file in the "results" folder