# cat 1: >= 3 tests return results, all results are identical
# cat 2: at least 3 return results, not all results are the same
# cat 3: 1 | 2 tests return results, all results the same
# cat 4: 1 | 2 tests return results, not all results the same
# cat 5: 0 tests return results

import os

def is_int(s):
	try:
		int(s)
		return True
	except ValueError:
		return False

server_cat = {}
icw_size = {}
for i in range(6):
	server_cat[i] = 0
	icw_size[i] = 0

directory = os.fsencode("./results")

for fname in os.listdir(directory):
	f = open(os.path.join(directory, fname))
	count = 0
	lines = f.readlines()
	print(lines)
	all_same = len(set(lines)) == 1
	for line in lines:
		if is_int(line):
			count += 1
	if count >= 3 and all_same:
		server_cat[1] += 1
		size = int(lines[0])
		if size >= 5:
			icw_size[5] += 1
		else:
			icw_size[size] += 1
	elif count >= 3 and not all_same:
		server_cat[2] += 1
	elif count > 0 and all_same:
		server_cat[3] += 1
	elif count > 0 and not all_same:
		server_cat[4] += 1
	elif count == 0:
		server_cat[5] += 1

for i in range(1,6):
	print("Number of servers in category {}: {}".format(i, server_cat[i]))
for i in range(1,6):
	print("Number of servers in category 1 with icw size {}: {}".format(i, icw_size[i]))
