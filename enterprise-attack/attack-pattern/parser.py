import glob
import os
import json
from tqdm import tqdm
cwd = os.getcwd()

# We only want to use the *-attack.json files provided by mitre/cti
files = glob.glob(cwd + '/attack-pattern--*.json')
objects = []
for (index, file) in tqdm(enumerate(files)):
	with open(file) as json_file:
		json_data = json.load(json_file)

		# We concatenate all objects into a single list
		objects += json_data['objects']
# Write output to corresponding json file
f = open('attack-patterns.json', "w+")
output = {}
output['type'] = 'bundle'
output['spec_version'] = '2.0'
output['objects'] = objects
json.dump(output, f, sort_keys=True, indent=4)

