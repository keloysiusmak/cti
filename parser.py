# A list of directories containing the *-attack.json files
ATTACK_PATHS = ['/enterprise-attack']

# A corresponding output path for each directory listed above
JSON_OUTPUT_PATHS = ['enterprise-attack/enterprise-techniques.json']

from bs4 import BeautifulSoup
from requests import get

import glob
import os
import json
from tqdm import tqdm
cwd = os.getcwd()

# We only want to use the *-attack.json files provided by mitre/cti
files = reduce(lambda x,y: x+y, map(lambda path: glob.glob(cwd + path + '/*-attack.json'), ATTACK_PATHS))

def snake_case(string):
	return '_'.join(map(lambda x: x.lower(),  string.split(' ')))

for (index, file) in enumerate(files):
	with open(file) as json_file:
		json_data = json.load(json_file)
		urls = []
		
		# We open the json object and get all the URLs found in the objects property
		for json_object in json_data['objects']:
			if 'external_references' in json_object:
				urls += [reference['url'] for reference in json_object['external_references'] if 'url' in reference and 'https://attack.mitre.org/techniques' in reference['url']]
		
		# We want to return an array of techniques
		techniques = []

		# Use tqdm to show progress
		for url in tqdm(urls[:]):
			# Get the HTML response from url and parse it into a BeautifulSoup object
			response = get(url)
			html_soup = BeautifulSoup(response.text, 'html.parser')

			# Find the main container
			main_container = html_soup.find_all('div', class_ = 'jumbotron jumbotron-fluid bg-white')[0]
			
			# Find each individual property
			title = main_container.find('h1')
			description = main_container.find('div', class_ = 'col-md-8 description-body').find('p')
			card_datas = main_container.find('div', class_ = 'card').find('div', class_ = 'card-body').find_all('div', class_ = 'card-data')
			tables = main_container.find_all('table')
			mitigations = [[unicode.strip(col[0].text), unicode.strip(col[1].text)] for col in [row.find_all('td') for row in tables[0].find('tbody').find_all('tr')]] if (len(tables) >= 1) else []
			examples = [[unicode.strip(col[0].text), unicode.strip(col[1].text)] for col in [row.find_all('td') for row in tables[1].find('tbody').find_all('tr')]] if (len(tables) >= 2) else []
			detection = main_container.find(id='detection').next_sibling.next_element.text if main_container.find(id='detection') else None
			references = list(map(lambda anchor: anchor['href'], main_container.find(id='references').next_sibling.next_element.find_all('a'))) if main_container.find(id='references') else []

			# We store the output in a dictionary
			technique = {}
			# Special case: Handling data in card by parsing each card data, using the snake cased title as key and text as value
			for card_data in card_datas:
				key = snake_case(card_data.next_element.text.split(':')[0])
				text = card_data.next_element.next_sibling.split(':')
				# Key is not always uniform, e.g. (The key can be "ID: " vs "ID" and value can be "VAL" vs ": VAL")
				text = unicode.strip(text[0] if len(text) == 1 else text[1])
				technique[key] = text
			technique["title"] = title.text
			technique["description"] = description.text
			technique["mitigations"] = mitigations
			if examples:
				technique["examples"] = examples
			if detection:
				technique["detection"] = detection
			technique["references"] = references

			# Strip any unnecessary whitespace
			technique = { k: unicode.strip(v) if (k not in ['references', 'mitigations', 'examples']) else v for k, v in technique.items() }
			techniques += [technique]

		# Write output to corresponding json file
		f = open(JSON_OUTPUT_PATHS[index], "w+")
		json.dump(techniques, f, sort_keys=True, indent=4)

