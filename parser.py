ATTACK_PATHS = ['/enterprise-attack']
JSON_OUTPUT_PATHS = ['enterprise-attack/enterprise-techniques.json']

from bs4 import BeautifulSoup
from requests import get

import glob
import os
import json
from tqdm import tqdm
cwd = os.getcwd()
files = reduce(lambda x,y: x+y, map(lambda path: glob.glob(cwd + path + '/*.json'), ATTACK_PATHS))
for (index, file) in enumerate(files):
	with open(file) as json_file:
		json_data = json.load(json_file)
		urls = []
		for json_object in json_data['objects']:
			if 'external_references' in json_object:
				urls += [reference['url'] for reference in json_object['external_references'] if 'url' in reference and 'https://attack.mitre.org/techniques' in reference['url']]
		techniques = []
		for url in tqdm(urls[:]):
			response = get(url)
			html_soup = BeautifulSoup(response.text, 'html.parser')
			main_container = html_soup.find_all('div', class_ = 'jumbotron jumbotron-fluid bg-white')[0]
			title = main_container.find('h1')
			description = main_container.find('div', class_ = 'col-md-8 description-body').find('p')
			card_datas = main_container.find('div', class_ = 'card').find('div', class_ = 'card-body').find_all('div', class_ = 'card-data')
			tables = main_container.find_all('table')
			mitigations = [[unicode.strip(col[0].text), unicode.strip(col[1].text)] for col in [row.find_all('td') for row in tables[0].find('tbody').find_all('tr')]] if (len(tables) >= 1) else []
			examples = [[unicode.strip(col[0].text), unicode.strip(col[1].text)] for col in [row.find_all('td') for row in tables[1].find('tbody').find_all('tr')]] if (len(tables) >= 2) else []
			detection = main_container.find(id='detection').next_sibling.next_element.text if main_container.find(id='detection') else None
			references = list(map(lambda anchor: anchor['href'], main_container.find(id='references').next_sibling.next_element.find_all('a'))) if main_container.find(id='references') else []

			technique = {}
			technique["id"] = card_datas[0].text.split(':')[1]
                        technique["tactic"] = card_datas[1].text.split(':')[1]
                        technique["platform"] = card_datas[2].text.split(':')[1]
                        technique["permissions_required"] = card_datas[3].text.split(':')[1]
                        technique["data_sources"] = card_datas[4].text.split(':')[1]
                        if len(card_datas) >= 6:
				technique["version"] = card_datas[5].text.split(':')[1]
			technique["title"] = title.text
			technique["description"] = description.text
			technique["mitigations"] = mitigations
			technique["examples"] = examples
			if detection:
				technique["detection"] = detection
			technique["references"] = references

			# Strip any unnecessary whitespace
			technique = { k: unicode.strip(v) if (k not in ['references', 'mitigations', 'examples']) else v for k, v in technique.items() }
			techniques += [technique]
		f = open(JSON_OUTPUT_PATHS[index], "w+")
		json.dump(techniques, f)
