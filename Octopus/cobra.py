# *************************************************************************************** #
# ---------------------------------- EULA NOTICE ---------------------------------------- #
#                     Agreement between "Haroon Awan" and "You"(user).                    #
# ---------------------------------- EULA NOTICE ---------------------------------------- #
#  1. By using this piece of software your bound to these point.                          #
#  2. This an End User License Agreement (EULA) is a legal between a software application #
#     author "Haroon Awan" and (YOU) user of this software.                               #
#  3. This software application grants users rights to use for any purpose or modify and  #
#     redistribute creative works.                                                        #
#  4. This software comes in "is-as" warranty, author "Haroon Awan" take no responsbility #
#     what you do with by/this software as your free to use this software.                #
#  5. Any other purpose(s) that it suites as long as it is not related to any kind of     #
#     crime or using it in un-authorized environment.                                     #
#  6. You can use this software to protect and secure your data information in any        #
#     environment.                                                                        #
#  7. It can also be used in state of being protection against the unauthorized use of    #
#     information.                                                                        #
#  8. It can be used to take measures achieve protection.                                 #
# *************************************************************************************** #


#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse, os, sys, threading
from sys import argv, stderr
from random import randint
from time import sleep
from urllib.parse import urljoin
import requests, re, yaml, datetime

cmd = "clear"
returned_value = os.system(cmd)
sys.stdout.write("\033[1;37m")

print ("""\
                            _.--....
                 _....---;:'::' ^__/
               .' `'`___....---=-'`
              /::' (`
              \'   `:.
               `\::.  ';-"":::-._  {}
            _.--'`\:' .'`-.`'`.' `{I}
         .-' `' .;;`\::.   '. _: {-I}`\\
       .'  .:.  `:: _):::  _;' `{=I}.:||
      /.  ::::`":::` ':'.-'`':. {_I}:://
      |:. ':'  :::::  .':'`:. `'|':||:'
       \:   .:. ''' .:| .:, _:./':.|
    jgs '--.:::...---'\:'.:`':`':./
                       '-::..:::-'
#  ------------   --------   -----------  -----------     ------    
#  ************  **********  ***********  ***********    ********   
#  ---          ----    ---- ----      ** ----    ---   ----------  
#  ***          ***      *** ***********  *********    ****    **** 
#  ---          ---      --- -----------  ---------    ------------ 
#  ***          ****    **** ****      ** ****  ****   ************ 
#  ------------  ----------  -----------  ----   ----  ----    ---- 
#  ************   ********   ***********  ****    **** ****    **** 
#	                                crawler for metadata v1.0a                              
[ Syntax ] 
python3 cobra.py --wait=2 --download https://www.victim.com
""")

__all__ = ['boss', 'download_files', 'download_file', 'run_cmd']
WANTED_EXT = '\.(html?|docx?|xlsx?|svg?|swf?|htm?|o(d|t)[cgmpst]|asp|aspx|php)$'
BIN_EXT = re.compile(
	'\.?(html?|docx?|xlsx?|svg?|swf?|htm?|o(d|t)[cgmpst]|asp|aspx|php)$', re.I)
RE_FIND_LINKS = re.compile('(href)="(.*?)"|url\("?\'?(.*?)\'?"?\)', re.I)
RE_REL_LINK = re.compile('^https?://', re.I)
RE_CONTENT_TYPE = re.compile('text/(html|css)', re.I)

def run_cmd(argv):
	regext = WANTED_EXT
	do_dl = False
	do_journal = False
	do_wait = 5
	do_random_wait = True
	single_page = False

	for i, arg in enumerate(argv):
		if i == 0:  # 1st arg of argv is the program name
			continue
		elif arg == '--download':
			do_dl = True
		elif arg.startswith('--wait'):
			do_wait = int(arg[len('--wait='):])
		elif arg.startswith('http'):
			continue
		elif arg == '--download-file':
			if len(argv) < 3:
				raise SystemExit("Argument missing, check usage\n")
			else:
				download_file(argv[-1], do_wait, do_random_wait)
				raise SystemExit
		elif arg == '--download-files':
			if len(argv) < 3:
				raise SystemExit("Argument missing, check usage\n")
			else:
				download_files(argv[-1], do_wait, do_random_wait)
				raise SystemExit
		elif arg.startswith('--test'):
			import doctest
			doctest.run_docstring_examples(globals()[arg[len('--test='):]], globals())
			raise SystemExit()
		else:
			raise SystemExit("Invalid argument "+arg+"\n")

	if len(argv) < 2:
		raise SystemExit("")

	boss(argv[-1], re.compile(regext, re.I), do_dl, do_journal, single_page)




def boss(base_url, wanted_ext=WANTED_EXT, do_dl=False, do_journal=False,
		do_wait=False, do_random_wait=False, single_page=False):
	journal = 0
	if do_journal:
#		logging.config.dictConfig(yaml.load(LOGGING))
		journal = logging.getLogger('journal')
	found_pages_list = [base_url]
	found_pages_set = set(found_pages_list)
	regurgited_pages = set()
	caught_docs = set()
	for page_url in found_pages_list:
		do_wait and controlled_sleep(do_wait, do_random_wait)
		do_journal and journal.info("tries page " + page_url)
		try:
			page = requests.get(page_url, stream=True)
		except Exception as e:
			do_journal and journal.error(e)
			stderr(e)
			continue
		if (page.status_code == requests.codes.ok and
				RE_CONTENT_TYPE.search(page.headers['content-type'])):
			found_pages_list, found_pages_set, regurgited_pages, caught_docs = explore_page(
				base_url, page_url, str(page.content), wanted_ext, journal, do_dl,
				found_pages_list, found_pages_set, regurgited_pages, caught_docs)
		page.close()
		if single_page:
			break
	if do_journal:
		journal.info("found %d pages, %d doc(s)" % (len(found_pages_set), len(caught_docs)))


def explore_page(base_url, page_url, page_str, wanted_ext, journal, do_dl,
		found_pages_list, found_pages_set, regurgited_pages, caught_docs):
	# extract links
	for a_href in RE_FIND_LINKS.finditer(page_str):
		a_href = a_href.group(a_href.lastindex)
		if not RE_REL_LINK.search(a_href):  # if it's a relative link
			a_href = urljoin(page_url, a_href)
		if wanted_ext.search(a_href) and a_href not in caught_docs:  # wanted doc ?
			caught_docs.add(a_href)
			do_dl and download_file(a_href) or print(a_href)
		elif base_url in a_href and not BIN_EXT.search(a_href):  # next page ?
			if a_href not in found_pages_set:
				journal and journal.info("will explore "+a_href)
				found_pages_list.append(a_href)
				found_pages_set.add(a_href)
		elif a_href not in regurgited_pages:  # junk link ?
			journal and journal.debug("regurgited link "+a_href)
			regurgited_pages.add(a_href)
	return found_pages_list, found_pages_set, regurgited_pages, caught_docs


def controlled_sleep(seconds=1, do_random_wait=False):
	sleep(randint(1, seconds) if do_random_wait else seconds)


def download_file(URL, do_wait=False, do_random_wait=False):
	do_wait and controlled_sleep(do_wait, do_random_wait)
	with open(URL.split('/')[-1], 'wb') as f:
		f.write(requests.get(URL, stream=True).content)


def download_files(URLs_file, do_wait=False, do_random_wait=False):
	line_nb = 0
	downloaded_files = 0
	with open(URLs_file) as f:
		for line in f:
			line = line.rstrip('\n')
			if line is '':
				continue
			line_nb += 1
			print('download %d - %s' % (line_nb, line))
			try:
				download_file(line, do_wait, do_random_wait)
				downloaded_files += 1
			except Exception as e:
				stderr(e)
	print('downloaded %d / %d' % (downloaded_files, line_nb))


if __name__ == '__main__':
	run_cmd(argv)