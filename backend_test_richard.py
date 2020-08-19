"""
Python version used: python 3.6.4
Script takes filename with urls as command line argument: python backend_test_richard -i input_filename
Script creates a results.json file containing the results after expanding and checking urls
"""

import requests
import email
import re
import json
import pydnsbl
import tldextract
import multiprocessing
import os.path
import sys
from argparse import ArgumentParser
from pydnsbl.providers import Provider

GOOGLE_API_KEY = "AIzaSyBXiO8W_abA6189zf0VkvH5Qc828l0CZQ8"


class ProcessUrls(object):
    def __init__(self, file_name):
        self.urls_list = self.extract_urls_from_file(file_name)
        self.expanded_urls = self.expand_urls()
        self.google_safe = []
        self.uribl_safe = []

    def extract_urls_from_file(self, file_name):
        if os.path.exists(file_name):
            file_extension = os.path.splitext(file_name)[1]
        else:
            sys.exit('Error: Invalid path to input file')

        if file_extension == '.eml':
            urls = self.extract_from_email(file_name)
        else:
            urls = self.extract_from_txt(file_name)
        return urls

    def extract_from_email(self, file_name):
        try:
            with open(file_name, 'r') as f:
                msg = email.message_from_file(f)
        except IOError as e:
            print("I/O error {}: {}".format(e.errno, e.strerror))
            sys.exit()
        except Exception as e:
            print("Unexpected error ", sys.exc_info()[0])
            sys.exit()

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disp = str(part.get('Content-Disposition'))
                if content_type == 'text/plain' and 'attachment' not in content_disp:
                    body = part.get_payload(decode=True)
                    break
        else:
            body = msg.get_payload(decode=True)
        #print(body.decode('utf-8'))
        urls = self.find_urls_in_body(body.decode('utf-8'))
        return urls

    def find_urls_in_body(self, email_body):
        regex = r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)" \
                r"(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+" \
                r"(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))"
        urls = re.findall(regex, email_body)
        return [url[0] for url in urls]

    def extract_from_txt(self, file_name):
        try:
            f = open(file_name, 'r', encoding='utf-8')
        except IOError as e:
            print("I/O error {}: {}".format(e.errno, e.strerror))
            sys.exit()
        except Exception as e:
            print("Unexpected error ", sys.exc_info()[0])

        urls = []
        with f:
            for line in f:
                if line[0].strip():
                    urls.append(line.strip())
        return urls

    def expand_urls(self):
        pool = multiprocessing.Pool(10)
        expanded_urls = pool.map(ProcessUrls.expand_url, self.urls_list)
        pool.close()
        return expanded_urls

    def google_checks(self):
        pool = multiprocessing.Pool()
        for check in pool.map(ProcessUrls.google_check, self.expanded_urls):
            self.google_safe.append(check)
        pool.close()

    def uribl_checks(self):
        pool = multiprocessing.Pool()
        for check in pool.map(ProcessUrls.uribl_check, self.expanded_urls):
            self.uribl_safe.append(check)
        pool.close()

    @staticmethod
    def expand_url(short_url):
        try:
            req = requests.get(short_url.strip(), headers={'User-Agent': 'Mozilla/5.0'})
        except requests.exceptions.RequestException as e:
            long_url = None
            print("{} exception: {}".format(short_url, e))
        else:
            if req.status_code != 200:
                print("{} bad request: {}".format(short_url, req.status_code))
                long_url = None
            else:
                long_url = req.url

        return long_url

    @staticmethod
    def extract_base_domain(url):
        try:
            url_parts = tldextract.extract(url)
        except Exception as e:
            print('{} extract base domain exception : {}'.format(url, e))
            return 'unknown_domain'

        return url_parts.domain + '.' + url_parts.suffix

    @staticmethod
    def google_check(url):
        post_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + GOOGLE_API_KEY
        data = {
            "client": {
                "clientId": "yourcompanyname",
                "clientVersion": "1.5.2"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                                "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [
                    {"url": url}
                ]
            }
        }

        try:
            resp = requests.post(post_url, json=data)
        except requests.exceptions.RequestException as e:
            print("exception: {}".format(e))
            return 'Unknown'
        else:
            if resp.status_code == 200:
                response = resp.json()
                # print(response)
                if 'matches' in response:
                    return 'YES'
                else:
                    return 'NO'
            else:
                print("{} Bad request - status_code: {}".format(url, resp.status_code))
                return 'Unknown'

    @staticmethod
    def uribl_check(url):
        try:
            domain = ProcessUrls.extract_base_domain(url)
            providers = [Provider('multi.uribl.com')]
            domain_checker = pydnsbl.DNSBLDomainChecker(providers=providers)
            result = domain_checker.check(domain)
        except Exception as e:
            print('{} uribl_check exception: {}'.format(url, e))
            return "Unknown"
        else:
            if result.blacklisted:
                return "YES"
            else:
                return "NO"


def main():
    parser = ArgumentParser()
    parser.add_argument("-i", dest="filename", help="Input file name", required=True)
    args = parser.parse_args()
    file_name = args.filename.strip()

    p = ProcessUrls(file_name)
    initial_urls = p.urls_list
    expanded_urls = p.expand_urls()
    p.google_checks()
    p.uribl_checks()

    results = []
    for i in range(len(initial_urls)):
        result = {'url': initial_urls[i],
                'expandedUrl': expanded_urls[i],
                'googleBlackListed': p.google_safe[i],
                'uriblBlackListed': p.uribl_safe[i]
                }
        results.append(result)
    print(results)

    with open('results.json', 'w') as f:
        json.dump(results, f)


if __name__ == '__main__':
    main()

