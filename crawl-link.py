import requests
import os
import re
import sys
from urllib.parse import urlparse

# get argv
def get_argv():
    if len(sys.argv) != 2:
        print("Usage: python3 crawl.py <url>")
        exit(1)
    return sys.argv[1]

def unique(links):
    return list(set(links))

def crawl(url):
    if url.startswith("/"):
        url = sys.argv[1] + url
    try:
        # get html
        html = requests.get(url).text
        # get all links 
        links = re.findall('<a href="(.*?)"', html)
        links += re.findall('<script src="(.*?)"', html)
        # get all string start with http in html
        links += re.findall(r'http[s]{0,}:\/\/[a-zA-Z0-9:]{1,}([\./]{1,}[a-zA-Z0-9:?%#!=]{1,}){1,}', html)
        return links
    except:
        return []

def show(links):
    for link in links:
        if link.startswith("/") :
            print("[+] {}{}".format(sys.argv[1], link))
        elif link.startswith("http"):
            print("[+] {}".format(link))
        else:
            pass

# Main
if __name__ == '__main__':
    url = get_argv()
    host = urlparse(url).netloc.split(".")[1]
    links = crawl(url)
    for link in links:
        if host in urlparse(link).netloc:
            link_size = len(links)
            sublink = crawl(link)
            # get unique links from sublinks and links
            # print("[+] sublinks: ",sublink)
            links = unique(sublink + links)
            tmp = len(links)
            if tmp > link_size:
                print("discovered {} links".format(link_size))
    show(links)