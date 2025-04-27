#!/usr/bin/env python3
import argparse
import sys 
from urllib import request, parse
import urllib.error
import http.cookiejar
from collections import deque
import re

def parseargs():
    parser = argparse.ArgumentParser(usage = './webcrawler id1 id2')
    parser.add_argument('id1')
    parser.add_argument('id2')

    try:
        args = parser.parse_args()
        return (args.id1, args.id2)
    
    except argparse.ArgumentError:
        parser.print_usage()
        sys.exit(1)

def submit_form(id1, id2, base_url):
    cookie_jar = http.cookiejar.CookieJar()
    opener = request.build_opener(request.HTTPCookieProcessor(cookie_jar))
    request.install_opener(opener)

    form_data = {
        "input1": id1,
        "input2": id2
    }

    data = parse.urlencode(form_data).encode('utf-8')
    
    try:
        submit_url = base_url.rstrip('/') + '/save-cookie'
        
        req = request.Request(submit_url, data=data, method='POST')
        req.add_header('Content-Type', 'application/x-www-form-urlencoded')
        req.add_header('User-Agent', 'Mozilla/5.0')
        response = opener.open(req)
        return response.geturl(), opener
        
    except urllib.error.URLError as e:
        print("Error occurred:", e.reason)
        return None, None

def parse_url(content):
    base = "http://cluesky.colab.duke.edu:3000"
    links = re.findall(r'href="([^"]+)"', content)
    links = [base + link for link in links]
    return links

def find_flag(content):
    flag_match = re.search(r'class="secret_flag"[^>]*>\s*FLAG:\s*([a-zA-Z0-9]{16})', content)
    if flag_match:
        # print(flag_match.group(1))
        return flag_match.group(1)
    else:
        return

def crawl(root, opener):
    visited = set()
    flags = set()
    queue = deque([root])

    retry = {}
    max_retry = 3

    while queue:
        if len(flags) == 5:
            return flags
        curr_url = queue.popleft()
        if curr_url in visited:
            continue
        visited.add(curr_url)

        try:
            req = request.Request(curr_url)
            req.add_header('User-Agent', 'Mozilla/5.0')
            response = opener.open(req)

            content = response.read().decode('utf-8')

            flag = find_flag(content)

            if flag:
                flags.add(flag)
            else:
                new_links = parse_url(content)
                for link in new_links:
                    if link not in visited:
                        queue.append(link)
            
        except urllib.error.URLError as e:
            if e.code in [403, 404]:
                continue

            elif e.code == 301:
                new_url = e.headers.get("Location")
                if new_url and new_url not in visited:
                    queue.appendleft(new_url)
            
            elif e.code == 500:
                retries = retry.get(curr_url, 0)
                if retries < max_retry:
                    retry[curr_url] = retries + 1
                    queue.append(curr_url)

            # print(f"Error accessing {curr_url} : {e.reason}")

if __name__ == "__main__":
    id1, id2 = parseargs()
    root, opener = submit_form(str(id1), str(id2), "http://cluesky.colab.duke.edu:3000/")

    if root and opener:
        flags = crawl(root, opener)

        for flag in sorted(flags):
            print(flag)
    
    else:
        sys.exit(1)