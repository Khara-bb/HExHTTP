#!/usr/bin/env python3

import random
import socket
import string
import sys
import time

# import os
import traceback
from urllib.parse import urlparse

import requests
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CONTENT_DELTA_RANGE = 500
BIG_CONTENT_DELTA_RANGE = 5000


def get_domain_from_url(url: str) -> str:
    domain = urlparse(url).netloc
    return domain


def get_ip_from_url(url: str) -> str:
    domain = get_domain_from_url(url)
    ip = socket.gethostbyname(domain)
    return ip


def generate_cache_buster(length: int | None = 12) -> str:
    if not isinstance(length, int) or length <= 0:
        raise ValueError("[!] Length of cacheBuster be a positive integer")
    return "".join(random.choice(string.ascii_lowercase) for i in range(length))


def human_time(human: str) -> None:
    # print(human)
    if human.isdigit():
        time.sleep(int(human))
    elif human.lower() == "r" or human.lower() == "random":
        time.sleep(random.randrange(6))
    else:
        pass


def cache_tag_verify(req: requests.Response) -> str:
    cachetag = str(False)
    for rh in req.headers:
        if "age" in rh.lower() or "hit" in rh.lower() or "cache" in rh.lower():
            cachetag = "True"
        else:
            pass
    cachetag = (
        f"\033[32m{cachetag}\033[0m" if cachetag else f"\033[31m{cachetag}\033[0m"
    )
    return cachetag


def check_auth(auth: str, url: str) -> tuple[str, str] | None:
    try:
        authent = (auth.split(":")[0], auth.split(":")[1])
        r = requests.get(
            url, allow_redirects=False, verify=False, auth=authent, timeout=10
        )
        if r.status_code in [200, 302, 301]:
            print("\n+ Authentication successful\n")
            return authent
        else:
            print("\nAuthentication error")
            continue_error = input("The authentication seems bad, continue ? [y/N]")
            if continue_error not in ["y", "Y"]:
                print("Exiting")
                sys.exit()
            else:
                return None
    except Exception:
        traceback.print_exc()
        print('Error, the authentication format need to be "user:pass"')
        sys.exit()
