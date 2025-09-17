#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Check support for different HTTP methods (NOT DELETE & PATCH)
Improved version with deduplication and CONNECT verification
"""

import urllib3
from urllib3 import Timeout, PoolManager
from utils.utils import requests, configure_logger, human_time, get_ip_from_url, socket
from utils.style import Colors
from collections import defaultdict

logger = configure_logger(__name__)

desc_method = {
    200: f"\033[32m200 OK{Colors.RESET}",
    204: f"204 No Content{Colors.RESET}",
    400: f"\033[33m400 Bad Request{Colors.RESET}",
    401: f"\033[31m401 HTTP Authent{Colors.RESET}",
    403: f"\033[31m403 Forbidden{Colors.RESET}",
    405: f"\033[33m405 Method Not Allowed{Colors.RESET}",
    406: f"\033[33m406 Not Acceptable{Colors.RESET}",
    409: f"\033[33m409 Conflict{Colors.RESET}",
    410: f"410 Gone",
    412: f"\033[33m412 Precondition Failed{Colors.RESET}",
    500: f"\033[31m500 Internal Server Error{Colors.RESET}",
    501: f"\033[31m501 Not Implemented{Colors.RESET}",
    502: f"\033[31m502 Bad Gateway{Colors.RESET}",
    301: f"{Colors.REDIR}301 Moved Permanently{Colors.RESET}",
    302: f"{Colors.REDIR}302 Moved Temporarily{Colors.RESET}"
}

header = {
    "User-agent": "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; LCJB; rv:11.0) like Gecko"
}


def get(url):
    req_g = requests.get(
        url, verify=False, allow_redirects=False, headers=header, timeout=120
    )
    return req_g.status_code, req_g.headers, "GET", len(req_g.content), req_g.content


def post(url):
    req_p = requests.post(
        url, verify=False, allow_redirects=False, headers=header, timeout=120
    )
    return req_p.status_code, req_p.headers, "POST", len(req_p.content), req_p.content


def put(url):
    req_pt = requests.put(
        url, verify=False, allow_redirects=False, headers=header, timeout=120
    )
    return (
        req_pt.status_code,
        req_pt.headers,
        "PUT",
        len(req_pt.content),
        req_pt.content,
    )


def patch(url):
    req_ptch = requests.patch(
        url, verify=False, allow_redirects=False, headers=header, timeout=120
    )
    return (
        req_ptch.status_code,
        req_ptch.headers,
        "PATCH",
        len(req_ptch.content),
        req_ptch.content,
    )


def options(url):
    req_o = requests.options(
        url, verify=False, allow_redirects=False, headers=header, timeout=120
    )
    return (
        req_o.status_code,
        req_o.headers,
        "OPTIONS",
        len(req_o.content),
        req_o.content,
    )


def verify_connect_method(url, http):
    target_ip = get_ip_from_url(url)

    connect_tests = [
        f"{url}",
        f"{url}test",
        f"{url}nonexistent",
        "google.com:443",
        f"{target_ip}:80",
        f"{target_ip}:443",
        "127.0.0.1:80",
        "192.168.1.1:80",
        "10.0.0.1:80",
        "172.16.0.1:80"
    ]
    
    results = []
    for test_url in connect_tests:
        try:
            resp = http.request("CONNECT", test_url)
            results.append((test_url, resp.status, len(resp.data)))
            logger.debug(f"CONNECT test on {test_url}: {resp.status}")
        except Exception as e:
            results.append((test_url, "ERROR", 0))
            logger.debug(f"CONNECT test error on {test_url}: {e}")
    
    status_codes = [r[1] for r in results if r[1] != "ERROR"]
    
    if len(set(status_codes)) == 1 and len(status_codes) > 1:
        return True, f""
    
    success_on_invalid = any(r[1] in [200, 201, 202, 204] for r in results[2:])
    if success_on_invalid:
        return True, ""
    
    return False, "Seems legitimate"


def check_other_methods(ml, url, http, pad, results_tracker):
    try:
        test_url = url
        if ml == "DELETE":
            test_url = f"{url}plopiplop.css"
            
        resp = http.request(ml, test_url)
        rs = resp.status
        resp_h = resp.headers

        cache_status = False
        try:
            rs_display = desc_method[rs]
        except KeyError:
            rs_display = str(rs)
            logger.debug("No descriptions available for status %s", rs)

        for rh in resp_h:
            if (
                "Cache-Status" in rh
                or "X-Cache" in rh
                or "x-drupal-cache" in rh
                or "X-Proxy-Cache" in rh
                or "X-HS-CF-Cache-Status" in rh
                or "X-Vercel-Cache" in rh
                or "X-nananana" in rh
                or "x-vercel-cache" in rh
                or "X-TZLA-EDGE-Cache-Hit" in rh
                or "x-spip-cache" in rh
                or "x-nextjs-cache" in rh
            ):
                cache_status = True
                
        len_req = len(resp.data.decode("utf-8"))
        
        # Créer une clé unique pour le tri (status + length)
        result_key = (rs, len_req)
        results_tracker[result_key].append({
            'method': ml,
            'status': rs,
            'status_display': rs_display,
            'length': len_req,
            'cache_status': cache_status,
            'response_data': resp.data
        })

    except urllib3.exceptions.MaxRetryError:
        results_tracker[('ERROR', 0)].append({
            'method': ml,
            'status': 'ERROR',
            'status_display': 'Error due to too many redirects',
            'length': 0,
            'cache_status': False,
            'response_data': b''
        })
    except Exception as e:
        logger.exception(e)
        results_tracker[('ERROR', 0)].append({
            'method': ml,
            'status': 'ERROR',
            'status_display': f'Error: {str(e)}',
            'length': 0,
            'cache_status': False,
            'response_data': b''
        })


def display_deduplicated_results(results_tracker, pad, url, http):
    displayed_groups = set()
    
    for result_key, methods_list in results_tracker.items():
        if len(methods_list) >= 3:
            if result_key not in displayed_groups:
                first_method = methods_list[0]
                space = " " * (pad - len(first_method['method']) + 1)
                other_methods = [m['method'] for m in methods_list[1:]]
                
                print(f" ├── {first_method['method']}{space}{first_method['status_display']:<3}  "
                      f"[{first_method['length']} bytes]{'':<2} "
                      f"({Colors.CYAN}+{len(other_methods)} similar{Colors.RESET})")#{', '.join(other_methods)})
                
                displayed_groups.add(result_key)
        else:
            for method_result in methods_list:
                space = " " * (pad - len(method_result['method']) + 1)
                
                connect_info = ""
                if method_result['method'] == "CONNECT" and method_result['status'] not in ['ERROR', 405, 501]:
                    is_fp, fp_reason = verify_connect_method(url, http)
                    connect_info = f"[{Colors.GREEN}{'VALID'}: {fp_reason}{Colors.RESET}]" if not is_fp else ''
                
                print(f" ├── {method_result['method']}{space}{method_result['status_display']:<3}  "
                      f"[{method_result['length']} bytes]{'':<2} {connect_info}")


def check_methods(url, custom_header, authent, human):
    htimeout = Timeout(connect=7.0, read=7.0)
    http = PoolManager(timeout=htimeout)

    print("\033[36m ├ Methods analysis\033[0m")
    result_list = []
    for funct in [get, post, put, patch, options]:
        try:
            result_list.append(funct(url))
        except Exception as e:
            print(f" ├── Error with {funct} method: {e}")
            logger.exception("Error with %s method", funct, exc_info=True)

    for rs, req_head, type_r, len_req, req_content in result_list:
        try:
            rs_display = desc_method[rs]
        except KeyError:
            rs_display = str(rs)
            logger.debug("No descriptions available for status %s", rs)

        cache_status = False
        cache_res = ""

        for rh in req_head:
            if "cache" in rh.lower():
                cache_status = True
                cache_res = rh
        print(f" ├── {type_r:<10} {rs_display:<3} [{len_req} bytes] ")
        if type_r == "OPTIONS":
            for x in req_head:
                if x.lower() == "allow":
                    print(f"    |-- allow: {req_head[x]}")

    list_path = "modules/lists/methods_list.lst"
    try:
        with open(list_path, "r") as method_list:
            method_list = method_list.read().splitlines()
            pad = max(len(m) for m in method_list)
            
            results_tracker = defaultdict(list)
            
            for ml in method_list:
                check_other_methods(ml, url, http, pad, results_tracker)
                human_time(human)
            
            display_deduplicated_results(results_tracker, pad, url, http)
            
    except FileNotFoundError:
        logger.error(f"Methods list file not found: {list_path}")
        print(f" ├── Error: Methods list file not found: {list_path}")
    except Exception as e:
        logger.exception("Error reading methods list")
        print(f" ├── Error reading methods list: {e}")