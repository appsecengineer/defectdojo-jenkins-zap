import requests
from zapv2 import ZAPv2 as ZAP
import time
import datetime
from os import getcwd

# Test Automation Part of the Script

target_url = 'http://127.0.0.1:5050'
proxies = {
    'http': 'http://127.0.0.1:8090',
    'https': 'http://127.0.0.1:8090',
}

auth_dict = {'username': 'admin', 'password': 'admin123'}

login = requests.post(target_url + '/login',
                      proxies=proxies, json=auth_dict, verify=False)


if login.status_code == 200:  # if login is successful
    auth_token = login.headers['Authorization']
    auth_header = {"Authorization": auth_token}

    # now lets run some operations
    # GET Customer by ID

    get_cust_id = requests.get(
        target_url + '/get/2', proxies=proxies, headers=auth_header, verify=False)
    if get_cust_id.status_code == 200:
        print("Get Customer by ID Response")
        print(get_cust_id.json())
        print()

    post = {'id': 2}
    fetch_customer_post = requests.post(
        target_url + '/fetch/customer', json=post, proxies=proxies, headers=auth_header, verify=False)
    if fetch_customer_post.status_code == 200:
        print("Fetch Customer POST Response")
        print(fetch_customer_post.json())
        print()

    search = {'search': 'dleon'}
    search_customer_username = requests.post(
        target_url + '/search', json=search, proxies=proxies, headers=auth_header, verify=False)
    if search_customer_username.status_code == 200:
        print("Search Customer POST Response")
        print(search_customer_username.json())
        print()


# ZAP Operations

zap = ZAP(proxies={'http': 'http://127.0.0.1:8090',
                   'https': 'http://127.0.0.1:8090'})

if 'Light' not in zap.ascan.scan_policy_names:
    print("Adding scan policies")
    zap.ascan.add_scan_policy(
        "Light", alertthreshold="Medium", attackstrength="Low")

print(zap.core.urls())

active_scan_id = zap.ascan.scan(target_url, scanpolicyname='Light')

print("active scan id: {0}".format(active_scan_id))

# now we can start monitoring the spider's status
while int(zap.ascan.status(active_scan_id)) < 100:
    print("Current Status of ZAP Active Scan: {0}%".format(
        zap.ascan.status(active_scan_id)))
    time.sleep(10)

f = open("report.html", "x")
f.write(zap.core.htmlreport())
f.close()

zap.core.shutdown()
