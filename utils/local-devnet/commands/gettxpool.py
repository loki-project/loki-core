#!/usr/bin/python3

import sys
sys.path.append('../testdata')
import config

import requests
import json


def instruct_daemon(method, params):
    payload = json.dumps({"method": method, "params": params})
    headers = {'content-type': "application/json"}
    try:
        response = requests.request("POST", "http://"+config.listen_ip+":"+config.listen_port+"/json_rpc", data=payload, headers=headers)
        return json.loads(response.text)
    except requests.exceptions.RequestException as e:
        print(e)
    except:
        print('No response from daemon, check daemon is running on this machine')

# $ curl http://127.0.0.1:18081/get_transaction_pool -H 'Content-Type: application/json'

answer = instruct_daemon('get_transaction_pool', [])
print(json.dumps(answer, indent=4, sort_keys=True))
