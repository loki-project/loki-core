#!/usr/bin/python3

import sys
sys.path.append('../testdata')
import config

import requests
import json


def instruct_daemon(method, params):
    payload = json.dumps({"method": method, "params": params}, skipkeys=False)
    # print(payload)
    headers = {'content-type': "application/json"}
    try:
        response = requests.request("POST", "http://"+config.listen_ip+":"+config.listen_port+"/json_rpc", data=payload, headers=headers)
        return json.loads(response.text)
    except requests.exceptions.RequestException as e:
        print(e)
    except:
        print('No response from daemon, check daemon is running on this machine')

service_node_pubkeys = []
answer = instruct_daemon('get_service_nodes', [])

# Transform json input to python objects

# sn.json_rpc("get_n_service_nodes", {"fields":{"quorumnet_port":True}}).json()['result']['service_node_states'])
# Filter python objects with list comprehensions
output_dict = [x['quorumnet_port'] for x in answer['result']['service_node_states']]

print("Quorumnet Ports:")
print(json.dumps(output_dict, indent=4, sort_keys=True))


