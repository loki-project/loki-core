#!/usr/bin/python3

import sys
sys.path.append('../testdata')
import config

import requests
import argparse
import json
from datetime import datetime


def instruct_daemon(method, params):
    payload = json.dumps({"method": method, "params": params}, skipkeys=False)
    print(payload)
    headers = {'content-type': "application/json"}
    try:
        response = requests.request("POST", "http://"+config.listen_ip+":"+config.listen_port+"/json_rpc", data=payload, headers=headers)
        return json.loads(response.text)
    except requests.exceptions.RequestException as e:
        print(e)
    except:
        print('No response from daemon, check daemon is running on this machine')


parser = argparse.ArgumentParser(description='Get Block.')
parser.add_argument("--height", help="An integer for the height to be queried", type=int)
args = parser.parse_args()

params = {"decode_as_json": True}
for arg in vars(args):
    # params['height'] = args.height
    if (getattr(args,arg) is not None):
        params[arg] = getattr(args, arg)

# $ curl -X POST http://127.0.0.1:18081/json_rpc -d '{"jsonrpc":"2.0","id":"0","method":"get_block","params":{"height":912345}}' -H 'Content-Type: application/json'

answer = instruct_daemon('get_block', params)
print(json.dumps(answer['result']['block_header']['timestamp'], indent=4, sort_keys=True))
blocktime = datetime.fromtimestamp(answer['result']['block_header']['timestamp'])
print(blocktime)

now = datetime.utcnow()
diff = now - blocktime
print(str(diff.seconds/1000) + " seconds ago")


