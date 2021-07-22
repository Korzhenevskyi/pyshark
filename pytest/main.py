__author__ = 'ok'

import pyshark
import json
import requests
import os

directory = 'data'

class CustomEncoder(json.JSONEncoder):
    def default(self, o):
        return o.__dict__

def store_packet_as_json(packet, i):
    with open('%s/packet %d.json' % (directory, i), 'a') as w:
        w.write(json.dumps(packet, cls=CustomEncoder))

def check_the_packet_for_harm(packet, url):
    requests.post(url=url, json=json.dumps(packet, cls=CustomEncoder))

if not os.path.exists(directory):
    os.mkdir(directory)

capture = pyshark.LiveCapture(interface='wifi')
capture.sniff(timeout=20)

for i in range(len(capture)):
    print("packet "+str(i))
    store_packet_as_json(capture[i], i)