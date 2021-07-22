__author__ = 'ok'

import pyshark
import json
import requests
import os

class CustomEncoder(json.JSONEncoder):
    def default(self, o):
        return o.__dict__

def store_packet_as_json(packet, i):
    with open('packet %d.json' % i, 'a') as w:
        w.write(json.dumps(packet, cls=CustomEncoder))

def check_the_packet_for_harm(packet, url):
    requests.post(url=url, json=json.dumps(packet, cls=CustomEncoder))

capture = pyshark.LiveCapture(interface='wifi')
capture.sniff(timeout=10)

for i in range(len(capture)):
    store_packet_as_json(capture[i], i)