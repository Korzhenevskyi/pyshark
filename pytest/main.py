__author__ = 'ok'

import pyshark
import json
import requests
import os

# --------------------- Directory creation -----------------------
directory = os.getenv("PYSHARK_RESULTS_FOLDER", "data")

if not os.path.exists(directory):
    os.makedirs(directory)


# --------------------- Store data -------------------------------

class CustomEncoder(json.JSONEncoder):
    def default(self, o):
        return o.__dict__

def store_packet_as_json(packet, i):
    with open('%s/packet %d.json' % (directory, i), 'a') as w:
        w.write(json.dumps(packet, cls=CustomEncoder))


# -------------------- Malicious payload detections -----------------
def check_the_packet_for_harm(packet, url):
    requests.post(url=url, json=json.dumps(packet, cls=CustomEncoder))


capture = pyshark.LiveCapture(interface='wifi')
capture.sniff(timeout=20)

for i in range(len(capture)):
    print("packet "+str(i))
    store_packet_as_json(capture[i], i)