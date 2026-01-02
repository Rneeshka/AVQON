#!/usr/bin/env python3
import sys
import struct
import json

# Простейшая реализация native messaging host

def read_message():
    raw_len = sys.stdin.buffer.read(4)
    if len(raw_len) == 0:
        return None
    msg_len = struct.unpack('<I', raw_len)[0]
    msg = sys.stdin.buffer.read(msg_len).decode('utf-8')
    return json.loads(msg)

def send_message(msg_obj):
    encoded = json.dumps(msg_obj).encode('utf-8')
    sys.stdout.buffer.write(struct.pack('<I', len(encoded)))
    sys.stdout.buffer.write(encoded)
    sys.stdout.buffer.flush()

# Простая заглушка сканера
BAD_MARKERS = ['badsite', 'malware', 'phish']

def scan_url(url):
    for m in BAD_MARKERS:
        if m in url.lower():
            return {'result': 'malicious', 'reason': f"contains '{m}'"}
    return {'result': 'clean'}

def main():
    while True:
        msg = read_message()
        if msg is None:
            break
        action = msg.get('action')
        if action == 'scan_url':
            url = msg.get('url')
            res = scan_url(url)
            send_message(res)
        else:
            send_message({'result': 'unknown_action'})

if __name__ == '__main__':
    main()
