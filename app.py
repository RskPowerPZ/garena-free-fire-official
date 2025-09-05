from flask import Flask, request, jsonify
import json
import binascii
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import urllib3
from datetime import datetime, timedelta
import os
import threading
from functools import lru_cache
import time
import requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from google.protobuf.json_format import MessageToJson
import uid_generator_pb2
import like_count_pb2

app = Flask(__name__)

def load_tokens(region):
    try:
        if region == "IND":
            with open("token_ind.json", "r") as f:
                tokens = json.load(f)
        elif region in {"BR", "US", "SAC", "NA"}:
            with open("token_br.json", "r") as f:
                tokens = json.load(f)
        else:
            with open("token_bd.json", "r") as f:
                tokens = json.load(f)
        return tokens
    except Exception as e:
        return None

def encrypt_message(plaintext):
    try:
        key = b'Yg&tc%DEuh6%Zc^8'
        iv = b'6oyZDr22E3ychjM%'
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_message = pad(plaintext, AES.block_size)
        encrypted_message = cipher.encrypt(padded_message)
        return binascii.hexlify(encrypted_message).decode('utf-8')
    except Exception as e:
        return None

def create_protobuf(uid):
    try:
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        return message.SerializeToString()
    except Exception as e:
        return None

def enc(uid):
    protobuf_data = create_protobuf(uid)
    if protobuf_data is None:
        return None
    encrypted_uid = encrypt_message(protobuf_data)
    return encrypted_uid

def make_request_threaded(encrypt, region, token, session, results, index):
    try:
        if region == "IND":
            url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
        elif region in {"BR", "US", "SAC", "NA"}:
            url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
        else:
            url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"
            
        edata = bytes.fromhex(encrypt)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB50"
        }
        
        response = session.post(url, data=edata, headers=headers, verify=False, timeout=5)
        if response.status_code != 200:
            results[index] = None
        else:
            binary = response.content
            results[index] = decode_protobuf(binary)
    except Exception as e:
        results[index] = None

def decode_protobuf(binary):
    try:
        items = like_count_pb2.Info()
        items.ParseFromString(binary)
        return items
    except Exception as e:
        return None

def update_tokens():
    while True:
        try:
            with open('accs.txt', 'r') as f:
                lines = f.readlines()
            new_tokens = []
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                try:
                    uid, password = line.split(':')
                    url = f"https://100067.vercel.app/token?uid={uid}&password={password}"
                    resp = requests.get(url, verify=False, timeout=10)
                    if resp.status_code == 200:
                        data = resp.json()
                        token = data.get('token')
                        if token:
                            new_tokens.append({'token': token})
                    else:
                        print(f"Failed for {uid}: status {resp.status_code}")
                except Exception as e:
                    print(f"Error for {uid}: {e}")
            if new_tokens:
                with open('token_ind.json', 'w') as f:
                    json.dump(new_tokens, f)
                print("Tokens updated.")
            else:
                print("No tokens updated.")
        except Exception as e:
            print(f"Scheduler error: {e}")
        time.sleep(7 * 3600)  # 7 hours

@app.route('/visit', methods=['GET'])
def visit():
    target_uid = request.args.get("uid")
    region = request.args.get("region", "").upper()
    
    if not all([target_uid, region]):
        return jsonify({"error": "UID and region are required"}), 400
        
    try:
        tokens = load_tokens(region)
        if tokens is None:
            raise Exception("Failed to load tokens.")
            
        encrypted_target_uid = enc(target_uid)
        if encrypted_target_uid is None:
            raise Exception("Encryption of target UID failed.")
            
        total_visits = len(tokens) * 20
        success_count = 0
        failed_count = 0
        player_name = None
        total_responses = []
        
        with requests.Session() as session:
            results = [None] * (len(tokens) * 20)
            threads = []
            for i, token in enumerate(tokens):
                for j in range(20):
                    thread = threading.Thread(target=make_request_threaded, args=(encrypted_target_uid, region, token['token'], session, results, i * 20 + j))
                    threads.append(thread)
                    thread.start()
            
            for thread in threads:
                thread.join()
            
            for info in results:
                total_responses.append(info)
                if info:
                    if not player_name:
                        jsone = MessageToJson(info)
                        data_info = json.loads(jsone)
                        player_name = data_info.get('AccountInfo', {}).get('PlayerNickname', '')
                    success_count += 1
                else:
                    failed_count += 1
                
        summary = {
            "TotalVisits": total_visits,
            "SuccessfulVisits": success_count,
            "FailedVisits": failed_count,
            "PlayerNickname": player_name,
            "UID": int(target_uid),
            "TotalResponses": total_responses
        }
        
        return jsonify(summary)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    scheduler_thread = threading.Thread(target=update_tokens, daemon=True)
    scheduler_thread.start()

    app.run(debug=True, use_reloader=False)
