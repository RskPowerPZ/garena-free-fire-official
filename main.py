from flask import Flask, request, jsonify
import json
import binascii
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import requests
import urllib3
import os
import threading
from google.protobuf.json_format import MessageToJson
import uid_generator_pb2
import like_count_pb2

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
app.logger.setLevel("DEBUG")

@app.route("/")
def health():
    return "Server is running!"

def load_tokens(region):
    try:
        fname = {
            "IND": "token_ind.json",
            "BR": "token_br.json",
            "US": "token_br.json",
            "SAC": "token_br.json",
            "NA": "token_br.json",
        }.get(region, "token_bd.json")

        if not os.path.exists(fname):
            raise FileNotFoundError(f"Missing token file: {fname}")

        with open(fname, "r") as f:
            return json.load(f)
    except Exception as e:
        app.logger.error(f"Token load error: {e}")
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
        app.logger.error(f"Encryption error: {e}")
        return None

def create_protobuf(uid):
    try:
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Protobuf creation error: {e}")
        return None

def enc(uid):
    protobuf_data = create_protobuf(uid)
    if protobuf_data is None:
        return None
    return encrypt_message(protobuf_data)

def make_request_threaded(encrypt, region, token, results, index):
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
            'ReleaseVersion': "OB49"
        }

        response = requests.post(url, data=edata, headers=headers, verify=False, timeout=5)
        if response.status_code != 200:
            results[index] = None
        else:
            results[index] = decode_protobuf(response.content)
    except Exception as e:
        app.logger.error(f"Threaded request error: {e}")
        results[index] = None

def decode_protobuf(binary):
    try:
        items = like_count_pb2.Info()
        items.ParseFromString(binary)
        return items
    except Exception as e:
        app.logger.error(f"Protobuf decode error: {e}")
        return None

@app.route('/visit', methods=['GET'])
def visit():
    target_uid = request.args.get("uid")
    region = request.args.get("region", "").upper()

    if not all([target_uid, region]):
        return jsonify({"error": "UID and region are required"}), 400

    try:
        tokens = load_tokens(region)
        if not tokens:
            raise Exception("Failed to load tokens")

        encrypted_target_uid = enc(target_uid)
        if encrypted_target_uid is None:
            raise Exception("Encryption failed")

        total_visits = len(tokens) * 20
        results = [None] * total_visits
        threads = []

        for i, token in enumerate(tokens):
            for j in range(20):
                idx = i * 20 + j
                t = threading.Thread(target=make_request_threaded, args=(encrypted_target_uid, region, token['token'], results, idx))
                threads.append(t)
                t.start()

        for t in threads:
            t.join()

        success_count = sum(1 for r in results if r)
        failed_count = total_visits - success_count
        player_name = None

        for r in results:
            if r and not player_name:
                jsone = MessageToJson(r)
                player_name = json.loads(jsone).get('AccountInfo', {}).get('PlayerNickname', '')

        return jsonify({
            "TotalVisits": total_visits,
            "SuccessfulVisits": success_count,
            "FailedVisits": failed_count,
            "PlayerNickname": player_name,
            "UID": int(target_uid),
        })

    except Exception as e:
        app.logger.error(f"/visit failed: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
