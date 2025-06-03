from flask import Flask, request, jsonify
import json
import binascii
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import requests
import urllib3
import os
import concurrent.futures
import random
import time
from google.protobuf.json_format import MessageToJson
import uid_generator_pb2
import like_count_pb2

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
app.logger.setLevel("INFO")  # Reduced from DEBUG to avoid verbose logs

# Ultra-Safe Configuration
MAX_WORKERS = 8             # Conservative concurrency
VISITS_PER_TOKEN = 2        # Very safe limit for guest accounts
REQUEST_TIMEOUT = 8         # Balanced timeout
DELAY_BETWEEN_BATCHES = 0.5 # Small delay to prevent flooding
MAX_TOKENS_PER_REQUEST = 50 # Process only 350 of 440 tokens for safety

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
            tokens = json.load(f)
            random.shuffle(tokens)  # Distribute load randomly
            return tokens[:MAX_TOKENS_PER_REQUEST]  # Safety limit
        
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

def make_safe_request(encrypt, region, token):
    """Extra-safe request function with built-in delays"""
    try:
        time.sleep(random.uniform(0.1, 0.3))  # Random delay between requests
        
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

        response = requests.post(
            url, 
            data=edata, 
            headers=headers, 
            verify=False, 
            timeout=REQUEST_TIMEOUT
        )
        
        if response.status_code == 429:  # Rate limit detected
            time.sleep(2)  # Back off if rate limited
            return None
            
        return response if response.status_code == 200 else None

    except Exception as e:
        app.logger.warning(f"Request failed (safe mode): {str(e)[:100]}")  # Truncated error
        return None

@app.route('/safe-mass-visit', methods=['GET'])
def safe_mass_visit():
    start_time = time.time()
    target_uid = request.args.get("uid")
    region = request.args.get("region", "").upper()

    if not all([target_uid, region]):
        return jsonify({"error": "UID and region are required"}), 400

    try:
        # Load and shuffle tokens
        tokens = load_tokens(region)
        if not tokens:
            raise Exception("Failed to load tokens (safe mode)")
        
        encrypted_target_uid = enc(target_uid)
        if encrypted_target_uid is None:
            raise Exception("Encryption failed (safe mode)")

        # Calculate expected visits (350 tokens × 3 visits = 1050)
        expected_visits = len(tokens) * VISITS_PER_TOKEN
        success_count = 0
        player_name = None

        # Process in batches with delays
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = []
            
            for token in tokens:
                for _ in range(VISITS_PER_TOKEN):
                    if time.time() - start_time > 50:  # Stay under 60s limit
                        app.logger.info("Stopping early to avoid timeout")
                        break
                        
                    futures.append(
                        executor.submit(
                            make_safe_request,
                            encrypted_target_uid,
                            region,
                            token['token']
                        )
                    )
                time.sleep(DELAY_BETWEEN_BATCHES)  # Small delay between tokens

            # Process results
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        success_count += 1
                        protobuf_data = decode_protobuf(result.content)
                        if protobuf_data and not player_name:
                            jsone = MessageToJson(protobuf_data)
                            player_name = json.loads(jsone).get('AccountInfo', {}).get('PlayerNickname', '')
                except Exception as e:
                    app.logger.warning(f"Safe result processing error: {str(e)[:100]}")

        failed_count = expected_visits - success_count

        return jsonify({
            "TotalExpectedVisits": expected_visits,
            "SuccessfulVisits": success_count,
            "FailedVisits": failed_count,
            "PlayerNickname": player_name,
            "UID": int(target_uid),
            "TokensUsed": len(tokens),
            "TimeElapsed": round(time.time() - start_time, 2),
            "Note": "Ultra-safe mode: 350 tokens × 3 visits each"
        })

    except Exception as e:
        app.logger.error(f"Safe mass visit failed: {str(e)[:200]}")
        return jsonify({
            "error": "Safe processing error",
            "details": str(e)[:200]  # Truncated error
        }), 500

if __name__ == '__main__':
    app.run(debug=False)  # Disable debug mode for production
