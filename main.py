from flask import Flask, request, jsonify
import json
import binascii
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import requests
import urllib3
import os
import concurrent.futures
from google.protobuf.json_format import MessageToJson
import uid_generator_pb2
import like_count_pb2
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
app.logger.setLevel("DEBUG")

# Optimized Configuration
MAX_WORKERS = 15  # Increased concurrency
MAX_RETRIES = 2   # Reduced retries to save time
REQUEST_TIMEOUT = 5  # Faster timeout
VISITS_PER_TOKEN = 3  # Reduced from 5 to process more tokens
SAFETY_MARGIN = 5  # Seconds to finish before Vercel's 60s timeout

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
            # Shuffle tokens to distribute load
            import random
            random.shuffle(tokens)
            return tokens
    except Exception as e:
        app.logger.error(f"Token load error: {e}")
        return None

# [Keep all other helper functions the same as previous solution]

@app.route('/visit', methods=['GET'])
def visit():
    start_time = time.time()
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

        # Calculate max tokens we can process within time limit
        max_possible_tokens = min(50, len(tokens))  # Process up to 50 tokens
        tokens = tokens[:max_possible_tokens]
        
        total_visits = len(tokens) * VISITS_PER_TOKEN
        success_count = 0
        player_name = None
        processed_count = 0

        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = []
            for token in tokens:
                # Check time remaining
                elapsed = time.time() - start_time
                if elapsed > (60 - SAFETY_MARGIN):
                    app.logger.warning(f"Stopping early due to time constraints. Processed {processed_count}/{len(tokens)} tokens")
                    break
                    
                for _ in range(VISITS_PER_TOKEN):
                    futures.append(
                        executor.submit(
                            make_request,
                            encrypted_target_uid,
                            region,
                            token['token']
                        )
                    )
                processed_count += 1

            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        success_count += 1
                        if not player_name:
                            jsone = MessageToJson(result)
                            player_name = json.loads(jsone).get('AccountInfo', {}).get('PlayerNickname', '')
                except Exception as e:
                    app.logger.error(f"Future error: {e}")

        failed_count = total_visits - success_count

        return jsonify({
            "TotalVisits": total_visits,
            "SuccessfulVisits": success_count,
            "FailedVisits": failed_count,
            "PlayerNickname": player_name,
            "UID": int(target_uid),
            "TokensUsed": processed_count,
            "TimeElapsed": round(time.time() - start_time, 2),
            "Note": f"Processed {processed_count} tokens with {VISITS_PER_TOKEN} visits each"
        })
    except Exception as e:
        app.logger.error(f"/visit failed: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
