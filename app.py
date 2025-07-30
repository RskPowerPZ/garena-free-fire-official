from flask import Flask, request, jsonify
import asyncio
import aiohttp
import json
import time
from datetime import datetime, timedelta
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
from visit_count_pb2 import Info  # Assuming you have the protobuf for visits
from byte import encrypt_api, Encrypt_ID  # Assuming these are your encryption utilities

app = Flask(__name__)

# API key management
API_KEY = "1yearkeysforujjaiwal"
API_KEY_EXPIRY = datetime(2026, 7, 25, 18, 0)  # Set to 1 year from now (July 25, 2025)
API_REQUEST_LIMIT = 9999
api_requests_made = 0

# Encrypt a message
def encrypt_message(plaintext):
    try:
        key = b'Yg&tc%DEuh6%Zc^8'
        iv = b'6oyZDr22E3ychjM%'
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_message = pad(plaintext, AES.block_size)
        encrypted_message = cipher.encrypt(padded_message)
        return binascii.hexlify(encrypted_message).decode('utf-8')
    except Exception as e:
        app.logger.error(f"Error encrypting message: {e}")
        return None

# Fetch tokens from tokens.json file (synchronous)
def fetch_all_tokens():
    try:
        with open('tokens.json', 'r') as file:
            data = json.load(file)
        # Handle both list and dict formats
        if isinstance(data, list):
            tokens = data
        elif isinstance(data, dict):
            tokens = data.get("tokens", [])
        else:
            app.logger.error("Invalid tokens.json format: must be a list or dict with 'tokens' key.")
            return None
        if not tokens:
            app.logger.error("No tokens found in tokens.json.")
            return None
        if len(tokens) < 150:
            app.logger.warning(f"Only {len(tokens)} tokens found in tokens.json, expected 100.")
        return tokens[:150]  # Limit to 100 tokens
    except Exception as e:
        app.logger.error(f"Error reading tokens from tokens.json: {e}")
        return None

# Get the appropriate URL for the server
def get_url(server_name):
    if server_name == "IND":
        return "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
    elif server_name in {"BR", "US", "SAC", "NA"}:
        return "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
    else:
        return "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"

# Parse protobuf response
def parse_protobuf_response(response_data):
    try:
        info = Info()
        info.ParseFromString(response_data)
        player_data = {
            "uid": info.AccountInfo.UID if info.AccountInfo.UID else 0,
            "nickname": info.AccountInfo.PlayerNickname if info.AccountInfo.PlayerNickname else "",
            "likes": info.AccountInfo.Likes if info.AccountInfo.Likes else 0,
            "region": info.AccountInfo.PlayerRegion if info.AccountInfo.PlayerRegion else "",
            "level": info.AccountInfo.Levels if info.AccountInfo.Levels else 0
        }
        return player_data
    except Exception as e:
        app.logger.error(f"Protobuf parsing error: {e}")
        return None

# Async get player info
async def get_player_info(session, encrypt, server_name, token):
    try:
        url = get_url(server_name)
        edata = bytes.fromhex(encrypt)
        headers = {
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/x-www-form-urlencoded",
            "Expect": "100-continue",
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1",
            "ReleaseVersion": "OB40"
        }
        async with session.post(url, data=edata, headers=headers, ssl=False) as response:
            if response.status == 200:
                binary = await response.read()
                return parse_protobuf_response(binary)
            return None
    except Exception as e:
        app.logger.error(f"Error in get_player_info: {e}")
        return None

# Send a single visit
async def send_single_visit(session, url, token, data):
    headers = {
        "ReleaseVersion": "OB49",
        "X-GA": "v1 1",
        "Authorization": f"Bearer {token}",
        "Host": url.replace("https://", "").split("/")[0]
    }
    try:
        async with session.post(url, headers=headers, data=data, ssl=False) as resp:
            if resp.status == 200:
                return True, await resp.read()
            return False, None
    except Exception:
        return False, None

# Send visits in a single batch
async def send_visits_in_batches(uid, server_name, tokens, target_visits=1000):
    url = get_url(server_name)
    connector = aiohttp.TCPConnector(limit=100)  # Explicitly set high connection limit
    total_success = 0
    total_sent = 0
    first_success_response = None
    player_info = None
    visit_process = []
    start_time = time.time()

    async with aiohttp.ClientSession(connector=connector) as session:
        encrypted = encrypt_api("08" + Encrypt_ID(str(uid)) + "1801")
        if not encrypted:
            return 0, 0, None, "", "0:00:00"
        data = bytes.fromhex(encrypted)

        visits_per_token = target_visits // len(tokens)  # 1000 visits / 100 tokens = 10 visits per token
        tasks = []
        for token in tokens:
            for _ in range(visits_per_token):
                tasks.append(send_single_visit(session, url, token, data))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        total_sent = len(tasks)
        for success, response in results:
            if success and response is not None:
                total_success += 1
                if first_success_response is None:
                    first_success_response = response
                    player_info = parse_protobuf_response(response)

        visit_process.append(f"{total_success}")
        print(f"Batch sent: {total_sent}, Success: {total_success}")

    end_time = time.time()
    total_time = str(timedelta(seconds=int(end_time - start_time)))
    return total_success, total_sent, player_info, visit_process[0], total_time

@app.route('/visit', methods=['GET'])
async def handle_visits():
    global api_requests_made
    uid = request.args.get("uid")
    server_name = request.args.get("region", "").upper()
    key = request.args.get("key")

    if not uid or not server_name or not key:
        return jsonify({"error": "UID, region, and key are required"}), 400

    if key != API_KEY:
        return jsonify({"error": "Invalid API key"}), 403

    api_requests_made += 1
    if api_requests_made > API_REQUEST_LIMIT:
        return jsonify({"error": "API request limit exceeded"}), 429

    try:
        async def process_request():
            # Fetch tokens synchronously for initial info
            tokens_list = fetch_all_tokens()
            if not tokens_list:
                raise Exception("No tokens received from tokens.json.")
            token = tokens_list[0]

            encrypted_uid = encrypt_api("08" + Encrypt_ID(str(uid)) + "1801")
            if encrypted_uid is None:
                raise Exception("Encryption of UID failed.")

            # Get player info before visits
            async with aiohttp.ClientSession() as session:
                before_info = await get_player_info(session, encrypted_uid, server_name, token)
                if before_info is None:
                    raise Exception("Failed to retrieve initial player info.")
                before_visits = before_info.get("likes", 0)

                # Fetch tokens for sending visits
                tokens = fetch_all_tokens()
                if not tokens or len(tokens) < 100:
                    raise Exception(f"Failed to fetch 100 tokens, got {len(tokens) if tokens else 0}.")

                # Send 1000 visits
                total_success, total_sent, player_info, visit_process, total_time = await send_visits_in_batches(
                    uid, server_name, tokens, target_visits=1000
                )

                # Use player_info from visits to avoid redundant call
                after_visits = player_info.get("likes", 0) if player_info else before_visits

            visits_given = after_visits - before_visits
            status = 1 if visits_given > 0 else 2

            # Calculate API key expiry time
            time_left = API_KEY_EXPIRY - datetime.now()
            days, seconds = time_left.days, time_left.seconds
            hours = seconds // 3600
            minutes = (seconds % 3600) // 60
            seconds = seconds % 60
            expiry_str = f"{days} day(s) {hours} hour(s) {minutes} minute(s) {seconds} second(s)"

            result = {
                "APIKeyExpiresAt": expiry_str,
                "APIKeyRemainingRequests": f"{API_REQUEST_LIMIT - api_requests_made}/{API_REQUEST_LIMIT}",
                "VisitSendingProcess": f"{visit_process}/{total_success}",
                "VisitsGivenByAPI": visits_given,
                "Likes": after_visits,
                "PlayerNickname": player_info.get("nickname", "") if player_info else "",
                "TotalTimeCaptureFromAllProcess": total_time,
                "TotalTokenGenerateFromJWTAPI": f"{len(tokens)}/100",
                "UID": int(player_info.get("uid", 0)) if player_info else 0,
                "status": status
            }
            return result

        result = await process_request()
        return jsonify(result)
    except Exception as e:
        app.logger.error(f"Error processing request: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
