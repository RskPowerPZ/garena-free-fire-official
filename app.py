from flask import Flask, request, jsonify
import asyncio
import aiohttp
import requests
import json
import time
from datetime import datetime, timedelta
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
import binascii
from visit_count_pb2 import Info  # Assuming you have the protobuf for visits
from byte import encrypt_api, Encrypt_ID  # Assuming these are your encryption utilities

app = Flask(__name__)

# API key management
API_KEY = "1yearkeysforujjaiwal"
API_KEY_EXPIRY = datetime(2026, 7, 25, 18, 0)  # Set to 1 year from now (July 25, 2025)
API_REQUEST_LIMIT = 9999
api_requests_made = 0

# Encrypt a protobuf message
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

# Create visit protobuf message
def create_visit_protobuf(uid, region):
    try:
        message = Info()  # Adjust based on your visit_count_pb2 structure
        message.AccountInfo.UID = int(uid)
        message.AccountInfo.PlayerRegion = region
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating visit protobuf message: {e}")
        return None

# Fetch tokens from all 5 JWT APIs
async def fetch_all_tokens():
    urls = [
        "https://free-fire-india-six.vercel.app/token",
        "https://free-fire-india-five.vercel.app/token",
        "https://free-fire-india-four.vercel.app/token",
        "https://free-fire-india-tthree.vercel.app/token",
        "https://free-fire-india-two.vercel.app/token"
    ]
    all_tokens = []
    try:
        async with aiohttp.ClientSession() as session:
            tasks = [session.get(url) for url in urls]
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            for response in responses:
                if isinstance(response, Exception):
                    app.logger.error(f"Error fetching token: {response}")
                    continue
                if response.status != 200:
                    app.logger.error(f"Token API failed with status: {response.status}")
                    continue
                data = await response.json()
                tokens = data.get("tokens", [])
                if not tokens:
                    app.logger.error("No tokens in this response.")
                    continue
                all_tokens.extend(tokens)
        if len(all_tokens) < 100:
            app.logger.warning(f"Only {len(all_tokens)} tokens fetched, expected 100.")
        return all_tokens[:100]  # Limit to 100 tokens
    except Exception as e:
        app.logger.error(f"Error fetching tokens: {e}")
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
                response_data = await resp.read()
                return True, response_data
            else:
                return False, None
    except Exception as e:
        app.logger.error(f"Visit error: {e}")
        return False, None

# Send visits in batches to achieve 1000 visits
async def send_visits_in_batches(uid, server_name, tokens, target_visits=1000):
    url = get_url(server_name)
    connector = aiohttp.TCPConnector(limit=0)
    total_success = 0
    total_sent = 0
    first_success_response = None
    player_info = None
    visit_process = []
    start_time = time.time()

    async with aiohttp.ClientSession(connector=connector) as session:
        encrypted = encrypt_api("08" + Encrypt_ID(str(uid)) + "1801")
        data = bytes.fromhex(encrypted)

        visits_per_token = target_visits // len(tokens)  # 1000 visits / 100 tokens = 10 visits per token
        for i in range(0, len(tokens), 20):  # Process in batches of 20 tokens
            batch_tokens = tokens[i:i+20]
            batch_size = len(batch_tokens) * visits_per_token
            tasks = []
            for token in batch_tokens:
                for _ in range(visits_per_token):
                    tasks.append(send_single_visit(session, url, token, data))

            results = await asyncio.gather(*tasks)
            batch_success = sum(1 for success, _ in results if success)
            total_success += batch_success
            total_sent += len(tasks)

            if first_success_response is None:
                for success, response in results:
                    if success and response is not None:
                        first_success_response = response
                        player_info = parse_protobuf_response(response)
                        break

            visit_process.append(f"{batch_success}+")
            print(f"Batch sent: {len(tasks)}, Success in batch: {batch_success}, Total success: {total_success}")

    end_time = time.time()
    total_time = str(timedelta(seconds=int(end_time - start_time)))
    return total_success, total_sent, player_info, "".join(visit_process)[:-1], total_time

# Get player info before and after visits
def get_player_info(encrypt, server_name, token):
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
            "ReleaseVersion": "OB49"
        }
        response = requests.post(url, data=edata, headers=headers, verify=False)
        binary = response.content
        return parse_protobuf_response(binary)
    except Exception as e:
        app.logger.error(f"Error in get_player_info: {e}")
        return None

@app.route('/visit', methods=['GET'])
def handle_visits():
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
        def process_request():
            # Fetch tokens synchronously for initial info
            tokens_data = requests.get("https://free-fire-india-six.vercel.app/token").json()
            tokens_list = tokens_data.get("tokens", [])
            if not tokens_list:
                raise Exception("No tokens received from JWT API.")
            token = tokens_list[0]

            encrypted_uid = encrypt_api("08" + Encrypt_ID(str(uid)) + "1801")
            if encrypted_uid is None:
                raise Exception("Encryption of UID failed.")

            # Get player info before visits
            before_info = get_player_info(encrypted_uid, server_name, token)
            if before_info is None:
                raise Exception("Failed to retrieve initial player info.")
            before_visits = before_info.get("likes", 0)  # Assuming likes field represents visits

            # Fetch 100 tokens for sending visits
            tokens = asyncio.run(fetch_all_tokens())
            if not tokens or len(tokens) < 100:
                raise Exception(f"Failed to fetch 100 tokens, got {len(tokens) if tokens else 0}.")

            # Send 1000 visits
            total_success, total_sent, player_info, visit_process, total_time = asyncio.run(
                send_visits_in_batches(uid, server_name, tokens, target_visits=1000)
            )

            # Get player info after visits
            after_info = get_player_info(encrypted_uid, server_name, token)
            if after_info is None:
                raise Exception("Failed to retrieve player info after visits.")
            after_visits = after_info.get("likes", 0)  # Assuming likes field represents visits

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

        result = process_request()
        return jsonify(result)
    except Exception as e:
        app.logger.error(f"Error processing request: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True, use_reloader=False)
