import os
from flask import Flask, request, jsonify
import asyncio
import aiohttp
import aiofiles
import json
import time
from datetime import datetime, timedelta
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
from visit_count_pb2 import Info  # Assuming Protobuf schema is available
from byte import encrypt_api, Encrypt_ID  # Assuming these are custom utilities
import logging
from threading import Lock
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# API key management
API_KEY = os.getenv("API_KEY", "1yearkeysforujjaiwal")
API_KEY_EXPIRY = datetime.strptime(os.getenv("API_KEY_EXPIRY", "2026-07-25 18:00:00"), "%Y-%m-%d %H:%M:%S")
API_REQUEST_LIMIT = int(os.getenv("API_REQUEST_LIMIT", 9999))
api_requests_made = 0
request_counter_lock = Lock()

# Encryption key and IV from environment variables
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", "Yg&tc%DEuh6%Zc^8").encode()
ENCRYPTION_IV = os.getenv("ENCRYPTION_IV", "6oyZDr22E3ychjM%").encode()

# Encrypt a message
def encrypt_message(plaintext: str) -> str | None:
    try:
        cipher = AES.new(ENCRYPTION_KEY, AES.MODE_CBC, ENCRYPTION_IV)
        padded_message = pad(plaintext.encode('utf-8'), AES.block_size)
        encrypted_message = cipher.encrypt(padded_message)
        return binascii.hexlify(encrypted_message).decode('utf-8')
    except Exception as e:
        logger.error(f"Error encrypting message: {e}")
        return None

# Fetch tokens asynchronously
async def fetch_all_tokens() -> list | None:
    try:
        async with aiofiles.open('tokens.json', mode='r') as file:
            data = json.loads(await file.read())
        tokens = data if isinstance(data, list) else data.get("tokens", [])
        if not tokens:
            logger.error("No tokens found in tokens.json.")
            return None
        if len(tokens) < 100:
            logger.warning(f"Only {len(tokens)} tokens found, expected 100.")
        return tokens[:100]  # Limit to 100 tokens
    except FileNotFoundError:
        logger.error("tokens.json file not found.")
        return None
    except json.JSONDecodeError:
        logger.error("Invalid JSON format in tokens.json.")
        return None
    except Exception as e:
        logger.error(f"Error reading tokens from tokens.json: {e}")
        return None

# Get the appropriate URL for the server
def get_url(server_name: str) -> str:
    server_map = {
        "IND": "https://client.ind.freefiremobile.com/GetPlayerPersonalShow",
        "BR": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
        "US": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
        "SAC": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
        "NA": "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
    }
    return server_map.get(server_name, "https://clientbp.ggblueshark.com/GetPlayerPersonalShow")

# Parse protobuf response
def parse_protobuf_response(response_data: bytes) -> dict | None:
    try:
        info = Info()
        info.ParseFromString(response_data)
        return {
            "uid": info.AccountInfo.UID or 0,
            "nickname": info.AccountInfo.PlayerNickname or "",
            "likes": info.AccountInfo.Likes or 0,
            "region": info.AccountInfo.PlayerRegion or "",
            "level": info.AccountInfo.Levels or 0
        }
    except Exception as e:
        logger.error(f"Protobuf parsing error: {e}")
        return None

# Async get player info
async def get_player_info(session: aiohttp.ClientSession, encrypt: str, server_name: str, token: str) -> dict | None:
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
            "ReleaseVersion": "OB50"
        }
        async with session.post(url, data=edata, headers=headers) as response:
            if response.status == 200:
                binary = await response.read()
                return parse_protobuf_response(binary)
            logger.warning(f"Failed to fetch player info, status: {response.status}")
            return None
    except aiohttp.ClientError as e:
        logger.error(f"Network error in get_player_info: {e}")
        return None
    except Exception as e:
        logger.error(f"Error in get_player_info: {e}")
        return None

# Send a single visit
async def send_single_visit(session: aiohttp.ClientSession, url: str, token: str, data: bytes) -> tuple[bool, bytes | None]:
    headers = {
        "ReleaseVersion": "OB50",
        "X-GA": "v1 1",
        "Authorization": f"Bearer {token}",
        "Host": url.replace("https://", "").split("/")[0]
    }
    try:
        async with session.post(url, headers=headers, data=data) as resp:
            if resp.status == 200:
                return True, await resp.read()
            logger.warning(f"Failed to send visit, status: {resp.status}")
            return False, None
    except aiohttp.ClientError:
        return False, None

# Send visits in a single batch
async def send_visits_in_batches(uid: str, server_name: str, tokens: list, target_visits: int = 1000) -> tuple[int, int, dict | None, str, str]:
    if not tokens:
        logger.error("No tokens provided for sending visits.")
        return 0, 0, None, "0", "0:00:00"

    url = get_url(server_name)
    connector = aiohttp.TCPConnector(limit=100)
    total_success = 0
    total_sent = 0
    first_success_response = None
    player_info = None
    start_time = time.time()

    async with aiohttp.ClientSession(connector=connector) as session:
        encrypted = encrypt_api("08" + Encrypt_ID(str(uid)) + "1801")
        if not encrypted:
            logger.error("Encryption of UID failed.")
            return 0, 0, None, "0", "0:00:00"
        data = bytes.fromhex(encrypted)

        visits_per_token = target_visits // len(tokens)
        tasks = [send_single_visit(session, url, token, data) for token in tokens for _ in range(visits_per_token)]

        results = await asyncio.gather(*tasks, return_exceptions=True)
        total_sent = len(tasks)
        for success, response in results:
            if success and response is not None:
                total_success += 1
                if first_success_response is None:
                    first_success_response = response
                    player_info = parse_protobuf_response(response)

        logger.info(f"Batch sent: {total_sent}, Success: {total_success}")

    total_time = str(timedelta(seconds=int(time.time() - start_time)))
    return total_success, total_sent, player_info, str(total_success), total_time

# Run async tasks in a synchronous Flask route
def run_async(coro):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()

@app.route('/visit', methods=['GET'])
def handle_visits():
    global api_requests_made
    uid = request.args.get("uid")
    server_name = request.args.get("region", "").upper()
    key = request.args.get("key")

    if not uid or not server_name or not key:
        return jsonify({"error": "uid, region, and key are required"}), 400

    if key != API_KEY:
        return jsonify({"error": "Invalid API key"}), 403

    with request_counter_lock:
        global api_requests_made
        api_requests_made += 1
        if api_requests_made > API_REQUEST_LIMIT:
            return jsonify({"error": "API request limit exceeded"}), 429

    try:
        async def process_request():
            tokens = await fetch_all_tokens()
            if not tokens:
                raise ValueError("No tokens received from tokens.json.")
            token = tokens[0]

            encrypted_uid = encrypt_api("08" + Encrypt_ID(str(uid)) + "1801")
            if not encrypted_uid:
                raise ValueError("Encryption of UID failed.")

            async with aiohttp.ClientSession() as session:
                before_info = await get_player_info(session, encrypted_uid, server_name, token)
            if not before_info:
                raise ValueError("Failed to retrieve initial player info.")
            before_visits = before_info.get("likes", 0)

            tokens = await fetch_all_tokens()
            if not tokens or len(tokens) < 100:
                raise ValueError(f"Failed to fetch 100 tokens, got {len(tokens) if tokens else 0}.")

            total_success, total_sent, player_info, visit_process, total_time = await send_visits_in_batches(uid, server_name, tokens, target_visits=1000)

            after_visits = player_info.get("likes", before_visits) if player_info else before_visits
            visits_given = after_visits - before_visits
            status = 1 if visits_given > 0 else 2

            time_left = API_KEY_EXPIRY - datetime.now()
            expiry_str = f"{time_left.days} day(s) {time_left.seconds // 3600} hour(s) {(time_left.seconds % 3600) // 60} minute(s) {time_left.seconds % 60} second(s)"

            return {
                "api_key_expires_at": expiry_str,
                "api_key_remaining_requests": f"{API_REQUEST_LIMIT - api_requests_made}/{API_REQUEST_LIMIT}",
                "visit_sending_process": f"{visit_process}/{total_success}",
                "visits_given_by_api": visits_given,
                "likes": after_visits,
                "player_nickname": player_info.get("nickname", "") if player_info else "",
                "total_time_capture_from_all_process": total_time,
                "total_token_generate_from_jwt_api": f"{len(tokens)}/100",
                "uid": int(player_info.get("uid", 0)) if player_info else 0,
                "status": status
            }

        result = run_async(process_request())
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error processing request: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
