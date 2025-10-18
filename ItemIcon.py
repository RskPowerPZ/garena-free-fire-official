from flask import Flask, render_template, request, jsonify, send_file
import json
import requests
import io
import time
from typing import List, Dict, Optional, Any
from werkzeug.exceptions import BadRequest, NotFound

app = Flask(__name__)

# Constants
ITEMS_URL = "https://raw.githubusercontent.com/RskPowerPZ/FLAME-ITEM-INFO-/main/itemData.json"
IMAGE_URL_TEMPLATE = "https://freefiremobile-a.akamaihd.net/common/Local/PK/FF_UI_Icon/{}.png"
REQUEST_TIMEOUT = 10

# Cache
items_cache: List[Dict[str, Any]] = []
cache_timestamp = 0
CACHE_DURATION = 3600

def load_json_from_url(url: str) -> List[Dict[str, Any]]:
    """Load ARRAY OF OBJECTS from GitHub."""
    try:
        response = requests.get(url, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        data = response.json()
        
        if not isinstance(data, list):
            app.logger.error("Invalid JSON: Expected array")
            return []
        
        app.logger.info(f"✅ Loaded {len(data)} items from GitHub")
        return data
    except Exception as e:
        app.logger.error(f"❌ Error: {str(e)}")
        return []

def get_items_data() -> List[Dict[str, Any]]:
    """Get cached data."""
    global items_cache, cache_timestamp
    if not items_cache or (time.time() - cache_timestamp) > CACHE_DURATION:
        items_cache = load_json_from_url(ITEMS_URL)
        cache_timestamp = time.time()
    return items_cache

def fetch_image(icon_name: str) -> Optional[send_file]:
    """Fetch from CDN."""
    if not icon_name:
        return None
    image_url = IMAGE_URL_TEMPLATE.format(icon_name)
    try:
        response = requests.get(image_url, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        return send_file(
            io.BytesIO(response.content),
            mimetype="image/png",
            as_attachment=False,
            download_name=f"{icon_name}.png"
        )
    except:
        return None

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/search", methods=["GET"])
def search_items():
    """Search by Id, name, or Icon."""
    items = get_items_data()
    if not items:
        return jsonify([]), 200
    
    query = request.args.get("q", "").strip()
    if not query:
        return jsonify([]), 200

    results = []
    for item in items:
        item_id = str(item.get("Id", ""))
        name = item.get("name", "")
        icon = item.get("Icon", "")
        
        if (query.lower() in str(name).lower() or 
            query == item_id or 
            query.lower() in str(icon).lower()):
            results.append({
                "Id": item_id,
                "name": name,
                "Icon": icon,
                "image_url": IMAGE_URL_TEMPLATE.format(icon) if icon else ""
            })
    
    return jsonify(results), 200

@app.route("/api/image/icon", methods=["GET"])
def get_image_by_icon():
    """Image by Icon name."""
    items = get_items_data()
    icon_name = request.args.get("icon", "").strip()
    if not icon_name:
        raise BadRequest("Icon name required")
    
    for item in items:
        if str(item.get("Icon", "")) == icon_name:
            result = fetch_image(icon_name)
            if result:
                return result
            raise NotFound(f"Image not found: {icon_name}")
    
    raise NotFound(f"Icon not found: {icon_name}")

@app.route("/api/image/id", methods=["GET"])
def get_image_by_id():
    """Image by Id (e.g., 203049001)."""
    items = get_items_data()
    item_id = request.args.get("id", "").strip()
    if not item_id:
        raise BadRequest("Item ID required")

    for item in items:
        if str(item.get("Id", "")) == item_id:
            icon_name = item.get("Icon", "")
            if not icon_name:
                raise NotFound(f"No icon for ID: {item_id}")
            
            app.logger.info(f"🔍 ID {item_id} → Icon '{icon_name}'")
            result = fetch_image(icon_name)
            if result:
                return result
            raise NotFound(f"Image not found: {icon_name}")
    
    raise NotFound(f"Item ID not found: {item_id}")

# Error handlers
@app.errorhandler(BadRequest)
def handle_bad_request(e): return jsonify({"error": str(e)}), 400

@app.errorhandler(NotFound)
def handle_not_found(e): return jsonify({"error": str(e)}), 404

@app.errorhandler(Exception)
def handle_general_exception(e):
    app.logger.error(f"Error: {str(e)}")
    return jsonify({"error": "Server error"}), 500

if __name__ == "__main__":
    print("🚀 Flame Item API Starting...")
    app.run(debug=True, host="0.0.0.0", port=5000)