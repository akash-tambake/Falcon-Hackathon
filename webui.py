import os
from flask import Flask, jsonify, render_template, request
import google.generativeai as genai

# --- Configuration ---
app = Flask(__name__)
live_logs = []
MAX_LOGS = 200

# --- Gemini AI Setup ---
# --- Gemini AI Setup ---
try:
    # The API key is now hardcoded directly here
    # ⚠️ Replace with your actual key
    api_key = "AIzaSyCjBtcobbAS1WjrSOz8jlcchCdYa8NePoQ" 
    genai.configure(api_key=api_key)
    gemini_model = genai.GenerativeModel("gemini-1.5-flash")
    print("✅ Gemini AI configured.")
except Exception as e:
    print(f"❌ WARNING: Could not configure Gemini. The scan feature will not work. Error: {e}")
# --- Web Server Routes ---

@app.route('/')
def dashboard():
    # Serves your HTML file from the 'templates' folder
    return render_template('dashboard.html')

@app.route('/log', methods=['POST'])
def receive_log():
    # This receives logs from your separate listener.py
    log_entry = request.get_json()
    live_logs.insert(0, log_entry)
    if len(live_logs) > MAX_LOGS:
        live_logs.pop()
    return jsonify({"status": "success"}), 200

@app.route('/logs')
def get_logs():
    # This sends the collected logs to the dashboard frontend
    return jsonify(live_logs)

@app.route('/gemini-scan', methods=['POST'])
def gemini_scan_route():
    if 'gemini_model' not in globals():
        return jsonify({"error": "Gemini AI is not configured on the server."}), 500
        
    data = request.get_json()
    user_url = data.get('url')
    if not user_url:
        return jsonify({"error": "URL not provided"}), 400

    prompt = f"Analyze URL for security risks (phishing, malware). Response format: ASSESSMENT:EXPLANATION. Assessment must be SAFE, UNSAFE, or UNKNOWN. URL: {user_url}"
    
    try:
        response = gemini_model.generate_content(prompt)
        parts = response.text.strip().split(':', 1)
        assessment = parts[0].strip().upper()
        explanation = parts[1].strip() if len(parts) > 1 else "No explanation."
        if assessment not in ['SAFE', 'UNSAFE', 'UNKNOWN']:
            assessment = 'UNKNOWN'
        
        return jsonify({"assessment": assessment, "explanation": explanation})
    except Exception as e:
        return jsonify({"error": f"Gemini API error: {e}"}), 500

if __name__ == '__main__':
    print("🌍 Starting Flask server for dashboard at http://127.0.0.1:5000")
    app.run(host='0.0.0.0', port=5000)