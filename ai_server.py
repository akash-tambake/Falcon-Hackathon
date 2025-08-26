import os
import google.generativeai as genai
from flask import Flask, request, jsonify, render_template

# --- IMPORTANT: CONFIGURE YOUR API KEY ---
# Load the API key from environment variables for security
genai.configure(api_key=os.getenv("AIzaSyCjBtcobbAS1WjrSOz8jlcchCdYa8NePoQ"))

# Initialize the Flask app
app = Flask(__name__)

# Global list to store logs from your sniffer (if running in the same script)
# In a real app, this might come from a database or a shared queue
live_logs = []

# --- Gemini AI Model Setup ---
# Create the model
generation_config = {
    "temperature": 0.1,
    "top_p": 0.95,
    "top_k": 64,
    "max_output_tokens": 8192,
}
model = genai.GenerativeModel(
    model_name="gemini-1.5-flash",
    generation_config=generation_config,
)

@app.route('/')
def index():
    # This serves your main dashboard HTML file
    return render_template('your_dashboard_file.html')

@app.route('/logs')
def get_logs():
    # This endpoint provides the live logs to the dashboard
    # You would populate the `live_logs` list from your sniffer script
    return jsonify(live_logs)

# --- NEW: GEMINI SCAN ENDPOINT ---
@app.route('/gemini-scan', methods=['POST'])
def gemini_scan():
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({"error": "URL not provided"}), 400

    user_url = data['url']

    # This is a carefully crafted prompt for reliable, parsable output
    prompt = f"""
    Analyze the following URL for security risks like phishing, malware, or scams.
    Provide a one-word assessment ('SAFE', 'UNSAFE', 'UNKNOWN') followed by a colon and then a brief, one-sentence explanation.
    URL: {user_url}
    """

    try:
        response = model.generate_content(prompt)
        
        # Parse the response from Gemini
        parts = response.text.strip().split(':', 1)
        assessment = parts[0].strip().upper()
        explanation = parts[1].strip() if len(parts) > 1 else "No detailed explanation provided."

        # Ensure assessment is one of the expected values
        if assessment not in ['SAFE', 'UNSAFE', 'UNKNOWN']:
            assessment = 'UNKNOWN' # Fallback
            explanation = response.text.strip()

        return jsonify({
            "assessment": assessment,
            "explanation": explanation
        })

    except Exception as e:
        print(f"Error calling Gemini API: {e}")
        return jsonify({"error": "Failed to analyze URL with AI"}), 500

if __name__ == '__main__':
    # To run this, you would also start your Scapy sniffer in a separate thread
    # and have it append logs to the `live_logs` list.
    app.run(debug=True, port=5000)