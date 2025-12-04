from flask import Flask, jsonify, request
from flask_cors import CORS
import json
import subprocess
import os
import uuid

app = Flask(__name__)
CORS(app)  # Allow React frontend (running on port 3000) to access this API

@app.route('/analyze', methods=['POST'])
def analyze_logs():
    try:
        # Get all uploaded files with the FormData field name 'logfiles'
        files = request.files.getlist("logfiles")
        if not files or len(files) == 0:
            return jsonify({"status": "error", "message": "No files uploaded"}), 400

        saved_paths = []
        # Save each uploaded file with a unique filename
        upload_dir = os.path.join(os.getcwd(), "uploaded_logs")
        os.makedirs(upload_dir, exist_ok=True)

        for file in files:
            if file.filename:
                unique_name = f"{uuid.uuid4().hex}_{file.filename}"
                uploaded_path = os.path.join(upload_dir, unique_name)
                file.save(uploaded_path)
                saved_paths.append(uploaded_path)

        if len(saved_paths) == 0:
            return jsonify({"status": "error", "message": "No valid files uploaded"}), 400

        # OPTION: Analyze each file separately or all at once
        # For demonstration, run a.py for each
        analysis_results = []
        for path in saved_paths:
            result = subprocess.run(
                ["python", "a.py", path],
                capture_output=True,
                text=True
            )
            if result.returncode != 0:
                analysis_results.append({
                    "file": os.path.basename(path),
                    "status": "error",
                    "message": result.stderr
                })
                continue

            json_path = os.path.join(os.getcwd(), "forensic_findings.json")
            if not os.path.exists(json_path):
                analysis_results.append({
                    "file": os.path.basename(path),
                    "status": "error",
                    "message": "forensic_findings.json not found for file"
                })
                continue

            with open(json_path, "r") as f:
                findings = json.load(f)
                analysis_results.append({
                    "file": os.path.basename(path),
                    "status": "success",
                    "data": findings
                })

        return jsonify({
            "status": "success",
            "results": analysis_results
        })

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

@app.route('/', methods=['GET'])
def home():
    return jsonify({"status": "running"}), 200

if __name__ == "__main__":
    app.run(debug=True)
