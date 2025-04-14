from flask import Flask, request, jsonify, render_template
import os
import requests
import subprocess
from werkzeug.utils import secure_filename

# Initialize Flask app
app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Allowed file extensions for uploads
ALLOWED_EXTENSIONS = {"pdf"}

# Function to check if the file is allowed
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

# Function to run pdfid.py and analyze the PDF
def analyze_pdf(pdf_path):
    try:
        # Run pdfid.py on the provided PDF file
        result = subprocess.run(["python", "pdfid.py", pdf_path], capture_output=True, text=True)
        output = result.stdout

        # Log the output for debugging
        print("PDFiD Output:\n", output)

        # Suspicious keywords indicating potential threats
        malicious_indicators = {
            "/JS": "JavaScript detected",
            "/JavaScript": "Embedded JavaScript detected",
            "/OpenAction": "Auto-execution found",
            "/AA": "Additional Actions present",
            "/EmbeddedFile": "Embedded file detected",
            "/RichMedia": "Embedded media detected",
            "/Launch": "Potential command execution"
        }

        detected_issues = [desc for indicator, desc in malicious_indicators.items() if indicator in output]

        # Determine if the file is malicious based on detected indicators
        is_malicious = len(detected_issues) > 1  # Adjust threshold as needed

        # Return structured analysis
        return {
            "status": "success",
            "malicious": is_malicious,
            "analysis": output,
            "suspicious_elements": detected_issues
        }
    except Exception as e:
        return {"status": "error", "message": f"Error during PDF analysis: {str(e)}"}

# Route: Home page (HTML Form)
@app.route("/", methods=["GET"])
def home():
    return render_template("index.html")  # Ensure index.html is styled properly

# Route: Upload and analyze a file
@app.route("/upload", methods=["POST"])
def upload_pdf():
    if "file" not in request.files:
        return jsonify({"status": "error", "message": "No file uploaded"})

    file = request.files["file"]

    if file.filename == "":
        return jsonify({"status": "error", "message": "No selected file"})

    if not allowed_file(file.filename):
        return jsonify({"status": "error", "message": "Invalid file type. Only PDF files are allowed."})

    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    file.save(filepath)

    result = analyze_pdf(filepath)

    os.remove(filepath)  # Delete the file after analysis

    return jsonify(result)

# Route: Analyze a PDF from a URL
@app.route("/scan_url", methods=["POST"])
def scan_pdf_url():
    data = request.get_json()

    if "url" not in data:
        return jsonify({"status": "error", "message": "No URL provided"})

    try:
        response = requests.get(data["url"], stream=True)
        if response.status_code != 200:
            return jsonify({"status": "error", "message": "Failed to download the PDF from the provided URL."})

        filename = secure_filename(data["url"].split("/")[-1]) or "downloaded.pdf"
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)

        with open(filepath, "wb") as file:
            file.write(response.content)

        result = analyze_pdf(filepath)

        os.remove(filepath)

        return jsonify(result)

    except Exception as e:
        return jsonify({"status": "error", "message": f"Error during URL scan: {str(e)}"})

# Run Flask App
if __name__ == "__main__":
    app.run(debug=True)
