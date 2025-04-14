from flask import Flask, request, render_template
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


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def analyze_pdf(pdf_path):
    try:
        result = subprocess.run(["python", "pdfid.py", pdf_path], capture_output=True, text=True)
        output = result.stdout
        malicious_indicators = ["/JS", "/JavaScript", "/OpenAction", "/AA", "/EmbeddedFile", "/RichMedia"]
        suspicious_count = sum(indicator in output for indicator in malicious_indicators)
        is_malicious = suspicious_count >= 2
        return {"malicious": is_malicious, "analysis": output, "suspicious_count": suspicious_count}
    except Exception as e:
        return {"error": str(e)}


@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "POST":
        if "file" not in request.files:
            return render_template("index.html", error="No file uploaded.")

        file = request.files["file"]
        if file.filename == "":
            return render_template("index.html", error="No selected file.")

        if not allowed_file(file.filename):
            return render_template("index.html", error="Invalid file type. Only PDFs are allowed.")

        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(filepath)

        result = analyze_pdf(filepath)
        os.remove(filepath)

        return render_template("index.html", result=result, filename=filename)

    return render_template("index.html")


if __name__ == "__main__":
    app.run(debug=True)
