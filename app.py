from flask import Flask, request, render_template, send_file, redirect, url_for, session
import os
import requests
import subprocess
import time
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)

# Function to run pdfid.py and analyze the PDF
def analyze_pdf(pdf_path):
    try:
        result = subprocess.run(["python", "pdfid.py", pdf_path], capture_output=True, text=True)
        output = result.stdout

        # PDF Structure Categories
        structure = {
            "Basic": ["obj", "endobj", "stream", "endstream", "xref", "trailer", "startxref", "/Page"],
            "Security": ["/Encrypt", "/ObjStm"],
            "JavaScript": ["/JS", "/JavaScript", "/AA", "/OpenAction"],
            "Embedded": ["/AcroForm", "/RichMedia", "/Launch", "/EmbeddedFile", "/XFA", "/JBIG2Decode", "/Colors > 2^24"]
        }

        analysis = {"Basic": {}, "Security": {}, "JavaScript": {}, "Embedded": {}}
        suspicious_count = 0
        safe_count = 0

        # Parse output and categorize data
        for line in output.split("\n"):
            parts = line.strip().split()
            if len(parts) == 2:
                key, value = parts
                value = int(value)

                for category, keywords in structure.items():
                    if key in keywords:
                        analysis[category][key] = value
                        if category in ["JavaScript", "Embedded"] and value > 0:
                            suspicious_count += 1
                        else:
                            safe_count += 1

        is_malicious = suspicious_count > 0

        return {
            "malicious": is_malicious,
            "suspicious_count": suspicious_count,
            "safe_count": safe_count,
            "analysis": analysis,
        }
    except Exception as e:
        return {"error": f"Error during PDF analysis: {str(e)}"}

# Home Page Route
@app.route("/", methods=["GET"])
def home():
    return render_template("login.html")

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

@app.before_first_request
def create_tables():
    db.create_all()

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        if User.query.filter_by(username=username).first():
            return "Username already exists!"
        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('dashboard'))
        return "Invalid credentials!"
    return render_template('index.html')



@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

# Upload and Analyze PDF
@app.route("/upload", methods=["POST"])
def upload_pdf():
    if "file" not in request.files:
        return redirect(url_for("home", error="No file uploaded!"))

    file = request.files["file"]
    if file.filename == "":
        return redirect(url_for("home", error="No file selected!"))

    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    file.save(filepath)

    time.sleep(3)  # Simulated scanning time

    result = analyze_pdf(filepath)

    if result["malicious"]:
        os.remove(filepath)
        return render_template(
            "result.html",
            status="danger",
            message="🚨 WARNING! This PDF is as safe as a hacker’s diary! Proceed with caution! 🚨",
            analysis=result["analysis"],
            download=False,
        )

    return render_template(
        "result.html",
        status="success",
        message="🎉 Congratulations! Your PDF is cleaner than my search history! Download it below! ⬇️",
        analysis=result["analysis"],
        download=True,
        filename=filename,
    )

# Scan PDF from URL
@app.route("/scan_url", methods=["POST"])
def scan_pdf_url():
    data = request.form
    pdf_url = data.get("pdf_url")
    if not pdf_url:
        return redirect(url_for("home", error="No URL provided!"))

    try:
        response = requests.get(pdf_url, stream=True)
        if response.status_code != 200:
            return redirect(url_for("home", error="Failed to download the PDF!"))

        filename = secure_filename(pdf_url.split("/")[-1]) or "downloaded.pdf"
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)

        with open(filepath, "wb") as file:
            file.write(response.content)

        time.sleep(3)  # Simulated scanning time
        result = analyze_pdf(filepath)

        if result["malicious"]:
            os.remove(filepath)
            return render_template(
                "result.html",
                status="danger",
                message="⚠️ Alert! This PDF is one suspicious click away from ruining your day! 🚨",
                analysis=result["analysis"],
                download=False,
            )

        return render_template(
            "result.html",
            status="success",
            message="✅ Your PDF is so clean it could get a job at a hospital! Download it below! ⬇️",
            analysis=result["analysis"],
            download=True,
            filename=filename,
        )

    except Exception as e:
        return redirect(url_for("home", error=f"Error: {str(e)}"))

# Download Safe PDF
@app.route("/download/<filename>")
def download_pdf(filename):
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    if os.path.exists(filepath):
        return send_file(filepath, as_attachment=True)
    return "File not found!", 404

if __name__ == "__main__":
    app.run(debug=True)
