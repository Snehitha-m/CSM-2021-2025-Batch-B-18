import requests
import os
import numpy as np
import PyPDF2
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler
from io import BytesIO

# 1. Function to Download PDF from User-Provided URL
def download_pdf(url, save_path="temp.pdf"):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            with open(save_path, "wb") as f:
                f.write(response.content)
            print("✅ PDF downloaded successfully.")
            return save_path
        else:
            print("❌ Failed to download PDF. Check the URL.")
            return None
    except Exception as e:
        print("❌ Error downloading PDF:", e)
        return None

# 2. Function to Extract Features from the PDF
def extract_pdf_features(pdf_path):
    try:
        with open(pdf_path, "rb") as f:
            pdf_reader = PyPDF2.PdfReader(f)
            num_pages = len(pdf_reader.pages)

        # Example Feature Extraction
        features = {
            "num_pages": num_pages,
            "contains_js": 1 if "JavaScript" in str(pdf_reader.pages) else 0,
            "contains_embedded_files": 1 if "/EmbeddedFile" in str(pdf_reader.pages) else 0,
            "file_size_kb": os.path.getsize(pdf_path) / 1024
        }

        return features
    except Exception as e:
        print("❌ Error extracting features:", e)
        return None

# 3. Load Pre-Trained Models
rf_model = RandomForestClassifier(n_estimators=100, random_state=42)  # Load trained RF model
svm_model = SVC(kernel="rbf", C=1.0, gamma="scale")  # Load trained SVM model
scaler = StandardScaler()  # Normalize features before passing to SVM

# 4. Function to Predict if the PDF is Malicious or Benign
def predict_pdf_malware():
    pdf_url = input("Enter the PDF URL: ")  # User provides the URL
    pdf_path = download_pdf(pdf_url)

    if pdf_path:
        features = extract_pdf_features(pdf_path)
        if features:
            feature_values = np.array(list(features.values())).reshape(1, -1)

            # Select top N features using RF feature importances
            important_features = rf_model.feature_importances_
            top_n_indices = np.argsort(important_features)[-10:]  # Select top 10 features
            selected_features = feature_values[:, top_n_indices]

            # Normalize the selected features before SVM classification
            selected_features = scaler.fit_transform(selected_features)

            # Predict using SVM
            prediction = svm_model.predict(selected_features)

            print("\n🔍 Prediction:", "🚨 Malicious PDF" if prediction[0] == 1 else "✅ Benign PDF")
        else:
            print("❌ Error: Could not extract features.")
    else:
        print("❌ Error: Could not download PDF.")

# 5. Run the Prediction
predict_pdf_malware()
