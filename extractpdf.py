import PyPDF2
import os
import re


# Function to analyze the PDF and extract necessary details
def analyze_pdf_details(pdf_path):
    try:
        # Open the PDF file
        with open(pdf_path, "rb") as file:
            reader = PyPDF2.PdfFileReader(file)

            # PDF Header
            pdf_header = reader.getDocumentInfo()

            # Initialize variables to collect various details
            obj_count = 0
            stream_count = 0
            javascript_found = False
            openaction_found = False
            embedded_files_found = False

            # Analyze each page in the PDF
            for page_num in range(reader.getNumPages()):
                page = reader.getPage(page_num)

                # Count objects and streams by checking for specific patterns in the page content
                content = page.extractText()
                obj_count += content.count("obj")
                stream_count += content.count("stream")

                # Check for JavaScript, OpenAction, and Embedded Files
                if "/JS" in content or "/JavaScript" in content:
                    javascript_found = True
                if "/OpenAction" in content:
                    openaction_found = True
                if "/EmbeddedFile" in content:
                    embedded_files_found = True

            # Compile all extracted details
            analysis = f"""
PDF Header: {pdf_header}
obj {obj_count}
endobj {obj_count}
stream {stream_count}
endstream {stream_count}
/JS {1 if javascript_found else 0}
/JavaScript {1 if javascript_found else 0}
/OpenAction {1 if openaction_found else 0}
/EmbeddedFile {1 if embedded_files_found else 0}
"""

            # Return the analysis as a dictionary
            result = {
                "analysis": analysis.strip(),
                "malicious": javascript_found or openaction_found or embedded_files_found,
                # Simple malicious detection rule
                "status": "success"
            }
            return result

    except Exception as e:
        return {"status": "error", "message": str(e)}


# Example of how to use this function
pdf_path = "path_to_your_pdf_file.pdf"
result = analyze_pdf_details(pdf_path)

# Print the result for testing
print(result)
