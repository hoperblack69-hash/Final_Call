import PyPDF2

pdf_path = r"c:\Users\Ashish\Downloads\Phishing_Detection_Project_Report.pdf"

with open(pdf_path, 'rb') as file:
    reader = PyPDF2.PdfReader(file)
    text = ""
    for page in reader.pages:
        text += page.extract_text()
    print(text)