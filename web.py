import streamlit as st
from main import read_zip


# Web page configuration
st.set_page_config(page_title="ZipReader", layout="wide")
st.subheader("ZipReader")
st.title("Upload and Process Your Zip File")

# Adding a block for downloading a ZIP file
uploaded_file = st.file_uploader("Choose a ZIP file to upload:", type="zip")

if uploaded_file is not None:
    # If file was downloaded creating the button
    # Pressing the button will execute the read_zip() function from main.py
    if st.button("Process Uploaded File"):
        success = read_zip(uploaded_file)
        if success:
            # After executing read_zip(), additional files are being created: hash.txt, log.txt, report.txt
            # These files are read and displayed in web blocks
            try:
                with open("files/hash.txt", "r") as file:
                    hash_content = file.read().strip()
                    st.write("**Hash Content:**")
                    st.code(hash_content, language="text")
            except FileNotFoundError:
                st.warning("Hash file not found.")
            try:
                with open("files/report.txt", "r") as file:
                    report_content = file.read().strip()
                    st.write("**Report Content:**")
                    st.code(report_content, language="text")
            except FileNotFoundError:
                st.warning("Report file not found.")

        try:
            with open("files/log.txt", "r") as file:
                log_content = file.read().strip()
                st.write("**Log Content:**")
                st.code(log_content, language="text")
        except FileNotFoundError:
            st.warning("Log file not found.")

        if success:
            # After executing read_zip(), new_zipfile.zip is created
            with open('new_zipfile.zip', "rb") as f:
                # Pressing the button will download the newly created ZIP file
                if st.download_button('Download Zip', f, 'new_zipfile.zip'):
                    st.write("Zip file uploaded")
            st.write("**Password Clue:**")
            st.image('password_clue.png')

else:
    st.info("Please upload a ZIP file to proceed.")
