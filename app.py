import streamlit as st

st.title("🚀 Guest Posting Tool")
st.write("Welcome Faizan! 🎉")

url = st.text_input("Enter Website URL:")

if url:
    st.success(f"🔗 You entered: {url}")
