import streamlit as st
from app.sanitizer import sanitize_text
from app.config import settings

# Page Config
st.set_page_config(page_title="IronLayer Demo", page_icon="🛡️")

# Load Custom Secrets for the demo
settings.CUSTOM_SECRET_WORDS = st.text_input(
    "Define your Custom Secrets (comma separated):", 
    "ProjectStarlight, CocaColaFormula"
)

st.title("🛡️ IronLayer: The DLP Layer for AI")
st.markdown("""
### See how IronLayer protects your data.
Type a message containing sensitive information (like emails, credit cards, or your custom secrets) below. 
We will show you exactly what the AI would see vs. what the user types.
""")

# Input Area
user_input = st.text_area(
    "User Input (Simulated Prompt):", 
    "My email is agent@secret.com and my phone is 555-0199. The password for ProjectStarlight is 1234.",
    height=100
)

if st.button("Sanitize Prompt"):
    if user_input:
        with st.spinner("Scanning..."):
            # Run the sanitizer
            clean_text = sanitize_text(user_input)
            
            # Display Results
            col1, col2 = st.columns(2)
            
            with col1:
                st.error("❌ Original (Risk)")
                st.code(user_input, language="text")
            
            with col2:
                st.success("✅ Sanitized (Safe)")
                st.code(clean_text, language="text")
            
            st.info("The AI receives the **Safe** version, protecting your secrets.")
    else:
        st.warning("Please enter some text.")