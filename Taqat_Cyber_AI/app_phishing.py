import streamlit as st
import re
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import base64

# ----------------- 1. Utility Functions -----------------
def get_base64_image(image_path):
    """Converts a local image file to a Base64 string for CSS embedding."""
    try:
        with open(image_path, "rb") as img_file:
            return base64.b64encode(img_file.read()).decode()
    except FileNotFoundError:
        st.error(f"❌ ERROR: File not found: {image_path}. Ensure it's in the same folder.")
        return "" 

# Feature Extraction Functions (ML Core)
def has_ip(url): return 1 if re.search(r'//\d+\.\d+\.\d+\.\d+', url) else 0
def num_dots(url): return url.count('.')
def url_len(url): return len(url) # Corresponds to 'len' in DataFrame
def has_at(url): return 1 if '@' in url else 0
def is_https(url): return 1 if url.lower().startswith('https') else 0
def suspicious_kw(url):
    kws = ['login','secure','verify','update','bank','confirm','account','paypal','ebay']
    u = url.lower()
    return 1 if any(k in u for k in kws) else 0

def extract_features(url):
    # Order matches DataFrame columns: ['len','dots','has_ip','has_at','https','kw']
    return [url_len(url), num_dots(url), has_ip(url), has_at(url), is_https(url), suspicious_kw(url)]

# ----------------- 2. Model Training -----------------
@st.cache_resource
def train_and_load_model():
    """Trains a simple Random Forest model for demonstration."""
    # Training Data (for demonstration only)
    rows = [
        [20, 2, 0, 0, 1, 0, 0], [85, 6, 1, 0, 0, 1, 1], [40, 3, 0, 0, 1, 0, 0],
        [95, 7, 1, 0, 0, 1, 1], [30, 2, 0, 0, 1, 0, 0], [70, 5, 0, 1, 0, 1, 1], 
        [55, 4, 0, 0, 0, 1, 1], [25, 2, 0, 0, 1, 0, 0]
    ]
    columns = ['len','dots','has_ip','has_at','https','kw','malicious']
    df = pd.DataFrame(rows, columns=columns)
    
    X = df[['len','dots','has_ip','has_at','https','kw']]
    y = df['malicious']
    
    model = RandomForestClassifier(random_state=0, n_estimators=50)
    model.fit(X, y)
    
    return model, columns[:-1]

# ----------------- 3. Streamlit Main App -----------------
def main():
    st.set_page_config(page_title="Phishing Detector AI", layout="wide", initial_sidebar_state="collapsed")
    
    # Custom CSS for aesthetics (White Background & Purple Metrics)
    st.markdown("""
        <style>
        /* White Background & Default Text Color */
        .stApp {
            background-color: #FFFFFF; 
            color: #333333; 
        }
        /* Style for the Purple Metric Boxes (Custom Box for Results) */
        .purple-box {
            background-color: #6A5ACD; /* Medium Purple */
            color: white;
            padding: 15px;
            border-radius: 10px;
            text-align: center;
            margin-bottom: 10px;
            box-shadow: 3px 3px 8px rgba(0, 0, 0, 0.2);
            height: 120px;
        }
        /* Style for the Final Analysis Box */
        .analysis-box {
            background-color: #F0F8FF; /* AliceBlue - Light background for explanation */
            color: #333333;
            padding: 15px;
            border-left: 5px solid #6A5ACD;
            border-radius: 10px;
            box-shadow: 2px 2px 5px rgba(0, 0, 0, 0.1);
        }
        /* Style the Text Input Box */
        .stTextInput > div > div > input {
            background-color: #F8F8FF;
            color: #333333;
            border: 1px solid #C0C0C0;
        }
        /* Style the DataFrame */
        .stDataFrame {
            border-radius: 10px;
            box-shadow: 1px 1px 5px rgba(0, 0, 0, 0.1);
        }
        </style>
        """, unsafe_allow_html=True)
        
    # Load Model (Executed once)
    model, feature_names = train_and_load_model()
    
    # --- Three-Column Layout for Header (Logo on the right) ---
    header_col1, header_col2, header_col3 = st.columns([1, 4, 1])

    with header_col3:
        # Taqat Logo on the far right
        st.image("taqat_logo.png", width=180) 

    # --- Two-Column Layout for Main Content ---
    col_input, col_analysis = st.columns([1, 2])

    # -------------------------------------------------------------
    # LEFT COLUMN: Header, Image, Input, and Button
    # -------------------------------------------------------------
    with col_input:
        st.title("Cyber Shield AI 🛡️")
        st.markdown("### Phishing Detection System")
        st.markdown("<hr style='border: 1px solid #CCCCCC'>", unsafe_allow_html=True)
        
        st.subheader("AI-Powered URL Analysis")
        
        # Image placement
        st.image("hacker_background.png", use_container_width=True) 
        st.markdown("<p style='text-align: center; color: #888888; font-size: 14px;'>Upload image to this folder and use its name.</p>", unsafe_allow_html=True)


        # Input (FIX: Added unique key)
        default_url = "http://secure.paypal.com@verify-account.info/login.html"
        user_url = st.text_input("Enter URL to Analyze:", default_url, key="url_input_field")
        
        # Unique Button
        if st.button("Analyze Link", key="primary_analyze_btn"): 
             st.session_state['analysis_started'] = True
        
    # -------------------------------------------------------------
    # RIGHT COLUMN: Analysis and Results
    # -------------------------------------------------------------
    with col_analysis:
        st.header("Analysis Results")
        st.markdown("<hr style='border: 1px solid #6A5ACD'>", unsafe_allow_html=True)
        
        # Check if the analysis button was clicked (flag is set)
        if st.session_state.get('analysis_started', False):
            
            # 1. Input Validation
            if not user_url.strip():
                st.error("Please enter a valid URL.")
                return

            # 2. Feature Extraction & Prediction
            feats_list = extract_features(user_url)
            feats_dict = dict(zip(feature_names, feats_list))

            with st.spinner('Analyzing and Classifying URL...'):
                X_test = pd.DataFrame([feats_list], columns=feature_names) 
                pred = model.predict(X_test)[0]
                prob = model.predict_proba(X_test)[0].max()
                label = "MALICIOUS 🚨" if pred == 1 else "SAFE ✅"
            
            # --- Results Display (Custom Purple Boxes) ---
            col_res1, col_res2 = st.columns(2)

            with col_res1:
                st.markdown(f"<div class='purple-box'><strong>CLASSIFICATION:</strong><br><span style='font-size: 24px;'>{label}</span></div>", unsafe_allow_html=True)
            
            with col_res2:
                st.markdown(f"<div class='purple-box'><strong>CONFIDENCE:</strong><br><span style='font-size: 24px;'>{prob:.2f}</span></div>", unsafe_allow_html=True)
            
            # 3. Feature Table
            st.subheader("Extracted URL Features:")
            feature_df = pd.DataFrame(feats_dict.items(), columns=['Feature', 'Value'])
            st.dataframe(feature_df, use_container_width=True)
            
            # 4. Decision Explanation (Analysis Box)
            st.subheader("AI Decision Explanation:")
            
            analysis_text = ""
            
            # FIX: Using the correct key 'len'
            if feats_dict['len'] > 60:
                analysis_text += "- ⚠️ **Excessive Length:** Long URLs (>60 chars) are often used to evade detection.<br>"
            if feats_dict['has_at'] == 1:
                analysis_text += "- ❌ **Presence of @:** A classic phishing tactic used to hide the true domain.<br>"
            if feats_dict['has_ip'] == 1:
                analysis_text += "- ❌ **IP Address Used:** Using raw numbers instead of a domain name is highly suspicious.<br>"
            if feats_dict['kw'] == 1:
                analysis_text += "- ⚠️ **Suspicious Keywords:** Contains sensitive words like 'login' or 'bank'.<br>"
            

            st.markdown(f"<div class='analysis-box'><strong>MODEL INSIGHTS:</strong><br>{analysis_text or 'No highly suspicious features detected.'}</div>", unsafe_allow_html=True)


if __name__ == '__main__':
    # Initial setup for session state
    if 'analysis_started' not in st.session_state:
        st.session_state['analysis_started'] = False
    
    main()