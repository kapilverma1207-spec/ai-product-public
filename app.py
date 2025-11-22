import os
import json
import yaml
import pandas as pd
import streamlit as st
from dotenv import load_dotenv
from openai import OpenAI

# ------------------ Load API Key ------------------
load_dotenv()
OPENAI_API_KEY = st.secrets["OPENAI_API_KEY"]

client = OpenAI(api_key=OPENAI_API_KEY)


# ------------------ System Prompt ------------------
SYSTEM_PROMPT = """
You are an AI Security Auditor specializing in identifying misconfigurations,
secret exposures, insecure defaults, and IAM risks across configuration files.

Analyze the uploaded file for:
- Hardcoded API keys, secrets, tokens
- Overly permissive IAM roles (admin, owner, editor, wildcard privileges)
- Public access (0.0.0.0/0, public buckets, open firewall rules)
- Unsafe environment variables
- Terraform misconfigurations
- Cloud or DevOps insecure settings
- Kubernetes, Docker, YAML, JSON, .env, TF file risks

For each issue, include:
1. Severity: HIGH / MEDIUM / LOW
2. Where it appears (line/key/resource)
3. Impact
4. Remediation steps

Return output in Markdown.
"""


# ------------------ Helpers ------------------
def parse_uploaded_file(uploaded_file):
    filename = uploaded_file.name.lower()

    # Excel → Convert to CSV-like text
    if filename.endswith(".xlsx"):
        try:
            df = pd.read_excel(uploaded_file)
            return df.to_csv(index=False)
        except Exception as e:
            return f"ERROR reading Excel: {e}"

    # Other text formats
    try:
        content = uploaded_file.read().decode("utf-8")
        uploaded_file.seek(0)
    except:
        return "Unable to decode file."

    # YAML
    if filename.endswith((".yaml", ".yml")):
        try:
            parsed = yaml.safe_load(content)
            return yaml.safe_dump(parsed, sort_keys=False)
        except:
            return content

    # JSON
    if filename.endswith(".json"):
        try:
            parsed = json.loads(content)
            return json.dumps(parsed, indent=2)
        except:
            return content

    return content


def call_llm(file_content, notes=""):
    prompt = f"""
### Configuration File Content: 

{file_content}


### Additional User Instruction:
{notes}

### Task:
Perform a full security audit of this configuration.
"""

    response = client.responses.create(
        model="gpt-4.1",  
        input=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt}
        ],
        max_output_tokens=1500,
    )

# New OpenAI SDK: extract text safely
    try:
        return response.output_text
    except:
        # Fallback if response is structured differently
        for item in response.output:
            if hasattr(item, "content"):
                return item.content[0].text
        return str(response)

# ------------------ Streamlit UI ------------------
st.set_page_config(page_title="AI Security Config Scanner", page_icon="🛡️", layout="wide")

st.title("AI Security Config Scanner")
st.write("Upload any configuration file and let an AI-powered auditor detect misconfigurations, secrets, and IAM risks.")

uploaded = st.file_uploader(
    "Upload a config file",
    type=["yaml", "yml", "json", "tf", "txt", "env", "ini", "cfg", "xml", "sh", "properties", "xlsx"],
)

notes = st.text_area(
    "Optional: Add extra instructions (example: 'focus on IAM roles only')"
)

if st.button("Run Security Scan", type="primary"):
    if not uploaded:
        st.error("Please upload a configuration file first.")
    else:
        st.info(f"Processing file: {uploaded.name}")

        content = parse_uploaded_file(uploaded)

        with st.expander("Parsed File Content"):
            st.code(content)

        with st.spinner("Running AI security audit..."):
            result = call_llm(content, notes)

        st.subheader("Security Findings")
        st.markdown(result)

        st.download_button(
            label="Download Report",
            data=result,
            file_name=f"{uploaded.name}_security_report.md",
            mime="text/markdown"
        )
