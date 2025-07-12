# LLM Red Team Simulator

This project provides an **Advanced LLM Red Team Simulator** for security testing of large language models (LLMs) such as Google Gemini, OpenAI, and Anthropic. It allows you to test your LLM prompts and API endpoints against 50+ attack vectors, analyze vulnerabilities, and receive remediation suggestions.

## Features
- **Base Prompt Testing:** Test your LLM prompt against a comprehensive suite of adversarial attacks.
- **Endpoint Red Teaming:** Test your deployed API endpoints for security weaknesses.
- **Analytics Dashboard:** Visualize vulnerabilities, risk scores, and attack success rates.
- **Remediation Suggestions:** Get actionable recommendations to improve your LLM security.
- **PDF Report Generation:** Export professional security assessment reports.

## Setup
1. **Clone the repository:**
   ```bash
   git clone https://github.com/APAKSHAT/red-teaming.git
   cd red-teaming
   ```
2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   # Or install manually:
   pip install streamlit google-generativeai openai anthropic requests pandas plotly reportlab streamlit-option-menu
   ```
3. **Run the app:**
   ```bash
   streamlit run hi.py
   ```

## Usage
- Open your browser and go to [http://localhost:8501](http://localhost:8501)
- Enter your API key for your chosen LLM provider (Google Gemini, OpenAI, or Anthropic)
- Select attack vectors and run tests
- View analytics, responses, and download reports

## Security
- **API keys** are never stored and are only used for the current session.
- The tool is for research and security testing purposes only. Do not use for malicious activities.

## License
MIT License

---

For more details, see the code in `hi.py` or visit the [GitHub repository](https://github.com/APAKSHAT/red-teaming).