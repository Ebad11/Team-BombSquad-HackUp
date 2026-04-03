# BombSquad Phishing Scanner - Gmail Add-on

This folder contains the Google Apps Script project for integrating our state-of-the-art ML Phishing Model directly into Gmail. 

Your teammates are building the URL extension and the Web App; your component is this contextual add-on!

## Features (Hackathon Highlights)
1. **Contextual Scanning:** A "Scan This Email" button appears automatically when reading an email.
2. **Explainable AI (XAI):** We don't just protect users; **we teach them**. The add-on passes flagged emails to the Gemini API which returns a 3-bullet-point explanation tailored to the user, highlighting red flags (urgency, deceptive URLs).
3. **Feedback Loop:** A dummy "Report False Positive" button is included. For the pitch, mention that this integrates with Om's model memory engine to personalize detection per-user.

## Prerequisites for Demo

Since Google Apps Script runs entirely on Google's cloud servers, it **cannot** reach `localhost:5000` on your laptop. You must expose your local Flask model.

1. **Start the Flask Model:**
   ```bash
   cd ../phishing_models
   python app.py
   ```

2. **Run LocalTunnel (Easier than Ngrok):**
   Since Ngrok requires making an account, we can use LocalTunnel directly from npm without signing up.
   ```bash
   npx localtunnel --port 5000
   ```
   *Copy the resulting URL: e.g., `https://cold-foxes-smile.loca.lt`*

3. **Get a Gemini API Key:**
   Go to [Google AI Studio](https://aistudio.google.com/app/apikey) and generate a free API key to power the Explainable AI (XAI) feature.

## How to Deploy to your Gmail

1. Go to [script.google.com](https://script.google.com/).
2. Click **New Project**.
3. Name it "BombSquad Phishing Scanner".
4. Delete the default `Code.gs` content and copy-paste the contents of `phishing-gmail-addon/Code.gs` into it.
5. In `Code.gs`, update the two configuration variables at the top:
   ```javascript
   var NGROK_URL = "https://abcd-12-34.ngrok-free.app"; 
   var GEMINI_API_KEY = "your_actual_gemini_api_key";
   ```
6. Click the **Settings** gear icon (Project Settings) on the left sidebar.
7. Check the box that says **"Show 'appsscript.json' manifest file in editor"**.
8. Go back to the **Editor**, select `appsscript.json`, and paste the contents from `phishing-gmail-addon/appsscript.json`.
9. Click **Save**.
10. Click **Deploy > Test deployments**.
11. Click **Install**.
12. Go to your Gmail inbox and refresh. You will see the add-on icon on the right-hand sidebar!

## How to Win the Pitch

When demonstrating this part of the project:
*   Show them the inbox level scan first.
*   Open an obviously fake email and show the "Scan this Email" button.
*   **Highlight the XAI:** Show how the add-on doesn't just say `Phishing` but explicitly calls out *why*. Emphasize the phrase: **"We don't want users dependent on our software forever; our goal is to inoculate them."**
*   **Highlight the Feedback:** Click the "Report False Positive" button and explain how this fuels the dynamic model updates Om is building.
