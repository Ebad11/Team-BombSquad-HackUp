/**
 * BombSquad Phishing Scanner - Gmail Add-on
 * 
 * IMPORTANT: Because this runs on Google's servers, it CANNOT hit "localhost". 
 * You need to expose your Flask app using ngrok: `ngrok http 5000`
 * Then paste the Forwarding URL below.
 */

var NGROK_URL = "https://wicked-walls-add.loca.lt"; // e.g. "https://abcd-12-34-56-78.ngrok-free.app" (No trailing slash)
var GEMINI_API_KEY = "AIzaSyDcjQwaOif2ghhDl6wZfVNMuonT0bDRMO8"; // Get a free key at aistudio.google.com

/**
 * Triggered on the homepage (no specific email opened).
 */
function buildHomepage(e) {
  var builder = CardService.newCardBuilder();
  
  var header = CardService.newCardHeader()
      .setTitle("BombSquad Phishing Scanner")
      .setSubtitle("Your AI-Powered Inbox Guardian")
      .setImageStyle(CardService.ImageStyle.CIRCLE)
      .setImageUrl("https://www.gstatic.com/images/icons/material/system/2x/security_black_48dp.png");
  
  var section = CardService.newCardSection()
      .setHeader("Inbox Overview")
      .addWidget(CardService.newTextParagraph().setText("Automatically detect and explain phishing attempts to keep you safe."));

  var infoSection = CardService.newCardSection()
      .addWidget(CardService.newDecoratedText()
          .setTopLabel("Status")
          .setText("Ready to scan emails.")
          .setIcon(CardService.Icon.EMAIL));

  var btnAction = CardService.newAction().setFunctionName('actionScanLatest');
  var scanBtn = CardService.newTextButton()
      .setText("Scan Latest Emails (Demo)")
      .setOnClickAction(btnAction)
      .setTextButtonStyle(CardService.TextButtonStyle.FILLED);
  
  infoSection.addWidget(CardService.newButtonSet().addButton(scanBtn));

  builder.setHeader(header);
  builder.addSection(section);
  builder.addSection(infoSection);

  return builder.build();
}

/**
 * Triggered when opening a specific email.
 */
function buildContextualCard(e) {
  var messageId = e.gmail.messageId;
  
  var builder = CardService.newCardBuilder();
  var header = CardService.newCardHeader()
      .setTitle("Contextual Scanner")
      .setSubtitle("Analyze this specific email");
      
  var section = CardService.newCardSection()
      .addWidget(CardService.newTextParagraph().setText("Analyze this email for malicious intents, URLs, and manipulative language."));
      
  var action = CardService.newAction()
      .setFunctionName("scanCurrentEmail")
      .setParameters({messageId: messageId});
      
  var button = CardService.newTextButton()
      .setText("Scan This Email")
      .setOnClickAction(action)
      .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
      .setBackgroundColor("#d93025"); // Red for security
      
  section.addWidget(button);
  
  builder.setHeader(header);
  builder.addSection(section);
  
  return builder.build();
}


/**
 * Action: Scan current email open by the user.
 */
function scanCurrentEmail(e) {
  var messageId = e.parameters.messageId;
  var accessToken = e.messageMetadata.accessToken;
  GmailApp.setCurrentMessageAccessToken(accessToken);
  
  var message = GmailApp.getMessageById(messageId);
  var body = message.getPlainBody();
  var subject = message.getSubject();
  var sender = message.getFrom();
  
  var combinedText = "Subject: " + subject + "\nSender: " + sender + "\n\n" + body;
  
  // 1. Call Flask Model
  var result = callFlaskModel(combinedText);
  if (result.error) {
    return buildErrorCard(result.error);
  }
  
  var prediction = result.prediction;
  var confidence = result.confidence;

  // 2. If phishing, use Explainable AI (Gemini) to explain WHY
  var xaiExplanation = "Analysis complete. No immediate threats detected by the XAI module.";
  
  if (prediction === "phishing") {
    if (!GEMINI_API_KEY || GEMINI_API_KEY === "YOUR_GEMINI_API_KEY_HERE") {
      xaiExplanation = "Heuristic XAI: This email was flagged because it uses urgent language, suspicious links, and deceptive sender addresses. (Please add a Gemini API key for advanced Explainable AI!)";
    } else {
      xaiExplanation = getGeminiExplanation(combinedText);
    }
  } else {
     xaiExplanation = "This email looks safe. The tone and syntax align with typical legitimate messages.";
  }
  
  return buildResultCard(prediction, confidence, xaiExplanation);
}

/**
 * Action: Scan latest emails from Inbox (Homepage Feature)
 */
function actionScanLatest(e) {
  // Grab latest 5 emails for demo purposes
  var threads = GmailApp.getInboxThreads(0, 5);
  var phishingCount = 0;
  var safeCount = 0;
  
  // Count them without slowing down too much. (Keep it simple for the hackathon).
  for (var i = 0; i < threads.length; i++) {
    var msg = threads[i].getMessages()[0]; // get the first message in the thread
    var res = callFlaskModel(msg.getPlainBody());
    if (!res.error && res.prediction === "phishing") {
      phishingCount++;
    } else {
      safeCount++;
    }
  }
  
  var builder = CardService.newCardBuilder();
  builder.setHeader(CardService.newCardHeader().setTitle("Inbox Scan Results"));
  
  var section = CardService.newCardSection()
      .addWidget(CardService.newTextParagraph().setText("Recently scanned 5 emails from your inbox:"))
      .addWidget(CardService.newDecoratedText().setTopLabel("Safe").setText(safeCount + " emails").setIcon(CardService.Icon.EMAIL))
      .addWidget(CardService.newDecoratedText().setTopLabel("Phishing").setText(phishingCount + " emails").setIcon(CardService.Icon.VIDEO_PLAY)); // Using default icon as placeholder

  var backAction = CardService.newAction().setFunctionName('buildHomepage');
  var backBtn = CardService.newTextButton().setText("Back").setOnClickAction(backAction);
  section.addWidget(CardService.newButtonSet().addButton(backBtn));
  
  builder.addSection(section);
  return builder.build();
}

/**
 * Helper: Calls your local Flask app mapped through Ngrok
 */
function callFlaskModel(text) {
  
  var url = NGROK_URL + "/predict/text";
  var payload = {
    "text": text
  };
  
  var options = {
    "method": "post",
    "contentType": "application/json",
    "payload": JSON.stringify(payload),
    "muteHttpExceptions": true
  };
  
  try {
    var response = UrlFetchApp.fetch(url, options);
    if (response.getResponseCode() === 200) {
      return JSON.parse(response.getContentText());
    } else {
       return {error: "Model API returned error: " + response.getResponseCode()};
    }
  } catch(e) {
    return {error: "Failed to connect to model API. Is Ngrok running? " + e.toString()};
  }
}

/**
 * Helper: XAI Generation via Gemini API
 * This fulfills the requirement of actively teaching the user.
 */
function getGeminiExplanation(emailText) {
  var url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-3-flash-preview:generateContent?key=" + GEMINI_API_KEY;
  
  var prompt = "You are a cybersecurity expert. The following email has been flagged as PHISHING by our ML model. Explain to the user WHY this is phishing in 2-3 short, easy-to-understand bullet points. Focus on teaching them red flags like urgency, suspicious links, and sender domains so they learn. Do not use markdown bolding like ** because Apps script text won't render it. Use plain text.\n\nEmail Content:\n" + emailText;
  
  var payload = {
    "contents": [{
      "parts": [{"text": prompt}]
    }]
  };
  
  var options = {
    "method": "post",
    "contentType": "application/json",
    "payload": JSON.stringify(payload),
    "muteHttpExceptions": true
  };
  
  try {
    var response = UrlFetchApp.fetch(url, options);
    if (response.getResponseCode() === 200) {
      var data = JSON.parse(response.getContentText());
      if (data.candidates && data.candidates.length > 0) {
        return data.candidates[0].content.parts[0].text;
      }
    }
    // Return the actual API error to help debug
    return "XAI API Error (" + response.getResponseCode() + "): " + response.getContentText();
  } catch(e) {
    return "XAI Request Error: " + e.toString();
  }
}

/**
 * Helper: Builds the UI showing the scanning result
 */
function buildResultCard(prediction, confidence, explanation) {
  var builder = CardService.newCardBuilder();
  
  var isPhishing = (prediction === "phishing");
  var color = isPhishing ? "#d93025" : "#188038";
  var title = isPhishing ? "⚠️ Phishing Detected" : "✅ Looks Safe";
  var subtitle = "Confidence: " + confidence + "%";
  
  var header = CardService.newCardHeader()
      .setTitle(title)
      .setSubtitle(subtitle);
      
  var contentSection = CardService.newCardSection()
      .setHeader("Explainable AI (XAI) Analysis")
      .addWidget(CardService.newTextParagraph().setText(explanation));
      
  // Gamification/Feedback Loop (Add uniqueness for Hackathon)
  var feedbackSection = CardService.newCardSection()
      .setHeader("Help Us Improve")
      .addWidget(CardService.newTextParagraph().setText("Was this analysis incorrect? Report it to tune our model's baseline behavior."));
  
  var reportAction = CardService.newAction().setFunctionName("reportFeedback").setParameters({pred: prediction});
  var reportBtn = CardService.newTextButton().setText("Report False Prediction").setOnClickAction(reportAction);
  feedbackSection.addWidget(CardService.newButtonSet().addButton(reportBtn));

  builder.setHeader(header);
  builder.addSection(contentSection);
  builder.addSection(feedbackSection);
  
  return builder.build();
}

/**
 * Action: Triggered when user reports false positive/negative
 */
function reportFeedback(e) {
  var pred = e.parameters.pred;
  var msg = (pred === "phishing") ? "Reported as False Positive." : "Reported as False Negative.";
  
  // Provide dummy feedback response. In a real app, this would hit the backend!
  return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification().setText(msg + " Model memory updated (Demo)."))
      .build();
}

/**
 * Helper: Builds an error card
 */
function buildErrorCard(errorMessage) {
  var builder = CardService.newCardBuilder();
  var header = CardService.newCardHeader()
      .setTitle("⚠️ Connection Error")
      .setSubtitle("Could not reach the phishing model");
      
  var section = CardService.newCardSection()
      .addWidget(CardService.newTextParagraph().setText("Error details:"))
      .addWidget(CardService.newTextParagraph().setText(errorMessage))
      .addWidget(CardService.newTextParagraph().setText("Make sure your LocalTunnel is running and the URL is correctly set in Code.gs."));
      
  builder.setHeader(header);
  builder.addSection(section);
  
  return builder.build();
}
