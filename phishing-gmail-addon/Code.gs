/**
 * BombSquad Phishing Scanner - Gmail Add-on
 */

var NGROK_URL = "https://loose-moles-turn.loca.lt"; // Setup your localtunnel URL here!
var GEMINI_API_KEY = "AIzaSyDfFdW-G5u0Z7QoPydxxGgPU-r5lle2OJI"; 

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
      .setHeader("Inbox Scanning Options")
      .addWidget(CardService.newTextParagraph().setText("Automatically detect and explain phishing attempts to keep you safe."));

  var btnRecent = CardService.newTextButton()
      .setText("Scan Recent 10 Emails")
      .setOnClickAction(CardService.newAction().setFunctionName('actionScan10'))
      .setTextButtonStyle(CardService.TextButtonStyle.FILLED);
      
  var btnAll = CardService.newTextButton()
      .setText("Scan All Emails (Max 50)")
      .setOnClickAction(CardService.newAction().setFunctionName('actionScan50'))
      .setTextButtonStyle(CardService.TextButtonStyle.FILLED);
  
  section.addWidget(CardService.newButtonSet().addButton(btnRecent).addButton(btnAll));

  builder.setHeader(header);
  builder.addSection(section);
  return builder.build();
}

/**
 * Actions mapping for Homepage Interface
 */
function actionScan10(e) {
  return runInboxScan(10);
}

function actionScan50(e) {
  return runInboxScan(50);
}

/**
 * Shared Inbox Scanning Logic
 */
function runInboxScan(count) {
  var threads = GmailApp.getInboxThreads(0, count);
  var phishingCount = 0;
  var safeCount = 0;
  
  var phishingThreadsData = [];
  var cachedIds = [];
  
  for (var i = 0; i < threads.length; i++) {
    var msg = threads[i].getMessages()[0]; 
    if (!msg) continue;
    
    var res = callFlaskModel(msg.getPlainBody());
    if (!res.error && res.prediction === "phishing") {
      phishingCount++;
      phishingThreadsData.push({
         id: threads[i].getId(),
         msgId: msg.getId(),
         subject: msg.getSubject()
      });
      cachedIds.push(threads[i].getId());
    } else {
      safeCount++;
    }
  }
  
  // Cache the newly found phishing thread IDs to memory so the Contextual Card knows which ones to "auto-scan" later
  PropertiesService.getUserProperties().setProperty('PHISHING_THREADS', JSON.stringify(cachedIds));
  
  var builder = CardService.newCardBuilder();
  builder.setHeader(CardService.newCardHeader().setTitle("Inbox Scan Results"));
  
  var summarySection = CardService.newCardSection()
      .addWidget(CardService.newTextParagraph().setText("Scanned " + count + " recent emails:"))
      .addWidget(CardService.newDecoratedText().setTopLabel("Safe").setText(safeCount + " emails").setIcon(CardService.Icon.EMAIL))
      .addWidget(CardService.newDecoratedText().setTopLabel("Phishing").setText(phishingCount + " emails").setIcon(CardService.Icon.VIDEO_PLAY)); 
      
  builder.addSection(summarySection);
      
  if (phishingCount > 0) {
      var listSection = CardService.newCardSection()
          .setHeader("Flagged Emails (Click to Analyze)");
          
      for (var j = 0; j < phishingThreadsData.length; j++) {
          var tId = phishingThreadsData[j].id; 
          var tSubject = phishingThreadsData[j].subject || "(No Subject)";
          var emailUrl = "https://mail.google.com/mail/u/0/#inbox/" + tId;
          
          listSection.addWidget(CardService.newDecoratedText()
             .setText(tSubject)
             .setTopLabel("Warning: Suspicious")
             .setWrapText(true)
             .setOpenLink(CardService.newOpenLink()
                 .setUrl(emailUrl)
                 .setOpenAs(CardService.OpenAs.FULL_SIZE)
                 .setOnClose(CardService.OnClose.NOTHING)));
      }
      builder.addSection(listSection);
  }

  var backSection = CardService.newCardSection();
  var backBtn = CardService.newTextButton().setText("Back").setOnClickAction(CardService.newAction().setFunctionName('buildHomepage'));
  backSection.addWidget(CardService.newButtonSet().addButton(backBtn));
  
  builder.addSection(backSection);
  return builder.build();
}


/**
 * Triggered when opening a specific email.
 */
function buildContextualCard(e) {
  var threadId = e.gmail.threadId;
  
  // Check memory: Did the user flag this thread during an inbox scan?
  var cachedStr = PropertiesService.getUserProperties().getProperty('PHISHING_THREADS');
  var wasFlagged = false;
  if (cachedStr) {
    try {
      var cachedIds = JSON.parse(cachedStr);
      if (cachedIds.indexOf(threadId) > -1) {
        wasFlagged = true;
      }
    } catch(err) {}
  }
  
  // If user came here via a known flagged email, bypass the manual button and instantly run XAI scan.
  if (wasFlagged) {
      return scanCurrentEmail(e, true);
  }
  
  // Otherwise, present standard manual button Interface
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
      .setBackgroundColor("#d93025"); 
      
  section.addWidget(button);
  builder.setHeader(header);
  builder.addSection(section);
  
  return builder.build();
}


/**
 * Action: Run scan directly from the sidebar list
 */
function actionAnalyzeFromList(e) {
  // It returns the built result card from scanCurrentEmail, which Apps Script automatically pushes to the UI
  return scanCurrentEmail(e, true);
}


/**
 * Action: Scan current email open by the user.
 */
function scanCurrentEmail(e, isAutoScan) {
  // If auto-scanning, the parameters map might not be populated in the same way by the Action handler, but it still has messageId
  var messageId = (e.parameters && e.parameters.messageId) ? e.parameters.messageId : e.gmail.messageId;
  
  if (e.messageMetadata && e.messageMetadata.accessToken) {
      GmailApp.setCurrentMessageAccessToken(e.messageMetadata.accessToken);
  }
  
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
    xaiExplanation = getGeminiExplanation(combinedText);
  } else {
    xaiExplanation = "This email looks safe. The tone and syntax align with typical legitimate messages.";
  }
  
  return buildResultCard(prediction, confidence, xaiExplanation, isAutoScan);
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
    return {error: "Failed to connect to model API. Is your URL running? " + e.toString()};
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
    return "XAI API Error (" + response.getResponseCode() + "): " + response.getContentText();
  } catch(e) {
    return "XAI Request Error: " + e.toString();
  }
}

/**
 * Helper: Builds the UI showing the scanning result
 */
function buildResultCard(prediction, confidence, explanation, isAutoScan) {
  var builder = CardService.newCardBuilder();
  
  var isPhishing = (prediction === "phishing");
  var color = isPhishing ? "#d93025" : "#188038";
  var title = isPhishing ? "⚠️ Phishing Detected" : "✅ Looks Safe";
  var subtitle = "Confidence: " + confidence + "%";
  
  if (isAutoScan) {
     title = "(Auto-Scanned) " + title;
  }
  
  var header = CardService.newCardHeader()
      .setTitle(title)
      .setSubtitle(subtitle);
      
  var contentSection = CardService.newCardSection()
      .setHeader("Explainable AI (XAI) Analysis")
      .addWidget(CardService.newTextParagraph().setText(explanation));
      
  // Gamification/Feedback Loop 
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
