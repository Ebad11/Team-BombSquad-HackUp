/**
 * ═══════════════════════════════════════════════
 *  PhishGuard — AI-Powered Email Security Add-on
 * ═══════════════════════════════════════════════
 *  Update NGROK_URL each time you restart LocalTunnel.
 *  Run:  npx localtunnel --port 5000
 */

var NGROK_URL     = "https://spicy-wings-stop.loca.lt";
var GEMINI_API_KEY = "AIzaSyBUUY4W1kyLWupEukSgfLmWtqKeuX7b3Rc";

// ─── Risk Theme Helpers ───────────────────────────────────────────────────────
var RISK_ICON  = { PHISHING: "🚨", SAFE: "✅" };
var RISK_LABEL = { PHISHING: "Phishing Detected", SAFE: "All Clear" };


// ═══════════════════════════════════════════════════════════════════
//  HOMEPAGE
// ═══════════════════════════════════════════════════════════════════

function buildHomepage(e) {
  var card = CardService.newCardBuilder();

  // ── Header ──────────────────────────────────────────────────────
  card.setHeader(
    CardService.newCardHeader()
      .setTitle("PhishGuard")
      .setSubtitle("AI-Powered Email Security")
      .setImageStyle(CardService.ImageStyle.CIRCLE)
      .setImageUrl("https://www.gstatic.com/images/icons/material/system/2x/security_black_48dp.png")
  );

  // ── Status Banner ────────────────────────────────────────────────
  card.addSection(
    CardService.newCardSection()
      .addWidget(
        CardService.newDecoratedText()
          .setText("PhishGuard is active and monitoring your inbox.")
          .setTopLabel("🛡️  Protection Status: ON")
          .setWrapText(true)
      )
  );

  // ── Quick Actions ────────────────────────────────────────────────
  var scanSection = CardService.newCardSection()
    .setHeader("Quick Scan");

  scanSection.addWidget(
    CardService.newTextParagraph()
      .setText("Choose how many emails to scan. PhishGuard will extract URLs, read the email body, and run your AI pipeline on each.")
  );

  scanSection.addWidget(
    CardService.newButtonSet()
      .addButton(
        CardService.newTextButton()
          .setText("⚡  Scan Recent 10")
          .setOnClickAction(CardService.newAction().setFunctionName("actionScan10"))
          .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
      )
      .addButton(
        CardService.newTextButton()
          .setText("📥  Scan All (Max 50)")
          .setOnClickAction(CardService.newAction().setFunctionName("actionScan50"))
          .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
      )
  );

  card.addSection(scanSection);

  // ── How It Works ─────────────────────────────────────────────────
  card.addSection(
    CardService.newCardSection()
      .setHeader("How It Works")
      .setCollapsible(true)
      .addWidget(CardService.newDecoratedText().setTopLabel("Step 1 — Scan").setText("Select scan scope above to analyse your inbox.").setWrapText(true))
      .addWidget(CardService.newDecoratedText().setTopLabel("Step 2 — Review").setText("Flagged emails are listed with their threat score.").setWrapText(true))
      .addWidget(CardService.newDecoratedText().setTopLabel("Step 3 — Understand").setText("Click any flagged email. PhishGuard auto-runs XAI to explain exactly why it is dangerous.").setWrapText(true))
  );

  return card.build();
}


// ═══════════════════════════════════════════════════════════════════
//  HOMEPAGE ACTION TRIGGERS
// ═══════════════════════════════════════════════════════════════════

function actionScan10(e) { return runInboxScan(10); }
function actionScan50(e) { return runInboxScan(50); }


// ═══════════════════════════════════════════════════════════════════
//  INBOX SCAN ENGINE
// ═══════════════════════════════════════════════════════════════════

function runInboxScan(count) {
  var threads = GmailApp.getInboxThreads(0, count);
  var flaggedThreads = [];
  var safeCount = 0;

  for (var i = 0; i < threads.length; i++) {
    var msg = threads[i].getMessages()[0];
    if (!msg) continue;

    var res = callFlaskModel(msg.getSubject(), msg.getPlainBody());

    if (!res.error && res.risk_tier === "PHISHING") {
      flaggedThreads.push({
        id:      threads[i].getId(),
        subject: msg.getSubject() || "(No Subject)"
      });
    } else {
      safeCount++;
    }
  }

  // Persist flagged IDs so contextual card can auto-scan them
  PropertiesService.getUserProperties().setProperty(
    "PHISHING_THREADS",
    JSON.stringify(flaggedThreads.map(function(t) { return t.id; }))
  );

  return buildScanResultsCard(count, flaggedThreads, safeCount);
}

function buildScanResultsCard(count, flaggedThreads, safeCount) {
  var phishingCount = flaggedThreads.length;
  var card = CardService.newCardBuilder();

  // ── Results Header ───────────────────────────────────────────────
  card.setHeader(
    CardService.newCardHeader()
      .setTitle("Scan Complete")
      .setSubtitle("Analysed " + count + " emails · " + new Date().toLocaleTimeString())
  );

  // ── Summary Stats ────────────────────────────────────────────────
  var summary = CardService.newCardSection().setHeader("Summary");
  summary.addWidget(
    CardService.newDecoratedText()
      .setTopLabel("✅  Safe")
      .setText(safeCount + " email" + (safeCount !== 1 ? "s" : ""))
      .setIcon(CardService.Icon.EMAIL)
  );
  summary.addWidget(
    CardService.newDecoratedText()
      .setTopLabel("🚨  Phishing")
      .setText(phishingCount + " email" + (phishingCount !== 1 ? "s" : ""))
      .setIcon(CardService.Icon.BOOKMARK)
  );
  card.addSection(summary);

  // ── Flagged List ─────────────────────────────────────────────────
  if (phishingCount > 0) {
    var listSection = CardService.newCardSection()
      .setHeader("⚠️  Flagged Emails — Click to open & auto-scan");

    for (var j = 0; j < flaggedThreads.length; j++) {
      var emailUrl = "https://mail.google.com/mail/u/0/#inbox/" + flaggedThreads[j].id;
      listSection.addWidget(
        CardService.newDecoratedText()
          .setText(flaggedThreads[j].subject)
          .setTopLabel("Suspicious · Tap to open")
          .setBottomLabel("PhishGuard will auto-scan when you open this email")
          .setWrapText(true)
          .setOpenLink(
            CardService.newOpenLink()
              .setUrl(emailUrl)
              .setOpenAs(CardService.OpenAs.FULL_SIZE)
              .setOnClose(CardService.OnClose.NOTHING)
          )
      );
    }
    card.addSection(listSection);
  } else {
    card.addSection(
      CardService.newCardSection()
        .addWidget(
          CardService.newTextParagraph()
            .setText("🎉  Great news! No phishing emails were detected in the scanned batch. Stay vigilant and feel free to run another scan anytime.")
        )
    );
  }

  // ── Back Button ──────────────────────────────────────────────────
  card.addSection(
    CardService.newCardSection()
      .addWidget(
        CardService.newButtonSet()
          .addButton(
            CardService.newTextButton()
              .setText("← Back to Home")
              .setOnClickAction(CardService.newAction().setFunctionName("buildHomepage"))
          )
      )
  );

  return card.build();
}


// ═══════════════════════════════════════════════════════════════════
//  CONTEXTUAL CARD  (opens when user reads an email)
// ═══════════════════════════════════════════════════════════════════

function buildContextualCard(e) {
  var threadId  = e.gmail.threadId;
  var messageId = e.gmail.messageId;

  // Check if this thread was flagged during a prior inbox scan
  var wasFlagged = false;
  try {
    var cached = PropertiesService.getUserProperties().getProperty("PHISHING_THREADS");
    if (cached) {
      wasFlagged = JSON.parse(cached).indexOf(threadId) > -1;
    }
  } catch (_) {}

  // Auto-scan flagged emails — no user click needed
  if (wasFlagged) {
    return scanCurrentEmail(e, true);
  }

  // Standard manual-scan card
  var card = CardService.newCardBuilder();

  card.setHeader(
    CardService.newCardHeader()
      .setTitle("PhishGuard")
      .setSubtitle("Ready to scan this email")
      .setImageStyle(CardService.ImageStyle.CIRCLE)
      .setImageUrl("https://www.gstatic.com/images/icons/material/system/2x/security_black_48dp.png")
  );

  card.addSection(
    CardService.newCardSection()
      .setHeader("Email Analysis")
      .addWidget(
        CardService.newDecoratedText()
          .setText("Run PhishGuard's full AI pipeline on this email: URL analysis, text classification, and Gemini-powered explanation.")
          .setTopLabel("What happens when you scan?")
          .setWrapText(true)
      )
      .addWidget(
        CardService.newButtonSet()
          .addButton(
            CardService.newTextButton()
              .setText("🔍  Scan This Email")
              .setOnClickAction(
                CardService.newAction()
                  .setFunctionName("scanCurrentEmail")
                  .setParameters({ messageId: messageId })
              )
              .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
              .setBackgroundColor("#d93025")
          )
      )
  );

  return card.build();
}


// ═══════════════════════════════════════════════════════════════════
//  SCAN ENGINE — core analysis
// ═══════════════════════════════════════════════════════════════════

function actionAnalyzeFromList(e) {
  return scanCurrentEmail(e, true);
}

function scanCurrentEmail(e, isAutoScan) {
  var messageId = (e.parameters && e.parameters.messageId)
                    ? e.parameters.messageId
                    : e.gmail.messageId;

  if (e.messageMetadata && e.messageMetadata.accessToken) {
    GmailApp.setCurrentMessageAccessToken(e.messageMetadata.accessToken);
  }

  var message = GmailApp.getMessageById(messageId);
  var subject  = message.getSubject()    || "";
  var body     = message.getPlainBody()  || "";
  var combined = "Subject: " + subject + "\n\n" + body;

  // ── 1. Flask ML Pipeline ─────────────────────────────────────────
  var result = callFlaskModel(subject, body);
  if (result.error) {
    return buildErrorCard(result.error);
  }

  var tier              = result.risk_tier;           // "PHISHING" | "SAFE"
  var confidence        = Math.round(result.risk_score * 100);
  var topSignals        = result.top_signals     || [];
  var story             = result.attack_story    || "";
  var campaignDetected  = result.campaign_detected || false;

  // ── 2. Gemini XAI (only for flagged emails) ──────────────────────
  var xaiExplanation;
  if (tier === "PHISHING") {
    xaiExplanation = getGeminiExplanation(combined);
  } else {
    xaiExplanation = "No phishing patterns were detected. The email's language, URLs, and structure all appear consistent with a legitimate message.";
  }

  return buildResultCard(tier, confidence, xaiExplanation, isAutoScan, topSignals, story, campaignDetected);
}


// ═══════════════════════════════════════════════════════════════════
//  FLASK API CALL
// ═══════════════════════════════════════════════════════════════════

function callFlaskModel(subject, body) {
  var options = {
    method:            "post",
    payload:           { subject: subject, body: body },
    muteHttpExceptions: true
  };

  try {
    var response = UrlFetchApp.fetch(NGROK_URL + "/predict/email", options);
    if (response.getResponseCode() === 200) {
      return JSON.parse(response.getContentText());
    }
    return { error: "Backend returned HTTP " + response.getResponseCode() };
  } catch (err) {
    return { error: "Could not reach the PhishGuard backend. Is LocalTunnel running?\n\n" + err.toString() };
  }
}


// ═══════════════════════════════════════════════════════════════════
//  GEMINI XAI
// ═══════════════════════════════════════════════════════════════════

function getGeminiExplanation(emailText) {
  var endpoint = "https://generativelanguage.googleapis.com/v1beta/models/gemini-3-flash-preview:generateContent?key=" + GEMINI_API_KEY;

  var prompt =
    "You are a cybersecurity expert writing for a non-technical user. " +
    "The following email was flagged as PHISHING by an AI pipeline. " +
    "Write exactly 3 bullet points explaining WHY this is a phishing email. " +
    "Each bullet should teach the reader one red flag (e.g. urgency, fake sender, suspicious link). " +
    "Use plain, simple language. Do NOT use markdown bold (**) or headers. Start each point with a dash (-).\n\n" +
    "Email:\n" + emailText.substring(0, 2000);

  var options = {
    method:            "post",
    contentType:       "application/json",
    payload:           JSON.stringify({ contents: [{ parts: [{ text: prompt }] }] }),
    muteHttpExceptions: true
  };

  try {
    var response = UrlFetchApp.fetch(endpoint, options);
    if (response.getResponseCode() === 200) {
      var data = JSON.parse(response.getContentText());
      if (data.candidates && data.candidates[0]) {
        return data.candidates[0].content.parts[0].text;
      }
    }
    return "XAI analysis unavailable (API error " + response.getResponseCode() + ").";
  } catch (err) {
    return "XAI analysis unavailable: " + err.toString();
  }
}


// ═══════════════════════════════════════════════════════════════════
//  RESULT CARD BUILDER
// ═══════════════════════════════════════════════════════════════════

function buildResultCard(tier, confidence, explanation, isAutoScan, signals, story, campaignDetected) {
  var isPhishing = (tier === "PHISHING");
  var card = CardService.newCardBuilder();

  // ── Header ───────────────────────────────────────────────────────
  var titlePrefix = isAutoScan ? "Auto-Scan · " : "";
  var titleEmoji  = isPhishing ? "🚨 " : "✅ ";
  var titleText   = titlePrefix + titleEmoji + (isPhishing ? "Phishing Detected" : "All Clear");
  var subtitleText = "Threat Score: " + confidence + "% · " + tier;

  card.setHeader(
    CardService.newCardHeader()
      .setTitle(titleText)
      .setSubtitle(subtitleText)
  );

  // ── Campaign Repeat Banner ────────────────────────────────────────
  if (campaignDetected) {
    card.addSection(
      CardService.newCardSection()
        .addWidget(
          CardService.newDecoratedText()
            .setText("This exact email fingerprint has been seen before in your inbox. This may be part of a coordinated phishing campaign targeting you repeatedly.")
            .setTopLabel("🔁  REPEAT CAMPAIGN DETECTED")
            .setWrapText(true)
        )
    );
  }

  // ── Threat Breakdown ─────────────────────────────────────────────
  if (story) {
    card.addSection(
      CardService.newCardSection()
        .setHeader("Threat Overview")
        .addWidget(
          CardService.newTextParagraph().setText(story)
        )
    );
  }

  // ── Model Indicators ─────────────────────────────────────────────
  if (signals && signals.length > 0) {
    var sigSection = CardService.newCardSection().setHeader("🔎  Risk Indicators");
    for (var i = 0; i < signals.length; i++) {
      sigSection.addWidget(
        CardService.newDecoratedText()
          .setText(signals[i])
          .setTopLabel("Signal " + (i + 1))
          .setWrapText(true)
      );
    }
    card.addSection(sigSection);
  }

  // ── Gemini XAI Explanation ────────────────────────────────────────
  card.addSection(
    CardService.newCardSection()
      .setHeader("🤖  Explainable AI (Gemini Analysis)")
      .addWidget(
        CardService.newTextParagraph().setText(explanation)
      )
  );

  // ── Feedback ─────────────────────────────────────────────────────
  card.addSection(
    CardService.newCardSection()
      .setHeader("Improve PhishGuard")
      .addWidget(
        CardService.newDecoratedText()
          .setText("Help tune the model by reporting incorrect predictions.")
          .setTopLabel("Was this analysis wrong?")
          .setWrapText(true)
      )
      .addWidget(
        CardService.newButtonSet()
          .addButton(
            CardService.newTextButton()
              .setText("⚑  Report False Prediction")
              .setOnClickAction(
                CardService.newAction()
                  .setFunctionName("reportFeedback")
                  .setParameters({ pred: tier })
              )
          )
      )
  );

  return card.build();
}


// ═══════════════════════════════════════════════════════════════════
//  FEEDBACK ACTION
// ═══════════════════════════════════════════════════════════════════

function reportFeedback(e) {
  var pred = e.parameters.pred;
  var msg  = (pred === "PHISHING")
               ? "Marked as false positive. Thank you for the feedback!"
               : "Marked as false negative. Thank you for the feedback!";
  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText(msg))
    .build();
}


// ═══════════════════════════════════════════════════════════════════
//  ERROR CARD
// ═══════════════════════════════════════════════════════════════════

function buildErrorCard(errorMessage) {
  return CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle("⚠️  Connection Error")
        .setSubtitle("Could not reach the PhishGuard backend")
    )
    .addSection(
      CardService.newCardSection()
        .setHeader("Troubleshooting")
        .addWidget(
          CardService.newDecoratedText()
            .setTopLabel("1. Start the Flask server")
            .setText("Run: python app.py  (inside phishing_models/)")
            .setWrapText(true)
        )
        .addWidget(
          CardService.newDecoratedText()
            .setTopLabel("2. Start LocalTunnel")
            .setText("Run: npx localtunnel --port 5000  — then update NGROK_URL in Code.gs")
            .setWrapText(true)
        )
        .addWidget(
          CardService.newDecoratedText()
            .setTopLabel("3. Error Details")
            .setText(errorMessage)
            .setWrapText(true)
        )
    )
    .build();
}
