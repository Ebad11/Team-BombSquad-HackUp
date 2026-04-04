/**
 * ═══════════════════════════════════════════════════════
 *  PhishGuard — AI-Powered Email Security Add-on
 *  by Team BombSquad
 * ═══════════════════════════════════════════════════════
 *  Update NGROK_URL each time you restart LocalTunnel.
 *  Run:  npx localtunnel --port 5000
 */

var NGROK_URL      = "https://real-humans-joke.loca.lt";
var GEMINI_API_KEY = "AIzaSyBACEAnBkQx-TxhOFERINsMrMfLPu9zxZk";

// ═══════════════════════════════════════════════════════════════════
//  HOMEPAGE
// ═══════════════════════════════════════════════════════════════════

function buildHomepage(e) {
  var card = CardService.newCardBuilder();

  card.setHeader(
    CardService.newCardHeader()
      .setTitle("PhishGuard")
      .setSubtitle("AI-Powered Email Security")
      .setImageStyle(CardService.ImageStyle.CIRCLE)
      .setImageUrl("https://www.gstatic.com/images/icons/material/system/2x/security_black_48dp.png")
  );

  // ── Live Stats from PropertiesService ────────────────────────────
  var stats = getUserStats();

  // ── IQ Rank helper ──────────────────────────────────────────────
  var iq        = stats.phishingIQ || 0;
  var iqAnswered = stats.iqAnswered || 0;
  var iqCorrect  = stats.iqCorrect  || 0;
  var iqRank;
  if (iq >= 20)      iqRank = "🏆 Security Expert";
  else if (iq >= 10) iqRank = "🥈 Phish Hunter";
  else if (iq >= 5)  iqRank = "🥉 Aware User";
  else               iqRank = "🎓 Beginner";

  card.addSection(
    CardService.newCardSection()
      .setHeader("📊 Your Threat Dashboard")
      .addWidget(
        CardService.newDecoratedText()
          .setTopLabel("Total Scans")
          .setText((stats.totalScans || 0) + " emails analysed")
          .setIcon(CardService.Icon.EMAIL)
      )
      .addWidget(
        CardService.newDecoratedText()
          .setTopLabel("Phishing Caught")
          .setText((stats.totalPhishing || 0) + " threats blocked")
          .setIcon(CardService.Icon.BOOKMARK)
      )
      .addWidget(
        CardService.newDecoratedText()
          .setTopLabel("Campaign Alerts")
          .setText((stats.campaignCount || 0) + " repeat campaigns detected")
          .setIcon(CardService.Icon.STAR)
      )
      .addWidget(
        CardService.newDecoratedText()
          .setTopLabel("Top Attack Type")
          .setText(stats.topAttackType || "No data yet")
          .setIcon(CardService.Icon.VIDEO_PLAY)
      )
  );

  // ── Phishing IQ Panel ─────────────────────────────────────────────
  card.addSection(
    CardService.newCardSection()
      .setHeader("🧠 Phishing IQ — " + iqRank)
      .addWidget(
        CardService.newDecoratedText()
          .setTopLabel("IQ Score")
          .setText(iq + " point" + (iq !== 1 ? "s" : ""))
          .setIcon(CardService.Icon.STAR)
      )
      .addWidget(
        CardService.newDecoratedText()
          .setTopLabel("Quiz Record")
          .setText(iqCorrect + " correct out of " + iqAnswered + " question" + (iqAnswered !== 1 ? "s" : ""))
          .setWrapText(true)
      )
      .addWidget(
        CardService.newTextParagraph()
          .setText("Complete Teach Me quizzes after scanning phishing emails to level up your Phishing IQ!")
      )
  );

  // ── Quick Scan Buttons ────────────────────────────────────────────
  card.addSection(
    CardService.newCardSection()
      .setHeader("Quick Scan")
      .addWidget(
        CardService.newTextParagraph()
          .setText("Run PhishGuard's 3-layer AI pipeline (XGBoost URL model + TF-IDF text classifier + DistilBERT) across your inbox.")
      )
      .addWidget(
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
      )
  );

  // ── How It Works (collapsible) ────────────────────────────────────
  card.addSection(
    CardService.newCardSection()
      .setHeader("How PhishGuard Works")
      .setCollapsible(true)
      .addWidget(CardService.newDecoratedText().setTopLabel("Layer 1 — URL XGBoost").setText("Every link in your email is scored by a 30-feature XGBoost model trained on real phishing datasets.").setWrapText(true))
      .addWidget(CardService.newDecoratedText().setTopLabel("Layer 2 — Text Classifier").setText("TF-IDF + Logistic Regression reads the email body for urgency, financial keywords, and social engineering phrases.").setWrapText(true))
      .addWidget(CardService.newDecoratedText().setTopLabel("Layer 3 — DistilBERT Neural").setText("A fine-tuned transformer model provides deep semantic understanding of the full email context.").setWrapText(true))
      .addWidget(CardService.newDecoratedText().setTopLabel("Layer 4 — Gemini XAI").setText("Google Gemini explains exactly why the email is dangerous in plain language so you can learn and stay safe.").setWrapText(true))
  );

  return card.build();
}


// ═══════════════════════════════════════════════════════════════════
//  HOMEPAGE ACTION TRIGGERS
// ═══════════════════════════════════════════════════════════════════

function actionScan10(e) { return runInboxScan(10); }
function actionScan50(e) { return runInboxScan(50); }


// ═══════════════════════════════════════════════════════════════════
//  FEATURE 2: PERSONAL THREAT INTELLIGENCE
//  Persists scan history in PropertiesService across sessions.
// ═══════════════════════════════════════════════════════════════════

function getUserStats() {
  var props = PropertiesService.getUserProperties();
  try {
    return JSON.parse(props.getProperty("PHISHGUARD_STATS") || "{}");
  } catch (_) { return {}; }
}

function updateUserStats(isPhishing, attackType, campaignDetected) {
  var props = PropertiesService.getUserProperties();
  var stats;
  try { stats = JSON.parse(props.getProperty("PHISHGUARD_STATS") || "{}"); }
  catch (_) { stats = {}; }

  stats.totalScans    = (stats.totalScans    || 0) + 1;
  stats.totalPhishing = (stats.totalPhishing || 0) + (isPhishing ? 1 : 0);
  stats.campaignCount = (stats.campaignCount || 0) + (campaignDetected ? 1 : 0);

  // Track attack type frequency
  if (isPhishing && attackType) {
    var freq = stats.attackFreq || {};
    freq[attackType] = (freq[attackType] || 0) + 1;
    stats.attackFreq = freq;

    // Determine most common attack type
    var topType = "Unknown";
    var topCount = 0;
    for (var t in freq) {
      if (freq[t] > topCount) { topCount = freq[t]; topType = t; }
    }
    stats.topAttackType = topType.replace(/-/g, " ").replace(/\b\w/g, function(c) { return c.toUpperCase(); });
  }

  props.setProperty("PHISHGUARD_STATS", JSON.stringify(stats));
}

// Called by submitQuizAnswer — updates IQ points and record
function updateIQScore(isCorrect) {
  var props = PropertiesService.getUserProperties();
  var stats;
  try { stats = JSON.parse(props.getProperty("PHISHGUARD_STATS") || "{}"); }
  catch (_) { stats = {}; }

  stats.iqAnswered  = (stats.iqAnswered  || 0) + 1;
  stats.iqCorrect   = (stats.iqCorrect   || 0) + (isCorrect ? 1 : 0);
  stats.phishingIQ  = (stats.phishingIQ  || 0) + (isCorrect ? 1 : 0);

  props.setProperty("PHISHGUARD_STATS", JSON.stringify(stats));
  return { iq: stats.phishingIQ, correct: stats.iqCorrect, answered: stats.iqAnswered };
}


// ═══════════════════════════════════════════════════════════════════
//  INBOX SCAN ENGINE
// ═══════════════════════════════════════════════════════════════════

function runInboxScan(count) {
  var threads      = GmailApp.getInboxThreads(0, count);
  var flagged      = [];
  var safeCount    = 0;

  for (var i = 0; i < threads.length; i++) {
    var msg = threads[i].getMessages()[0];
    if (!msg) continue;

    var res = callFlaskModel(msg.getSubject(), msg.getPlainBody());

    if (!res.error && res.risk_tier === "PHISHING") {
      flagged.push({
        id:          threads[i].getId(),
        subject:     msg.getSubject() || "(No Subject)",
        score:       Math.round((res.risk_score || 0) * 100),
        attackType:  res.attack_type  || "unknown",
        impact:      res.impact       || ""
      });
      // Update personal threat stats
      updateUserStats(true, res.attack_type, res.campaign_detected);
    } else {
      safeCount++;
      updateUserStats(false, null, false);
    }
  }

  // Persist flagged thread IDs for contextual card auto-scan
  PropertiesService.getUserProperties().setProperty(
    "PHISHING_THREADS",
    JSON.stringify(flagged.map(function(t) { return t.id; }))
  );

  return buildScanResultsCard(count, flagged, safeCount);
}

function buildScanResultsCard(count, flagged, safeCount) {
  var phishingCount = flagged.length;
  var card = CardService.newCardBuilder();

  card.setHeader(
    CardService.newCardHeader()
      .setTitle("Scan Complete")
      .setSubtitle("Analysed " + count + " emails · " + phishingCount + " threat" + (phishingCount !== 1 ? "s" : "") + " found")
  );

  // ── Summary Stats ────────────────────────────────────────────────
  var summary = CardService.newCardSection().setHeader("Results Summary");
  summary.addWidget(
    CardService.newDecoratedText()
      .setTopLabel("✅  Safe Emails")
      .setText(safeCount + " email" + (safeCount !== 1 ? "s" : "") + " — no threats detected")
      .setIcon(CardService.Icon.EMAIL)
  );
  summary.addWidget(
    CardService.newDecoratedText()
      .setTopLabel("🚨  Phishing Detected")
      .setText(phishingCount + " email" + (phishingCount !== 1 ? "s" : "") + " flagged")
      .setIcon(CardService.Icon.BOOKMARK)
  );
  card.addSection(summary);

  // ── Flagged List with inline threat scores ────────────────────────
  if (phishingCount > 0) {
    var listSection = CardService.newCardSection()
      .setHeader("⚠️  Flagged Emails — Open email to auto-scan");

    for (var j = 0; j < flagged.length; j++) {
      var t = flagged[j];
      var emailUrl = "https://mail.google.com/mail/u/0/#inbox/" + t.id;
      var attackLabel = t.attackType.replace(/-/g, " ").replace(/\b\w/g, function(c) { return c.toUpperCase(); });

      listSection.addWidget(
        CardService.newDecoratedText()
          .setText(t.subject)
          .setTopLabel("🚨 " + t.score + "% risk · " + attackLabel)
          .setBottomLabel(t.impact || "Open email · PhishGuard will auto-analyse")
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
            .setText("🎉  No phishing emails detected in this batch. Your inbox looks clean!")
        )
    );
  }

  // ── Navigation ───────────────────────────────────────────────────
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
//  CONTEXTUAL CARD (opens when user reads an email)
// ═══════════════════════════════════════════════════════════════════

function buildContextualCard(e) {
  var threadId  = e.gmail.threadId;
  var messageId = e.gmail.messageId;

  var wasFlagged = false;
  try {
    var cached = PropertiesService.getUserProperties().getProperty("PHISHING_THREADS");
    if (cached) {
      wasFlagged = JSON.parse(cached).indexOf(threadId) > -1;
    }
  } catch (_) {}

  if (wasFlagged) {
    return scanCurrentEmail(e, true);
  }

  var card = CardService.newCardBuilder();
  card.setHeader(
    CardService.newCardHeader()
      .setTitle("PhishGuard")
      .setSubtitle("Ready to analyse this email")
      .setImageStyle(CardService.ImageStyle.CIRCLE)
      .setImageUrl("https://www.gstatic.com/images/icons/material/system/2x/security_black_48dp.png")
  );

  card.addSection(
    CardService.newCardSection()
      .setHeader("On-Demand Analysis")
      .addWidget(
        CardService.newDecoratedText()
          .setText("Run all 4 layers of PhishGuard's AI pipeline on this specific email.")
          .setTopLabel("XGBoost + TF-IDF + DistilBERT + Gemini XAI")
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

  // ── Detect Attachments — offer Sandbox button if any exist ───────
  var hasAttachments = false;
  var attachmentNames = []; 
  try {
    if (e.messageMetadata && e.messageMetadata.accessToken) {
      GmailApp.setCurrentMessageAccessToken(e.messageMetadata.accessToken);
    }
    var msgPreview = GmailApp.getMessageById(messageId);
    var atts = msgPreview.getAttachments();
    if (atts && atts.length > 0) {
      hasAttachments = true;
      for (var ai = 0; ai < atts.length; ai++) {
        attachmentNames.push(atts[ai].getName() + " (" + atts[ai].getContentType() + ")");
      }
    }
  } catch (_) {}

  if (hasAttachments) {
    card.addSection(
      CardService.newCardSection()
        .setHeader("🧪  Attachment Sandbox")
        .addWidget(
          CardService.newDecoratedText()
            .setTopLabel(atts.length + " attachment" + (atts.length !== 1 ? "s" : "") + " detected")
            .setText(attachmentNames.join("\n"))
            .setWrapText(true)
        )
        .addWidget(
          CardService.newTextParagraph()
            .setText("Run static sandbox analysis: PhishGuard extracts URLs, scripts, and text from each attachment and runs them through the full AI pipeline — nothing is downloaded or executed on your device.")
        )
        .addWidget(
          CardService.newButtonSet()
            .addButton(
              CardService.newTextButton()
                .setText("🧪  Run Sandbox Analysis")
                .setOnClickAction(
                  CardService.newAction()
                    .setFunctionName("runSandboxAnalysis")
                    .setParameters({ messageId: messageId })
                )
                .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
                .setBackgroundColor("#7b1fa2")
            )
        )
    );
  }

  return card.build();
}


// ═══════════════════════════════════════════════════════════════════
//  FEATURE 6: ATTACHMENT SANDBOX SIMULATION
// ═══════════════════════════════════════════════════════════════════

/**
 * Reads all message attachments, sends them to the Flask backend
 * along with the email body, and shows a full Sandbox Report card.
 * Nothing is downloaded to the user's device.
 */
function runSandboxAnalysis(e) {
  var messageId = e.parameters.messageId;
  if (e.messageMetadata && e.messageMetadata.accessToken) {
    GmailApp.setCurrentMessageAccessToken(e.messageMetadata.accessToken);
  }

  var message = GmailApp.getMessageById(messageId);
  var subject = message.getSubject()   || "";
  var body    = message.getPlainBody() || "";
  var atts    = message.getAttachments();

  // ── Extract attachment metadata and readable text ──────────────
  var sandboxItems = [];
  var allExtractedText = body;

  for (var i = 0; i < atts.length; i++) {
    var att      = atts[i];
    var name     = att.getName();
    var mimeType = att.getContentType();
    var sizeKb   = Math.round(att.getSize() / 1024);
    var text     = "";
    var urls     = [];

    // Extract readable text from the attachment for static analysis
    try {
      if (mimeType.indexOf("text") !== -1 ||
          mimeType.indexOf("html") !== -1 ||
          name.match(/\.(txt|html|htm|eml|csv|xml)$/i)) {
        text = att.getDataAsString();
      } else {
        // For binary types, record that we cannot extract text
        text = "[Binary file — content extraction not supported in static analysis]";
      }
    } catch (_) {
      text = "[Could not read attachment content]";
    }

    // Extract URLs from the attachment text
    var urlMatches = text.match(/https?:\/\/[^\s"'<>]+/g) || [];
    urls = urlMatches.slice(0, 10); // cap at 10

    // Accumulate all text for the model call
    allExtractedText += "\n\n--- Attachment: " + name + " ---\n" + text.substring(0, 3000);

    // Check for suspicious patterns in the attachment text
    var suspiciousPatterns = [];
    var textLower = text.toLowerCase();
    if (/<script/i.test(text))                                  suspiciousPatterns.push("Embedded JavaScript detected");
    if (/powershell|cmd\.exe|shell\.application/i.test(text))  suspiciousPatterns.push("Shell command strings found");
    if (/eval\(|base64_decode|unescape\(/i.test(text))         suspiciousPatterns.push("Code obfuscation pattern found");
    if (textLower.indexOf("password") !== -1)                  suspiciousPatterns.push("Credential-harvesting phrases");
    if (textLower.indexOf("verify your account") !== -1)       suspiciousPatterns.push("Account verification phishing phrase");
    if (textLower.indexOf("click here") !== -1)                suspiciousPatterns.push("Social engineering CTA detected");
    if (urls.length > 3)                                        suspiciousPatterns.push(urls.length + " embedded URLs found");

    sandboxItems.push({
      name:     name,
      mimeType: mimeType,
      sizeKb:   sizeKb,
      urls:     urls,
      patterns: suspiciousPatterns,
      textSample: text.substring(0, 300)
    });
  }

  // ── Send to Flask backend for full AI analysis ────────────────
  var flaskResult = callFlaskModel(subject, allExtractedText);

  return buildSandboxReportCard(subject, sandboxItems, flaskResult);
}

/**
 * Builds a detailed Sandbox Report card displaying the static
 * analysis results for all attachments in the email.
 */
function buildSandboxReportCard(subject, sandboxItems, flaskResult) {
  var card = CardService.newCardBuilder();

  // ── Header ────────────────────────────────────────────────────
  var overallRisk  = (flaskResult && flaskResult.risk_tier) ? flaskResult.risk_tier : "UNKNOWN";
  var overallScore = (flaskResult && flaskResult.risk_score) ? Math.round(flaskResult.risk_score * 100) : 0;
  var titleEmoji   = (overallRisk === "PHISHING") ? "🚨" : "✅";

  card.setHeader(
    CardService.newCardHeader()
      .setTitle("🧪  Sandbox Analysis Report")
      .setSubtitle(titleEmoji + " Combined Risk: " + overallScore + "% · " + overallRisk)
  );

  // ── Methodology Note ───────────────────────────────────────
  card.addSection(
    CardService.newCardSection()
      .addWidget(
        CardService.newDecoratedText()
          .setTopLabel("Analysis Method: Static Sandbox (Layer 1)")
          .setText("Content extracted from " + sandboxItems.length + " attachment" + (sandboxItems.length !== 1 ? "s" : "") + " without downloading or executing. Embedded URLs, scripts, and text patterns analysed by XGBoost + TF-IDF + DistilBERT pipeline.")
          .setWrapText(true)
      )
  );

  // ── Per-attachment reports ─────────────────────────────────
  for (var i = 0; i < sandboxItems.length; i++) {
    var item    = sandboxItems[i];
    var hasSusp = item.patterns.length > 0;
    var fileRisk = hasSusp ? "⚠️ Suspicious" : "✅ Clean";

    var section = CardService.newCardSection()
      .setHeader("📎  File " + (i + 1) + " · " + fileRisk);

    section.addWidget(
      CardService.newDecoratedText()
        .setTopLabel("Filename · Type · Size")
        .setText(item.name + " · " + item.mimeType + " · " + item.sizeKb + " KB")
        .setWrapText(true)
    );

    if (item.patterns.length > 0) {
      section.addWidget(
        CardService.newDecoratedText()
          .setTopLabel("🚩  Suspicious patterns found")
          .setText(item.patterns.join("\n"))
          .setWrapText(true)
      );
    } else {
      section.addWidget(
        CardService.newDecoratedText()
          .setTopLabel("Pattern scan")
          .setText("No script injections, obfuscation, or phishing phrases detected.")
          .setWrapText(true)
      );
    }

    if (item.urls.length > 0) {
      var urlList = "";
      for (var u = 0; u < item.urls.length; u++) {
        urlList += (u + 1) + ". " + item.urls[u] + "\n";
      }
      section.addWidget(
        CardService.newDecoratedText()
          .setTopLabel("🔗  Embedded URLs (" + item.urls.length + ")")
          .setText(urlList.trim())
          .setWrapText(true)
      );
    } else {
      section.addWidget(
        CardService.newDecoratedText()
          .setTopLabel("Embedded URLs")
          .setText("None found.")
      );
    }

    card.addSection(section);
  }

  // ── Flask AI combined verdict ──────────────────────────────
  if (flaskResult && !flaskResult.error && flaskResult.top_signals) {
    var sigText = flaskResult.top_signals.join("\n");
    card.addSection(
      CardService.newCardSection()
        .setHeader("🤖  AI Combined Verdict (Email + Attachments)")
        .addWidget(
          CardService.newDecoratedText()
            .setTopLabel("Risk Tier · Score")
            .setText(overallRisk + " · " + overallScore + "% confidence")
        )
        .addWidget(
          CardService.newDecoratedText()
            .setTopLabel("Top AI Signals")
            .setText(sigText || "None")
            .setWrapText(true)
        )
    );
  }

  // ── Back button ──────────────────────────────────────────────
  card.addSection(
    CardService.newCardSection()
      .addWidget(
        CardService.newButtonSet()
          .addButton(
            CardService.newTextButton()
              .setText("🏠  Back to Home")
              .setOnClickAction(CardService.newAction().setFunctionName("buildHomepage"))
          )
      )
  );

  return card.build();
}


// ═══════════════════════════════════════════════════════════════════
//  SCAN ENGINE — core analysis with all bonus features
// ═══════════════════════════════════════════════════════════════════

function actionAnalyzeFromList(e) { return scanCurrentEmail(e, true); }

function scanCurrentEmail(e, isAutoScan) {
  var messageId = (e.parameters && e.parameters.messageId)
                    ? e.parameters.messageId
                    : e.gmail.messageId;

  if (e.messageMetadata && e.messageMetadata.accessToken) {
    GmailApp.setCurrentMessageAccessToken(e.messageMetadata.accessToken);
  }

  var message  = GmailApp.getMessageById(messageId);
  var subject  = message.getSubject()   || "";
  var body     = message.getPlainBody() || "";
  var sender   = message.getFrom()      || "";
  var combined = "Subject: " + subject + "\nFrom: " + sender + "\n\n" + body;

  // ── 1. Flask ML Pipeline ─────────────────────────────────────────
  var result = callFlaskModel(subject, body);
  if (result.error) {
    return buildErrorCard(result.error);
  }

  var tier             = result.risk_tier;
  var confidence       = Math.round((result.risk_score || 0) * 100);
  var topSignals       = result.top_signals          || [];
  var story            = result.attack_story         || "";
  var attackType       = result.attack_type          || "unknown";
  var impact           = result.impact               || "";
  var campaignDetected = result.campaign_detected    || false;
  var breakdown        = result.risk_breakdown       || {};
  var techDetails      = result.technical_details    || {};
  var urlResults       = techDetails.url_results     || [];

  // Update personal stats
  updateUserStats(tier === "PHISHING", attackType, campaignDetected);

  // ── 2. Feature 3: Sender Reputation check ────────────────────────
  var senderRep = checkSenderReputation(sender, tier === "PHISHING");

  // ── 3. Gemini XAI ────────────────────────────────────────────────
  var xaiExplanation;
  if (tier === "PHISHING") {
    xaiExplanation = getGeminiExplanation(combined, attackType, topSignals);
  } else {
    xaiExplanation = "No phishing patterns were detected. The email's language, URLs, and structure all appear consistent with a legitimate message.";
  }

  return buildResultCard({
    messageId:       messageId,
    tier:            tier,
    confidence:      confidence,
    xaiExplanation:  xaiExplanation,
    isAutoScan:      isAutoScan,
    topSignals:      topSignals,
    story:           story,
    attackType:      attackType,
    impact:          impact,
    campaignDetected: campaignDetected,
    breakdown:       breakdown,
    urlResults:      urlResults,
    senderRep:       senderRep,
    sender:          sender
  });
}


// ═══════════════════════════════════════════════════════════════════
//  FEATURE 3: SENDER REPUTATION TRACKER
//  Persists per-sender trust history across sessions.
// ═══════════════════════════════════════════════════════════════════

function checkSenderReputation(senderRaw, isPhishing) {
  var props = PropertiesService.getUserProperties();
  var repStore;
  try { repStore = JSON.parse(props.getProperty("SENDER_REP") || "{}"); }
  catch (_) { repStore = {}; }

  // Extract domain from sender e.g. "Name <user@domain.com>" → "domain.com"
  var domainMatch = senderRaw.match(/@([\w.\-]+)/);
  var domain = domainMatch ? domainMatch[1].toLowerCase() : senderRaw.toLowerCase();

  var record = repStore[domain] || { seen: 0, flagged: 0, firstSeen: new Date().toLocaleDateString() };
  record.seen++;
  if (isPhishing) record.flagged++;
  record.lastSeen = new Date().toLocaleDateString();
  repStore[domain] = record;

  props.setProperty("SENDER_REP", JSON.stringify(repStore));

  var trustLevel;
  if (record.flagged === 0)                          trustLevel = "✅ Trusted";
  else if (record.flagged === 1 && record.seen <= 2) trustLevel = "⚠️ Suspicious";
  else                                               trustLevel = "🚨 Known Bad Sender";

  return {
    domain:     domain,
    seen:       record.seen,
    flagged:    record.flagged,
    firstSeen:  record.firstSeen,
    lastSeen:   record.lastSeen,
    trustLevel: trustLevel
  };
}


// ═══════════════════════════════════════════════════════════════════
//  FLASK API CALL
// ═══════════════════════════════════════════════════════════════════

function callFlaskModel(subject, body) {
  var options = {
    method:             "post",
    payload:            { subject: subject, body: body },
    muteHttpExceptions: true
  };
  try {
    var response = UrlFetchApp.fetch(NGROK_URL + "/predict/email", options);
    if (response.getResponseCode() === 200) {
      return JSON.parse(response.getContentText());
    }
    return { error: "Backend returned HTTP " + response.getResponseCode() };
  } catch (err) {
    return { error: "Could not reach the PhishGuard backend.\n\n" + err.toString() };
  }
}


// ═══════════════════════════════════════════════════════════════════
//  GEMINI XAI — context-aware prompt using attack type and signals
// ═══════════════════════════════════════════════════════════════════

function getGeminiExplanation(emailText, attackType, signals) {
  var endpoint = "https://generativelanguage.googleapis.com/v1beta/models/gemini-3-flash-preview:generateContent?key=" + GEMINI_API_KEY;

  var signalNote = signals.length > 0
    ? "Our models flagged these red flags: " + signals.join(", ") + ". "
    : "";

  var prompt =
    "You are a cybersecurity expert writing for a non-technical user. " +
    "The following email was classified as a '" + attackType + "' phishing attack by an AI pipeline. " +
    signalNote +
    "Write exactly 3 bullet points explaining WHY this is a phishing email and what the attacker is trying to do. " +
    "Each bullet should teach the reader one specific red flag. " +
    "Use plain, simple language. Do NOT use markdown bold (**). Start each point with a dash (-).\n\n" +
    "Email:\n" + emailText.substring(0, 2000);

  var options = {
    method:             "post",
    contentType:        "application/json",
    payload:            JSON.stringify({ contents: [{ parts: [{ text: prompt }] }] }),
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
//  FEATURE 7: AI-GENERATED PHISHING DETECTION
//  Uses Gemini to detect LLM fingerprints in the email.
//  Score is INDEPENDENT — does NOT influence phishing risk.
// ═══════════════════════════════════════════════════════════════════

function buildAIFingerprintCard(e) {
  var messageId = e.parameters.messageId;
  if (e.messageMetadata && e.messageMetadata.accessToken) {
    GmailApp.setCurrentMessageAccessToken(e.messageMetadata.accessToken);
  }
  var message  = GmailApp.getMessageById(messageId);
  var subject  = message.getSubject()   || "";
  var body     = message.getPlainBody() || "";
  var sender   = message.getFrom()      || "";
  var combined = "Subject: " + subject + "\nFrom: " + sender + "\n\n" + body;

  var ai = detectAIGeneration(combined);
  var aiScore   = ai.ai_score || 0;
  var aiFingers = ai.fingerprints || [];
  var aiEmoji   = aiScore >= 70 ? "🤖" : aiScore >= 40 ? "⚠️" : "✅";
  var aiLabel   = aiScore >= 70 ? "Likely AI-Generated"
                : aiScore >= 40 ? "Possibly AI-Assisted"
                : "Likely Human-Written";

  var card = CardService.newCardBuilder();
  card.setHeader(
    CardService.newCardHeader()
      .setTitle("🤖 LLM Fingerprint Result")
      .setSubtitle(aiEmoji + "  " + aiScore + "% — " + aiLabel)
  );

  var aiSection = CardService.newCardSection()
    .addWidget(
      CardService.newDecoratedText()
        .setTopLabel("⚠️  This score does NOT affect the Phishing Risk Score")
        .setText("It measures independently whether the email content appears to be machine-generated, which is increasingly common in sophisticated phishing campaigns.")
        .setWrapText(true)
    );

  if (aiFingers.length > 0) {
    var fingerText = "";
    for (var fi = 0; fi < aiFingers.length; fi++) {
      fingerText += "• " + aiFingers[fi] + "\n";
    }
    aiSection.addWidget(
      CardService.newDecoratedText()
        .setTopLabel("LLM Fingerprints Detected")
        .setText(fingerText.trim())
        .setWrapText(true)
    );
  } else {
    aiSection.addWidget(
      CardService.newTextParagraph()
        .setText("No distinct LLM writing patterns detected.")
    );
  }
  
  aiSection.addWidget(
    CardService.newButtonSet()
      .addButton(
        CardService.newTextButton()
          .setText("🏠  Back to Home")
          .setOnClickAction(CardService.newAction().setFunctionName("buildHomepage"))
      )
  );

  card.addSection(aiSection);
  return card.build();
}

function detectAIGeneration(emailText) {
  var endpoint = "https://generativelanguage.googleapis.com/v1beta/models/gemini-3-flash-preview:generateContent?key=" + GEMINI_API_KEY;

  var prompt =
    "You are an AI text detection expert specialising in identifying LLM-generated phishing emails. " +
    "Analyse the following email text and estimate the probability (0-100) that it was written by an AI/LLM (such as GPT, Gemini, or Claude). " +
    "Look specifically for these LLM fingerprints:\n" +
    "- Unnaturally flawless grammar and punctuation with zero typos\n" +
    "- Generic formal salutations ('Dear valued customer', 'Dear user')\n" +
    "- Polite urgency contradiction (threatening tone delivered very formally)\n" +
    "- LLM-typical transition phrases ('Please note that', 'Rest assured', 'We kindly request', 'Please be advised')\n" +
    "- Uniform sentence complexity with no human 'messiness' or colloquialisms\n" +
    "- Perfectly structured paragraphs with balanced length\n" +
    "- Overly diplomatic threat language\n" +
    "- Brand impersonation that is syntactically perfect but feels generic\n\n" +
    "Return ONLY valid JSON with no markdown, no code fences: " +
    "{\"ai_score\": 85, \"fingerprints\": [\"Unnaturally perfect grammar\", \"LLM phrase: 'Please note that'\", \"Polite urgency contradiction\"]}\n\n" +
    "Email:\n" + emailText.substring(0, 2500);

  var options = {
    method:             "post",
    contentType:        "application/json",
    payload:            JSON.stringify({ contents: [{ parts: [{ text: prompt }] }] }),
    muteHttpExceptions: true
  };

  try {
    var response = UrlFetchApp.fetch(endpoint, options);
    if (response.getResponseCode() === 200) {
      var data = JSON.parse(response.getContentText());
      if (data.candidates && data.candidates[0]) {
        var raw = data.candidates[0].content.parts[0].text.trim();
        raw = raw.replace(/^```[a-z]*\n?/i, "").replace(/```$/i, "").trim();
        return JSON.parse(raw);
      }
    }
  } catch (_) {}

  // Fallback: heuristic-only score if Gemini fails
  return _heuristicAIScore(emailText);
}

/** Lightweight heuristic fallback if Gemini is unavailable. */
function _heuristicAIScore(text) {
  var score       = 0;
  var fingerprints = [];
  var t = text.toLowerCase();

  var llmPhrases = [
    ["please note that",       "LLM phrase: 'Please note that'"],
    ["rest assured",           "LLM phrase: 'Rest assured'"],
    ["we kindly request",      "LLM phrase: 'We kindly request'"],
    ["please be advised",      "LLM phrase: 'Please be advised'"],
    ["dear valued",            "Generic salutation: 'Dear valued...'"],
    ["dear user",              "Generic salutation: 'Dear user'"],
    ["dear customer",          "Generic salutation: 'Dear customer'"],
    ["your account has been",  "Formal account-threat phrasing"],
    ["immediate action",       "Formal urgency phrasing"],
    ["failure to comply",      "Polite threat phrasing"],
  ];

  for (var i = 0; i < llmPhrases.length; i++) {
    if (t.indexOf(llmPhrases[i][0]) !== -1) {
      score += 10;
      fingerprints.push(llmPhrases[i][1]);
    }
  }

  // Penalise very short text (AI tends to write complete paragraphs)
  if (text.length < 100) score = Math.max(0, score - 20);

  return { ai_score: Math.min(score, 95), fingerprints: fingerprints };
}


// ═══════════════════════════════════════════════════════════════════
//  RESULT CARD — all features surfaced here
// ═══════════════════════════════════════════════════════════════════

function buildResultCard(d) {
  var isPhishing = (d.tier === "PHISHING");
  var card = CardService.newCardBuilder();

  // ── Header ───────────────────────────────────────────────────────
  var prefix = d.isAutoScan ? "Auto-Scan · " : "";
  card.setHeader(
    CardService.newCardHeader()
      .setTitle(prefix + (isPhishing ? "🚨 Phishing Detected" : "✅ All Clear"))
      .setSubtitle("Threat Score: " + d.confidence + "% · " + d.tier)
  );

  // ── Campaign Banner ───────────────────────────────────────────────
  if (d.campaignDetected) {
    card.addSection(
      CardService.newCardSection()
        .addWidget(
          CardService.newDecoratedText()
            .setTopLabel("🔁  REPEAT CAMPAIGN DETECTED")
            .setText("This exact email fingerprint has been seen before. You are being targeted repeatedly by the same campaign.")
            .setWrapText(true)
        )
    );
  }

  // ── FEATURE 3: Sender Reputation ─────────────────────────────────
  if (d.senderRep) {
    var rep = d.senderRep;
    card.addSection(
      CardService.newCardSection()
        .setHeader("👤  Sender Reputation — " + rep.trustLevel)
        .addWidget(
          CardService.newDecoratedText()
            .setTopLabel("Domain")
            .setText(rep.domain)
            .setIcon(CardService.Icon.EMAIL)
        )
        .addWidget(
          CardService.newDecoratedText()
            .setTopLabel("History")
            .setText("Seen " + rep.seen + " time" + (rep.seen !== 1 ? "s" : "") + " · " + rep.flagged + " flagged as phishing")
            .setWrapText(true)
        )
        .addWidget(
          CardService.newDecoratedText()
            .setTopLabel("First seen · Last seen")
            .setText(rep.firstSeen + " · " + rep.lastSeen)
        )
    );
  }

  // ── FEATURE 2: Multi-Layer Score Breakdown ────────────────────────
  if (d.breakdown && (d.breakdown.url || d.breakdown.text || d.breakdown.attachment)) {
    var urlPct  = Math.round((d.breakdown.url        || 0) * 100);
    var textPct = Math.round((d.breakdown.text       || 0) * 100);
    var attPct  = Math.round((d.breakdown.attachment || 0) * 100);

    card.addSection(
      CardService.newCardSection()
        .setHeader("📊  AI Score Breakdown (Weighted)")
        .addWidget(
          CardService.newDecoratedText()
            .setTopLabel("Layer 1 — URL XGBoost Model  (40% weight)")
            .setText(urlPct + "% phishing confidence")
            .setIcon(CardService.Icon.STAR)
        )
        .addWidget(
          CardService.newDecoratedText()
            .setTopLabel("Layer 2 — Text Classifier  (30% weight)")
            .setText(textPct + "% phishing confidence")
            .setIcon(CardService.Icon.STAR)
        )
        .addWidget(
          CardService.newDecoratedText()
            .setTopLabel("Layer 3 — Attachment Scanner  (5% weight)")
            .setText(attPct > 0 ? attPct + "% phishing confidence" : "No attachments detected")
            .setIcon(CardService.Icon.STAR)
        )
    );
  }

  // ── FEATURE 7: AI-Generated Phishing Detection Button ────────────────
  if (d.messageId) {
    card.addSection(
      CardService.newCardSection()
        .setHeader("🤖  LLM Fingerprint Detection")
        .addWidget(
          CardService.newDecoratedText()
            .setText("Check if this email was generated by an AI (like ChatGPT or Gemini). This is an independent analysis and does NOT affect the phishing risk score.")
            .setWrapText(true)
        )
        .addWidget(
          CardService.newButtonSet()
            .addButton(
              CardService.newTextButton()
                .setText("🕵️  Scan for AI Fingerprints")
                .setOnClickAction(
                  CardService.newAction()
                    .setFunctionName("buildAIFingerprintCard")
                    .setParameters({ messageId: d.messageId })
                )
                .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
                .setBackgroundColor("#00796b")
            )
        )
    );
  }

  // ── FEATURE 1: Per-URL Threat Breakdown ──────────────────────────
  if (d.urlResults && d.urlResults.length > 0) {
    var urlSection = CardService.newCardSection()
      .setHeader("🔗  URL-by-URL Threat Analysis (" + d.urlResults.length + " link" + (d.urlResults.length !== 1 ? "s" : "") + " found)");

    for (var i = 0; i < Math.min(d.urlResults.length, 5); i++) {
      var u         = d.urlResults[i];
      var uScore    = Math.round((u.phishing_prob || 0) * 100);
      var xgbScore  = u.xgb_prob != null ? Math.round(u.xgb_prob * 100) + "% XGB" : "N/A";
      var lrScore   = u.lr_prob  != null ? Math.round(u.lr_prob  * 100) + "% LR"  : "N/A";
      var urlLabel  = u.url || "Unknown URL";
      var urlShort  = urlLabel.length > 55 ? urlLabel.substring(0, 52) + "..." : urlLabel;
      var urlEmoji  = uScore >= 70 ? "🚨" : uScore >= 40 ? "⚠️" : "✅";

      urlSection.addWidget(
        CardService.newDecoratedText()
          .setTopLabel(urlEmoji + " " + uScore + "% risk  ·  " + xgbScore + "  ·  " + lrScore)
          .setText(urlShort)
          .setWrapText(true)
      );

      // Show URL-specific signals if any
      if (u.signals && u.signals.length > 0) {
        urlSection.addWidget(
          CardService.newTextParagraph()
            .setText("   └ " + u.signals.join(" · "))
        );
      }
    }

    if (d.urlResults.length > 5) {
      urlSection.addWidget(
        CardService.newTextParagraph()
          .setText("... and " + (d.urlResults.length - 5) + " more URLs analysed.")
      );
    }

    card.addSection(urlSection);
  }

  // ── Threat Overview ───────────────────────────────────────────────
  if (d.story) {
    var attackLabel = d.attackType.replace(/-/g, " ").replace(/\b\w/g, function(c) { return c.toUpperCase(); });
    card.addSection(
      CardService.newCardSection()
        .setHeader("🎯  Attack Classification: " + attackLabel)
        .addWidget(CardService.newTextParagraph().setText(d.story))
    );
  }

  // ── Top Model Signals ─────────────────────────────────────────────
  if (d.topSignals && d.topSignals.length > 0) {
    var sigSection = CardService.newCardSection().setHeader("🔎  Top Risk Indicators");
    for (var k = 0; k < d.topSignals.length; k++) {
      sigSection.addWidget(
        CardService.newDecoratedText()
          .setTopLabel("Indicator " + (k + 1))
          .setText(d.topSignals[k])
          .setWrapText(true)
      );
    }
    card.addSection(sigSection);
  }

  // ── FEATURE 4: One-Click Abuse Report ────────────────────────────
  if (isPhishing) {
    var reportUrl = "https://mail.google.com/mail/u/0/?view=cm&fs=1" +
                    "&to=reportphishing%40google.com" +
                    "&su=" + encodeURIComponent("[PHISHING REPORT] " + (d.story || "Phishing email detected")) +
                    "&body=" + encodeURIComponent(
                        "I received a phishing email.\n\n" +
                        "PhishGuard Risk Score: " + d.confidence + "%\n" +
                        "Attack Type: " + d.attackType + "\n" +
                        "Top Signals: " + (d.topSignals || []).join(", ") + "\n\n" +
                        "Please investigate this sender."
                    );

    card.addSection(
      CardService.newCardSection()
        .setHeader("🚨  Take Action")
        .addWidget(
          CardService.newTextParagraph()
            .setText("Report this phishing email directly to Google's security team with one click. Your report helps protect everyone.")
        )
        .addWidget(
          CardService.newButtonSet()
            .addButton(
              CardService.newTextButton()
                .setText("📢  Report to Google")
                .setOpenLink(
                  CardService.newOpenLink()
                    .setUrl(reportUrl)
                    .setOpenAs(CardService.OpenAs.FULL_SIZE)
                    .setOnClose(CardService.OnClose.NOTHING)
                )
            )
        )
    );
  }

  // ── Gemini XAI ────────────────────────────────────────────────────
  card.addSection(
    CardService.newCardSection()
      .setHeader("🤖  Gemini Explainable AI")
      .addWidget(CardService.newTextParagraph().setText(d.xaiExplanation))
  );

  // ── FEATURE 5: Teach Me Mode ──────────────────────────────────────
  if (isPhishing && d.topSignals && d.topSignals.length >= 2) {
    card.addSection(
      CardService.newCardSection()
        .setHeader("🧠  Test Your Knowledge — Teach Me Mode")
        .addWidget(
          CardService.newDecoratedText()
            .setTopLabel("Phishing IQ Challenge")
            .setText("Ready to test what you just learned? PhishGuard will quiz you on the red flags in this email. Correct answer = +1 IQ point!")
            .setWrapText(true)
        )
        .addWidget(
          CardService.newButtonSet()
            .addButton(
              CardService.newTextButton()
                .setText("🎓  Start Quiz")
                .setOnClickAction(
                  CardService.newAction()
                    .setFunctionName("buildQuizCard")
                    .setParameters({
                      signals:    JSON.stringify(d.topSignals),
                      attackType: d.attackType || "phishing"
                    })
                )
                .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
                .setBackgroundColor("#1a73e8")
            )
        )
    );
  }

  // ── Feedback ─────────────────────────────────────────────────────
  card.addSection(
    CardService.newCardSection()
      .setHeader("Help Improve PhishGuard")
      .addWidget(
        CardService.newDecoratedText()
          .setText("Help tune the model by flagging incorrect predictions.")
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
                  .setParameters({ pred: d.tier })
              )
          )
      )
  );

  return card.build();
}


// ═══════════════════════════════════════════════════════════════════
//  FEATURE 5: TEACH ME MODE — QUIZ ENGINE
// ═══════════════════════════════════════════════════════════════════

/**
 * Calls Gemini to generate a 3-option multiple choice quiz from the
 * email's top signals. Stores quiz data in PropertiesService so the
 * answer buttons can retrieve the correct answer.
 */
function buildQuizCard(e) {
  var signals    = [];
  var attackType = "phishing";
  try {
    signals    = JSON.parse(e.parameters.signals || "[]");
    attackType = e.parameters.attackType || "phishing";
  } catch (_) {}

  // Generate quiz via Gemini
  var quiz = getGeminiQuiz(signals, attackType);

  if (!quiz || !quiz.options || quiz.options.length < 3) {
    // Fallback if Gemini fails: build quiz from signals directly
    quiz = buildFallbackQuiz(signals);
  }

  // Persist correct answer so we can retrieve it in submitQuizAnswer
  PropertiesService.getUserProperties().setProperty(
    "QUIZ_CORRECT", String(quiz.correctIndex)
  );

  var card = CardService.newCardBuilder();
  card.setHeader(
    CardService.newCardHeader()
      .setTitle("🧠  Phishing IQ Quiz")
      .setSubtitle("Choose the biggest red flag")
  );

  var stats = getUserStats();
  card.addSection(
    CardService.newCardSection()
      .addWidget(
        CardService.newDecoratedText()
          .setTopLabel("Your current IQ score")
          .setText((stats.phishingIQ || 0) + " point" + ((stats.phishingIQ || 0) !== 1 ? "s" : ""))
          .setIcon(CardService.Icon.STAR)
      )
  );

  var qSection = CardService.newCardSection()
    .setHeader(quiz.question);

  for (var i = 0; i < quiz.options.length; i++) {
    qSection.addWidget(
      CardService.newButtonSet()
        .addButton(
          CardService.newTextButton()
            .setText(quiz.options[i])
            .setOnClickAction(
              CardService.newAction()
                .setFunctionName("submitQuizAnswer")
                .setParameters({ chosen: String(i) })
            )
        )
    );
  }

  card.addSection(qSection);
  return card.build();
}

/** Uses Gemini to produce a 3-option quiz JSON from the email signals. */
function getGeminiQuiz(signals, attackType) {
  var endpoint = "https://generativelanguage.googleapis.com/v1beta/models/gemini-3-flash-preview:generateContent?key=" + GEMINI_API_KEY;

  var signalList = signals.join("; ");
  var prompt =
    "You are building a phishing awareness quiz. " +
    "A user just received a '" + attackType + "' phishing email. " +
    "The AI detected these red flags: " + signalList + ". " +
    "Create one multiple-choice question: 'Which of these is the BIGGEST red flag that reveals this is phishing?' " +
    "Provide exactly 3 answer options. Make one option the real critical red flag. " +
    "Make the other two sound plausible but be less significant or slightly incorrect. " +
    "Return ONLY valid JSON in this exact format, no markdown, no code block: " +
    "{\"question\": \"Which of these is the biggest red flag?\", \"options\": [\"A. ...\", \"B. ...\", \"C. ...\"], \"correctIndex\": 0}";

  var options = {
    method:             "post",
    contentType:        "application/json",
    payload:            JSON.stringify({ contents: [{ parts: [{ text: prompt }] }] }),
    muteHttpExceptions: true
  };

  try {
    var response = UrlFetchApp.fetch(endpoint, options);
    if (response.getResponseCode() === 200) {
      var data = JSON.parse(response.getContentText());
      if (data.candidates && data.candidates[0]) {
        var raw = data.candidates[0].content.parts[0].text.trim();
        // Strip any accidental markdown code fences
        raw = raw.replace(/^```[a-z]*\n?/i, "").replace(/```$/i, "").trim();
        return JSON.parse(raw);
      }
    }
  } catch (_) {}
  return null;
}

/** Fallback quiz built directly from signals (no Gemini needed). */
function buildFallbackQuiz(signals) {
  var correct = signals[0] || "Suspicious URL detected";
  var decoys  = [
    "The email was sent on a weekend",
    "The email had an unusual font"
  ];
  return {
    question:     "Which of these is the biggest red flag?",
    options:      ["A. " + correct, "B. " + decoys[0], "C. " + decoys[1]],
    correctIndex: 0
  };
}

/** Handles the user's quiz answer — awards IQ and shows result. */
function submitQuizAnswer(e) {
  var chosen  = parseInt(e.parameters.chosen  || "0", 10);
  var correct = parseInt(
    PropertiesService.getUserProperties().getProperty("QUIZ_CORRECT") || "0", 10
  );

  var isCorrect = (chosen === correct);
  var updated   = updateIQScore(isCorrect);

  var card = CardService.newCardBuilder();

  if (isCorrect) {
    card.setHeader(
      CardService.newCardHeader()
        .setTitle("✅  Correct! +1 IQ Point")
        .setSubtitle("Your Phishing IQ: " + updated.iq + " points")
    );
    card.addSection(
      CardService.newCardSection()
        .addWidget(
          CardService.newTextParagraph()
            .setText("Great job! You correctly identified the biggest red flag. You're getting better at spotting phishing attacks. Keep scanning to level up!")
        )
    );
  } else {
    card.setHeader(
      CardService.newCardHeader()
        .setTitle("❌  Not Quite")
        .setSubtitle("Your Phishing IQ: " + updated.iq + " points — keep practising!")
    );
    card.addSection(
      CardService.newCardSection()
        .addWidget(
          CardService.newTextParagraph()
            .setText("That wasn't the primary red flag this time. Review the Gemini XAI explanation above to understand the key signals — you'll recognise them faster next time!")
        )
    );
  }

  card.addSection(
    CardService.newCardSection()
      .addWidget(
        CardService.newDecoratedText()
          .setTopLabel("Quiz Record")
          .setText(updated.correct + " correct out of " + updated.answered + " question" + (updated.answered !== 1 ? "s" : ""))
          .setWrapText(true)
      )
      .addWidget(
        CardService.newButtonSet()
          .addButton(
            CardService.newTextButton()
              .setText("🏠  Back to Home")
              .setOnClickAction(CardService.newAction().setFunctionName("buildHomepage"))
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
               ? "Marked as false positive — thank you!"
               : "Marked as false negative — thank you!";
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
        .setSubtitle("PhishGuard backend unreachable")
    )
    .addSection(
      CardService.newCardSection()
        .setHeader("Troubleshooting Steps")
        .addWidget(CardService.newDecoratedText().setTopLabel("Step 1").setText("Run: python app.py  (in phishing_models/)").setWrapText(true))
        .addWidget(CardService.newDecoratedText().setTopLabel("Step 2").setText("Run: npx localtunnel --port 5000  — copy the URL into NGROK_URL in Code.gs").setWrapText(true))
        .addWidget(CardService.newDecoratedText().setTopLabel("Step 3 — Error details").setText(errorMessage).setWrapText(true))
    )
    .build();
}
