console.log("🔥 Background script started");

const checkCache = new Map();

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return; // Only top-level frames

  const url = details.url;
  // Ignore chrome:// and other internal URLs
  if (!url.startsWith('http')) return;

  const now = Date.now();
  if (checkCache.has(url) && (now - checkCache.get(url).timestamp < 60000)) {
    handleResult(details.tabId, checkCache.get(url).data, url);
    return;
  }

  console.log("Checking URL preemptively:", url);

  try {
    const res = await fetch("http://127.0.0.1:5001/predict/url", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url })
    });
    const data = await res.json();
    console.log("Prediction:", data);
    
    checkCache.set(url, { timestamp: now, data: data });
    handleResult(details.tabId, data, url);
  } catch (err) {
    console.error("Error:", err);
  }
});

function handleResult(tabId, data, url) {
  if (data.is_phishing || data.prediction === "phishing") {
    // Attempt to execute a dummy script. If it fails, we are on a chrome-error:// 
    // or strongly restricted page, so we forcibly redirect to our own Warning page.
    chrome.scripting.executeScript({
      target: { tabId: tabId },
      func: () => true
    }).then(() => {
      // Injection succeeded! Send the message to the content script to show overlay.
      chrome.tabs.sendMessage(tabId, {
        type: "SHOW_WARNING",
        confidence: data.confidence,
        risk_score: data.risk_score || data.confidence,
        reasons: data.reasons || []
      });
    }).catch((err) => {
      // Injection blocked. This happens precisely on NXDOMAIN / Safe Browsing screens.
      // Redirect to the internal extension blocked.html page
      const blockedUrl = chrome.runtime.getURL(`blocked.html?url=${encodeURIComponent(url)}&risk=${data.risk_score || data.confidence}`);
      chrome.tabs.update(tabId, { url: blockedUrl });
    });
  }
}