console.log("🔥 Background script started");

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  console.log("Tab updated event fired");

  if (changeInfo.status === "complete" && tab.url) {

    console.log("Checking URL:", tab.url);

    fetch("http://127.0.0.1:5000/predict/url", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ url: tab.url })
    })
    .then(res => res.json())
    .then(data => {
      console.log("Prediction:", data);

      if (data.prediction === "phishing") {
        chrome.tabs.sendMessage(tabId, {
        type: "SHOW_WARNING",
        confidence: data.confidence
      });
      }
    })
    .catch(err => console.error("Error:", err));
  }
});