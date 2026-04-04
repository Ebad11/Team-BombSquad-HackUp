chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === "SHOW_WARNING") {
    if (document.getElementById("phishing-banner")) return;

    const banner = document.createElement("div");
    banner.id = "phishing-banner";
    
    // Create rich UI
    banner.style.position = "fixed";
    banner.style.top = "0";
    banner.style.left = "0";
    banner.style.width = "100%";
    banner.style.backgroundColor = "#ff3b30";
    banner.style.color = "white";
    banner.style.fontSize = "16px";
    banner.style.fontFamily = "system-ui, -apple-system, sans-serif";
    banner.style.padding = "15px";
    banner.style.zIndex = "2147483647"; // Max z-index
    banner.style.textAlign = "center";
    banner.style.boxShadow = "0px 4px 10px rgba(0,0,0,0.3)";

    const title = document.createElement("h2");
    title.style.margin = "0 0 10px 0";
    title.style.fontSize = "22px";
    title.innerText = `⚠️ Danger: Malicious Site Detected! (Risk Score: ${msg.risk_score}%)`;
    
    const subtitle = document.createElement("p");
    subtitle.style.margin = "0 0 10px 0";
    subtitle.style.fontSize = "16px";
    subtitle.innerText = "We strongly recommend you close this tab. The following risks were identified:";

    const reasonsList = document.createElement("ul");
    reasonsList.style.listStyleType = "none";
    reasonsList.style.padding = "0";
    reasonsList.style.margin = "0 0 15px 0";
    reasonsList.style.display = "inline-block";
    reasonsList.style.textAlign = "left";

    const reasons = msg.reasons && msg.reasons.length > 0 ? msg.reasons : ["Suspicious domain characteristics"];
    for (const reason of reasons) {
      const li = document.createElement("li");
      li.style.margin = "5px 0";
      li.style.fontSize = "15px";
      li.innerText = `• ${reason}`;
      reasonsList.appendChild(li);
    }
    
    const proceedBtn = document.createElement("button");
    proceedBtn.innerText = "I understand the risks, hide warning";
    proceedBtn.style.padding = "8px 16px";
    proceedBtn.style.backgroundColor = "transparent";
    proceedBtn.style.color = "white";
    proceedBtn.style.border = "1px solid white";
    proceedBtn.style.borderRadius = "4px";
    proceedBtn.style.cursor = "pointer";
    proceedBtn.onclick = () => banner.remove();

    banner.appendChild(title);
    banner.appendChild(subtitle);
    banner.appendChild(reasonsList);
    banner.appendChild(document.createElement("br"));
    banner.appendChild(proceedBtn);

    // Ensure document.body exists, which might not be true PRE-LOAD
    if (document.body) {
      document.body.prepend(banner);
    } else {
      document.addEventListener("DOMContentLoaded", () => {
        if (!document.getElementById("phishing-banner")) {
          document.body.prepend(banner);
        }
      });
    }
  }
});