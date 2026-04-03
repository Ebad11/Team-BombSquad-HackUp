chrome.runtime.onMessage.addListener((msg) => {

  if (msg.type === "SHOW_WARNING") {

    if (document.getElementById("phishing-banner")) return;

    const banner = document.createElement("div");
    banner.id = "phishing-banner";

    banner.innerText =
      "⚠️ WARNING: This site may be phishing!\nConfidence: "
      + msg.confidence + "%";

    banner.style.position = "fixed";
    banner.style.top = "0";
    banner.style.left = "0";
    banner.style.width = "100%";
    banner.style.backgroundColor = "red";
    banner.style.color = "white";
    banner.style.fontSize = "16px";
    banner.style.padding = "10px";
    banner.style.zIndex = "999999";
    banner.style.textAlign = "center";

    document.body.prepend(banner);
  }

});