document.addEventListener("DOMContentLoaded", () => {
    const params = new URLSearchParams(window.location.search);
    const risk = params.get("risk");
    const targetUrl = params.get("url");

    if (risk) {
        document.getElementById("risk-score").innerText = parseFloat(risk).toFixed(0);
    } else {
        document.getElementById("risk-score").innerText = "High";
    }

    if (targetUrl) {
        document.getElementById("target-url").innerText = decodeURIComponent(targetUrl);
    } else {
        document.getElementById("target-url").innerText = "Unknown";
    }

    document.getElementById("back-btn").addEventListener("click", () => {
        // Navigating back using window.history.back() can get trapped in 
        // redirect loops or send the user back to the phishing site URL itself. 
        // The safest, 100% reliable method is to navigate them to a safe homepage.
        window.location.href = "https://www.google.com";
    });
});
