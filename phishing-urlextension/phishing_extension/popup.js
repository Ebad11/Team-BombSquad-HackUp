document.getElementById("checkBtn").addEventListener("click", () => {

  const url = document.getElementById("url").value;

  fetch("http://127.0.0.1:5001/predict/url", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ url: url })
  })
  .then(res => res.json())
  .then(data => {

    document.getElementById("result").innerText =
      "Result: " + data.prediction +
      " (" + data.confidence + "%)";

  })
  .catch(err => {
    document.getElementById("result").innerText = "Error connecting to backend";
  });

});