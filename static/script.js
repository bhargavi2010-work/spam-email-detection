function predict() {
    const message = document.getElementById("messageInput").value;

    fetch("/predict", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({message})
    })
    .then(res => res.json())
    .then(data => {
        document.getElementById("result").innerText =
            "Prediction: " + data.prediction;
    });
}
