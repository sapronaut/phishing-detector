from flask import Flask, render_template, request, jsonify
from detector import analyze_url
from db import init_db, save_scan, get_history

app = Flask(__name__)

init_db()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    # Prepend scheme if missing so tldextract works
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    result = analyze_url(url)

    save_scan(
        url,
        result["verdict"],
        result["score"]
    )

    return jsonify(result)


@app.route("/history")
def history():
    return jsonify(get_history())


if __name__ == "__main__":
    app.run(debug=True)