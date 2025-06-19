from flask import Flask, render_template_string, request
from modules import xss

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def home():
    payloads = []
    if request.method == "POST":
        payloads = xss.get_xss_payloads()
    return render_template_string('''
    <form method="post">
        <button type="submit">Generate XSS Payloads</button>
    </form>
    {% for p in payloads %}
        <p>{{ p['type'] }}: {{ p['payload'] }}</p>
    {% endfor %}
    ''', payloads=payloads)

app.run(port=8080)
