from flask import Flask, make_response
import uuid

app = Flask(__name__)

# پشتیبانی از مفهوم Clean URL: دریافت هر مسیری بعد از /profile
@app.route('/profile', defaults={'path': ''})
@app.route('/profile/<path:path>')
def profile(path):
    # تولید یک توکن CSRF داینامیک برای هر درخواست
    csrf_token = uuid.uuid4().hex
    
    # قالب HTML جدید و جذاب‌تر با استفاده از CSS داخلی
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>User Profile | Secure Portal</title>
        <style>
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background-color: #e9ecef;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                margin: 0;
            }}
            .profile-card {{
                background: #ffffff;
                padding: 40px;
                border-radius: 12px;
                box-shadow: 0 10px 30px rgba(0,0,0,0.1);
                max-width: 400px;
                width: 100%;
                text-align: center;
                border-top: 6px solid #dc3545; /* Changed to red accent for password context */
            }}
            .profile-card h2 {{
                color: #343a40;
                margin-top: 0;
                margin-bottom: 25px;
            }}
            .token-box {{
                background: #fff3cd;
                color: #856404;
                border: 1px solid #ffeeba;
                padding: 15px;
                border-radius: 8px;
                margin: 20px 0;
                font-family: 'Courier New', Courier, monospace;
                font-size: 1.1em;
                word-wrap: break-word;
            }}
            .warning {{
                color: #dc3545;
                font-size: 0.9em;
                font-weight: bold;
                margin-bottom: 25px;
            }}
            /* Updated style targets to password inputs */
            input[type="password"] {{
                width: 100%;
                padding: 12px;
                margin-bottom: 15px;
                border: 1px solid #ced4da;
                border-radius: 6px;
                box-sizing: border-box;
                font-size: 1em;
            }}
            input[type="password"]:focus {{
                outline: none;
                border-color: #80bdff;
                box-shadow: 0 0 0 0.2rem rgba(0,123,255,.25);
            }}
            button {{
                background-color: #dc3545; /* Changed button color to contrast with password update action */
                color: white;
                border: none;
                padding: 14px 20px;
                border-radius: 6px;
                cursor: pointer;
                width: 100%;
                font-size: 1.05em;
                font-weight: bold;
                transition: background-color 0.3s ease;
            }}
            button:hover {{
                background-color: #bd2130;
            }}
        </style>
    </head>
    <body>
        <div class="profile-card">
            <h2>👤 Account Settings</h2>
            
            <div class="token-box">
                <span style="font-size: 0.8em; color: #666;">SECRET CSRF TOKEN:</span><br>
                <strong>{csrf_token}</strong>
            </div>
            
            <p class="warning">⚠️ This page contains sensitive data and should never be cached!</p>
            
            <form action="/update-password" method="POST">
                <input type="hidden" name="csrf_token" value="{csrf_token}">
                <input type="password" name="password" placeholder="Enter new secure password" required>
                <button type="submit">Update Password</button>
            </form>
        </div>
    </body>
    </html>
    """
    
    response = make_response(html_content)
    # تنظیم هدرهای امنیتی برای جلوگیری از کش شدن محتوا در حالت عادی
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    return response

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)