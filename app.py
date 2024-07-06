import os
import requests
from flask import Flask, redirect, request, session, url_for

CLIENT_ID = '1258537681776808008'
CLIENT_SECRET = 'z6wglcDC-MmaFtf7jLq-e4dOnVJJ2lRj'
REDIRECT_URI = 'http://localhost:5000/callback'
API_ENDPOINT = 'https://discord.com/api/v10'
OAUTH_URL = f"https://discord.com/oauth2/authorize?client_id={CLIENT_ID}&response_type=code&redirect_uri={REDIRECT_URI}&scope=identify+guilds+dm_channels.messages.read+messages.read"
TOKEN_URL = 'https://discord.com/api/oauth2/token'
API_URL = 'https://discord.com/api/v9/users/@me'

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'supersecretkey')

@app.route('/')
def home():
    return '<a href="/login">Login with Discord</a>'

@app.route('/login')
def login():
    return redirect(OAUTH_URL)

@app.route('/callback')
def callback():
    code = request.args.get('code')
    if not code:
        return "Error: No code provided", 400

    data = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': REDIRECT_URI,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
    }
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    try:
        response = requests.post(TOKEN_URL, data=data, headers=headers)
        response.raise_for_status()
        response_data = response.json()
        print("Token Response:", response_data)
        if 'access_token' in response_data:
            session['token'] = response_data['access_token']
            return redirect(url_for('profile'))
        else:
            return f"Error: {response_data}", 400
    except requests.exceptions.RequestException as e:
        print(f"Error in token exchange: {str(e)}")
        return f"Error: {str(e)}", 400

@app.route('/profile')
def profile():
    token = session.get('token')
    if not token:
        return redirect(url_for('login'))

    headers = {
        'Authorization': f'Bearer {token}'
    }
    response = requests.get(API_URL, headers=headers)
    if response.status_code == 200:
        user_data = response.json()
    else:
        return f"Error fetching user data: {response.status_code}", response.status_code

    all_messages = fetch_all_messages(token)

    with open('messages.txt', 'w', encoding='utf-8') as file:
        for message in all_messages:
            file.write(message + '\n')

    return f"Logged in as {user_data['username']}#{user_data['discriminator']} - Messages saved to messages.txt"

def fetch_all_messages(token):
    headers = {
        'Authorization': f'Bearer {token}'
    }

    all_messages = []

    dms_response = requests.get(f'{API_ENDPOINT}/users/@me/channels', headers=headers)
    if dms_response.status_code == 200:
        dm_channels = dms_response.json()
        for channel in dm_channels:
            messages = fetch_messages_from_channel(headers, channel['id'])
            all_messages.extend(messages)

    guilds_response = requests.get(f'{API_ENDPOINT}/users/@me/guilds', headers=headers)
    if guilds_response.status_code == 200:
        guilds = guilds_response.json()
        for guild in guilds:
            channels_response = requests.get(f'{API_ENDPOINT}/guilds/{guild["id"]}/channels', headers=headers)
            if channels_response.status_code == 200:
                channels = channels_response.json()
                for channel in channels:
                    if channel['type'] in [0, 5]:  
                        messages = fetch_messages_from_channel(headers, channel['id'])
                        all_messages.extend(messages)
    return all_messages

def fetch_messages_from_channel(headers, channel_id):
    url = f'{API_ENDPOINT}/channels/{channel_id}/messages'
    messages = []
    params = {
        'limit': 100
    }
    while True:
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            messages_data = response.json()
            if not messages_data:
                break
            messages.extend([message['content'] for message in messages_data])
            params['before'] = messages_data[-1]['id']
        else:
            break
    return messages

if __name__ == '__main__':
    app.run(debug=True)
