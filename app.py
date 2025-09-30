import os
import uuid
import io
from datetime import datetime, timezone
import pandas as pd
import boto3
from botocore.exceptions import ClientError
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, session, Response
import base64
from email.mime.text import MIMEText
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
import json
import logging

logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'default_secret_key')

# AWS S3 Config
AWS_ACCESS_KEY_ID = os.environ.get('AWS_ACCESS_KEY_ID')
AWS_SECRET_ACCESS_KEY = os.environ.get('AWS_SECRET_ACCESS_KEY')
AWS_DEFAULT_REGION = os.environ.get('AWS_DEFAULT_REGION')
AWS_S3_BUCKET = "alx-peerfinder-storage-bucket"
CSV_OBJECT_KEY = 'ai_peer-matcing_data.csv'

s3 = boto3.client('s3')

# Gmail API scopes and token file
SCOPES = ['https://www.googleapis.com/auth/gmail.send']
TOKEN_FILE = 'token.json'

ADMIN_PASSWORD = "alx_admin_2025_peer_finder"

# --- Gmail API functions ---

def get_gmail_service():
    creds = None
    token_data = os.environ.get('GOOGLE_TOKEN')
    if token_data and not os.path.exists(TOKEN_FILE):
        try:
            with open(TOKEN_FILE, 'w') as token:
                token.write(token_data)
        except Exception as e:
            logger.error(f"Failed to write token.json from GOOGLE_TOKEN: {e}")

    if os.path.exists(TOKEN_FILE):
        try:
            creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
        except Exception as e:
            logger.error(f"Failed to load token.json: {e}")

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
                with open(TOKEN_FILE, 'w') as token:
                    token.write(creds.to_json())
            except Exception as e:
                logger.error(f"Failed to refresh token: {e}")
                creds = None
        if not creds:
            try:
                client_secrets = json.loads(os.environ.get('GOOGLE_CLIENT_SECRETS'))
                flow = InstalledAppFlow.from_client_config(client_secrets, SCOPES)
                flow.redirect_uri = 'https://alx-aice-peerfinder.onrender.com/oauth2callback'
                creds = flow.run_local_server(port=5000, open_browser=True)
                with open(TOKEN_FILE, 'w') as token:
                    token.write(creds.to_json())
                logger.info("Generated new token.json via OAuth flow")
            except Exception as e:
                logger.error(f"Failed to authenticate with Gmail API: {e}")
                raise
    return build('gmail', 'v1', credentials=creds)

# --- Helper functions for CSV handling ---

def download_csv():
    try:
        obj = s3.get_object(Bucket=AWS_S3_BUCKET, Key=CSV_OBJECT_KEY)
        data = obj['Body'].read().decode('utf-8')
        df = pd.read_csv(io.StringIO(data))

        # Normalize data
        if 'email' in df.columns:
            df['email'] = df['email'].astype(str).str.lower().str.strip()
        if 'phone' in df.columns:
            df['phone'] = df['phone'].astype(str).str.strip()
            df['phone'] = df['phone'].apply(lambda x: '+' + x if x and not x.startswith('+') else x)
        if 'matched' in df.columns:
            df['matched'] = df['matched'].astype(str).str.upper() == 'TRUE'
        else:
            df['matched'] = False

        # Add missing columns
        expected_cols = [
            'id', 'name', 'phone', 'email', 'country', 'language', 'cohort',
            'topic_module', 'learning_preferences', 'availability', 'preferred_study_setup',
            'kind_of_support', 'connection_type', 'timestamp', 'matched', 'group_id',
            'unpair_reason', 'matched_timestamp', 'match_attempted', 'english_comfort',
            'open_to_inter_city'
        ]
        for col in expected_cols:
            if col not in df.columns:
                if col == 'matched' or col == 'match_attempted':
                    df[col] = False
                else:
                    df[col] = ''
        return df
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchKey':
            # Return empty DataFrame with correct columns
            columns = [
                'id', 'name', 'phone', 'email', 'country', 'language', 'cohort',
                'topic_module', 'learning_preferences', 'availability', 'preferred_study_setup',
                'kind_of_support', 'connection_type', 'timestamp', 'matched', 'group_id',
                'unpair_reason', 'matched_timestamp', 'match_attempted', 'english_comfort', 'open_to_inter_city'
            ]
            dtypes = {col: 'object' for col in columns}
            dtypes['matched'] = bool
            dtypes['match_attempted'] = bool
            return pd.DataFrame(columns=columns).astype(dtypes)
        raise

def upload_csv(df):
    if 'phone' in df.columns:
        df['phone'] = df['phone'].astype(str).str.strip()
        df['phone'] = df['phone'].apply(lambda x: '+' + x if x and not x.startswith('+') else x)
    if 'email' in df.columns:
        df['email'] = df['email'].astype(str).str.lower().str.strip()
    csv_buffer = io.StringIO()
    df.to_csv(csv_buffer, index=False)
    s3.put_object(Bucket=AWS_S3_BUCKET, Key=CSV_OBJECT_KEY, Body=csv_buffer.getvalue())

def availability_match(a1, a2):
    # Flexible matches any availability
    if a1 == 'Flexible' or a2 == 'Flexible':
        return True
    return a1 == a2

# --- Email Sending Functions ---

def send_match_email(user_email, user_name, group_members):
    peer_info_list = []
    for m in group_members:
        if m['email'] != user_email and m['email'] != 'unpaired':
            support = m.get('kind_of_support', '') or "Accountability"
            peer_info_list.append(
                f"Name: {m['name']}\nEmail Address: {m['email']}\nWhatsApp: {m['phone']}\nSupport Type: {support}"
            )
    peer_info = '\n\n'.join(peer_info_list) if peer_info_list else "No other members found."

    body = f"""Hi {user_name},

You have been matched with the following peer(s):

{peer_info}

Kindly reach out to your peer(s) for collaboration and support! 👍

⚠️ Please Read Carefully

We want this to be a positive and supportive experience for everyone. To help make that happen:

- Please show up for your partner or group — ghosting affects their progress.
- Only fill this form with accurate details.
- Consider supporting others if you've finished your modules.
- Let your partner/group know before unpairing.
- Register again to be paired anew.

Best regards,
Peer Finder Team
"""

    message = MIMEText(body)
    message['to'] = user_email
    message['from'] = 'aice@alxafrica.com'
    message['subject'] = "You've been matched!"
    message['reply-to'] = 'aice@alxafrica.com'

    raw = base64.urlsafe_b64encode(message.as_bytes()).decode()

    try:
        service = get_gmail_service()
        service.users().messages().send(userId='me', body={'raw': raw}).execute()
        logger.info(f"Sent match email to {user_email}")
    except Exception as e:
        logger.error(f"Failed to send match email to {user_email}: {e}")
        raise

def send_waiting_email(user_email, user_name, user_id):
    confirm_link = url_for('check_match', _external=True)
    body = f"""Hi {user_name},

Waiting to Be Matched

Your request is in the queue.
As soon as a suitable peer or group is available, you'll be matched.
Kindly copy your ID below to check your status later:

Your ID: {user_id}

Check your status here: {confirm_link}

Best regards,
Peer Finder Team
"""
    message = MIMEText(body)
    message['to'] = user_email
    message['from'] = 'aice@alxafrica.com'
    message['subject'] = "PeerFinder - Waiting to Be Matched"
    message['reply-to'] = 'aice@alxafrica.com'

    raw = base64.urlsafe_b64encode(message.as_bytes()).decode()

    try:
        service = get_gmail_service()
        service.users().messages().send(userId='me', body={'raw': raw}).execute()
        logger.info(f"Sent waiting email to {user_email}")
    except Exception as e:
        logger.error(f"Failed to send waiting email to {user_email}: {e}")
        raise


# --- Flask Routes ---

@app.route('/')
def landing():
    return render_template('landing.html')

# Serve form fragments dynamically (modal forms)
@app.route('/form_fragment/<activity>')
def form_fragment(activity):
    if activity not in ['debate', 'interview', 'study_buddy']:
        return "Invalid activity", 404
    return render_template(f'form_fragment_{activity}.html')

@app.route('/join', methods=['POST'])
def join_queue():
    data = request.form
    connection_type = data.get('connection_type')
    # Normalize possible old name to new one
    if connection_type == 'study':
        connection_type = 'study_buddy'

    if connection_type not in ['debate', 'interview', 'study_buddy']:
        return render_template('landing.html', error="Invalid connection type selected.")

    name = data.get('name', '').strip()
    phone = data.get('phone', '').strip()
    email = data.get('email', '').strip().lower()
    country = data.get('country', '').strip()
    english_comfort = data.get('english_comfort', '').strip()
    open_to_inter_city = data.get('open_pairing', '').strip()
    availability = data.get('availability', '').strip()
    preferred_study_setup = data.get('group_size', '').strip()

    required_fields = [name, phone, email, country, english_comfort, open_to_inter_city, availability, preferred_study_setup]

    if not all(required_fields):
        return render_template(f'form_fragment_{connection_type}.html', connection_type=connection_type, error="Please fill all required fields.")

    if not phone.startswith('+'):
        phone = '+' + phone

    # Validate preferred study setup based on connection type
    if connection_type == 'interview' and preferred_study_setup != '2':
        return render_template('form_fragment_interview.html', error="Interview group size must be 2.")
    if connection_type == 'debate' and preferred_study_setup not in ['2', '4']:
        return render_template('form_fragment_debate.html', error="Debate group size must be 2 or 4.")
    if connection_type == 'study_buddy' and preferred_study_setup not in ['2', '3']:
        return render_template('form_fragment_study_buddy.html', error="Study Buddy group size must be 2 or 3.")

    df = download_csv()

    # Check duplicates by email or phone
    dup_mask = (df['email'] == email) | (df['phone'] == phone)
    duplicates = df[dup_mask]

    if not duplicates.empty:
        dup = duplicates.iloc[0]
        if dup['matched']:
            group_id = dup['group_id']
            group_members = df[df['group_id'] == group_id]
            return render_template('already_matched.html', user=dup, group_members=group_members.to_dict(orient='records'))
        else:
            return render_template('already_in_queue.html', user_id=dup['id'])

    # No duplicates, append new user to CSV
    new_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()

    new_row = {
        'id': new_id,
        'name': name,
        'phone': phone,
        'email': email,
        'country': country,
        'language': '',  # Language options may be added in future
        'cohort': '',
        'topic_module': '',
        'learning_preferences': '',
        'availability': availability,
        'preferred_study_setup': preferred_study_setup,
        'kind_of_support': '',
        'connection_type': connection_type,
        'timestamp': timestamp,
        'matched': False,
        'group_id': '',
        'unpair_reason': '',
        'matched_timestamp': '',
        'match_attempted': False,
        'english_comfort': english_comfort,
        'open_to_inter_city': open_to_inter_city
    }

    df = pd.concat([df, pd.DataFrame([new_row])], ignore_index=True)
    upload_csv(df)

    # Send waiting email asynchronously if possible, else here
    send_waiting_email(email, name, new_id)

    return redirect(url_for('waiting', user_id=new_id))

@app.route('/waiting/')
def waiting():
    user_id = request.args.get('user_id')
    if not user_id:
        flash("User ID not provided.", "warning")
        return render_template('waiting.html', user_id=None)
    df = download_csv()
    user = df[df['id'] == user_id]
    if user.empty:
        flash("User not found. Please check your ID.", "warning")
        return render_template('waiting.html', user_id=user_id, match_attempted=False)
    user = user.iloc[0]
    match_attempted = user.get('match_attempted', False)
    if user['matched']:
        group_id = user['group_id']
        group_members = df[df['group_id'] == group_id]
        return render_template('waiting.html', user_id=user_id, matched=True, user=user.to_dict(), group_members=group_members.to_dict(orient='records'), match_attempted=match_attempted)
    return render_template('waiting.html', user_id=user_id, matched=False, match_attempted=match_attempted)

@app.route('/match', methods=['POST'])
def match_users():
    data = request.json
    user_id = data.get('user_id')
    if not user_id:
        return jsonify({'error': 'User ID required'}), 400

    df = download_csv()
    user = df[df['id'] == user_id]
    if user.empty:
        return jsonify({'error': 'User not found'}), 404
    user = user.iloc[0]

    df.at[user.name, 'match_attempted'] = True

    connection_type = user['connection_type']
    preferred_study_setup = user['preferred_study_setup']
    availability = user['availability']
    country = user['country']
    open_to_inter_city = user['open_to_inter_city']

    try:
        group_size = int(preferred_study_setup)
    except ValueError:
        upload_csv(df)
        return jsonify({'error': 'Invalid preferred study setup'}), 400

    # Group size validation
    if connection_type == 'debate' and group_size not in [2, 4]:
        upload_csv(df)
        return jsonify({'error': 'Unsupported group size for debate'}), 400
    if connection_type == 'interview' and group_size != 2:
        upload_csv(df)
        return jsonify({'error': 'Unsupported group size for interview'}), 400
    if connection_type == 'study_buddy' and group_size not in [2, 3]:
        upload_csv(df)
        return jsonify({'error': 'Unsupported group size for study buddy'}), 400

    # Select eligible group members to form match
    eligible = df[
        (df['matched'] == False) &
        (df['connection_type'] == connection_type) &
        (df['preferred_study_setup'] == preferred_study_setup) &
        (df['english_comfort'] == 'Yes')
    ]

    eligible = eligible[eligible['availability'].apply(lambda x: availability_match(x, availability))]

    if open_to_inter_city != 'Yes':
        eligible = eligible[eligible['country'] == country]

    updated = False

    while len(eligible) >= group_size:
        group = eligible.iloc[:group_size]

        # Ensure unique email and phone per group
        if len(set(group['email'])) < group_size or len(set(group['phone'])) < group_size:
            eligible = eligible.iloc[1:]  # Skip one record and retry
            continue

        group_id = f"group-{uuid.uuid4()}"
        now_iso = datetime.now(timezone.utc).isoformat()

        df.loc[group.index, 'matched'] = True
        df.loc[group.index, 'group_id'] = group_id
        df.loc[group.index, 'matched_timestamp'] = now_iso
        updated = True
        eligible = eligible.iloc[group_size:]

    if updated:
        upload_csv(df)

    user = df[df['id'] == user_id].iloc[0]
    if user['matched']:
        group_members = df[df['group_id'] == user['group_id']].to_dict(orient='records')
        for member in group_members:
            if member['email'] != 'unpaired':
                send_match_email(member['email'], member['name'], group_members)
        return jsonify({'matched': True, 'redirect': url_for('waiting', user_id=user_id)})
    else:
        upload_csv(df)
        return jsonify({'matched': False, 'redirect': url_for('waiting', user_id=user_id)})

# Status check page by ID
@app.route('/check', methods=['GET', 'POST'])
def check_match():
    if request.method == 'POST':
        user_id = request.form.get('user_id', '').strip()
        if not user_id:
            return render_template('check.html', error="Please enter your ID.")
        df = download_csv()
        user = df[df['id'] == user_id]
        if user.empty:
            return render_template('check.html', error="ID not found. Please check and try again.")
        user = user.iloc[0]
        if user['matched']:
            group_id = user['group_id']
            group_members = df[df['group_id'] == group_id]
            return render_template('check.html', matched=True, group_members=group_members.to_dict(orient='records'), user=user)
        else:
            return render_template('check.html', matched=False, user=user)
    else:
        return render_template('check.html')

# Unpair user from group
@app.route('/unpair', methods=['POST'])
def unpair():
    user_id = request.form.get('user_id')
    reason = request.form.get('reason', '').strip()
    if not user_id or not reason:
        return jsonify({'error': 'User ID and reason are required'}), 400
    df = download_csv()
    user_row = df[df['id'] == user_id]
    if user_row.empty:
        return jsonify({'error': 'User not found'}), 404
    user = user_row.iloc[0]
    group_id = user['group_id']
    if user['matched'] and group_id:
        group_indices = df.index[df['group_id'] == group_id].tolist()
    else:
        group_indices = [user_row.index[0]]
    for idx in group_indices:
        df.at[idx, 'email'] = 'unpaired'
        df.at[idx, 'phone'] = 'unpaired'
        df.at[idx, 'topic_module'] = 'unpaired'
        df.at[idx, 'unpair_reason'] = reason
        # Do NOT change matched status
    upload_csv(df)
    return jsonify({'success': True})

# Admin & utility routes can remain unchanged or simplified

@app.route('/admin')
def admin():
    return render_template('admin.html')

@app.route('/admin/download_csv', methods=['GET', 'POST'])
def download_queue():
    if request.method == 'POST':
        password = request.form.get('password', '')
        if password == ADMIN_PASSWORD:
            df = download_csv()
            csv_buffer = io.StringIO()
            df.to_csv(csv_buffer, index=False)
            csv_buffer.seek(0)
            return Response(
                csv_buffer.getvalue(),
                mimetype='text/csv',
                headers={"Content-Disposition": "attachment;filename=registration_data.csv"}
            )
        else:
            flash("Incorrect password. Access denied.")
            return redirect(url_for('download_queue'))
    return render_template('password_prompt.html', file_type='Queue CSV')

@app.route('/disclaimer')
def disclaimer():
    return render_template('disclaimer.html')

if __name__ == '__main__':
    app.run(debug=True)
