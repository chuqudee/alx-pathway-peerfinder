import os
import uuid
import io
import json
import logging
from datetime import datetime, timedelta, timezone
from flask import Flask, request, jsonify, render_template, redirect, url_for, Response, flash, session
import pandas as pd
import boto3
from botocore.exceptions import ClientError
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
import base64
from email.mime.text import MIMEText
import math

# Configure logging
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# === ENVIRONMENT VARIABLES REQUIRED ===
SECRET_KEY = "e8f3473b716cfe3760fd522e38a3bd5b9909510b0ef003f050e0a445fa3a6e83"
AWS_ACCESS_KEY_ID = os.environ.get('AWS_ACCESS_KEY_ID')
AWS_SECRET_ACCESS_KEY = os.environ.get('AWS_SECRET_ACCESS_KEY')
AWS_DEFAULT_REGION = os.environ.get('AWS_DEFAULT_REGION')
app.secret_key = os.environ.get('SECRET_KEY', 'default_secret_key')

# Gmail API configuration
SCOPES = ['https://www.googleapis.com/auth/gmail.send']
TOKEN_FILE = 'token.json'  # Temporary file for token storage during runtime

# AWS S3 configuration
AWS_S3_BUCKET = "alx-peerfinder-storage-bucket"
if not AWS_S3_BUCKET:
    raise Exception("AWS_S3_BUCKET environment variable not set")
s3 = boto3.client('s3')
CSV_OBJECT_KEY = 'pathway_peer-matcing_data.csv'
ADMIN_PASSWORD = "alx_admin_2025_peer_finder"

# === Gmail API Helper Functions ===
def get_gmail_service():
    creds = None
    # Check for GOOGLE_TOKEN environment variable
    token_data = os.environ.get('GOOGLE_TOKEN')
    if token_data and not os.path.exists(TOKEN_FILE):
        try:
            with open(TOKEN_FILE, 'w') as token:
                token.write(token_data)
        except Exception as e:
            logger.error(f"Failed to write token.json from GOOGLE_TOKEN: {str(e)}")
    # Load credentials from token.json if it exists
    if os.path.exists(TOKEN_FILE):
        try:
            creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
        except Exception as e:
            logger.error(f"Failed to load token.json: {str(e)}")
    # If no valid credentials, authenticate
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
                # Update token.json with new access token
                with open(TOKEN_FILE, 'w') as token:
                    token.write(creds.to_json())
            except Exception as e:
                logger.error(f"Failed to refresh token: {str(e)}")
                # If refresh fails, proceed to re-authenticate
                creds = None
        if not creds:
            try:
                client_secrets = json.loads(os.environ.get('GOOGLE_CLIENT_SECRETS'))
                flow = InstalledAppFlow.from_client_config(client_secrets, SCOPES)
                flow.redirect_uri = 'https://alx-foundations-peer-finder.onrender.com/oauth2callback'  # Update for your Render app
                creds = flow.run_local_server(port=5000, open_browser=True)
                # Save credentials for reuse
                with open(TOKEN_FILE, 'w') as token:
                    token.write(creds.to_json())
                logger.info("Generated new token.json via OAuth flow")
            except Exception as e:
                logger.error(f"Failed to authenticate with Gmail API: {str(e)}")
                raise
    return build('gmail', 'v1', credentials=creds)

def send_match_email(user_email, user_name, group_members):
    peer_info_list = []
    for m in group_members:
        if m['email'] != user_email and m['email'] != 'unpaired':
            support = m.get('kind_of_support', '')
            if support == '' or (isinstance(support, float) and math.isnan(support)):
                support = "Accountability"
            support_info = f"\nSupport Type: {support}"
            peer_info_list.append(f"Name: {m['name']}\nEmail Address: {m['email']}\nWhatsApp: {m['phone']}{support_info}")
    peer_info = '\n\n'.join(peer_info_list)
    if not peer_info:
        peer_info = "No other members found."
    body = f"""Hi {user_name},
You have been matched with the following peer(s):
{peer_info}
Kindly reach out to your peer(s) for collaboration and support!👍

⚠️ Please Read Carefully
We want this to be a positive and supportive experience for everyone. To help make that happen:
- Please show up for your partner or group — ghosting is discouraged and can affect their progress.
- Only fill this form with accurate details. If you've entered incorrect information, kindly unpair yourself.
- If you've completed all your modules, consider supporting others who are catching up — your help can make a real difference.🤗
- If you no longer wish to participate, let your partner/group know first before unpairing.
- If you'd like to be paired with someone new, you'll need to register again.

Thank you for helping create a respectful and encouraging learning community.
Best regards,
Peer Finder Team
"""
    message = MIMEText(body)
    message['to'] = user_email
    message['from'] = 'alxfoundations@alxafrica.com'
    message['subject'] = "You've been matched!"
    message['reply-to'] = 'alxfoundations@alxafrica.com'
    raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
    try:
        service = get_gmail_service()
        service.users().messages().send(userId='me', body={'raw': raw}).execute()
        logger.info(f"Sent match email to {user_email}")
    except Exception as e:
        logger.error(f"Failed to send match email to {user_email}: {str(e)}")
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
    message['from'] = 'alxfoundations@alxafrica.com'
    message['subject'] = 'PeerFinder - Waiting to Be Matched'
    message['reply-to'] = 'alxfoundations@alxafrica.com'
    raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
    try:
        service = get_gmail_service()
        service.users().messages().send(userId='me', body={'raw': raw}).execute()
        logger.info(f"Sent waiting email to {user_email}")
    except Exception as e:
        logger.error(f"Failed to send waiting email to {user_email}: {str(e)}")
        raise

# === Other Helper Functions ===
def download_csv():
    try:
        obj = s3.get_object(Bucket=AWS_S3_BUCKET, Key=CSV_OBJECT_KEY)
        data = obj['Body'].read().decode('utf-8')
        df = pd.read_csv(io.StringIO(data))

        # Normalize email and phone
        if 'email' in df.columns:
            df['email'] = df['email'].astype(str).str.lower().str.strip()
        if 'phone' in df.columns:
            df['phone'] = df['phone'].astype(str).str.strip()
            df['phone'] = df['phone'].apply(lambda x: '+' + x if x and not x.startswith('+') else x)

        if 'matched' in df.columns:
            df['matched'] = df['matched'].astype(str).str.upper() == 'TRUE'
        else:
            df['matched'] = False
        
        expected_columns = [
            'id', 'name', 'phone', 'email', 'country', 'language', 'cohort', 'topic_module',
            'learning_preferences', 'availability', 'preferred_study_setup', 'kind_of_support',
            'connection_type', 'timestamp', 'matched', 'group_id', 'unpair_reason', 'matched_timestamp',
            'match_attempted', 'term'
        ]
        for col in expected_columns:
            if col not in df.columns:
                if col == 'matched' or col == 'match_attempted':
                    df[col] = False
                else:
                    df[col] = ''
        
        string_columns = [
            'id', 'name', 'phone', 'email', 'country', 'language', 'cohort', 'topic_module',
            'learning_preferences', 'availability', 'preferred_study_setup', 'kind_of_support',
            'connection_type', 'timestamp', 'group_id', 'unpair_reason', 'matched_timestamp', 'term'
        ]
        for col in string_columns:
            df[col] = df[col].astype('object')

        return df
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchKey':
            columns = [
                'id', 'name', 'phone', 'email', 'country', 'language', 'cohort', 'topic_module',
                'learning_preferences', 'availability', 'preferred_study_setup', 'kind_of_support',
                'connection_type', 'timestamp', 'matched', 'group_id', 'unpair_reason', 'matched_timestamp',
                'match_attempted', 'term'
            ]
            dtypes = {col: 'object' for col in columns}
            dtypes['matched'] = bool
            dtypes['match_attempted'] = bool
            return pd.DataFrame(columns=columns).astype(dtypes)
        else:
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
    if a1 == 'Flexible' or a2 == 'Flexible':
        return True
    return a1 == a2

def fallback_match_unmatched():
    df = download_csv()
    now = datetime.utcnow()
    updated = False
    unmatched = df[
        (df['matched'] == False) &
        (df['connection_type'] == 'find')
    ]
    def is_older_than_4_days(ts):
        try:
            dt = datetime.fromisoformat(ts)
            return (now - dt) > timedelta(days=4)
        except Exception:
            return False
    unmatched = unmatched[unmatched['timestamp'].apply(is_older_than_4_days)]
    for group_size in [2, 3, 5]:
        eligible = unmatched[unmatched['preferred_study_setup'] == str(group_size)]
        while len(eligible) >= group_size:
            group = eligible.iloc[:group_size]
            if len(set(group['id'])) < group_size:
                eligible = eligible.iloc[group_size:]
                continue
            group_id = f"group-fallback-{uuid.uuid4()}"
            now_iso = now.isoformat()
            df.loc[group.index, 'matched'] = True
            df.loc[group.index, 'group_id'] = group_id
            df.loc[group.index, 'matched_timestamp'] = now_iso
            updated = True
            eligible = eligible.iloc[group_size:]
    if updated:
        df['phone'] = df['phone'].astype(str).str.strip()
        df['phone'] = df['phone'].apply(lambda x: '+' + x if x and not x.startswith('+') else x)
        upload_csv(df)

# === Flask Routes ===
@app.route('/')
def landing():
    return render_template('landing.html')

@app.route('/start/')
def start_form():
    connection_type = request.args.get('connection_type')
    if connection_type not in ['find', 'offer', 'need']:
        return "Invalid connection type", 404
    return render_template('form.html', connection_type=connection_type)

@app.route('/join', methods=['POST'])
def join_queue():
    data = request.form
    connection_type = data.get('connection_type')
    if connection_type not in ['find', 'offer', 'need']:
        return render_template('landing.html', error="Invalid connection type selected.")

    # Parse and clean form data
    name = data.get('name', '').strip()
    phone = str(data.get('phone', '').strip())
    email = data.get('email', '').strip().lower()
    country = data.get('country', '').strip()
    language = data.get('language', '').strip()
    cohort = data.get('cohort', '').strip()
    topic_module = data.get('topic_module', '').strip()
    learning_preferences = data.get('learning_preferences', '').strip()
    availability = data.get('availability', '').strip()
    term = data.get('term', '').strip()

    # Normalize phone
    if not phone.startswith('+'):
        phone = '+' + phone

    required_fields = [name, phone, email, country, language, cohort, topic_module, learning_preferences, availability, term]
    if not all(required_fields):
        return render_template('form.html', connection_type=connection_type, error="Please fill all required fields.")

    if len(phone) < 7:
        return render_template('form.html', connection_type=connection_type, error="Please enter a valid phone number starting with a plus (+) and country code.")

    preferred_study_setup = ''
    kind_of_support = ''
    if connection_type == 'find':
        preferred_study_setup = data.get('preferred_study_setup', '').strip()
        if not preferred_study_setup or preferred_study_setup not in ['2', '3', '5']:
            return render_template('form.html', connection_type=connection_type, error="Please select a valid preferred study setup.")
    elif connection_type in ['offer', 'need']:
        kind_of_support = data.get('kind_of_support', '').strip()
        if not kind_of_support:
            return render_template('form.html', connection_type=connection_type, error="Please select kind of support.")

    try:
        df = download_csv()
    except ClientError as e:
        logger.error(f"Failed to download CSV from S3: {str(e)}")
        flash("Registration failed due to storage error. Please try again later.", "error")
        return redirect(url_for('start_form', connection_type=connection_type))

    # Duplicate check based on email or phone only
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

    # No duplicates - add new user
    new_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()
    new_row = {
        'id': new_id,
        'name': name,
        'phone': phone,
        'email': email,
        'country': country,
        'language': language,
        'cohort': cohort,
        'topic_module': topic_module,
        'learning_preferences': learning_preferences,
        'availability': availability,
        'preferred_study_setup': preferred_study_setup,
        'kind_of_support': kind_of_support,
        'connection_type': connection_type,
        'timestamp': timestamp,
        'matched': False,
        'group_id': '',
        'unpair_reason': '',
        'matched_timestamp': '',
        'match_attempted': False,
        'term': term
    }
    new_row_df = pd.DataFrame([new_row])
    df = pd.concat([df, new_row_df], ignore_index=True)
    try:
        upload_csv(df)
    except ClientError as e:
        logger.error(f"Failed to upload CSV to S3: {str(e)}")
        flash("Registration failed due to storage error. Please try again later.", "error")
        return redirect(url_for('start_form', connection_type=connection_type))
    
    try:
        send_waiting_email(email, name, new_id)
    except Exception as e:
        logger.error(f"Failed to send waiting email in /join: {str(e)}")
        flash("Registration successful, but failed to send confirmation email.", "warning")
    
    return redirect(url_for('waiting', user_id=new_id))

@app.route('/waiting/')
def waiting():
    user_id = request.args.get('user_id')
    if not user_id:
        flash("User ID required", "warning")
        return render_template('waiting.html', user_id=None, match_attempted=False)
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
        flash("User ID required.", "warning")
        return jsonify({'error': 'User ID required', 'redirect': url_for('waiting', user_id=user_id)}), 400

    try:
        df = download_csv()
    except ClientError as e:
        logger.error(f"Failed to download CSV from S3: {str(e)}")
        flash("Matching failed due to storage error. Please try again later.", "error")
        return jsonify({'error': 'Storage error', 'redirect': url_for('waiting', user_id=user_id)}), 500

    user = df[df['id'] == user_id]
    if user.empty:
        flash("User not found. Please check your ID.", "warning")
        return jsonify({'error': 'User not found', 'redirect': url_for('waiting', user_id=user_id)}), 404
    user = user.iloc[0]

    # Mark match attempt
    df.at[user.name, 'match_attempted'] = True
    updated = False

    if user['connection_type'] == 'find':
        country = user['country']
        cohort = user['cohort']
        topic_module = user['topic_module']
        preferred_study_setup = user['preferred_study_setup']
        availability = user['availability']
        term = user['term']

        try:
            group_size = int(preferred_study_setup)
        except ValueError:
            flash("Invalid preferred study setup.", "warning")
            upload_csv(df)
            return jsonify({'error': 'Invalid preferred study setup', 'redirect': url_for('waiting', user_id=user_id)}), 400

        if group_size not in [2, 3, 5]:
            flash("Unsupported group size.", "warning")
            upload_csv(df)
            return jsonify({'error': 'Unsupported group size', 'redirect': url_for('waiting', user_id=user_id)}), 400

        eligible = df[
            (df['matched'] == False) &
            (df['connection_type'] == 'find') &
            (df['country'] == country) &
            (df['cohort'] == cohort) &
            (df['topic_module'] == topic_module) &
            (df['preferred_study_setup'] == preferred_study_setup) &
            (df['term'] == term)
        ]
        eligible = eligible[eligible['availability'].apply(lambda x: availability_match(x, availability))]

        while len(eligible) >= group_size:
            group = eligible.iloc[:group_size]

            # Ensure unique email and phone in the group
            if len(set(group['email'])) < group_size or len(set(group['phone'])) < group_size:
                eligible = eligible.iloc[1:]  # Skip the first record and try again
                continue

            group_id = f"group-{uuid.uuid4()}"
            now_iso = datetime.now(timezone.utc).isoformat()

            df.loc[group.index, 'matched'] = True
            df.loc[group.index, 'group_id'] = group_id
            df.loc[group.index, 'matched_timestamp'] = now_iso
            updated = True

            eligible = eligible.iloc[group_size:]

    elif user['connection_type'] in ['offer', 'need']:
        country = user['country']
        cohort = user['cohort']
        availability = user['availability']
        term = user['term']
        opposite_type = 'need' if user['connection_type'] == 'offer' else 'offer'

        eligible = df[
            (df['matched'] == False) &
            (df['connection_type'] == opposite_type) &
            (df['country'] == country) &
            (df['cohort'] == cohort) &
            (df['term'] == term)
        ]
        eligible = eligible[eligible['availability'].apply(lambda x: availability_match(x, availability))]

        if not eligible.empty:
            matched_user_idx = eligible.index[0]
            matched_user = df.loc[matched_user_idx]

            # Ensure the matched user is not the same person
            if matched_user['email'] == user['email'] or matched_user['phone'] == user['phone']:
                flash("You have not been matched yet! Check back later with your ID, by clicking on the check match status", "warning")
                upload_csv(df)
                return jsonify({'matched': False, 'redirect': url_for('waiting', user_id=user_id)})

            group_id = f"group-{uuid.uuid4()}"
            now_iso = datetime.now(timezone.utc).isoformat()

            df.at[user.name, 'matched'] = True
            df.at[user.name, 'group_id'] = group_id
            df.at[user.name, 'matched_timestamp'] = now_iso

            df.at[matched_user_idx, 'matched'] = True
            df.at[matched_user_idx, 'group_id'] = group_id
            df.at[matched_user_idx, 'matched_timestamp'] = now_iso

            updated = True

    else:
        flash("Unsupported connection type.", "warning")
        upload_csv(df)
        return jsonify({'error': 'Unsupported connection type', 'redirect': url_for('waiting', user_id=user_id)}), 400

    if updated:
        try:
            upload_csv(df)
            user = df[df['id'] == user_id].iloc[0]
            if user['matched']:
                group_id = user['group_id']
                group_members = df[df['group_id'] == group_id].to_dict(orient='records')
                for member in group_members:
                    if member['email'] != 'unpaired':
                        try:
                            send_match_email(member['email'], member['name'], group_members)
                        except Exception as e:
                            logger.error(f"Failed to send match email to {member['email']}: {str(e)}")
                            flash(f"Match successful, but failed to send email to {member['email']}.", "warning")
                return jsonify({
                    'matched': True,
                    'redirect': url_for('waiting', user_id=user_id)
                })
        except ClientError as e:
            logger.error(f"Failed to upload CSV to S3: {str(e)}")
            flash("Matching failed due to storage error. Please try again later.", "error")
            return jsonify({'error': 'Storage error', 'redirect': url_for('waiting', user_id=user_id)}), 500

    flash("You have not been matched yet! Check back later with your ID, by clicking on the check match status", "warning")
    upload_csv(df)
    return jsonify({'matched': False, 'redirect': url_for('waiting', user_id=user_id)})

@app.route('/matched/')
def matched():
    user_id = request.args.get('user_id')
    df = download_csv()
    user = df[df['id'] == user_id]
    if user.empty:
        return "User not found", 404
    user = user.iloc[0]
    if not user['matched']:
        return redirect(url_for('waiting', user_id=user_id))
    group_id = user['group_id']
    group_members = df[df['group_id'] == group_id]
    return render_template('matched.html', user=user, group_members=group_members.to_dict(orient='records'))

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
        df.at[idx, 'unpair_reason'] = reason  # Do NOT change matched status as requested
    upload_csv(df)
    return jsonify({'success': True})

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

@app.route('/admin/fallback', methods=['GET', 'POST'])
def admin_fallback():
    if request.method == 'POST':
        password = request.form.get('password', '')
        if password == ADMIN_PASSWORD:
            session['admin_authenticated'] = True
            return redirect(url_for('admin_fallback_match'))
        else:
            flash('Incorrect password. Access denied.')
            return redirect(url_for('admin_fallback'))
    return render_template('admin_fallback.html')

@app.route('/admin/fallback_match')
def admin_fallback_match():
    if not session.get('admin_authenticated', False):
        flash('Please authenticate first.')
        return redirect(url_for('admin_fallback'))
    fallback_match_unmatched()
    flash("Fallback matching process executed successfully.")
    return redirect(url_for('admin'))

@app.route('/admin/download_feedback')
def download_feedback():
    # Placeholder for feedback CSV download
    return "Feedback download not implemented yet", 501

@app.route('/disclaimer')
def disclaimer():
    return render_template('disclaimer.html')

@app.route('/authorize')
def authorize():
    try:
        client_secrets = json.loads(os.environ.get('GOOGLE_CLIENT_SECRETS', '{}'))
        if not client_secrets:
            logger.error("GOOGLE_CLIENT_SECRETS not found in environment variables")
            flash("Authorization failed: Missing client secrets.", "error")
            return redirect(url_for('landing'))
        flow = InstalledAppFlow.from_client_config(client_secrets, SCOPES)
        flow.redirect_uri = 'http://localhost:5000/oauth2callback'
        authorization_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true',
            prompt='consent'
        )
        session['state'] = state
        return redirect(authorization_url)
    except Exception as e:
        logger.error(f"Failed to start OAuth flow: {str(e)}")
        flash("Failed to start authorization. Please check logs.", "error")
        return redirect(url_for('landing'))

@app.route('/oauth2callback')
def oauth2callback():
    try:
        state = session.get('state')
        client_secrets = json.loads(os.environ.get('GOOGLE_CLIENT_SECRETS', '{}'))
        if not client_secrets:
            logger.error("GOOGLE_CLIENT_SECRETS not found in environment variables")
            flash("Authorization failed: Missing client secrets.", "error")
            return redirect(url_for('landing'))
        flow = InstalledAppFlow.from_client_config(client_secrets, SCOPES, state=state)
        flow.redirect_uri = 'http://localhost:5000/oauth2callback'
        flow.fetch_token(authorization_response=request.url)
        creds = flow.credentials
        with open(TOKEN_FILE, 'w') as token:
            token.write(creds.to_json())
        logger.info("Successfully generated token.json")
        flash("Authorization successful. Token generated.", "success")
        return redirect(url_for('landing'))
    except Exception as e:
        logger.error(f"OAuth callback error: {str(e)}")
        flash(f"Authorization failed: {str(e)}", "error")
        return redirect(url_for('landing'))

if __name__ == '__main__':
    # Allow HTTP for localhost during OAuth (for local testing)
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

    app.run(debug=True, port=5000)
