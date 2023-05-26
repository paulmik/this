import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from getpass import getpass
import os
from random import choice, choices
import string
from pathlib import Path
from base64 import b64encode
import time
from datetime import datetime, timedelta
from pywebio.input import *
from pywebio.output import *
from pywebio.platform.flask import webio_view
from flask import Flask
import threading
import paramiko
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

# List of countries
COUNTRIES = ['Country1', 'Country2', 'Country3']

# SMTP options
smtp_options = {
    'host': 'smtp.example.com',  # Replace with your SMTP server
    'port': 587,  # Replace with your SMTP port
    'username': 'your_username',  # Replace with your SMTP username
    'password': getpass('SMTP password: ')  # Prompt for SMTP password securely
}

# Webmail options
webmail_options = {
    'service': 'Gmail',  # Replace with the name of your webmail service
    'api_key': 'YOUR_API_KEY',  # Replace with your webmail API key (if applicable)
    'smtp_server': 'smtp.example.com',  # Replace with your webmail SMTP server
    'smtp_port': 587,  # Replace with your webmail SMTP port
    'username': 'your_username',  # Replace with your webmail username
    'password': getpass('Webmail password: '),  # Prompt for webmail password securely
}

# SSH options
ssh_options = {
    'enabled': False,  # Set to True to enable SSH sending
    'host': 'example.com',  # Replace with the SSH server host
    'port': 22,  # Replace with the SSH server port
    'username': 'your_username',  # Replace with your SSH username
    'password': getpass('SSH password: '),  # Prompt for SSH password securely
}

# Gmail API options
gmail_api_options = {
    'enabled': False,  # Set to True to enable Gmail API sending
    'credentials_path': 'credentials.json',  # Path to the credentials JSON file
    'token_path': 'token.json',  # Path to the token JSON file
    'scope': ['https://www.googleapis.com/auth/gmail.send'],  # Scopes for Gmail API
}

# Path to your files
message_html_path = Path('message.html')
sender_email_path = Path('senderfrom_email.txt')
recipient_email_path = Path('receipents_email.txt')
sender_name_path = Path('senderfrom_name.txt')
subject_line_path = Path('subjectline.txt')
attachfile_path = Path('attachfile.html')

# Enable/Disable options
html_to_image_enabled = False
html_to_pdf_enabled = False
html_to_eml_enabled = False
html_file_enabled = False
reply_to_enabled = False
encryption_enabled = False
priority_enabled = False
priority_value = 1
test_email_enabled = False
test_email_interval = 1000
test_email_recipient = 'test@example.com'
webmail_enabled = False

# Maximum number of connections
max_connections = 5

def random_string(length):
    letters = string.ascii_lowercase
    return ''.join(choice(letters) for _ in range(length))

def random_country():
    return choice(COUNTRIES)

def random_phone_number():
    digits = string.digits
    return ''.join(choices(digits, k=10))

def read_file(path):
    with path.open() as f:
        return f.read().strip()

def create_message(sender_email, recipient_email, sender_name, subject, body, reply_to=None):
    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = recipient_email
    message["Subject"] = subject
    message.attach(MIMEText(body, "plain"))
    
    if reply_to:
        message["Reply-To"] = reply_to
    
    return message

def send_email(message):
    if ssh_options['enabled']:
        send_email_ssh(message)
    elif webmail_enabled:
        send_email_webmail(message)
    elif proxy_options['enabled']:
        send_email_proxy(message)
    else:
        send_email_smtp(message)

def send_email_smtp(message):
    with smtplib.SMTP(smtp_options['host'], smtp_options['port']) as server:
        server.starttls()
        server.login(smtp_options['username'], smtp_options['password'])
        server.send_message(message)

def send_email_proxy(message):
    with smtplib.SMTP(proxy_options['host'], proxy_options['port']) as server:
        server.starttls()
        server.login(proxy_options['username'], proxy_options['password'])
        
        with server.open_connection(smtp_options['host'], smtp_options['port']) as smtp_conn:
            smtp_conn.starttls()
            smtp_conn.login(smtp_options['username'], smtp_options['password'])
            smtp_conn.send_message(message)

def send_email_webmail(message):
    if webmail_options['service'] == 'Gmail':
        with smtplib.SMTP(webmail_options['smtp_server'], webmail_options['smtp_port']) as server:
            server.starttls()
            server.login(webmail_options['username'], webmail_options['password'])
            server.send_message(message)
    elif webmail_options['service'] == 'OtherWebmailService':
        # Add your specific logic for other webmail services here
        pass

def send_email_ssh(message):
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_client.connect(ssh_options['host'], ssh_options['port'], ssh_options['username'], ssh_options['password'])
    
    stdin, stdout, stderr = ssh_client.exec_command(f'echo "{message.as_string()}" | sendmail -t')
    ssh_client.close()

def send_email_gmail_api(message):
    credentials = Credentials.from_authorized_user_file(gmail_api_options['token_path'], gmail_api_options['scope'])
    service = build('gmail', 'v1', credentials=credentials)
    
    email_message = {
        'raw': b64encode(message.as_bytes()).decode(),
    }
    service.users().messages().send(userId='me', body=email_message).execute()

# Read files
sender_email = read_file(sender_email_path)
recipient_email = read_file(recipient_email_path)
sender_name = read_file(sender_name_path)
subject_line = read_file(subject_line_path)
message_body = read_file(message_html_path)

# Generate random strings and country
random_strings = {
    'randomstring5': random_string(5),
    'randomstring8': random_string(8),
    'randomstring25': random_string(25),
    'randomstring12': random_string(12),
    'randomcountry': random_country(),
    'receipents_emailbese64': b64encode(recipient_email.encode()).decode(),
    'time': time.strftime("%H:%M:%S"),  # Current time
    'date': time.strftime("%Y-%m-%d"),  # Current date
    'month': time.strftime("%B"),  # Current month
    'day': time.strftime("%A"),  # Current day
    'yesterday': (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d"),  # Yesterday's date
    'tomorrow': (datetime.now() + timedelta(days=1)).strftime("%Y-%m-%d"),  # Tomorrow's date
    'randomphonenumber': random_phone_number(),  # Random phone number
}

# Merge fields into the message body
for field, value in random_strings.items():
    message_body = message_body.replace(f'{{{field}}}', value)

# Enable/Disable options
def enable_disable_options():
    global html_to_image_enabled, html_to_pdf_enabled, html_to_eml_enabled, html_file_enabled, reply_to_enabled, encryption_enabled, priority_enabled, test_email_enabled, webmail_enabled
    
    options = ["Enable", "Disable"]
    enabled_options = checkbox("Enable/Disable Options", options, default_value=options)
    
    if "Enable" in enabled_options:
        html_to_image_enabled = True
    if "Disable" in enabled_options:
        html_to_image_enabled = False
    
    if "Enable" in enabled_options:
        html_to_pdf_enabled = True
    if "Disable" in enabled_options:
        html_to_pdf_enabled = False
    
    if "Enable" in enabled_options:
        html_to_eml_enabled = True
    if "Disable" in enabled_options:
        html_to_eml_enabled = False
    
    if "Enable" in enabled_options:
        html_file_enabled = True
    if "Disable" in enabled_options:
        html_file_enabled = False
    
    reply_to_enabled = radio("Enable/Disable Reply-To", options=["Enable", "Disable"]) == "Enable"
    
    encryption_enabled = radio("Enable/Disable Encryption", options=["Enable", "Disable"]) == "Enable"
    
    priority_enabled = radio("Enable/Disable Priority", options=["Enable", "Disable"]) == "Enable"
    
    test_email_enabled = checkbox("Enable/Disable Test Email", ["Enable"], value=[test_email_enabled])
    
    webmail_enabled = radio("Enable/Disable Webmail", options=["Enable", "Disable"]) == "Enable"

# Enable/Disable options
enable_disable_options()

# Set priority value
if priority_enabled:
    priority_value = input("Enter Priority Value (1-5):", type=NUMBER, validate=lambda v: 1 <= v <= 5)

# Encode content with HTML escape codes
def encode_html_escape_codes(content):
    html_escape_codes = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        '\'': '&#39;'
    }
    
    encoded_content = ""
    for char in content:
        if char in html_escape_codes:
            encoded_content += html_escape_codes[char]
        else:
            encoded_content += char
    
    return encoded_content

# Encrypt file content
def encrypt_content(content):
    if encryption_enabled:
        # Perform encryption on content
        # Replace this with your encryption logic
        encrypted_content = "<encrypted>" + content + "</encrypted>"
        return encrypted_content
    else:
        return content

# Function to convert HTML to image
def convert_to_image():
    if html_to_image_enabled:
        # Perform conversion to image and save it to image_path
        image_path = Path('htmltoimage.html')
        # Add your conversion logic here
        
        # Create message
        subject = subject_line  # Replace with the subject line read from subjectline.txt
        message = create_message(sender_email, recipient_email, sender_name, subject, message_body)
        if reply_to_enabled:
            message["Reply-To"] = recipient_email
        if priority_enabled:
            message["X-Priority"] = str(priority_value)

        # Send email
        send_email(message)

        # Check if test email should be sent
        if test_email_enabled and successful_sent_messages % test_email_interval == 0:
            send_test_email()

# Function to convert HTML to PDF
def convert_to_pdf():
    if html_to_pdf_enabled:
        # Perform conversion to PDF and save it to pdf_path
        pdf_path = Path('htmltopdf.html')
        # Add your conversion logic here
        
        # Create message
        subject = subject_line  # Replace with the subject line read from subjectline.txt
        message = create_message(sender_email, recipient_email, sender_name, subject, message_body)
        if reply_to_enabled:
            message["Reply-To"] = recipient_email
        if priority_enabled:
            message["X-Priority"] = str(priority_value)

        # Send email
        send_email(message)

        # Check if test email should be sent
        if test_email_enabled and successful_sent_messages % test_email_interval == 0:
            send_test_email()

# Function to convert HTML to EML
def convert_to_eml():
    if html_to_eml_enabled:
        # Perform conversion to EML and save it to eml_path
        eml_path = Path('htmltoeml.html')
        # Add your conversion logic here
        
        # Create message
        subject = subject_line  # Replace with the subject line read from subjectline.txt
        message = create_message(sender_email, recipient_email, sender_name, subject, message_body)
        if reply_to_enabled:
            message["Reply-To"] = recipient_email
        if priority_enabled:
            message["X-Priority"] = str(priority_value)

        # Send email
        send_email(message)

        # Check if test email should be sent
        if test_email_enabled and successful_sent_messages % test_email_interval == 0:
            send_test_email()

# Function to create HTML file
def create_html_file():
    if html_file_enabled:
        # Read content from attachfile.html
        with open(attachfile_path, 'r') as file:
            file_content = file.read()

        # Encrypt content if encryption is enabled
        encrypted_content = encrypt_content(file_content)

        # Write encrypted content to a new file
        encrypted_attachfile_path = Path('encrypted_attachfile.html')
        with open(encrypted_attachfile_path, 'w') as file:
            file.write(encrypted_content)

        # Create message
        subject = subject_line  # Replace with the subject line read from subjectline.txt
        message = create_message(sender_email, recipient_email, sender_name, subject, message_body)
        if reply_to_enabled:
            message["Reply-To"] = recipient_email
        if priority_enabled:
            message["X-Priority"] = str(priority_value)

        # Send email
        send_email(message)

        # Check if test email should be sent
        if test_email_enabled and successful_sent_messages % test_email_interval == 0:
            send_test_email()

# Function to send test email
def send_test_email():
    test_message = create_message(sender_email, test_email_recipient, sender_name, "Test Email", "This is a test email.")
    send_email(test_message)

# Function to send email using webmail
def send_email_webmail():
    global sender_email, webmail_options
    
    # Create message
    subject = subject_line  # Replace with the subject line read from subjectline.txt
    message = create_message(sender_email, recipient_email, sender_name, subject, message_body)
    if reply_to_enabled:
        message["Reply-To"] = recipient_email
    if priority_enabled:
        message["X-Priority"] = str(priority_value)

    # Send email using webmail
    if webmail_options['service'] == 'Gmail':
        with smtplib.SMTP(webmail_options['smtp_server'], webmail_options['smtp_port']) as server:
            server.starttls()
            server.login(webmail_options['username'], webmail_options['password'])
            server.send_message(message)
    elif webmail_options['service'] == 'OtherWebmailService':
        # Add your specific logic for other webmail services here
        pass

# Function to send email using Gmail API
def send_email_gmail_api():
    global sender_email
    
    # Create message
    subject = subject_line  # Replace with the subject line read from subjectline.txt
    message = create_message(sender_email, recipient_email, sender_name, subject, message_body)
    if reply_to_enabled:
        message["Reply-To"] = recipient_email
    if priority_enabled:
        message["X-Priority"] = str(priority_value)

    # Send email using Gmail API
    credentials = Credentials.from_authorized_user_file(gmail_api_options['token_path'], gmail_api_options['scope'])
    service = build('gmail', 'v1', credentials=credentials)
    
    email_message = {
        'raw': b64encode(message.as_bytes()).decode(),
    }
    service.users().messages().send(userId='me', body=email_message).execute()

# Create semaphore to limit the number of concurrent connections
semaphore = threading.Semaphore(max_connections)

# Create threads for each functionality
threads = []

# Counter for successful sent messages
successful_sent_messages = 0

# HTML to image thread
image_thread = threading.Thread(target=lambda: semaphore.acquire() or convert_to_image(), daemon=True)
threads.append(image_thread)

# HTML to PDF thread
pdf_thread = threading.Thread(target=lambda: semaphore.acquire() or convert_to_pdf(), daemon=True)
threads.append(pdf_thread)

# HTML to EML thread
eml_thread = threading.Thread(target=lambda: semaphore.acquire() or convert_to_eml(), daemon=True)
threads.append(eml_thread)

# Create HTML file thread
html_file_thread = threading.Thread(target=lambda: semaphore.acquire() or create_html_file(), daemon=True)
threads.append(html_file_thread)

# Webmail thread
webmail_thread = threading.Thread(target=lambda: semaphore.acquire() or send_email_webmail(), daemon=True)
threads.append(webmail_thread)

# Gmail API thread
gmail_api_thread = threading.Thread(target=lambda: semaphore.acquire() or send_email_gmail_api(), daemon=True)
threads.append(gmail_api_thread)

# Start all threads
for thread in threads:
    thread.start()

# Wait for all threads to complete
for thread in threads:
    thread.join()

# Release the semaphore
for _ in range(max_connections):
    semaphore.release()
