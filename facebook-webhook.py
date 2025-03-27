import os
import hmac
import hashlib
from flask import Flask, request, jsonify

app = Flask(__name__)

# Replace these with your actual Facebook App credentials
FACEBOOK_APP_SECRET = 'your_facebook_app_secret'
VERIFY_TOKEN = '123456789'

@app.route('/webhook', methods=['GET', 'POST'])
def webhook():
    # Webhook verification for initial setup
    if request.method == 'GET':
        # Verify the webhook from Facebook
        if (request.args.get('hub.mode') == 'subscribe' and 
            request.args.get('hub.verify_token') == VERIFY_TOKEN):
            return request.args.get('hub.challenge'), 200
        else:
            return 'Verification failed', 403
    
    # Handle incoming webhook events
    elif request.method == 'POST':
        # Verify the webhook signature
        if not verify_signature(request):
            return 'Signature verification failed', 403
        
        # Parse the webhook payload
        payload = request.get_json()
        
        # Process different types of events
        process_webhook_events(payload)
        
        return 'EVENT_RECEIVED', 200

def verify_signature(request):
    """
    Verify the signature of the incoming webhook request
    """
    try:
        # Get the X-Hub-Signature header
        signature = request.headers.get('X-Hub-Signature-256', '')
        
        # Compute the signature using the raw request body and app secret
        raw_body = request.get_data()
        expected_signature = 'sha256=' + hmac.new(
            FACEBOOK_APP_SECRET.encode('utf-8'),
            raw_body,
            hashlib.sha256
        ).hexdigest()
        
        # Compare signatures
        return hmac.compare_digest(signature, expected_signature)
    except Exception as e:
        print(f"Signature verification error: {e}")
        return False

def process_webhook_events(payload):
    """
    Process different types of Facebook Page webhook events
    """
    # Check if this is a page webhook
    if 'object' in payload and payload['object'] == 'page':
        # Iterate through each entry
        for entry in payload.get('entry', []):
            # Page ID of the page that triggered the webhook
            page_id = entry.get('id')
            
            # Process different messaging events
            for messaging in entry.get('messaging', []):
                # Handle message events
                if 'message' in messaging:
                    handle_message_event(messaging)
                
                # Handle postback events (like button clicks)
                elif 'postback' in messaging:
                    handle_postback_event(messaging)
                
                # Handle other event types as needed
                # Add more event handlers here

def handle_message_event(messaging):
    """
    Handle incoming message events
    """
    sender_id = messaging['sender']['id']
    message = messaging['message']
    
    # Log or process the incoming message
    print(f"Received message from {sender_id}: {message.get('text', 'No text')}")
    
    # Add your custom message handling logic here
    # For example, sending a response back to the user

def handle_postback_event(messaging):
    """
    Handle postback events (like button clicks)
    """
    sender_id = messaging['sender']['id']
    postback = messaging['postback']
    
    # Log or process the postback
    print(f"Received postback from {sender_id}: {postback.get('payload', 'No payload')}")
    
    # Add your custom postback handling logic here

if __name__ == '__main__':
    # Run the Flask app
    app.run(port=5000, debug=True)

# Requirements:
# pip install flask
# 
# Webhook Setup Steps:
# 1. Create a Facebook App in Facebook Developers Console
# 2. Configure the webhook URL in your Facebook App settings
# 3. Subscribe the webhook to your Facebook Page events
