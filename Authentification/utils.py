import os
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from dotenv import load_dotenv

# Charger les variables d'environnement
load_dotenv()

def send_email(subject, html_content, to_email):
    try:
        sendgrid_api_key = os.environ.get('SENDGRID_API_KEY')
        if not sendgrid_api_key:
            raise ValueError("No SendGrid API key found in environment variables.")
        
        sg = SendGridAPIClient(sendgrid_api_key)
        message = Mail(
            from_email='lokopetrarque2003@gmail.com',
            to_emails=to_email,
            subject=subject,
            html_content=html_content
        )
        response = sg.send(message)
        return response
    except Exception as e:
        print(f"Error sending email: {e}")
        return None