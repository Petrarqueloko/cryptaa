import os
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, Email, Content
from dotenv import load_dotenv

# Charger les variables d'environnement à partir du fichier .env
load_dotenv()

def send_test_email():
    # Récupérer la clé API SendGrid depuis les variables d'environnement
    sendgrid_api_key = os.getenv('SENDGRID_API_KEY')
    if not sendgrid_api_key:
        print("SendGrid API key not found.")
        return
    
    # Créer le client SendGrid en utilisant la clé API
    sg = SendGridAPIClient(api_key=sendgrid_api_key)
    
    # Créer le message
    from_email = Email('lokopetrarque2003@gmail.com')
    to_email = Email('footfans2024@gmail.com')
    subject = 'Test Email'
    content = Content('text/html', '<strong>Testing SendGrid integration</strong>')
    message = Mail(from_email, to_email, subject, content)
    
    try:
        response = sg.send(message)
        print(f"Email sent with response: {response.status_code}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == '__main__':
    send_test_email()