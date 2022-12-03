from django.core.mail import EmailMessage


def send_email(to_user, subject, body):
    EmailMessage(to=[to_user.email], subject=subject, body=body).send()
