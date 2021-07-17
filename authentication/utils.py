from django.core.mail import EmailMessage

class Util:
    @staticmethod
    def send_mail(data):
        email = EmailMessage(subject=data['subject'], body=data['body'], to=[data['to']])
        email.send()
