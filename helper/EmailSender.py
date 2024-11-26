import os
import mimetypes
from django.conf import settings
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.core.mail import EmailMultiAlternatives, send_mail

class EmailSender:
    '''
    subject         ->  str     :   Mandatory : Subject of the Mail
    recipient_list  ->  list    :   List of mail addresses that you want to send the mail
    user            ->  str     :   current user's username 
    message         ->  str     :   A message is optional if you want to send the template with the mail otherwise it is mandatory field and having with HTML attribute.
    cc_email        ->  list    :   List of mail addresses that you want to keep in cc
    bcc_email       ->  list    :   List of mail addresses that you want to keep in bcc
    template_name   ->  str     :   A template_name is optional if you just want to send a message with the mail otherwise it is mandatory field to send the template with the mail.
    links           ->  list    :   Optional : A Link with the mail
    otp             ->  str     :   Optional : A OTP with the mail
    token           ->  str     :   Optional : A token with the mail

    '''
    def __init__(self, subject, recipient_list, user=None, message=None, cc_email=None, bcc_email=None, template_name=None, file_name=None, links=None, otp=None, token=None):
        self.subject = subject
        self.from_mail = settings.EMAIL_HOST_USER
        self.recipient_list = recipient_list
        self.user = user
        self.message = message
        self.cc_email = cc_email
        self.bcc_email = bcc_email
        self.template_name = template_name
        self.file_name = file_name
        self.links = links
        self.otp = otp
        self.token = token

    def sending_mail(self):
        if self.template_name is not None:
            template = 'email_template/' + self.template_name
            context = {
                'user' : self.user,
                'recipient_list' : self.recipient_list,
                'links' : self.links,
                'otp' : self.otp,
                'token' : self.token,
            }
            html_content = render_to_string(template, context)
        else:
            html_content = self.message

        text_content = strip_tags(html_content) 
        msg = EmailMultiAlternatives(self.subject, text_content, self.from_mail, self.recipient_list)
        msg.attach_alternative(html_content, "text/html")

        if self.cc_email is not None:
            msg.cc = self.cc_email

        if self.bcc_email is not None:
            msg.bcc = self.bcc_email

        if self.file_name is not None:
            file_path = os.path.join(settings.MEDIA_ROOT, 'email_attachment', self.file_name)

            # Determine the content type and encoding for the attachment
            content_type, encoding = mimetypes.guess_type(file_path)
            if content_type is None or encoding is not None:
                content_type = 'application/octet-stream'  # Default content type if it cannot be determined

            with open(file_path, 'rb') as file:
                msg.attach(self.file_name, file.read(), content_type)


        msg.send()