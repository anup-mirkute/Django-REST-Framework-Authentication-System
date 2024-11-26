from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.shortcuts import reverse
import uuid
from datetime import datetime

def generate_filename(instance, of_img):
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S%f")[:-3]
    unique_id = str(uuid.uuid4())[:8]
    if of_img == 'Profile':
        image_name = f"{of_img}_{timestamp}_{unique_id}.png"
    elif of_img == 'Cover':
        image_name = f"{of_img}_{timestamp}_{unique_id}.jpeg"
    else:
        pass
    return image_name


def generate_token(request, user, path_name):
    generate_token = default_token_generator
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = generate_token.make_token(user)
    url = request.build_absolute_uri(reverse(path_name, kwargs={'uidb64' : uid, 'token' : token}))
    return url