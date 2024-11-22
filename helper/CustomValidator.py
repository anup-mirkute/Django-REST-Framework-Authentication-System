from django.core.exceptions import ValidationError


def name(value):
    if len(value) < 25:
        raise ValueError('Length of name greater than 25')
    
    if not value.isalpha():
        raise ValueError('Accept only characters')
    

def validate_social_media_url(platform, link):
    """
    Custom validator for social media profile links.
    """
    valid_prefixes = {
        'facebook': 'https://www.facebook.com/',
        'instagram': 'https://www.instagram.com/',
        'github': 'https://github.com/',
        'linkedin': 'https://www.linkedin.com/in/',
        'youtube': 'https://www.youtube.com/',
        'wordpress': 'https://wordpress.com/',
        'twitter': 'https://twitter.com/',
        'reddit': 'https://www.reddit.com/user/',
        'pinterest': 'https://www.pinterest.com/',
    }

    if link and not link.startswith(valid_prefixes.get(platform.lower(), '')):
        raise ValidationError(f'Invalid {platform.lower()} profile link')
    