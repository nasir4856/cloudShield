import io
import random
import string

from flask import session
from PIL import Image, ImageDraw, ImageFont


def generate_captcha() -> io.BytesIO:
    captcha_text = "".join(random.choices(string.ascii_uppercase + string.digits, k=6))
    session["captcha"] = captcha_text

    image = Image.new("RGB", (200, 50), color="darkblue")
    font = ImageFont.load_default()
    draw = ImageDraw.Draw(image)
    draw.text((50, 10), captcha_text, font=font, fill="white")

    image_io = io.BytesIO()
    image.save(image_io, "PNG")
    image_io.seek(0)
    return image_io

