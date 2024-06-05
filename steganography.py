from PIL import Image
import stepic
import os


# Encoding a secret message in an image
def encode_message(image, message):
    try:
        img = Image.open(image)
        img = img.convert("RGB")
        encoded_img = stepic.encode(img, message.encode())
        encoded_img.save('password_clue.png')
        os.remove('new_image.jpg')
        print("You now can find steganography with the new ZIP file password clue!")
    except Exception as e:
        print(f"Error: {str(e)}")


# Decoding an image's secret message
def decode_message(image):
    try:
        img = Image.open(image)
        img = img.convert("RGB")
        message = stepic.decode(img)
        return message
    except Exception as e:
        print(f"Error: {str(e)}")

