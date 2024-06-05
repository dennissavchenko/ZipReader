import requests
from PIL import Image
from io import BytesIO

# Unsplash API credentials
UNSPLASH_ACCESS_KEY = '2ae4VHpLVcxzYt4fD3O5OjRNKmgSbiJn2-KdA48iCBI'


def get_random_photo():
    url = "https://api.unsplash.com/photos/random"
    # Defining my Client-ID for authorization
    headers = {
        "Authorization": f"Client-ID {UNSPLASH_ACCESS_KEY}"
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        print("Failed to fetch photo from Unsplash")
        return None


# Saving the random photo to the project root as 'new_image.jpg'
def save_photo(photo_url):
    photo_name = 'new_image.jpg'
    response = requests.get(photo_url)
    if response.status_code == 200:
        img = Image.open(BytesIO(response.content))
        img.save(photo_name)
        return photo_name
    else:
        print("Failed to download the photo")


# Generates random photo (executing get_random_photo()), saves it in the root (executing save_photo())
def generate_random_photo():
    photo = get_random_photo()
    if photo:
        photo_url = photo['urls']['regular']
        return save_photo(photo_url)
