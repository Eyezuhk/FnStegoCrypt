# FnStegoCrypt

`FnStegoCrypt` is a Python script for securely hiding encrypted data inside image files using steganography.

Back it up with BTC: 
```
bc1qgch352sr3pf5l9nrr5knf7ls9hac3k60uxndwr
```

## Algorithms 
- **AES-GCM (Advanced Encryption Standard - Galois/Counter Mode)**: Used for data encryption.
- **PBKDF2 (Password-Based Key Derivation Function 2)**: Used to derive the key from the password provided.
- **LSB (Least Significant Bit) Steganography**: Used to hide encrypted data within images.

## Dependencies
Install the necessary dependencies using pip:
```bash
pip install numpy cryptography Pillow pillow-heif
```

## Image Format Support
- PNG JPG/JPEG HEIF/HEIC
 
## Theoretical capability
- Full HD (1920x1080 pixels) - approximately 778,600 bytes 750-800 KB
- 4K (3840x2160 pixels) - approximately 3,932,160 bytes (3.7-4.1 MB)

## Support Warning
This project is supplied "as it is", without any kind of support or guarantee. Use at your own risk. 

The author is not responsible for any damage or loss of data resulting from the use of this software

## Important Notes
The password must only contain ASCII characters.

Make sure that the capacity of the image is sufficient to store the data. Otherwise, an error message will be displayed.

The output image with the hidden data will be converted to PNG.

## Contributions
Feel free to contribute improvements, bug fixes or new features. Send a pull request or open an issue in the GitHub repository.]

## License
This project is licensed under the MIT License. See the LICENSE file for more details.
