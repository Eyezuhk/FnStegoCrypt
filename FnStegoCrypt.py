import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PIL import Image
import struct
import glob
from pillow_heif import register_heif_opener

print("{:^80}".format("""
#######         #####                              #####        #     #
#       #    # #     # ##### ######  ####   ####  #     # #####  #   # #####  #####
#       ##   # #         #   #      #    # #    # #       #    #  # #  #    #   #
#####   # #  #  #####    #   #####  #      #    # #       #    #   #   #    #   #
#       #  # #       #   #   #      #  ### #    # #       #####    #   #####    #
#       #   ##       #   #   #      #    # #    # #     # #   #    #   #        #
#       #    #  #####    #   ######  ####   ####   #####  #    #   #   #        #
"""))


# Registrar o opener HEIF
register_heif_opener()

# Constantes
SALT_SIZE = 16
NONCE_SIZE = 12
HASH_SIZE = 32
KDF_ITERATIONS = 100000

class ImprovedSteganography:
    def __init__(self):
        self.salt = os.urandom(SALT_SIZE)

    def _derive_key(self, password):
        """Deriva uma chave a partir da senha."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=KDF_ITERATIONS,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    def encrypt_data(self, data: bytes, password: str) -> bytes:
        """Encripta os dados usando AES-GCM."""
        key = self._derive_key(password)
        aesgcm = AESGCM(key)
        nonce = os.urandom(NONCE_SIZE)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        return nonce + ciphertext

    def decrypt_data(self, encrypted_data: bytes, password: str) -> bytes:
        """Decripta os dados usando AES-GCM."""
        key = self._derive_key(password)
        aesgcm = AESGCM(key)
        nonce = encrypted_data[:NONCE_SIZE]
        ciphertext = encrypted_data[NONCE_SIZE:]
        return aesgcm.decrypt(nonce, ciphertext, None)

    def hash_data(self, data: bytes) -> bytes:
        """Calcula o hash SHA-256 dos dados."""
        digest = hashes.Hash(hashes.SHA256())
        digest.update(data)
        return digest.finalize()

    def check_image_capacity(self, image_path: str, data_length: int):
        """Verifica se a imagem tem capacidade suficiente para os dados."""
        with Image.open(image_path) as img:
            if img.mode != 'RGB':
                img = img.convert('RGB')
            width, height = img.size
            max_bytes = (width * height * 3) // 8
            if data_length > max_bytes:
                raise ValueError("Data is too large for the image")

    def hide_data_in_image(self, image_path: str, data: bytes, output_dir: str):
        """Esconde os dados na imagem."""
        with Image.open(image_path) as img:
            if img.mode != 'RGB':
                img = img.convert('RGB')
            
            img_copy = img.copy()
            width, height = img_copy.size
            pixels = img_copy.load()

            data_hash = self.hash_data(data)
            data_to_hide = data_hash + data
            binary_data = struct.pack('>I', len(data_to_hide)) + data_to_hide
            binary_data = ''.join(format(byte, '08b') for byte in binary_data)
            data_length = len(binary_data)

            self.check_image_capacity(image_path, len(data_to_hide))

            index = 0
            for y in range(height):
                for x in range(width):
                    pixel = list(pixels[x, y])
                    for c in range(3):
                        if index < data_length:
                            pixel[c] = pixel[c] & ~1 | int(binary_data[index])
                            index += 1
                        else:
                            break
                    pixels[x, y] = tuple(pixel)
                    if index >= data_length:
                        break
                if index >= data_length:
                    break

            output_filename = os.path.join(output_dir, os.path.basename(image_path))
            _, ext = os.path.splitext(output_filename)
            if ext.lower() == '.heic':
                output_filename = output_filename[:-5] + "_stego.png"
                img_copy.save(output_filename, format="PNG")
            else:
                img_copy.save(output_filename)
            print(f"\nData hidden in image: {output_filename}")

    def extract_data_from_image(self, image_path: str) -> bytes:
        """Extrai os dados escondidos na imagem."""
        with Image.open(image_path) as img:
            if img.mode != 'RGB':
                img = img.convert('RGB')
            width, height = img.size
            pixels = img.load()

            binary_data = ""
            for y in range(height):
                for x in range(width):
                    pixel = pixels[x, y]
                    for c in range(3):
                        binary_data += str(pixel[c] & 1)

            data_length = struct.unpack('>I', int(binary_data[:32], 2).to_bytes(4, byteorder='big'))[0]
            extracted_data = int(binary_data[32:32+data_length*8], 2).to_bytes(data_length, byteorder='big')
            
            extracted_hash = extracted_data[:HASH_SIZE]
            extracted_content = extracted_data[HASH_SIZE:]
            if self.hash_data(extracted_content) != extracted_hash:
                raise ValueError("Data integrity check failed")
            
            return extracted_content

def clean_path(path: str) -> str:
    """Limpa e normaliza o caminho do arquivo."""
    return os.path.abspath(os.path.expanduser(path.strip().strip('"').strip("'")))

def process_directory(stego: ImprovedSteganography, input_dir: str, output_dir: str, data: bytes, password: str):
    """Processa todos os arquivos de imagem em um diretório."""
    supported_formats = ('.png', '.jpg', '.jpeg', '.heif', '.heic')
    for file_path in glob.glob(os.path.join(input_dir, '*')):
        if file_path.lower().endswith(supported_formats):
            try:
                encrypted_data = stego.encrypt_data(data, password)
                stego.hide_data_in_image(file_path, encrypted_data, output_dir)
            except Exception as e:
                print(f"\nError processing {file_path}: {str(e)}")

def main():
    stego = ImprovedSteganography()
    max_attempts = 3

    while True:
        choice = input("\nDo you want to write (w) or read (r) data? (or 'q' to quit): ").lower()

        if choice == 'q':
            break
        elif choice == 'w':
            password = input("Enter the password: ")
            input_path = clean_path(input("Enter the path to the image or directory: "))
            text_file = clean_path(input("Enter the path to the text file: "))
            output_dir = clean_path(input("Enter the path to save the output: "))

            if not os.path.exists(output_dir):
                os.makedirs(output_dir)

            try:
                with open(text_file, 'rb') as f:
                    data = f.read()

                if os.path.isdir(input_path):
                    process_directory(stego, input_path, output_dir, data, password)
                else:
                    encrypted_data = stego.encrypt_data(data, password)
                    stego.hide_data_in_image(input_path, encrypted_data, output_dir)
                print("\nData has been encrypted and hidden in the image(s)")
            except Exception as e:
                print(f"\nAn error occurred: {str(e)}")

        elif choice == 'r':
            image_path = clean_path(input("Enter the path to the stego image: "))
            
            for attempt in range(max_attempts):
                password = input("Enter the password: ")
                try:
                    extracted_data = stego.extract_data_from_image(image_path)
                    decrypted_data = stego.decrypt_data(extracted_data, password)
                    
                    print("\nPassword is correct. Data decrypted successfully.")
                    
                    output_choice = input("\nDo you want to view (v) the data or save (s) it to a file? ").lower()

                    if output_choice == 'v':
                        print("\nDecrypted data:\n")
                        print(decrypted_data.decode('utf-8'))
                    elif output_choice == 's':
                        output_file = clean_path(input("\nEnter the path for the output file: "))
                        with open(output_file, 'wb') as f:
                            f.write(decrypted_data)
                        print(f"\nDecrypted data has been saved to {output_file}")
                    else:
                        print("\nInvalid choice. Data will not be displayed or saved.")
                    break
                except ValueError as ve:
                    print(f"\nDecryption error: {str(ve)}. This might be due to an incorrect password or no hidden data.")
                    if attempt < max_attempts - 1:
                        print(f"You have {max_attempts - attempt - 1} attempts remaining.")
                    else:
                        print("Maximum number of attempts reached. Please try again later.")
                except Exception as e:
                    print(f"\nAn error occurred: {str(e)}")
                    break
        else:
            print("\nInvalid choice. Please enter 'w' for write, 'r' for read, or 'q' to quit.")

if __name__ == "__main__":
    main()
