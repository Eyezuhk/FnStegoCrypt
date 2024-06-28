import os
import numpy as np
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PIL import Image
import struct
import glob
from pillow_heif import register_heif_opener
import concurrent.futures

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
        self.salt = None

    def generate_salt(self):
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

    def check_image_capacity(self, img_array: np.ndarray, data_length: int):
        """Verifica se a imagem tem capacidade suficiente para os dados."""
        max_bytes = img_array.size * 3 // 8
        if data_length > max_bytes:
            raise ValueError("Data is too large for the image")

    def hide_data_in_image(self, image_path: str, data: bytes, output_dir: str):
        """Esconde os dados na imagem usando NumPy para melhor performance."""
        # Carrega a imagem como um array NumPy
        img = Image.open(image_path)
        if img.mode != 'RGB':
            img = img.convert('RGB')
        img_array = np.array(img)

        data_hash = self.hash_data(data)
        data_to_hide = self.salt + data_hash + data
        binary_data = struct.pack('>I', len(data_to_hide)) + data_to_hide

        self.check_image_capacity(img_array, len(binary_data))

        # Converte os dados para um array de bits
        bits = np.unpackbits(np.frombuffer(binary_data, dtype=np.uint8))

        # Prepara a máscara para os LSBs
        mask = np.zeros(img_array.shape[:2] + (3,), dtype=np.uint8)
        mask.flat[:bits.size] = bits

        # Aplica a máscara à imagem
        img_array[..., :3] &= 0xFE  # Zera o LSB
        img_array[..., :3] |= mask  # Aplica os novos LSBs

        # Salva a imagem modificada
        output_filename = os.path.join(output_dir, os.path.basename(image_path))
        _, ext = os.path.splitext(output_filename)
        if ext.lower() == '.heic':
            output_filename = output_filename[:-5] + "_stego.png"
        else:
            output_filename = output_filename[:-4] + "_stego.png"
        
        Image.fromarray(img_array).save(output_filename, format="PNG")
        return f"\nData hidden in image: {output_filename}"

    def extract_data_from_image(self, image_path: str) -> bytes:
        """Extrai os dados escondidos na imagem usando NumPy para melhor performance."""
        # Carrega a imagem como um array NumPy
        img_array = np.array(Image.open(image_path))

        # Extrai os LSBs
        lsb = img_array[..., :3] & 1
        bits = np.packbits(lsb.reshape(-1))

        # Extrai o comprimento dos dados
        data_length = struct.unpack('>I', bits[:4].tobytes())[0]
        
        # Extrai os dados
        extracted_data = bits[4:4+data_length].tobytes()

        self.salt = extracted_data[:SALT_SIZE]
        extracted_hash = extracted_data[SALT_SIZE:SALT_SIZE+HASH_SIZE]
        extracted_content = extracted_data[SALT_SIZE+HASH_SIZE:]
        
        if self.hash_data(extracted_content) != extracted_hash:
            raise ValueError("Data integrity check failed")
        
        return extracted_content

def clean_path(path: str) -> str:
    """Limpa e normaliza o caminho do arquivo."""
    return os.path.abspath(os.path.expanduser(path.strip().strip('"').strip("'")))

def process_single_image(stego: ImprovedSteganography, file_path: str, output_dir: str, data: bytes, password: str):
    """Processa uma única imagem."""
    try:
        stego.generate_salt()
        encrypted_data = stego.encrypt_data(data, password)
        return stego.hide_data_in_image(file_path, encrypted_data, output_dir)
    except Exception as e:
        return f"\nError processing {file_path}: {str(e)}"

def process_directory(stego: ImprovedSteganography, input_dir: str, output_dir: str, data: bytes, password: str):
    """Processa todos os arquivos de imagem em um diretório usando threads."""
    supported_formats = ('.png', '.jpg', '.jpeg', '.heif', '.heic')
    image_files = [f for f in glob.glob(os.path.join(input_dir, '*')) if f.lower().endswith(supported_formats)]
    
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = [executor.submit(process_single_image, stego, file_path, output_dir, data, password) 
                   for file_path in image_files]
        
        for future in concurrent.futures.as_completed(futures):
            print(future.result())

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
                    result = process_single_image(stego, input_path, output_dir, data, password)
                    print(result)
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
