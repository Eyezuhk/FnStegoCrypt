# FnStegoCrypt

`FnStegoCrypt` é um script Python para ocultar dados criptografados de forma segura dentro de arquivos de imagem utilizando esteganografia.
Apoie com BTC: bc1qgch352sr3pf5l9nrr5knf7ls9hac3k60uxndwr

## Algoritmos Utilizados
- **AES-GCM (Advanced Encryption Standard - Galois/Counter Mode)**: Utilizado para criptografia dos dados.
- **PBKDF2 (Password-Based Key Derivation Function 2)**: Utilizado para derivação de chave a partir da senha fornecida.
- **LSB (Least Significant Bit) Steganography**: Utilizado para esconder os dados criptografados dentro das imagens.

## Dependências
Instale as dependências necessárias usando pip:
```bash
pip install numpy cryptography Pillow pillow-heif
```

## Suporte a Formatos de Imagem
- PNG JPG/JPEG HEIF/HEIC

## Aviso de Suporte
Este projeto é fornecido "como está", sem qualquer tipo de suporte ou garantia. Use por sua conta e risco. O autor não se responsabiliza por qualquer dano ou perda de dados decorrente do uso deste software.

## Notas Importantes
A senha deve conter apenas caracteres ASCII.
Certifique-se de que a capacidade da imagem é suficiente para armazenar os dados. Caso contrário, uma mensagem de erro será exibida.
A imagem de saída com os dados ocultos será salva no formato original, a menos que seja HEIC, nesse caso será convertida para PNG.

## Contribuição
Sinta-se à vontade para contribuir com melhorias, correções de bugs ou novas funcionalidades. Envie um pull request ou abra uma issue no repositório GitHub.

## Licença
Este projeto está licenciado sob a Licença MIT. Veja o arquivo LICENSE para mais detalhes.
