#pragma once
#include "Prerequisites.h"
#include "openssl\rsa.h"
#include "openssl\aes.h"

class 
CryptoHelper {
public:
	CryptoHelper();
	~CryptoHelper();

  // RSA


  /**
  * @brief Genera un nuevo par de claves RSA de 2048 bits.
  */
  void 
  GenerateRSAKeys();
  

  /**
   * @brief Devuelve la clave pública en formato PEM (como string).
   */
  std::string 
  GetPublicKeyString() const;
  

  /**
   * @brief Carga la clave pública del peer desde un string PEM.
   */
  void 
  LoadPeerPublicKey(const std::string& pemKey);

  // AES

  /**
   * @brief Genera una clave AES-256 (32 bytes aleatorios).
   */
  void 
  GenerateAESKey();

  /**
   * @brief Cifra la clave AES con la clave pública del peer usando RSA.
   */
  std::vector<unsigned char> 
  EncryptAESKeyWithPeer();

  /**
   * @brief Descifra la clave AES enviada por el cliente.
   */
  void 
  DecryptAESKey(const std::vector<unsigned char>& encryptedKey);

  /**
   * @brief Cifra un mensaje usando AES-256 en modo CBC.
   * @param plaintext El texto plano a cifrar.
   * @param outIV Vector donde se guardará el IV usado para el cifrado.
   * @return El texto cifrado como vector de bytes.
	 */
  std::vector<unsigned char> 
  AESEncrypt(const std::string& plaintext, std::vector<unsigned char>& outIV);
  
  /**
   * @brief Descifra un mensaje cifrado con AES-256-CBC.
   * @param ciphertext Vector cifrado.
   * @param iv Vector con el IV usado durante el cifrado.
   * @return Texto original.
   */
  std::string 
  AESDecrypt(const std::vector<unsigned char>& ciphertext, 
             const std::vector<unsigned char>& iv);

private:
  RSA* rsaKeyPair;        // Par de claves propia
  RSA* peerPublicKey;     // Clave pública del peer
  unsigned char aesKey[32]; // Clave AES-256
};