#include "Client.h"

/**
 * @brief Constructor parametrizado del cliente.
 *
 * Inicializa la IP, puerto, socket y genera las claves criptográficas necesarias.
 *
 * - Genera un par de claves RSA (pública y privada).
 * - Genera la clave AES que se usará para el cifrado simétrico de mensajes.
 *
 * @param ip Dirección IP del servidor.
 * @param port Puerto del servidor.
 */
Client::Client(const std::string& ip, int port)
	: m_ip(ip), m_port(port), m_serverSock(INVALID_SOCKET) {
	m_crypto.GenerateRSAKeys();
	m_crypto.GenerateAESKey();
}

/**
 * @brief Destructor del cliente.
 *
 * Cierra el socket si aún está activo.
 */
Client::~Client() {
	if (m_serverSock != INVALID_SOCKET) {
		m_net.close(m_serverSock);
	}
}

/**
 * @brief Establece conexión TCP con el servidor.
 *
 * Intenta conectarse usando la IP y el puerto configurados.
 *
 * @return true si la conexión se estableció correctamente.
 * @return false si no fue posible conectarse.
 */
bool Client::Connect() {
	std::cout << "[Client] Conectando al servidor " << m_ip << ":" << m_port << "...\n";
	bool connected = m_net.ConnectToServer(m_ip, m_port);
	if (connected) {
		m_serverSock = m_net.m_serverSocket;
		std::cout << "[Client] Conexión establecida.\n";
	}
	else {
		std::cerr << "[Client] Error al conectar.\n";
	}
	return connected;
}

/**
 * @brief Intercambia claves públicas con el servidor.
 *
 * - Recibe la clave pública del servidor y la guarda.
 * - Envía la clave pública del cliente.
 */
void Client::ExchangeKeys() {
	std::string serverPubKey = m_net.ReceiveData(m_serverSock);
	m_crypto.LoadPeerPublicKey(serverPubKey);
	std::cout << "[Client] Clave pública del servidor recibida.\n";

	std::string clientPubKey = m_crypto.GetPublicKeyString();
	m_net.SendData(m_serverSock, clientPubKey);
	std::cout << "[Client] Clave pública del cliente enviada.\n";
}

/**
 * @brief Envía la clave AES cifrada con la clave pública del servidor.
 *
 * La clave AES generada previamente se cifra usando RSA con la clave del servidor.
 */
void Client::SendAESKeyEncrypted() {
	std::vector<unsigned char> encryptedAES = m_crypto.EncryptAESKeyWithPeer();
	m_net.SendData(m_serverSock, encryptedAES);
	std::cout << "[Client] Clave AES cifrada y enviada al servidor.\n";
}

/**
 * @brief Envía un mensaje cifrado al servidor.
 *
 * @param message Texto en claro que será cifrado con AES antes de enviarse.
 */
void Client::SendEncryptedMessage(const std::string& message) {
	std::vector<unsigned char> iv;
	auto cipher = m_crypto.AESEncrypt(message, iv);

	m_net.SendData(m_serverSock, iv);

	uint32_t clen = static_cast<uint32_t>(cipher.size());
	uint32_t nlen = htonl(clen);
	std::vector<unsigned char> len4(reinterpret_cast<unsigned char*>(&nlen),
		reinterpret_cast<unsigned char*>(&nlen) + 4);
	m_net.SendData(m_serverSock, len4);

	m_net.SendData(m_serverSock, cipher);
}

/**
 * @brief Bucle de envío continuo de mensajes cifrados.
 *
 * Permite al usuario escribir mensajes que se cifran y envían al servidor.
 * Se detiene si el usuario escribe "/exit".
 */
void Client::SendEncryptedMessageLoop() {
	std::string msg;
	while (true) {
		std::cout << "Cliente: ";
		std::getline(std::cin, msg);
		if (msg == "/exit") break;

		std::vector<unsigned char> iv;
		auto cipher = m_crypto.AESEncrypt(msg, iv);

		m_net.SendData(m_serverSock, iv);

		uint32_t clen = static_cast<uint32_t>(cipher.size());
		uint32_t nlen = htonl(clen);
		std::vector<unsigned char> len4(reinterpret_cast<unsigned char*>(&nlen),
			reinterpret_cast<unsigned char*>(&nlen) + 4);
		m_net.SendData(m_serverSock, len4);

		m_net.SendData(m_serverSock, cipher);
	}
}

/**
 * @brief Bucle de recepción de mensajes cifrados.
 *
 * Recibe mensajes desde el servidor, los descifra y los muestra por consola.
 * Se detiene si la conexión se cierra o hay un error de lectura.
 */
void Client::StartReceiveLoop() {
	while (true) {
		auto iv = m_net.ReceiveDataBinary(m_serverSock, 16);
		if (iv.empty()) {
			std::cout << "\n[Client] Conexión cerrada por el servidor.\n";
			break;
		}

		auto len4 = m_net.ReceiveDataBinary(m_serverSock, 4);
		if (len4.size() != 4) {
			std::cout << "[Client] Error al recibir tamaño.\n";
			break;
		}
		uint32_t nlen = 0;
		std::memcpy(&nlen, len4.data(), 4);
		uint32_t clen = ntohl(nlen);

		auto cipher = m_net.ReceiveDataBinary(m_serverSock, static_cast<int>(clen));
		if (cipher.empty()) {
			std::cout << "[Client] Error al recibir datos.\n";
			break;
		}

		std::string plain = m_crypto.AESDecrypt(cipher, iv);
		std::cout << "\n[Servidor]: " << plain << "\nCliente: ";
		std::cout.flush();
	}
	std::cout << "[Client] ReceiveLoop terminado.\n";
}

/**
 * @brief Inicia el chat seguro con el servidor.
 *
 * Crea un hilo para recibir mensajes mientras en el hilo principal
 * se envían mensajes cifrados.
 */
void Client::StartChatLoop() {
	std::thread recvThread([&]() {
		StartReceiveLoop();
		});

	SendEncryptedMessageLoop();

	if (recvThread.joinable())
		recvThread.join();
}
