#include "Server.h"

/**
 * @brief Constructor del servidor.
 *
 * Inicializa el puerto, el socket del cliente y genera las claves RSA del servidor.
 *
 * @param port Puerto en el que el servidor escuchará conexiones.
 */
Server::Server(int port) : m_port(port), m_clientSock(-1) {
	m_crypto.GenerateRSAKeys();
}

/**
 * @brief Destructor del servidor.
 *
 * Cierra la conexión con el cliente si aún está activa.
 */
Server::~Server() {
	if (m_clientSock != -1) {
		m_net.close(m_clientSock);
	}
}

/**
 * @brief Inicia el servidor en el puerto configurado.
 *
 * @return true si el servidor se inició correctamente.
 * @return false si ocurrió un error al iniciar.
 */
bool Server::Start() {
	std::cout << "[Server] Iniciando servidor en el puerto " << m_port << "...\n";
	return m_net.StartServer(m_port);
}

/**
 * @brief Espera la conexión de un cliente y realiza el intercambio de claves.
 *
 * - Acepta la conexión de un cliente.
 * - Envía la clave pública del servidor.
 * - Recibe la clave pública del cliente.
 * - Recibe la clave AES cifrada y la descifra.
 */
void Server::WaitForClient() {
	std::cout << "[Server] Esperando conexión de un cliente...\n";

	m_clientSock = m_net.AcceptClient();
	if (m_clientSock == INVALID_SOCKET) {
		std::cerr << "[Server] No se pudo aceptar cliente.\n";
		return;
	}
	std::cout << "[Server] Cliente conectado.\n";

	std::string serverPubKey = m_crypto.GetPublicKeyString();
	m_net.SendData(m_clientSock, serverPubKey);

	std::string clientPubKey = m_net.ReceiveData(m_clientSock);
	m_crypto.LoadPeerPublicKey(clientPubKey);

	std::vector<unsigned char> encryptedAESKey = m_net.ReceiveDataBinary(m_clientSock, 256);
	m_crypto.DecryptAESKey(encryptedAESKey);

	std::cout << "[Server] Clave AES intercambiada exitosamente.\n";
}

/**
 * @brief Recibe un único mensaje cifrado desde el cliente.
 *
 * Este método recibe el IV, el mensaje cifrado, lo descifra y lo muestra.
 */
void Server::ReceiveEncryptedMessage() {
	std::vector<unsigned char> iv = m_net.ReceiveDataBinary(m_clientSock, 16);
	std::vector<unsigned char> encryptedMsg = m_net.ReceiveDataBinary(m_clientSock, 128);
	std::string msg = m_crypto.AESDecrypt(encryptedMsg, iv);
	std::cout << "[Server] Mensaje recibido: " << msg << "\n";
}

/**
 * @brief Inicia el bucle de recepción de mensajes.
 *
 * Se queda esperando mensajes cifrados del cliente hasta que la conexión se cierre
 * o ocurra un error. Cada mensaje se descifra y se muestra.
 */
void Server::StartReceiveLoop() {
	while (true) {
		auto iv = m_net.ReceiveDataBinary(m_clientSock, 16);
		if (iv.empty()) {
			std::cout << "\n[Server] Conexión cerrada por el cliente.\n";
			break;
		}

		auto len4 = m_net.ReceiveDataBinary(m_clientSock, 4);
		if (len4.size() != 4) {
			std::cout << "[Server] Error al recibir tamaño.\n";
			break;
		}
		uint32_t nlen = 0;
		std::memcpy(&nlen, len4.data(), 4);
		uint32_t clen = ntohl(nlen);

		auto cipher = m_net.ReceiveDataBinary(m_clientSock, static_cast<int>(clen));
		if (cipher.empty()) {
			std::cout << "[Server] Error al recibir datos.\n";
			break;
		}

		std::string plain = m_crypto.AESDecrypt(cipher, iv);
		std::cout << "\n[Cliente]: " << plain << "\nServidor: ";
		std::cout.flush();
	}
}

/**
 * @brief Inicia el bucle de envío de mensajes cifrados.
 *
 * Permite al servidor escribir mensajes, cifrarlos y enviarlos al cliente.
 * Finaliza si el usuario escribe "/exit".
 */
void Server::SendEncryptedMessageLoop() {
	std::string msg;
	while (true) {
		std::cout << "Servidor: ";
		std::getline(std::cin, msg);
		if (msg == "/exit") break;

		std::vector<unsigned char> iv;
		auto cipher = m_crypto.AESEncrypt(msg, iv);

		m_net.SendData(m_clientSock, iv);

		uint32_t clen = static_cast<uint32_t>(cipher.size());
		uint32_t nlen = htonl(clen);
		std::vector<unsigned char> len4(
			reinterpret_cast<unsigned char*>(&nlen),
			reinterpret_cast<unsigned char*>(&nlen) + 4
		);
		m_net.SendData(m_clientSock, len4);
		m_net.SendData(m_clientSock, cipher);
	}
	std::cout << "[Server] Saliendo del chat.\n";
}

/**
 * @brief Inicia el chat seguro.
 *
 * Lanza un hilo para recibir mensajes mientras en el hilo principal
 * se envían mensajes.
 */
void Server::StartChatLoop() {
	std::thread recvThread([&]() {
		StartReceiveLoop();
		});

	SendEncryptedMessageLoop();

	if (recvThread.joinable())
		recvThread.join();
}
