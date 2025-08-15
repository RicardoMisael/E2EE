#include "Server.h"

/**
 * @brief Constructor del servidor.
 *
 * Inicializa el puerto, el socket del cliente y genera las claves RSA del servidor.
 *
 * @param port Puerto en el que el servidor escuchar� conexiones.
 */
Server::Server(int port) : m_port(port), m_clientSock(-1) {
	m_crypto.GenerateRSAKeys();
}

/**
 * @brief Destructor del servidor.
 *
 * Cierra la conexi�n con el cliente si a�n est� activa.
 */
Server::~Server() {
	if (m_clientSock != -1) {
		m_net.close(m_clientSock);
	}
}

/**
 * @brief Inicia el servidor en el puerto configurado.
 *
 * @return true si el servidor se inici� correctamente.
 * @return false si ocurri� un error al iniciar.
 */
bool Server::Start() {
	std::cout << "[Server] Iniciando servidor en el puerto " << m_port << "...\n";
	return m_net.StartServer(m_port);
}

/**
 * @brief Espera la conexi�n de un cliente y realiza el intercambio de claves.
 *
 * - Acepta la conexi�n de un cliente.
 * - Env�a la clave p�blica del servidor.
 * - Recibe la clave p�blica del cliente.
 * - Recibe la clave AES cifrada y la descifra.
 */
void Server::WaitForClient() {
	std::cout << "[Server] Esperando conexi�n de un cliente...\n";

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
 * @brief Recibe un �nico mensaje cifrado desde el cliente.
 *
 * Este m�todo recibe el IV, el mensaje cifrado, lo descifra y lo muestra.
 */
void Server::ReceiveEncryptedMessage() {
	std::vector<unsigned char> iv = m_net.ReceiveDataBinary(m_clientSock, 16);
	std::vector<unsigned char> encryptedMsg = m_net.ReceiveDataBinary(m_clientSock, 128);
	std::string msg = m_crypto.AESDecrypt(encryptedMsg, iv);
	std::cout << "[Server] Mensaje recibido: " << msg << "\n";
}

/**
 * @brief Inicia el bucle de recepci�n de mensajes.
 *
 * Se queda esperando mensajes cifrados del cliente hasta que la conexi�n se cierre
 * o ocurra un error. Cada mensaje se descifra y se muestra.
 */
void Server::StartReceiveLoop() {
	while (true) {
		auto iv = m_net.ReceiveDataBinary(m_clientSock, 16);
		if (iv.empty()) {
			std::cout << "\n[Server] Conexi�n cerrada por el cliente.\n";
			break;
		}

		auto len4 = m_net.ReceiveDataBinary(m_clientSock, 4);
		if (len4.size() != 4) {
			std::cout << "[Server] Error al recibir tama�o.\n";
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
 * @brief Inicia el bucle de env�o de mensajes cifrados.
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
 * se env�an mensajes.
 */
void Server::StartChatLoop() {
	std::thread recvThread([&]() {
		StartReceiveLoop();
		});

	SendEncryptedMessageLoop();

	if (recvThread.joinable())
		recvThread.join();
}
