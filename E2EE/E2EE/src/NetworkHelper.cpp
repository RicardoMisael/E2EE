#include "NetworkHelper.h"

/**
 * @brief Constructor de NetworkHelper.
 *
 * Inicializa Winsock (WSAStartup) para permitir operaciones de red.
 * Si la inicialización falla, muestra un error.
 */
NetworkHelper::NetworkHelper() : m_serverSocket(INVALID_SOCKET), m_initialized(false) {
	WSADATA wsaData;
	int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (result != 0) {
		std::cerr << "WSAStartup failed: " << result << std::endl;
	}
	else {
		m_initialized = true;
	}
}

/**
 * @brief Destructor de NetworkHelper.
 *
 * Cierra el socket si está abierto y limpia Winsock.
 */
NetworkHelper::~NetworkHelper() {
	if (m_serverSocket != INVALID_SOCKET) {
		closesocket(m_serverSocket);
	}
	if (m_initialized) {
		WSACleanup();
	}
}

/**
 * @brief Inicia un servidor TCP en el puerto indicado.
 *
 * - Crea el socket.
 * - Asigna dirección y puerto.
 * - Comienza a escuchar conexiones entrantes.
 *
 * @param port Puerto de escucha.
 * @return true si se inició correctamente.
 * @return false si ocurrió un error.
 */
bool NetworkHelper::StartServer(int port) {
	m_serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (m_serverSocket == INVALID_SOCKET) {
		std::cerr << "Error creating socket: " << WSAGetLastError() << std::endl;
		return false;
	}

	sockaddr_in serverAddress{};
	serverAddress.sin_family = AF_INET;
	serverAddress.sin_port = htons(port);
	serverAddress.sin_addr.s_addr = INADDR_ANY;

	if (bind(m_serverSocket, (sockaddr*)&serverAddress, sizeof(serverAddress)) == SOCKET_ERROR) {
		std::cerr << "Error binding socket: " << WSAGetLastError() << std::endl;
		closesocket(m_serverSocket);
		m_serverSocket = INVALID_SOCKET;
		return false;
	}

	if (listen(m_serverSocket, SOMAXCONN) == SOCKET_ERROR) {
		std::cerr << "Error listening on socket: " << WSAGetLastError() << std::endl;
		closesocket(m_serverSocket);
		m_serverSocket = INVALID_SOCKET;
		return false;
	}

	std::cout << "Server started on port " << port << std::endl;
	return true;
}

/**
 * @brief Acepta una conexión entrante.
 *
 * @return SOCKET del cliente o INVALID_SOCKET en caso de error.
 */
SOCKET NetworkHelper::AcceptClient() {
	SOCKET clientSocket = accept(m_serverSocket, nullptr, nullptr);
	if (clientSocket == INVALID_SOCKET) {
		std::cerr << "Error accepting client: " << WSAGetLastError() << std::endl;
		return INVALID_SOCKET;
	}
	std::cout << "Client connected." << std::endl;
	return clientSocket;
}

/**
 * @brief Conecta el cliente a un servidor TCP.
 *
 * @param ip Dirección IP del servidor.
 * @param port Puerto del servidor.
 * @return true si la conexión fue exitosa, false en caso contrario.
 */
bool NetworkHelper::ConnectToServer(const std::string& ip, int port) {
	m_serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (m_serverSocket == INVALID_SOCKET) {
		std::cerr << "Error creating socket: " << WSAGetLastError() << std::endl;
		return false;
	}

	sockaddr_in serverAddress{};
	serverAddress.sin_family = AF_INET;
	serverAddress.sin_port = htons(port);
	inet_pton(AF_INET, ip.c_str(), &serverAddress.sin_addr);

	if (connect(m_serverSocket, (sockaddr*)&serverAddress, sizeof(serverAddress)) == SOCKET_ERROR) {
		std::cerr << "Error connecting to server: " << WSAGetLastError() << std::endl;
		closesocket(m_serverSocket);
		m_serverSocket = INVALID_SOCKET;
		return false;
	}
	std::cout << "Connected to server at " << ip << ":" << port << std::endl;
	return true;
}

/**
 * @brief Envía datos de texto a través de un socket.
 *
 * @param socket Socket de destino.
 * @param data Cadena de texto a enviar.
 * @return true si se envió correctamente.
 */
bool NetworkHelper::SendData(SOCKET socket, const std::string& data) {
	return send(socket, data.c_str(), static_cast<int>(data.size()), 0) != SOCKET_ERROR;
}

/**
 * @brief Envía datos binarios a través de un socket.
 *
 * @param socket Socket de destino.
 * @param data Vector de bytes a enviar.
 * @return true si se envió correctamente.
 */
bool NetworkHelper::SendData(SOCKET socket, const std::vector<unsigned char>& data) {
	return SendAll(socket, data.data(), static_cast<int>(data.size()));
}

/**
 * @brief Recibe datos en formato texto desde un socket.
 *
 * @param socket Socket desde el que recibir.
 * @return Cadena con los datos recibidos.
 */
std::string NetworkHelper::ReceiveData(SOCKET socket) {
	char buffer[4096] = {};
	int len = recv(socket, buffer, sizeof(buffer), 0);
	return std::string(buffer, len);
}

/**
 * @brief Recibe datos binarios desde un socket.
 *
 * @param socket Socket desde el que recibir.
 * @param size Cantidad de bytes a recibir.
 * @return Vector de bytes con los datos recibidos.
 */
std::vector<unsigned char> NetworkHelper::ReceiveDataBinary(SOCKET socket, int size) {
	std::vector<unsigned char> buf(size);
	if (!ReceiveExact(socket, buf.data(), size)) return {};
	return buf;
}

/**
 * @brief Cierra un socket.
 *
 * @param socket Socket a cerrar.
 */
void NetworkHelper::close(SOCKET socket) {
	closesocket(socket);
}

/**
 * @brief Envía todos los datos de forma garantizada.
 *
 * @param s Socket de destino.
 * @param data Puntero a los datos.
 * @param len Longitud de los datos.
 * @return true si se enviaron todos los datos correctamente.
 */
bool NetworkHelper::SendAll(SOCKET s, const unsigned char* data, int len) {
	int sent = 0;
	while (sent < len) {
		int n = send(s, (const char*)data + sent, len - sent, 0);
		if (n == SOCKET_ERROR) return false;
		sent += n;
	}
	return true;
}

/**
 * @brief Recibe exactamente la cantidad de bytes especificada.
 *
 * @param s Socket de origen.
 * @param out Puntero al buffer donde almacenar los datos.
 * @param len Cantidad de bytes a recibir.
 * @return true si se recibieron todos los datos.
 */
bool NetworkHelper::ReceiveExact(SOCKET s, unsigned char* out, int len) {
	int recvd = 0;
	while (recvd < len) {
		int n = recv(s, (char*)out + recvd, len - recvd, 0);
		if (n <= 0) return false;
		recvd += n;
	}
	return true;
}
