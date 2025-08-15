#pragma once
#include "NetworkHelper.h"   ///< Funciones auxiliares para gestión de red y sockets.
#include "CryptoHelper.h"    ///< Funciones auxiliares para cifrado y descifrado (AES/RSA).
#include "Prerequisites.h"   ///< Configuración previa y dependencias necesarias (Winsock, etc.).

/**
 * @class Client
 * @brief Cliente para comunicación segura mediante cifrado híbrido (RSA + AES).
 *
 * La clase Client permite:
 * - Conectarse a un servidor mediante sockets TCP.
 * - Intercambiar claves públicas (RSA) para establecer un canal seguro.
 * - Generar y enviar una clave AES cifrada para comunicación simétrica.
 * - Enviar y recibir mensajes cifrados usando AES.
 * - Mantener un chat seguro en tiempo real.
 */
class Client {
public:
    /**
     * @brief Constructor por defecto.
     *
     * Inicializa un cliente sin parámetros. Los valores de IP y puerto
     * pueden configurarse posteriormente antes de llamar a Connect().
     */
    Client() = default;

    /**
     * @brief Constructor parametrizado.
     *
     * @param ip Dirección IP del servidor al que se conectará.
     * @param port Puerto del servidor al que se conectará.
     */
    Client(const std::string& ip, int port);

    /**
     * @brief Destructor.
     *
     * Libera recursos asociados como el socket de conexión.
     */
    ~Client();

    /**
     * @brief Establece conexión con el servidor.
     *
     * Intenta abrir un socket TCP y conectarse usando la IP y puerto configurados.
     *
     * @return true si la conexión fue exitosa.
     * @return false si ocurrió un error de conexión.
     */
    bool Connect();

    /**
     * @brief Intercambia claves públicas con el servidor.
     *
     * Envía la clave pública del cliente y recibe la clave pública del servidor,
     * para permitir el posterior envío de la clave AES cifrada.
     */
    void ExchangeKeys();

    /**
     * @brief Envía la clave AES cifrada con la clave pública del servidor.
     *
     * Genera una clave AES aleatoria, la cifra con RSA usando la clave pública del servidor
     * y la envía para establecer el cifrado simétrico.
     */
    void SendAESKeyEncrypted();

    /**
     * @brief Envía un mensaje cifrado al servidor.
     *
     * @param message Texto plano que será cifrado con AES y enviado.
     */
    void SendEncryptedMessage(const std::string& message);

    /**
     * @brief Bucle para envío continuo de mensajes cifrados.
     *
     * Solicita mensajes al usuario y los envía cifrados al servidor.
     */
    void SendEncryptedMessageLoop();

    /**
     * @brief Inicia el bucle principal de chat.
     *
     * Ejecuta envío y recepción de mensajes de forma paralela.
     */
    void StartChatLoop();

    /**
     * @brief Inicia el bucle de recepción de mensajes.
     *
     * Escucha mensajes cifrados desde el servidor, los descifra con AES y los muestra.
     */
    void StartReceiveLoop();

private:
    std::string m_ip;       ///< Dirección IP del servidor.
    int m_port;             ///< Puerto del servidor.
    SOCKET m_serverSock;    ///< Descriptor del socket de conexión.
    NetworkHelper m_net;    ///< Auxiliar para operaciones de red.
    CryptoHelper m_crypto;  ///< Auxiliar para operaciones criptográficas.
};
