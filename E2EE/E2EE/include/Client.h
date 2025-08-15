#pragma once
#include "NetworkHelper.h"   ///< Funciones auxiliares para gesti�n de red y sockets.
#include "CryptoHelper.h"    ///< Funciones auxiliares para cifrado y descifrado (AES/RSA).
#include "Prerequisites.h"   ///< Configuraci�n previa y dependencias necesarias (Winsock, etc.).

/**
 * @class Client
 * @brief Cliente para comunicaci�n segura mediante cifrado h�brido (RSA + AES).
 *
 * La clase Client permite:
 * - Conectarse a un servidor mediante sockets TCP.
 * - Intercambiar claves p�blicas (RSA) para establecer un canal seguro.
 * - Generar y enviar una clave AES cifrada para comunicaci�n sim�trica.
 * - Enviar y recibir mensajes cifrados usando AES.
 * - Mantener un chat seguro en tiempo real.
 */
class Client {
public:
    /**
     * @brief Constructor por defecto.
     *
     * Inicializa un cliente sin par�metros. Los valores de IP y puerto
     * pueden configurarse posteriormente antes de llamar a Connect().
     */
    Client() = default;

    /**
     * @brief Constructor parametrizado.
     *
     * @param ip Direcci�n IP del servidor al que se conectar�.
     * @param port Puerto del servidor al que se conectar�.
     */
    Client(const std::string& ip, int port);

    /**
     * @brief Destructor.
     *
     * Libera recursos asociados como el socket de conexi�n.
     */
    ~Client();

    /**
     * @brief Establece conexi�n con el servidor.
     *
     * Intenta abrir un socket TCP y conectarse usando la IP y puerto configurados.
     *
     * @return true si la conexi�n fue exitosa.
     * @return false si ocurri� un error de conexi�n.
     */
    bool Connect();

    /**
     * @brief Intercambia claves p�blicas con el servidor.
     *
     * Env�a la clave p�blica del cliente y recibe la clave p�blica del servidor,
     * para permitir el posterior env�o de la clave AES cifrada.
     */
    void ExchangeKeys();

    /**
     * @brief Env�a la clave AES cifrada con la clave p�blica del servidor.
     *
     * Genera una clave AES aleatoria, la cifra con RSA usando la clave p�blica del servidor
     * y la env�a para establecer el cifrado sim�trico.
     */
    void SendAESKeyEncrypted();

    /**
     * @brief Env�a un mensaje cifrado al servidor.
     *
     * @param message Texto plano que ser� cifrado con AES y enviado.
     */
    void SendEncryptedMessage(const std::string& message);

    /**
     * @brief Bucle para env�o continuo de mensajes cifrados.
     *
     * Solicita mensajes al usuario y los env�a cifrados al servidor.
     */
    void SendEncryptedMessageLoop();

    /**
     * @brief Inicia el bucle principal de chat.
     *
     * Ejecuta env�o y recepci�n de mensajes de forma paralela.
     */
    void StartChatLoop();

    /**
     * @brief Inicia el bucle de recepci�n de mensajes.
     *
     * Escucha mensajes cifrados desde el servidor, los descifra con AES y los muestra.
     */
    void StartReceiveLoop();

private:
    std::string m_ip;       ///< Direcci�n IP del servidor.
    int m_port;             ///< Puerto del servidor.
    SOCKET m_serverSock;    ///< Descriptor del socket de conexi�n.
    NetworkHelper m_net;    ///< Auxiliar para operaciones de red.
    CryptoHelper m_crypto;  ///< Auxiliar para operaciones criptogr�ficas.
};
