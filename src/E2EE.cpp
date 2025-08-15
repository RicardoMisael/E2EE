#include "Prerequisites.h"
#include "Server.h"
#include "Client.h"

/**
 * @brief Ejecuta el servidor.
 *
 * Crea una instancia de la clase Server, inicia la escucha en el puerto especificado,
 * espera la conexi�n de un cliente, realiza el intercambio de claves y
 * comienza el bucle de chat seguro.
 *
 * @param port Puerto en el que se ejecutar� el servidor.
 */
static void runServer(int port) {
    Server s(port);
    if (!s.Start()) {
        std::cerr << "[Main] No se pudo iniciar el servidor.\n";
        return;
    }
    s.WaitForClient(); ///< Intercambio de claves
    s.StartChatLoop(); ///< Bucle de chat en paralelo
}

/**
 * @brief Ejecuta el cliente.
 *
 * Crea una instancia de la clase Client, se conecta al servidor,
 * realiza el intercambio de claves, env�a la clave AES cifrada y
 * comienza el bucle de chat seguro.
 *
 * @param ip Direcci�n IP del servidor.
 * @param port Puerto del servidor.
 */
static void runClient(const std::string& ip, int port) {
    Client c(ip, port);
    if (!c.Connect()) {
        std::cerr << "[Main] No se pudo conectar.\n";
        return;
    }

    c.ExchangeKeys();
    c.SendAESKeyEncrypted();

    // Ahora s�, chat en paralelo
    c.StartChatLoop();
}

/**
 * @brief Funci�n principal.
 *
 * Punto de entrada del programa. Determina el modo de ejecuci�n
 * (servidor o cliente) a partir de los argumentos de l�nea de comandos
 * o solicitando la informaci�n al usuario.
 *
 * Formato de ejecuci�n:
 * - Servidor: `E2EE server <puerto>`
 * - Cliente: `E2EE client <ip> <puerto>`
 *
 * @param argc N�mero de argumentos.
 * @param argv Lista de argumentos.
 * @return int C�digo de salida (0 en �xito, 1 en error).
 */
int main(int argc, char** argv) {
    std::string mode, ip;
    int port = 0;

    if (argc >= 2) {
        mode = argv[1];
        if (mode == "server") {
            port = (argc >= 3) ? std::stoi(argv[2]) : 12345;
        }
        else if (mode == "client") {
            if (argc < 4) {
                std::cerr << "Uso: E2EE client <ip> <port>\n";
                return 1;
            }
            ip = argv[2];
            port = std::stoi(argv[3]);
        }
        else {
            std::cerr << "Modo no reconocido. Usa: server | client\n";
            return 1;
        }
    }
    else {
        std::cout << "Modo (server/client): ";
        std::cin >> mode;
        if (mode == "server") {
            std::cout << "Puerto: ";
            std::cin >> port;
        }
        else if (mode == "client") {
            std::cout << "IP: ";
            std::cin >> ip;
            std::cout << "Puerto: ";
            std::cin >> port;
        }
        else {
            std::cerr << "Modo no reconocido.\n";
            return 1;
        }
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    }

    if (mode == "server")
        runServer(port);
    else
        runClient(ip, port);

    return 0;
}
