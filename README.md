# 📡 Cliente-Servidor con Cifrado E2EE (RSA + AES)

## 📋 Descripción
Sistema en C++ que implementa comunicación **Cliente-Servidor** usando sockets TCP, con **cifrado de extremo a extremo (E2EE)**. Usa **RSA** para el intercambio seguro de claves y **AES** para el cifrado simétrico de todos los mensajes.

---

## 🚀 Características
- Conexión estable cliente-servidor.
- Intercambio seguro de claves RSA.
- Cifrado/descifrado AES en tiempo real.
- Comunicación bidireccional sin bloqueos.
- Cierre limpio de conexiones.

---

## 📂 Módulos
**Client** → Maneja conexión y mensajes cifrados.  
**Server** → Escucha, recibe y responde cifrado.  
**NetworkHelper** → Funciones de sockets.  
**CryptoHelper** → RSA y AES con OpenSSL.  
**E2EE** → Coordina intercambio y cifrado.

---

## 🔄 Flujo
1. Cliente se conecta al servidor.
2. Intercambio de claves RSA.
3. Cliente envía clave AES cifrada.
4. Comunicación cifrada con AES.
5. Cierre ordenado.

```mermaid
sequenceDiagram
    participant Cliente
    participant Servidor
    Cliente->>Servidor: Conexión TCP
    Servidor-->>Cliente: Clave pública RSA
    Cliente-->>Servidor: Clave pública RSA
    Cliente-->>Servidor: Clave AES cifrada
    loop Comunicación cifrada
        Cliente->>Servidor: Mensaje AES
        Servidor->>Cliente: Respuesta AES
    end
