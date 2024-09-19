## Breve Descripción del Proyecto

Este proyecto utiliza **SAP Cloud Application Programming (CAP)** para crear un servicio REST que expone un endpoint destinado al envío de correos electrónicos. La funcionalidad de envío de emails se basa en **Azure Communication Service**, y las credenciales necesarias para autenticar este servicio se gestionan a través de **SAP Credential Store**. El acceso a las credenciales inicialmente se muestra utilizando autenticación **Basic Authentication**, pero también se ofrecen ejemplos de implementación con **mTLS** y **OAuth 2.0 con mTLS**.

## Gestión de Credenciales

Para manejar las credenciales de forma segura, el proyecto utiliza **SAP Credential Store**. Este almacén permite gestionar las credenciales necesarias para interactuar con otros servicios, como **Azure Communication Service**. En este caso, las credenciales se almacenan de forma segura y se accede a ellas utilizando diferentes métodos de autenticación que se describen a continuación.

### Opciones de Autenticación

Este proyecto permite elegir entre tres opciones de autenticación según los requisitos de seguridad:

1. **Autenticación Básica (Basic Authentication):** Se autentica con un nombre de usuario y contraseña.
2. **mTLS (Mutual TLS):** Se autentica mediante certificados tanto para el cliente como para el servidor, validando ambas partes.
3. **OAuth 2.0 con mTLS:** Se utiliza OAuth para obtener un token de acceso que permite realizar las peticiones, y se asegura la conexión mediante mTLS.

Cada opción de autenticación se implementa con ejemplos prácticos que puedes adaptar a tus necesidades.

### Registro del Servicio en SAP BTP

El primer paso es registrar un servicio en **SAP BTP** para permitir la gestión de credenciales que se utilizarán en el proyecto. La siguiente imagen muestra cómo se visualiza el registro de un servicio en la plataforma:

![Registro de Servicio en SAP BTP](./img/sapcredentials.png)

En esta pantalla, se pueden observar los pasos necesarios para dar de alta un servicio y configurarlo para que interactúe con **SAP Credential Store**.

### Opciones de Autenticación

Al registrar el servicio, se ofrecen diferentes opciones de autenticación que puedes utilizar según los requisitos de seguridad.
  
A continuación, puedes ver una vista de las diferentes opciones de autenticación disponibles:

![Opciones de Autenticación](./img/parameters.png)

![Parámetros de Configuración](./img/parameters2.png)

## Creación de Credenciales en SAP BTP Credential Store

Para gestionar y utilizar credenciales seguras en tu proyecto utilizando **SAP Credential Store**, sigue estos pasos:

### 1. Gestionar Instancia

Primero, asegúrate de que tienes una instancia de **SAP Credential Store** configurada. Ve a la instancia que has creado  de **SAP Credential** dentro de tu **SAP Business Technology Platform (BTP)** y selecciona el botón de **Manage instance**.

### 2. Creación de un Namespace

El siguiente paso es crear un **Namespace** dentro de la instancia de Credential Store. El **Namespace** es como un contenedor lógico donde se almacenarán las credenciales.

1. En la pantalla de administración de tu instancia de Credential Store, selecciona la opción **Create Namespace**.
2. Introduce un nombre para el namespace. En este caso, por ejemplo, el nombre podría ser `email` si estás almacenando credenciales relacionadas con servicios de correo electrónico.

En la siguiente captura se puede observar el **Namespace** creado:

![Credential Store Instance](./img/sapcredentials_.png)

### 3. Creación de una Contraseña (Password)

Una vez creado el **Namespace**, es momento de añadir credenciales. En este caso, crearemos una **Password** que se usará para autenticar el servicio.

1. Selecciona el **Namespace** que has creado (en este caso `email`).
2. Haz clic en el botón **Add Credential**.
3. En el menú desplegable, selecciona la opción **Password**.
4. Rellena los siguientes campos:
   - **Name**: Nombre de la credencial (por ejemplo, `email-password`).
   - **Value**: Introduce la contraseña que se va a almacenar.
   - **Confirm Value**: Vuelve a ingresar la contraseña para confirmar.
   - **Status**: Selecciona el estado como **Enabled**.
   
   Opcionalmente, puedes añadir un nombre de usuario y metadatos adicionales si es necesario. Una vez completados los campos, la pantalla se verá de la siguiente manera:

   ![Creación de Password](./img/pass.png)

5. Haz clic en **Create** para guardar la credencial.

Una vez creada la credencial, aparecerá listada en tu **Namespace**.


### 4. Verificación de Credenciales

Después de haber creado las credenciales, puedes gestionarlas y verificar que están correctamente almacenadas desde la interfaz de **SAP Credential Store**. Asegúrate de vincular el servicio de credentials store correctamente a tu aplicación para permitir su uso en procesos de autenticación.

Con estos pasos, has configurado un **Namespace** y has creado una **Password** en **SAP Credential Store**, que podrá ser utilizada en tu aplicación para acceder de forma segura a servicios externos.

## Importancia de Vincular (Binding) la Aplicación con el Servicio de Credenciales

Después de configurar el **SAP Credential Store** y crear las credenciales necesarias, es fundamental realizar el **binding** de la instancia del servicio con tu aplicación en **SAP Business Technology Platform (BTP)**. El binding proporciona automáticamente los detalles esenciales para la autenticación con tu instancia SAP Credential Store, como claves privadas y públicas, certificados, URL de tokens, entre otros.

### Código de la Gestión de Credenciales (Basic Auth)

```javascript
const jose = require('node-jose');
const fetch = require('node-fetch');

function checkStatus(response) {
    if (!response.ok) throw Error("Unexpected status code: " + response.status);
    return response;
}

async function decryptPayload(privateKey, payload) {
    const key = await jose.JWK.asKey(`-----BEGIN PRIVATE KEY-----${privateKey}-----END PRIVATE KEY-----`,
        "pem",
        { alg: "RSA-OAEP-256", enc: "A256GCM" }
    );
    const decrypt = await jose.JWE.createDecrypt(key).decrypt(payload);
    const result = decrypt.plaintext.toString();
    return result;
}

async function encryptPayload(publicKey, payload) {
    const key = await jose.JWK.asKey(`-----BEGIN PUBLIC KEY-----${publicKey}-----END PUBLIC KEY-----`,
        "pem",
        { alg: "RSA-OAEP-256" }
    );
    const options = {
        contentAlg: "A256GCM",
        compact: true,
        fields: { "iat": Math.round(new Date().getTime() / 1000) }
    };
    return jose.JWE.createEncrypt(options, key).update(Buffer.from(payload, "utf8")).final();
}

function headers(binding, namespace, init) {
    const headers = new fetch.Headers(init);
    headers.set("Authorization", `Basic ${Buffer.from(`${binding.username}:${binding.password}`).toString("base64")}`);
    headers.set("sapcp-credstore-namespace", namespace);
    return headers;
}

async function fetchAndDecrypt(privateKey, url, method, headers, body) {
    return fetch(url, { method, headers, body })
        .then(checkStatus)
        .then(response => response.text())
        .then(payload => decryptPayload(privateKey, payload))
        .then(JSON.parse);
}

async function readCredential(binding, namespace, type, name) {
    return fetchAndDecrypt(
        binding.encryption.client_private_key,
        `${binding.url}/${type}?name=${encodeURIComponent(name)}`,
        "get",
        headers(binding, namespace)
    );
}

async function writeCredential(binding, namespace, type, credential) {
    return fetchAndDecrypt(
        binding.encryption.client_private_key,
        `${binding.url}/${type}`,
        "post",
        headers(binding, namespace, { "Content-Type": "application/jose" }),
        await encryptPayload(binding.encryption.server_public_key, JSON.stringify(credential))
    );
}

async function deleteCredential(binding, namespace, type, name) {
    await fetch(
        `${binding.url}/${type}?name=${encodeURIComponent(name)}`,
        {
            method: "delete",
            headers: headers(binding, namespace)
        }
    ).then(checkStatus);
}

module.exports = { readCredential, writeCredential, deleteCredential };
```

## Envío de Correos Electrónicos con Azure Communication Service

El proyecto también proporciona un servicio para enviar correos electrónicos mediante **Azure Communication Service**. Para lograr esto, primero se recuperan las credenciales necesarias desde el **SAP Credential Store** y luego se utiliza la **Azure Email Client SDK** para enviar los correos.

El endpoint expuesto permite enviar correos electrónicos mediante la siguiente lógica:

1. Se leen las credenciales de la conexión de Azure desde el **SAP Credential Store**.
2. Se recupera la dirección de correo del remitente desde el **SAP Credential Store**.
3. Se configura la **cadena de conexión** de Azure Communication Service.
4. Se construye el correo con los destinatarios, asunto y contenido.
5. Se utiliza el **cliente de email de Azure** para enviar el correo.

### Código de la Gestión de Envío de Emails

```javascript
const { EmailClient } = require('@azure/communication-email');
const cds = require('@sap/cds');
const {readCredential} =  require('./utils/cred_oauthmtls');
const binding = JSON.parse(process.env.VCAP_SERVICES).credstore[0].credentials;
module.exports = cds.service.impl(async function () {

    this.on('sendEmail', async (req) => {
        try {
            const readRes = await readCredential(binding, "email", "password", "AZURE_COMMUNICATION_CONNECTION_STRING");
            const senderAddress_ = await readCredential(binding, "email", "password", "SENDER_EMAIL");
            const { to, subject, content } = req.data;

            // Configura la cadena de conexión de Azure Communication Services
            const connectionString = readRes.value;

            // Inicializa el cliente de Azure Email
            const emailClient = new EmailClient(connectionString);

            // Construye el correo
            const emailMessage = {
                senderAddress: senderAddress_.value, 
                content: {
                    subject: subject,
                    plainText: content,  // Texto plano del correo
                },
                recipients: {
                    to: [{
                        address: to,
                        displayName: "Manel"
                    }]
                }
            };

            // Enviar el correo
            const poller = await emailClient.beginSend(emailMessage);
            // Espera el resultado
            const result = await poller.pollUntilDone();

            return { messageId: result.id, status: result.status };

        } catch (error) {
            req.error(500, 'Error enviando el correo electrónico,\nCódigo de error: '+ error.message);
        }
    });
});

```
# Enviar Correo Electrónico Mediante una Solicitud POST

Para enviar un correo electrónico a través de la aplicación, se debe realizar una solicitud `POST` a un endpoint específico con los detalles del correo. A continuación se describe cómo hacerlo.

## Configuración del Servicio

El servicio para enviar correos electrónicos está definido de la siguiente manera:

```cds
@rest service email {
   @POST
   action sendEmail(to: String, subject: String, content: String);
}
```

# Resumen

Para enviar un correo electrónico utilizando el servicio REST, se debe realizar una solicitud `POST` al endpoint correspondiente con el formato `application/json`.

- **URL Base:** `http://<url-donde-se-ha-desplegado-el-servicio>/rest/email`
- **Endpoint de Acción:** `/sendEmail`
- **Método HTTP:** `POST`
- **Formato de la Solicitud:** `application/json`

## Campos Requeridos:

- **`to`:** Dirección de correo del destinatario.
- **`subject`:** Asunto del correo.
- **`content`:** Contenido del mensaje.

### Ejemplo de Solicitud

```json
{
  "to": "destinatario@example.com",
  "subject": "Asunto del correo",
  "content": "Contenido del correo"
}
```