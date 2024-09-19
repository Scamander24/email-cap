const jose = require('node-jose');
const fetch = require('node-fetch');
const https = require('https');

// Function to check the HTTP status
async function checkStatus(response) {
    if (!response.ok) throw Error("Unexpected status code: " + response.status);
    return response;
}

// Function to decrypt payload using the private key
async function decryptPayload(privateKey, payload) {
    const key = await jose.JWK.asKey(`-----BEGIN PRIVATE KEY-----${privateKey}-----END PRIVATE KEY-----`,
        "pem",
        { alg: "RSA-OAEP-256", enc: "A256GCM" }
    );
    const decrypt = await jose.JWE.createDecrypt(key).decrypt(payload);
    const result = decrypt.plaintext.toString();
    return result;
}

// Function to encrypt payload using the public key
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

// Function to obtain OAuth token using client credentials
async function getOAuthToken(binding, namespace) {
    const tokenUrl = binding.oauth_token_url;
    const body = `grant_type=client_credentials&client_id=${encodeURIComponent(binding.username)}&credstore_namespace=${encodeURIComponent(namespace)}`;

    const response = await fetch(tokenUrl, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Cache-Control': 'no-cache'
        },
        body,
        agent: new https.Agent({
            cert: binding.certificate,
            key: binding.key
        })
    });

    const data = await checkStatus(response).then(res => res.json());
    return data.access_token; // Return the OAuth token
}

function headers_(binding, token) {
    const headers = new fetch.Headers();
    headers.set("Authorization", `Bearer ${token}`);
    headers.set("Cache-Control", "no-cache");

    // Devuelve el objeto que contiene los encabezados y el agente HTTPS
    return {
        headers,
        agent: new https.Agent({
            cert: binding.certificate,
            key: binding.key
        })
    };
}

// Function to fetch and decrypt the response
async function fetchAndDecrypt(privateKey, url, method, headers, body = null) {

    // Crear el objeto de opciones de la solicitud
    const options = {
        method, // Método (GET, POST, etc.)
        headers: headers.headers, // Pasar los encabezados correctamente
        agent: headers.agent, // Pasar el agente HTTPS
        body: body ? body : undefined // Cuerpo de la solicitud (si es necesario)
    };

    try {
        // Realizar la solicitud HTTP
        const response = await fetch(url, options);

        // Verificar el estado de la respuesta
        await checkStatus(response);

        // Obtener la respuesta como texto
        const payload = await response.text();

        // Desencriptar el payload
        const decryptedPayload = await decryptPayload(privateKey, payload);

        // Parsear el resultado como JSON y retornarlo
        return JSON.parse(decryptedPayload);

    } catch (error) {
        console.error("Error al realizar la solicitud:", error);
        throw error;
    }
}



// Function to read credentials from the API
async function readCredential(binding, namespace, type, name) {
    const token = await getOAuthToken(binding, namespace);
    const { headers, agent } = headers_(binding, token);

    return fetchAndDecrypt(
        binding.encryption.client_private_key,
        `${binding.url}/${type}?name=${encodeURIComponent(name)}`,
        "GET",
        { headers, agent }
    );
}

// Function to write credentials to the API
async function writeCredential(binding, namespace, type, credential) {
    const token = await getOAuthToken(binding, namespace);
    const { headers, agent } = headers_(binding, token);

    const encryptedPayload = await encryptPayload(binding.encryption.server_public_key, JSON.stringify(credential));

    return fetchAndDecrypt(
        binding.encryption.client_private_key,
        `${binding.url}/${type}`,
        "POST",
        { headers, agent },
        encryptedPayload
    );
}

// Function to delete credentials from the API
async function deleteCredential(binding, namespace, type, name) {
    const token = await getOAuthToken(binding, namespace);
    const { headers, agent } = headers_(binding, token);

    await fetch(
        `${binding.url}/${type}?name=${encodeURIComponent(name)}`,
        {
            method: "DELETE",
            headers,
            agent
        }
    ).then(checkStatus);
}

module.exports = { readCredential, writeCredential, deleteCredential };
