const jose = require('node-jose');
const fetch = require('node-fetch');
const https = require('https');

// Function to check the HTTP status
function checkStatus(response) {
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

// Updated headers function to support mTLS
function headers_(binding, namespace, init = {}) {
    // Initialize the headers from the init parameter
    const headers = new fetch.Headers(init);

    // Add the custom 'sapcp-credstore-namespace' header
    headers.set("sapcp-credstore-namespace", namespace);
    headers.set("Cache-Control", "no-cache");

    // Create the mTLS agent using the certificate and private key from the binding object
    const agent = new https.Agent({
        cert: binding.certificate,
        key: binding.key,
    });

    // Return both the headers and the agent in an object so they can be used in fetch options
    return { headers, agent };
}

// Function to fetch and decrypt the response
async function fetchAndDecrypt(privateKey, url, method, headers, body) {
    return fetch(url, { method, ...headers, body })
        .then(checkStatus)
        .then(response => response.text())
        .then(payload => decryptPayload(privateKey, payload))
        .then(JSON.parse);
}

// Function to read credentials from the API
async function readCredential(binding, namespace, type, name) {
    const { headers, agent } = headers_(binding, namespace);
    return fetchAndDecrypt(
        binding.encryption.client_private_key,
        `${binding.url}/${type}?name=${encodeURIComponent(name)}`,
        "GET",
        { headers, agent }
    );
}

// Function to write credentials to the API
async function writeCredential(binding, namespace, type, credential) {
    const { headers, agent } = headers_(binding, namespace);
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
    const { headers, agent } = headers_(binding, namespace);
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