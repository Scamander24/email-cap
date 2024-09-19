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
