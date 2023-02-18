const sm2 = require('sm-crypto').sm2;
const G2FA = require('google_authenticator').authenticator;

const google2FA = new G2FA(9);
const keypair = sm2.generateKeyPairHex();
const rnd = (offset = 0, min = 20000, max = 40000) => min + Math.round(
    (Math.random() * (max - min))
) + offset;


const body = {
    global: {
        google2fa: {
            secret: google2FA.createSecret(16),
            time: 10
        },
        privateKey: keypair.privateKey,
        publicKey: keypair.publicKey
    },
    client: {
        // HTTP Proxy Server Port
        proxyPort: rnd(1)
    },
    server: {
        //Your RelayServer IPv4 Address
        address: '',
        cert: {
            //Your SSL Certificate(Base64)
            crt: '',
            //Your SSL Key(Base64)
            key: ''
        },
        httpPort: rnd(2),
        httpsPort: rnd(3)
    }
}


console.log(body)