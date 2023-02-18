const configure = require('./relay-configure.json');
const sm2 = require('sm-crypto').sm2
const G2FA = require('google_authenticator').authenticator;
const google2FA = new G2FA(9);
const http = require('http');
const https = require('https');
const server_http = http.createServer();
const server_https = https.createServer({
    cert: Buffer.from(configure.server.cert.crt, 'base64').toString('utf8'),
    key: Buffer.from(configure.server.cert.key, 'base64').toString('utf8')
});
const proxy = require('http-proxy').createProxyServer({
    secure: false,
    xfwd: true,
    proxyTimeout: 5000,
    timeout: 5000,
    autoRewrite: true,
    followRedirects: true
});

/**
 * @param {http.IncomingMessage} req 
 * @param {http.ServerResponse} res 
 * @param {boolean} isSSL 
 */
function handle(req, res, isSSL = false) {
    if([
        req.headers['x-relay.protocol-g2fa'] == undefined,
        req.headers['x-relay.protocol-target'] == undefined,
        req.headers['x-relay.protocol-signed'] == undefined
    ].indexOf(true) !== -1) return res.socket.destroy();
    if([
        req.headers['x-relay.protocol-g2fa'].length !== 9,
        isNaN(req.headers['x-relay.protocol-g2fa'])
    ].indexOf(true) !== -1) return res.socket.destroy();
    if(google2FA.getCode(
            configure.global.google2fa.secret, 
            Math.floor((new Date())/1000/configure.global.google2fa.time
        )) !== req.headers['x-relay.protocol-g2fa']) return res.end();

    const state = sm2.doVerifySignature(req.headers['x-relay.protocol-target'], req.headers['x-relay.protocol-signed'], configure.global.publicKey)

    if(state) {
        req.headers['host'] = sm2.doDecrypt(req.headers['x-relay.protocol-target'], configure.global.privateKey, 1);
    } else return res.socket.destroy();

    proxy.once('proxyRes', (proxyRes, pReq, pRes) => {
        console.log(`${req.socket.remoteAddress}\t--->\t ${pReq.headers['host']} == ${proxyRes.statusCode}`)
    });

    
    proxy.web(req, res, {
        target: `http${isSSL?'s':''}://${req.headers['host']}`
    }, (perr, preq, pres) => {
        pres.statusCode = 504;
        pres.setHeader('Content-Type', 'text/plain');
        pres.write('504 Gateway Time-out',() => pres.end());
    });
}

server_http.on('request', (req, res) => handle(req, res, false));
server_https.on('request', (req, res) => handle(req, res, true));

server_http.listen(configure.server.httpPort, '0.0.0.0', () => console.log('HTTP Server'));
server_https.listen(configure.server.httpsPort, '0.0.0.0', () => console.log('HTTPS Server'));

proxy.on('error', function(err, req, res) {
    res.writeHead(500, {
        'Content-Type': 'text/plain'
    });
    res.end('Something went wrong. And we are reporting a custom error message.');
});