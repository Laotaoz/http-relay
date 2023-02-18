const configure = require('./relay-configure.json');
const sm2 = require('sm-crypto').sm2
const G2FA = require('google_authenticator').authenticator;
const google2FA = new G2FA(9);
const net = require('net');
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
    req.headers['x-relay.protocol-target'] = sm2.doEncrypt(req.headers['host'], configure.global.publicKey, 1);
    req.headers['x-relay.protocol-signed'] = sm2.doSignature(req.headers['x-relay.protocol-target'], configure.global.privateKey);
    req.headers['x-relay.protocol-g2fa'] = google2FA.getCode(configure.global.google2fa.secret, Math.floor((new Date())/1000/configure.global.google2fa.time));

    req.headers['host'] = configure.server.address;
    
    proxy.web(req, res, {
        target: `http${isSSL?'s':''}://${req.headers['host']}:${isSSL?32443:32080}`
    }, (perr, preq, pres) => {
        pres.statusCode = 504;
        pres.setHeader('Content-Type', 'text/plain');
        pres.write('504 Gateway Time-out',() => pres.end());
    });
}

server_http.on('request', (req, res) => handle(req, res, false));
server_https.on('request', (req, res) => handle(req, res, true));

server_http.listen(80, '0.0.0.0', () => console.log('HTTP Server'));
server_https.listen(443, '0.0.0.0', () => console.log('HTTPS Server'));

proxy.on('error', function(err, req, res) {
    res.writeHead(500, {
        'Content-Type': 'text/plain'
    });
    res.end('Something went wrong. And we are reporting a custom error message.');
});


function httpProxyServer(proxyPort, redirectServer) {
    const server = http.createServer()
    .on('connect', (req, socket, head) => {
        const userInfo = {
            cliAddr: `${req.socket.remoteAddress}:${req.socket.remotePort}`,
            target: {
                address: req.url.substring(0,req.url.lastIndexOf(':')),
                port: Number(req.url.substring(req.url.lastIndexOf(':')+1))
            }
        };
        const logger = (style) => console.log(style, `${userInfo.cliAddr} --> ${server.address().port} --> ${configure.server.address} --> ${userInfo.target.address}`);
        const remote = net.connect({port:userInfo.target.port,host:redirectServer,timeout: 5000}, () => {
            logger('\x1B[32m%s\x1B[39m')
            socket.write('HTTP/1.1 200 Connection Established\r\nProxy-agent: MITM-proxy\r\n\r\n');
            remote.write(head);socket.pipe(remote).pipe(socket);
        });
        remote.on('close', hadError => {})
        .on('end', () => {})
        .on('error', err => logger('\x1B[31m%s\x1B[39m'))
        .on('timeout', () => {})
    })
    .on('error', err => console.error(err))
    .on('clientError', (err, errSocket) => {})
    .on('listening', () => console.log('HTTP Proxy Server on ['+server.address().address+']:'+String(server.address().port)))
    .listen(proxyPort, '0.0.0.0');
}

process.on('uncaughtException',(err)=>{});httpProxyServer(configure.client.proxyPort, '127.0.0.1');