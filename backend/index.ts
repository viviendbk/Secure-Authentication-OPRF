import * as express from 'express';
import * as crypto from 'crypto';

const app = express();

let clientPublicKey: string = "";
let { privateKey, publicKey } = generateRSAKeyPair();

function generateRSAKeyPair(): { privateKey: string, publicKey: string } {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem'
    }
  });

  return {
    privateKey: privateKey,
    publicKey: publicKey
  };
}

app.get('/', (req, res) => {
  res.send('Hello World!');
});


app.post('/checkusers', (req, res) => {
    const encryptedData = req.body.M;
    const decryptedBuffer = crypto.privateDecrypt({
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
    }, encryptedData);
    const decryptedMessage = decryptedBuffer.toString();
    return BigInt(decryptedMessage);
});


app.post("/users", (req, res) => {
    const encryptedData = req.body.M;
    const decryptedBuffer = crypto.privateDecrypt({
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
    }, encryptedData);
    const decryptedMessage = decryptedBuffer.toString();
    console.log(decryptedMessage);
    res.send(BigInt(decryptedMessage));
});


app.get('/getR/:C/:pubKey', (req, res) => {
  const C = BigInt(req.params.C);
  clientPublicKey = req.params.pubKey;

  const salt = crypto.randomBytes(32);

  const R = BigInt(C) ** BigInt(salt.toString('hex'));

  res.json({ R: R, publicKey: publicKey });
});


app.get("/dh/:encryptedClientSecret", (req, res) => {
    const encryptedClientSecret = req.params.encryptedClientSecret;

    const clientSecret = crypto.privateDecrypt(
        {
        key: privateKey,
        passphrase: '',
        },
        Buffer.from(encryptedClientSecret, 'base64')
    );

    const sharedSecret = crypto.createDiffieHellman(clientSecret).generateKeys();

    const encryptedSharedSecret = crypto.publicEncrypt(
        {
        key: clientPublicKey,
        passphrase: '',
        },
        sharedSecret
    );

    res.json({ sharedSecret: encryptedSharedSecret });
});

app.listen(3000, () => {
  console.log('Server is running on http://localhost:3000');
});
