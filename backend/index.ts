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


app.get('/getR/:C/:pubKey', (req, res) => {
  const C = BigInt(req.params.C);
  clientPublicKey = req.params.pubKey;

  const salt = crypto.randomBytes(32);

  const R = BigInt(C) ** BigInt(salt.toString('hex'));

  res.json({ R: R, publicKey: publicKey });
});


app.listen(3000, () => {
  console.log('Server is running on http://localhost:3000');
});
