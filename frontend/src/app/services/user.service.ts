import {Injectable} from '@angular/core';
import {HttpClient} from '@angular/common/http';
import {Observable} from 'rxjs';
import {Buffer} from 'buffer';
import * as crypto from 'crypto';
import {generateKeyPair} from "crypto";

@Injectable({
  providedIn: 'root'
})
export class UserService {
  private apiUrl = '/api'; // Assuming your backend serves this route
  private serverPublicKey: string = '';
  constructor(private http: HttpClient) { }

  checkUser(email: string, password: string): Observable<string> {
    const K = this.getK(password, BigInt(2) ** BigInt(2048));
    if (K === BigInt(0)) {
      console.error('Error generating K');
      return new Observable<string>();
    }
    const sharedKey = this.performDHKeyExchange(this.serverPublicKey);
    const M = this.encryptWithAES(K.toString(), sharedKey);

    const requestBody = { email, M: M.toString('base64') };
    return this.http.post<string>(this.apiUrl + "/checkusers", requestBody);
  }

  createUser(email: string, password: string): Observable<string> {
    const K = this.getK(password, BigInt(2) ** BigInt(2048));
    if (K === BigInt(0)) {
      console.error('Error generating K');
      return new Observable<string>();
    }
    const M = this.encryptWithRSAPublicKey(K, this.serverPublicKey);

    const requestBody = { email, M: M.toString('base64') };

    return this.http.post<string>(this.apiUrl + "/users", requestBody);
  }

  computeHash(p: string, q: bigint): bigint {
    const s: bigint = BigInt("0x" + Buffer.from(p, 'utf-8').toString('hex'));  // Convert string P to integer
    const s_mod: bigint = (s % BigInt(q - BigInt(2))) + BigInt(2);  // Ensure s is in the range [2, q]
    return (s_mod ** BigInt(2)) % BigInt((BigInt(2) * q) + BigInt(1));  // Compute H(P) = s^2 mod (2q + 1)
  }

  // @ts-ignore
  getK(p: string, q: bigint): bigint {
    const h_p: bigint = this.computeHash(p, q);

    // Generate random scalar
    const randomBytes: Buffer = crypto.randomBytes(32);
    const r: bigint = BigInt("0x" + randomBytes.toString('hex'));

    // Client sends C = H(P) ** r to server
    const C: bigint = (h_p ** r) % BigInt(q);

    const { privateKey, publicKey } = this.generateRSAKeyPair();

    // Make a request to the server to get R
    this.http.get(this.apiUrl + "/getR/" + C.toString() + "/" + publicKey.toString())
      .subscribe(
        (response: any) => {
          const R = BigInt(response.data.R);
          this.serverPublicKey = response.data.publicKey;

          // Compute z = 1 / R
          const z: bigint = this.modInverse(R, BigInt(q));

          // Return K = R^z
          return (R ** z);
        },
        error => {
          console.error('Error fetching R:', error);
          return BigInt(0);
        }
      );
  }

  // Function to calculate the modular multiplicative inverse
  modInverse(a: bigint, m: bigint): bigint {
    const [x, , gcd] = this.extendedGCD(a, m);
    if (gcd !== BigInt(1)) {
      throw new Error('The modular inverse does not exist');
    }
    return (x % m + m) % m;
  }

  // Extended Euclidean algorithm to find gcd and the coefficients
  extendedGCD(a: bigint, b: bigint): [bigint, bigint, bigint] {
    if (a === BigInt(0)) {
      return [b, BigInt(0), BigInt(1)];
    } else {
      const [gcd, x, y] = this.extendedGCD(b % a, a);
      return [gcd, y - (b / a) * x, x];
    }
  }

  generateRSAKeyPair(): { privateKey: string, publicKey: string } {
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

  encryptWithRSAPublicKey(message: bigint, publicKey: string): Buffer {
    const bufferMessage = Buffer.from(message.toString());
    const encryptedBuffer = crypto.publicEncrypt({
      key: publicKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    }, bufferMessage);
    return encryptedBuffer;
  }
  // @ts-ignore
  performDHKeyExchange(serverPublicKey: string): Buffer {
    const clientSecret = crypto.randomBytes(32);

    // Encrypt client's secret with server's public key
    const encryptedClientSecret = crypto.publicEncrypt({
      key: serverPublicKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    }, clientSecret);

    this.http.get(this.apiUrl + "/dh/" + encryptedClientSecret.toString('base64'))
      .subscribe(
        (response: any) => {
          const encryptedServerSecret = Buffer.from(response.data.serverSecret, 'base64');
          // Decrypt server's secret using client's private key
          const decryptedServerSecret = crypto.privateDecrypt({
            key: encryptedServerSecret,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256',
          }, encryptedServerSecret);

          // The shared secret is derived from both decrypted secrets
          const sharedSecret = crypto.createHash('sha256')
            .update(clientSecret)
            .update(decryptedServerSecret)
            .digest();
          return sharedSecret;
        },
        error => {
          console.error('Error fetching R:', error);
          return Buffer.from('');
        }
      );
  }

  encryptWithAES(plaintext: string, sharedSecret: Buffer): Buffer {
    // Generate an initialization vector (IV)
    const iv = crypto.randomBytes(16);

    // Create a cipher using AES-256-CBC algorithm
    const cipher = crypto.createCipheriv('aes-256-cbc', sharedSecret, iv);

    // Encrypt the plaintext
    let encryptedData = cipher.update(plaintext, 'utf8', 'hex');
    encryptedData += cipher.final('hex');

    // Combine IV and encrypted data
    const encryptedBuffer = Buffer.concat([iv, Buffer.from(encryptedData, 'hex')]);

    return encryptedBuffer;
  }

  decryptWithAES(sharedSecret: Buffer, encryptedData: Buffer): string {
    // Extract IV from the encrypted data
    const iv = encryptedData.slice(0, 16); // IV size for AES-256-CBC is 16 bytes

    // Extract ciphertext from the encrypted data
    const ciphertext = encryptedData.slice(16);

    // Create a decipher using AES-256-CBC algorithm
    const decipher = crypto.createDecipheriv('aes-256-cbc', sharedSecret, iv);

    // Decrypt the ciphertext
    let decryptedData = decipher.update(ciphertext);
    decryptedData = Buffer.concat([decryptedData, decipher.final()]);

    // Return the decrypted plaintext as a string
    return decryptedData.toString('utf8');
  }

  decryptWithRSAPrivateKey(encryptedData: Buffer, privateKey: string): bigint {
    const decryptedBuffer = crypto.privateDecrypt({
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    }, encryptedData);
    const decryptedMessage = decryptedBuffer.toString();
    return BigInt(decryptedMessage);
  }
}
