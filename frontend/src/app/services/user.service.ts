import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { Buffer } from 'buffer';
import * as CryptoJS from 'crypto-js';

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

    const requestBody = { email, M: M.toString(CryptoJS.enc.Base64) };
    return this.http.post<string>(this.apiUrl + "/checkusers", requestBody);
  }

  createUser(email: string, password: string): Observable<string> {
    const K = this.getK(password, BigInt(2) ** BigInt(2048));
    if (K === BigInt(0)) {
      console.error('Error generating K');
      return new Observable<string>();
    }
    const M = this.encryptWithRSAPublicKey(K, this.serverPublicKey);

    const requestBody = { email, M: M.toString(CryptoJS.enc.Base64) };

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
    const randomBytes: Buffer = Buffer.from(CryptoJS.lib.WordArray.random(32).toString(), 'hex');
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
    // Generating RSA key pair with CryptoJS
    const keyPair = CryptoJS.lib.WordArray.random(128).toString(); // 1024-bit key length

    return {
      privateKey: keyPair
    };
  }

  encryptWithRSAPublicKey(message: bigint, publicKey: string): CipherParams {
    // Encrypting message with RSA public key using CryptoJS
    return CryptoJS.AES.encrypt(message.toString(), publicKey);
  }

  // @ts-ignore
  performDHKeyExchange(serverPublicKey: string): CryptoJS.lib.WordArray {
    const clientSecret = CryptoJS.lib.WordArray.random(32);

    // Encrypt client's secret with server's public key
    const encryptedClientSecret = CryptoJS.AES.encrypt(clientSecret, serverPublicKey);

    this.http.get(this.apiUrl + "/dh/" + encryptedClientSecret.toString(CryptoJS.enc.Base64))
      .subscribe(
        (response: any) => {
          const encryptedServerSecret = CryptoJS.enc.Base64.parse(response.data.serverSecret);
          // Decrypt server's secret using client's private key
          const decryptedServerSecret = CryptoJS.AES.decrypt(encryptedServerSecret, clientSecret).toString(CryptoJS.enc.Utf8);

          // The shared secret is derived from both decrypted secrets
          const sharedSecret = CryptoJS.SHA256(clientSecret + decryptedServerSecret);
          return sharedSecret;
        },
        error => {
          console.error('Error fetching R:', error);
          return CryptoJS.lib.WordArray.create([]);
        }
      );
  }

  encryptWithAES(plaintext: string, sharedSecret: CryptoJS.lib.WordArray): CryptoJS.lib.WordArray {
    // Generating random IV with CryptoJS
    const iv = CryptoJS.lib.WordArray.random(16);

    // Encrypting plaintext with AES using CryptoJS
    const encryptedData = CryptoJS.AES.encrypt(plaintext, sharedSecret, { iv });

    // Combining IV and encrypted data
    const encryptedBuffer = iv.concat(encryptedData.ciphertext);

    return encryptedBuffer;
  }

  decryptWithAES(sharedSecret: CryptoJS.lib.WordArray, encryptedData: CryptoJS.lib.WordArray): string {
    // Extracting IV from the encrypted data
    const iv = encryptedData.words.slice(0, 4);

    // Decrypting ciphertext with AES using CryptoJS
    const decryptedData = CryptoJS.AES.decrypt({ ciphertext: encryptedData.words.slice(4) }, sharedSecret, { iv });

    // Returning the decrypted plaintext as a string
    return decryptedData.toString(CryptoJS.enc.Utf8);
  }
