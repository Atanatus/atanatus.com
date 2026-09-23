const te = new TextEncoder();
const td = new TextDecoder();

export const CRYPTO_POLICY = Object.freeze({
  schema: 'ATAN_PASSKEY_ENVELOPE_V1',
  cipher: 'AES-GCM',
  aesBits: 256,
  ivBytes: 12,
  prfOutputBytes: 32,
  prfInputBytes: 32,
  hkdfSaltBytes: 32,
  hkdfHash: 'SHA-256',
  hkdfInfo: 'ATANATUS/WALLET/KEK/v1',
  plaintextMnemonicPersistence: 'FORBIDDEN',
  plaintextPrivateKeyPersistence: 'FORBIDDEN',
  serverSecretCustody: 'FORBIDDEN',
  credentialToJsonWithPrf: 'FORBIDDEN'
});

function wc(){
  if(!globalThis.crypto?.subtle || !globalThis.crypto?.getRandomValues){
    throw new Error('WEBCRYPTO_UNAVAILABLE');
  }
  return globalThis.crypto;
}

export function bytesToB64Url(bytes){
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let binary = '';
  for(const b of u8) binary += String.fromCharCode(b);
  return btoa(binary)
    .replace(/\+/g,'-')
    .replace(/\//g,'_')
    .replace(/=+$/,'');
}

export function b64UrlToBytes(value){
  const padded = String(value).replace(/-/g,'+').replace(/_/g,'/');
  const pad = padded.length % 4 === 0 ? '' : '='.repeat(4 - (padded.length % 4));
  const binary = atob(padded + pad);
  const out = new Uint8Array(binary.length);
  for(let i=0;i<binary.length;i++) out[i] = binary.charCodeAt(i);
  return out;
}

export function randomBytes(length){
  const out = new Uint8Array(length);
  wc().getRandomValues(out);
  return out;
}

export function canonicalAad(meta){
  const required = {
    schema: CRYPTO_POLICY.schema,
    origin: String(meta.origin),
    rpId: String(meta.rpId),
    walletPathPrefix: String(meta.walletPathPrefix),
    credentialId: String(meta.credentialId)
  };
  return te.encode(JSON.stringify(required));
}

export async function deriveNonExtractableKek(prfOutput,hkdfSalt){
  const prf = prfOutput instanceof Uint8Array ? prfOutput : new Uint8Array(prfOutput);
  const salt = hkdfSalt instanceof Uint8Array ? hkdfSalt : new Uint8Array(hkdfSalt);

  if(prf.byteLength !== CRYPTO_POLICY.prfOutputBytes){
    throw new Error('PRF_OUTPUT_LENGTH_INVALID');
  }
  if(salt.byteLength !== CRYPTO_POLICY.hkdfSaltBytes){
    throw new Error('HKDF_SALT_LENGTH_INVALID');
  }

  const baseKey = await wc().subtle.importKey(
    'raw',
    prf,
    'HKDF',
    false,
    ['deriveKey']
  );

  return wc().subtle.deriveKey(
    {
      name: 'HKDF',
      hash: CRYPTO_POLICY.hkdfHash,
      salt,
      info: te.encode(CRYPTO_POLICY.hkdfInfo)
    },
    baseKey,
    {
      name: 'AES-GCM',
      length: CRYPTO_POLICY.aesBits
    },
    false,
    ['encrypt','decrypt']
  );
}

export async function encryptSecretBytes({secretBytes,prfOutput,prfInput,origin,rpId,walletPathPrefix,credentialId}){
  const secret = secretBytes instanceof Uint8Array ? secretBytes : new Uint8Array(secretBytes);
  if(secret.byteLength < 1) throw new Error('EMPTY_SECRET_FORBIDDEN');

  const effectivePrfInput =
    prfInput === undefined
      ? randomBytes(CRYPTO_POLICY.prfInputBytes)
      : (
          prfInput instanceof Uint8Array
            ? new Uint8Array(prfInput)
            : new Uint8Array(prfInput)
        );

  if(effectivePrfInput.byteLength !== CRYPTO_POLICY.prfInputBytes){
    throw new Error('PRF_INPUT_LENGTH_INVALID');
  }
  const hkdfSalt = randomBytes(CRYPTO_POLICY.hkdfSaltBytes);
  const iv = randomBytes(CRYPTO_POLICY.ivBytes);

  const meta = {
    origin,
    rpId,
    walletPathPrefix,
    credentialId
  };

  const key = await deriveNonExtractableKek(prfOutput,hkdfSalt);
  const aad = canonicalAad(meta);

  const ciphertext = new Uint8Array(
    await wc().subtle.encrypt(
      {
        name: 'AES-GCM',
        iv,
        additionalData: aad,
        tagLength: 128
      },
      key,
      secret
    )
  );

  return {
    schema: CRYPTO_POLICY.schema,
    version: 1,
    kdf: {
      name: 'WebAuthn-PRF -> HKDF-SHA-256',
      hkdfInfo: CRYPTO_POLICY.hkdfInfo,
      prfInput: bytesToB64Url(effectivePrfInput),
      hkdfSalt: bytesToB64Url(hkdfSalt)
    },
    cipher: {
      name: 'AES-256-GCM',
      iv: bytesToB64Url(iv),
      ciphertext: bytesToB64Url(ciphertext),
      tagLength: 128
    },
    binding: meta
  };
}

export async function decryptSecretBytes({envelope,prfOutput,expectedBinding}){
  if(!envelope || envelope.schema !== CRYPTO_POLICY.schema || envelope.version !== 1){
    throw new Error('ENVELOPE_SCHEMA_INVALID');
  }

  const binding = envelope.binding || {};
  for(const key of ['origin','rpId','walletPathPrefix','credentialId']){
    if(String(binding[key]) !== String(expectedBinding[key])){
      throw new Error('ENVELOPE_BINDING_MISMATCH_' + key.toUpperCase());
    }
  }

  const hkdfSalt = b64UrlToBytes(envelope.kdf.hkdfSalt);
  const iv = b64UrlToBytes(envelope.cipher.iv);
  const ciphertext = b64UrlToBytes(envelope.cipher.ciphertext);
  const key = await deriveNonExtractableKek(prfOutput,hkdfSalt);
  const aad = canonicalAad(binding);

  return new Uint8Array(
    await wc().subtle.decrypt(
      {
        name: 'AES-GCM',
        iv,
        additionalData: aad,
        tagLength: 128
      },
      key,
      ciphertext
    )
  );
}

export function encodeSyntheticSecret(value){
  return te.encode(String(value));
}

export function decodeSyntheticSecret(bytes){
  return td.decode(bytes);
}

export function wipeBytes(bytes){
  if(bytes instanceof Uint8Array) bytes.fill(0);
}
