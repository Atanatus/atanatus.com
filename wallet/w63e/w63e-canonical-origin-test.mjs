import {
  CRYPTO_POLICY,
  randomBytes,
  encryptSecretBytes,
  decryptSecretBytes,
  encodeSyntheticSecret,
  decodeSyntheticSecret,
  wipeBytes
} from './passkey-wallet-crypto-core.mjs';

const $ = (id) => document.getElementById(id);
const logEl = $('log');
const runButton = $('run');
const downloadButton = $('download');
let sanitizedResult = null;

function log(line=''){
  logEl.textContent += String(line) + '\n';
  logEl.scrollTop = logEl.scrollHeight;
}

function equalBytes(a,b){
  const aa = a instanceof Uint8Array ? a : new Uint8Array(a);
  const bb = b instanceof Uint8Array ? b : new Uint8Array(b);
  if(aa.byteLength !== bb.byteLength) return false;
  let diff = 0;
  for(let i=0;i<aa.byteLength;i++) diff |= aa[i] ^ bb[i];
  return diff === 0;
}

function b64url(bytes){
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = '';
  for(const b of u8) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}

async function sha256B64Url(bytes){
  const digest = await crypto.subtle.digest('SHA-256',bytes);
  return b64url(new Uint8Array(digest));
}

function assertCanonicalOrigin(){
  if(location.origin !== 'https://atanatus.com'){
    throw new Error('CANONICAL_ORIGIN_REQUIRED');
  }
  if(!location.pathname.startsWith('/wallet/w63e/')){
    throw new Error('ISOLATED_W63E_PATH_REQUIRED');
  }
  if(self.isSecureContext !== true){
    throw new Error('SECURE_CONTEXT_REQUIRED');
  }
  if(self !== top){
    throw new Error('TOP_LEVEL_CONTEXT_REQUIRED');
  }
}

async function getPrf(credentialRawId,prfInput){
  const assertion = await navigator.credentials.get({
    publicKey:{
      challenge:randomBytes(32),
      rpId:'atanatus.com',
      allowCredentials:[{
        type:'public-key',
        id:credentialRawId
      }],
      userVerification:'required',
      timeout:120000,
      extensions:{
        prf:{eval:{first:prfInput}}
      }
    }
  });

  if(!assertion) throw new Error('ASSERTION_NULL');
  const ext = assertion.getClientExtensionResults?.() || {};
  const first = ext?.prf?.results?.first;
  return first ? new Uint8Array(first) : null;
}

function makeDownload(result){
  sanitizedResult = result;
  downloadButton.disabled = false;
}

downloadButton.addEventListener('click',()=>{
  if(!sanitizedResult) return;
  const blob = new Blob(
    [JSON.stringify(sanitizedResult,null,2) + '\n'],
    {type:'application/json'}
  );
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'ATAN_W63E_CANONICAL_ORIGIN_SANITIZED_RESULT.json';
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(()=>URL.revokeObjectURL(url),1000);
});

runButton.addEventListener('click',async ()=>{
  runButton.disabled = true;
  downloadButton.disabled = true;
  logEl.textContent = '';
  sanitizedResult = null;

  const result = {
    status:'FAIL',
    origin:location.origin,
    pathname:location.pathname,
    rpId:'atanatus.com',
    secureContext:false,
    topLevel:false,
    publicKeyCredentialApi:false,
    platformAuthenticatorAvailable:null,
    credentialCreated:false,
    credentialIdSha256:null,
    createPrfEnabled:null,
    createPrfResultPresent:false,
    firstAssertionPrfResultPresent:false,
    secondAssertionPrfResultPresent:false,
    prfOutputBytes:null,
    prfDeterministic:false,
    syntheticRoundtrip:false,
    wrongPrfRejected:false,
    tamperedCiphertextRejected:false,
    plaintextAbsentFromEnvelope:false,
    prfOutputAbsentFromEnvelope:false,
    syntheticBuffersZeroized:false,
    prfBuffersZeroized:false,
    credentialToJsonCalled:false,
    prfOutputSent:false,
    networkSubmissionPerformed:false,
    realMnemonicUsed:false,
    realPrivateKeyUsed:false,
    walletCodeMutated:false,
    transactionSigning:false,
    transactionBroadcast:false
  };

  let createPrf = null;
  let firstPrf = null;
  let secondPrf = null;
  let secretBytes = null;
  let decrypted = null;
  let wrongPrf = null;

  try{
    assertCanonicalOrigin();

    result.secureContext = self.isSecureContext === true;
    result.topLevel = self === top;
    result.publicKeyCredentialApi =
      typeof PublicKeyCredential !== 'undefined' &&
      !!navigator.credentials?.create &&
      !!navigator.credentials?.get;

    if(!result.publicKeyCredentialApi){
      throw new Error('WEBAUTHN_API_UNAVAILABLE');
    }

    if(typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === 'function'){
      result.platformAuthenticatorAvailable =
        await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    }

    log('Canonical origin: PASS');
    log('Secure context: PASS');
    log('WebAuthn API: PASS');
    log('Creating TEST passkey for atanatus.com…');
    log('No wallet seed or BCH private key is requested by this page.');

    const prfInput = randomBytes(CRYPTO_POLICY.prfInputBytes);
    const userId = randomBytes(32);

    const credential = await navigator.credentials.create({
      publicKey:{
        rp:{
          id:'atanatus.com',
          name:'ATANATUS W63E canonical-origin test'
        },
        user:{
          id:userId,
          name:'atanatus-w63e-test',
          displayName:'ATANATUS W63E TEST ONLY'
        },
        challenge:randomBytes(32),
        pubKeyCredParams:[
          {type:'public-key',alg:-7},
          {type:'public-key',alg:-257}
        ],
        timeout:120000,
        attestation:'none',
        authenticatorSelection:{
          residentKey:'required',
          requireResidentKey:true,
          userVerification:'required'
        },
        extensions:{
          prf:{eval:{first:prfInput}}
        }
      }
    });

    if(!credential) throw new Error('CREDENTIAL_CREATE_NULL');

    result.credentialCreated = true;
    result.credentialIdSha256 =
      await sha256B64Url(new Uint8Array(credential.rawId));

    const createExt = credential.getClientExtensionResults?.() || {};
    result.createPrfEnabled =
      createExt?.prf?.enabled === true
        ? true
        : (createExt?.prf ? false : null);

    if(createExt?.prf?.results?.first){
      createPrf = new Uint8Array(createExt.prf.results.first);
      result.createPrfResultPresent = true;
    }

    firstPrf = await getPrf(credential.rawId,prfInput);
    result.firstAssertionPrfResultPresent = !!firstPrf;
    if(!firstPrf || firstPrf.byteLength !== 32){
      throw new Error('FIRST_PRF_UNAVAILABLE_OR_NOT_32_BYTES');
    }

    secondPrf = await getPrf(credential.rawId,prfInput);
    result.secondAssertionPrfResultPresent = !!secondPrf;
    if(!secondPrf || secondPrf.byteLength !== 32){
      throw new Error('SECOND_PRF_UNAVAILABLE_OR_NOT_32_BYTES');
    }

    result.prfOutputBytes = firstPrf.byteLength;
    result.prfDeterministic = equalBytes(firstPrf,secondPrf);

    if(!result.prfDeterministic){
      throw new Error('PRF_NOT_DETERMINISTIC');
    }

    if(createPrf && createPrf.byteLength === 32 && !equalBytes(createPrf,firstPrf)){
      throw new Error('CREATE_ASSERTION_PRF_MISMATCH');
    }

    const synthetic =
      'ATANATUS_W63E_CANONICAL_ORIGIN_SYNTHETIC_SECRET_NOT_REAL_MNEMONIC';

    secretBytes = encodeSyntheticSecret(synthetic);

    const binding = {
      origin:'https://atanatus.com',
      rpId:'atanatus.com',
      walletPathPrefix:'/wallet/',
      credentialId:result.credentialIdSha256
    };

    const envelope = await encryptSecretBytes({
      secretBytes,
      prfOutput:firstPrf,
      ...binding
    });

    const serialized = JSON.stringify(envelope);
    result.plaintextAbsentFromEnvelope = !serialized.includes(synthetic);
    result.prfOutputAbsentFromEnvelope = !serialized.includes(b64url(firstPrf));

    if(!result.plaintextAbsentFromEnvelope){
      throw new Error('PLAINTEXT_PRESENT_IN_ENVELOPE');
    }
    if(!result.prfOutputAbsentFromEnvelope){
      throw new Error('PRF_OUTPUT_PRESENT_IN_ENVELOPE');
    }

    decrypted = await decryptSecretBytes({
      envelope,
      prfOutput:secondPrf,
      expectedBinding:binding
    });

    result.syntheticRoundtrip =
      decodeSyntheticSecret(decrypted) === synthetic;

    if(!result.syntheticRoundtrip){
      throw new Error('SYNTHETIC_ROUNDTRIP_FAILED');
    }

    wrongPrf = randomBytes(32);
    try{
      await decryptSecretBytes({
        envelope,
        prfOutput:wrongPrf,
        expectedBinding:binding
      });
    }catch{
      result.wrongPrfRejected = true;
    }

    const tampered = structuredClone(envelope);
    const original = tampered.cipher.ciphertext;
    tampered.cipher.ciphertext =
      (original[0] === 'A' ? 'B' : 'A') + original.slice(1);

    try{
      await decryptSecretBytes({
        envelope:tampered,
        prfOutput:secondPrf,
        expectedBinding:binding
      });
    }catch{
      result.tamperedCiphertextRejected = true;
    }

    if(!result.wrongPrfRejected) throw new Error('WRONG_PRF_NOT_REJECTED');
    if(!result.tamperedCiphertextRejected) throw new Error('TAMPER_NOT_REJECTED');

    wipeBytes(secretBytes);
    wipeBytes(decrypted);
    wipeBytes(wrongPrf);
    wipeBytes(firstPrf);
    wipeBytes(secondPrf);
    if(createPrf) wipeBytes(createPrf);

    result.syntheticBuffersZeroized =
      secretBytes.every(v=>v===0) &&
      decrypted.every(v=>v===0);

    result.prfBuffersZeroized =
      firstPrf.every(v=>v===0) &&
      secondPrf.every(v=>v===0) &&
      (!createPrf || createPrf.every(v=>v===0));

    if(!result.syntheticBuffersZeroized){
      throw new Error('SYNTHETIC_BUFFER_ZEROIZATION_FAILED');
    }
    if(!result.prfBuffersZeroized){
      throw new Error('PRF_BUFFER_ZEROIZATION_FAILED');
    }

    result.status='PASS';

    log('Canonical origin: PASS');
    log('PRF 32 bytes: PASS');
    log('PRF deterministic: PASS');
    log('AES-256-GCM synthetic round trip: PASS');
    log('Wrong PRF rejected: PASS');
    log('Ciphertext tamper rejected: PASS');
    log('PRF buffers zeroized: PASS');
    log('');
    log('W63E canonical-origin browser result: PASS');
    log('Click "Download sanitized result".');

    makeDownload(result);
  }
  catch(error){
    log('');
    log('W63E canonical-origin browser result: FAIL');
    log('ERROR=' + String(error?.name || 'Error') + ':' + String(error?.message || error));

    try{
      if(secretBytes) wipeBytes(secretBytes);
      if(decrypted) wipeBytes(decrypted);
      if(wrongPrf) wipeBytes(wrongPrf);
      if(firstPrf) wipeBytes(firstPrf);
      if(secondPrf) wipeBytes(secondPrf);
      if(createPrf) wipeBytes(createPrf);
    }catch{}

    result.errorName=String(error?.name || 'Error').slice(0,80);
    result.errorMessage=String(error?.message || error).slice(0,240);
    makeDownload(result);
  }
  finally{
    runButton.disabled=false;
  }
});
