import { createW62JUnsignedSettlementComposition } from './fee-abstraction-v2-w62j-unsigned-settlement-composer.mjs';

import {
  ATAN_SPONSORED_FEE_SHADOW_MODE,
  createSponsoredFeeShadowPreview
} from './fee-abstraction-v2-shadow.mjs';

import {
  createSponsorProtocolShadowState
} from './fee-abstraction-v2-sponsor-shadow-controller.mjs';

import {
  createExactSponsoredFeeEnvelopeV2,
  validateExactSponsoredFeeEnvelopeV2
} from './fee-abstraction-v2-exact-fee-planner.mjs';

import {
  createSponsorHttpsClient
} from './fee-abstraction-v2-sponsor-https-client.mjs';

import {
  CRYPTO_POLICY,
  b64UrlToBytes,
  bytesToB64Url,
  randomBytes,
  encryptSecretBytes,
  decryptSecretBytes,
  wipeBytes
} from './passkey-wallet-crypto-core.mjs';

const W62D_STAGED_SPONSOR_BASE_URL =
  'http://127.0.0.1:18787';

const W62D_PRODUCTION_SPONSOR_ORIGIN =
  'https://sponsor.atanatus.com';

const W62C_STAGED_EXACT_FEE_RATE_SATS_PER_KB =
  '1000';

const W62C_STAGED_FEE_RATE_SOURCE =
  'CERTIFIED_CANARY_PARITY_FIXTURE_NOT_LIVE_POLICY';

const ATAN_CATEGORY =
  '3c9af04021c731219908a6c1f9e900ce988d481d40463845e7f5befe61e0362b';

const DERIVATION_PATH =
  "m/44'/145'/0'/0/0";

const BCH_CHANGE_DERIVATION_PATH =
  "m/44'/145'/0'/0/1";

const PUBLIC_SMOKE_ADDRESS =
  'bitcoincash:qpue0pja34hemgz7h5zexlx8n36suy74lv83kkknxv';

const PASSKEY_STORAGE_KEY =
  'ATANATUS_WALLET_PASSKEY_ENVELOPE_V1';

const PASSKEY_CANONICAL_ORIGIN =
  'https://atanatus.com';

const PASSKEY_CANONICAL_RPID =
  'atanatus.com';

const PASSKEY_WALLET_PATH_PREFIX =
  '/wallet/';

const $ =
  id =>
    document.getElementById(id);

const state = {
  mainnet:
    null,

  wallet:
    null,

  changeWallet:
    null,

  pending:
    null
};


function requireElement(
  id
){
  const element =
    $(id);

  if(!element){
    throw new Error(
      'UI_ELEMENT_MISSING_' +
      id
    );
  }

  return element;
}


function setText(
  id,
  value
){
  const element =
    $(id);

  if(element){
    element.textContent =
      String(value);
  }
}


function setStatus(
  message,
  good = true
){
  const element =
    $('globalStatus');

  if(!element){
    return;
  }

  element.textContent =
    String(message);

  element.dataset.state =
    good
      ? 'ok'
      : 'error';
}


function formatFixed8(
  value
){
  const amount =
    BigInt(value);

  const whole =
    amount /
    100000000n;

  const fraction =
    (
      amount %
      100000000n
    )
      .toString()
      .padStart(
        8,
        '0'
      );

  return (
    whole.toString() +
    '.' +
    fraction
  );
}


function parseFixed8(
  value,
  label
){
  const text =
    String(
      value ||
      ''
    ).trim();

  const match =
    /^([0-9]+)(?:\.([0-9]{1,8}))?$/
      .exec(text);

  if(!match){
    throw new Error(
      label +
      '_INVALID_AMOUNT'
    );
  }

  const whole =
    BigInt(
      match[1]
    );

  const fraction =
    BigInt(
      (
        match[2] ||
        ''
      ).padEnd(
        8,
        '0'
      )
    );

  const result =
    whole *
      100000000n +
    fraction;

  if(result <= 0n){
    throw new Error(
      label +
      '_AMOUNT_MUST_BE_POSITIVE'
    );
  }

  return result;
}


function wipeWallet(
  wallet
){
  if(!wallet){
    return;
  }

  try{
    wallet.privateKey?.fill(0);
  }
  catch{
  }

  try{
    wallet.mnemonic = '';
  }
  catch{
  }
}


/* ATAN_W63F_P1_PASSKEY_BLOB_START */

function assertPasskeyEnvironment(){
  if(self !== top){
    throw new Error(
      'PASSKEY_TOP_LEVEL_CONTEXT_REQUIRED'
    );
  }

  if(self.isSecureContext !== true){
    throw new Error(
      'PASSKEY_SECURE_CONTEXT_REQUIRED'
    );
  }

  if(
    typeof PublicKeyCredential ===
      'undefined' ||
    !navigator.credentials?.create ||
    !navigator.credentials?.get
  ){
    throw new Error(
      'PASSKEY_WEBAUTHN_API_UNAVAILABLE'
    );
  }

  const canonical =
    location.origin ===
      PASSKEY_CANONICAL_ORIGIN;

  const local =
    location.hostname ===
      'localhost' ||
    location.hostname ===
      '127.0.0.1' ||
    location.hostname ===
      '[::1]';

  if(
    !canonical &&
    !local
  ){
    throw new Error(
      'PASSKEY_ORIGIN_NOT_ALLOWED'
    );
  }

  return {
    origin:
      location.origin,

    rpId:
      canonical
        ? PASSKEY_CANONICAL_RPID
        : location.hostname
  };
}


function validateStoredPasskeyEnvelope(
  envelope
){
  if(
    !envelope ||
    envelope.schema !==
      CRYPTO_POLICY.schema ||
    envelope.version !==
      1
  ){
    throw new Error(
      'PASSKEY_ENVELOPE_SCHEMA_INVALID'
    );
  }

  for(
    const value of [
      envelope?.binding?.origin,
      envelope?.binding?.rpId,
      envelope?.binding?.walletPathPrefix,
      envelope?.binding?.credentialId,
      envelope?.kdf?.prfInput,
      envelope?.kdf?.hkdfSalt,
      envelope?.cipher?.iv,
      envelope?.cipher?.ciphertext
    ]
  ){
    if(
      typeof value !==
        'string' ||
      value.length < 1
    ){
      throw new Error(
        'PASSKEY_ENVELOPE_REQUIRED_FIELD_INVALID'
      );
    }
  }

  return envelope;
}


function readStoredPasskeyEnvelope(){
  const serialized =
    localStorage.getItem(
      PASSKEY_STORAGE_KEY
    );

  if(serialized === null){
    return null;
  }

  let envelope =
    null;

  try{
    envelope =
      JSON.parse(
        serialized
      );
  }
  catch{
    throw new Error(
      'PASSKEY_ENVELOPE_JSON_INVALID'
    );
  }

  return validateStoredPasskeyEnvelope(
    envelope
  );
}


function persistPasskeyEnvelope(
  envelope
){
  validateStoredPasskeyEnvelope(
    envelope
  );

  const serialized =
    JSON.stringify(
      envelope
    );

  if(
    serialized.length >
      32768
  ){
    throw new Error(
      'PASSKEY_ENVELOPE_TOO_LARGE'
    );
  }

  localStorage.setItem(
    PASSKEY_STORAGE_KEY,
    serialized
  );
}


function removeStoredPasskeyEnvelope(){
  localStorage.removeItem(
    PASSKEY_STORAGE_KEY
  );
}


function refreshPasskeyUi(){
  let stored =
    false;

  let corrupt =
    false;

  try{
    stored =
      readStoredPasskeyEnvelope() !==
        null;
  }
  catch{
    corrupt =
      true;
  }

  const panel =
    $('passkeyUnlockPanel');

  if(panel){
    panel.hidden =
      !stored &&
      !corrupt;
  }

  const unlock =
    $('unlockPasskey');

  if(unlock){
    unlock.disabled =
      !stored ||
      corrupt;
  }

  const protect =
    $('protectPasskey');

  if(protect){
    protect.disabled =
      !state.wallet ||
      stored ||
      corrupt;

    protect.textContent =
      stored
        ? 'Passkey protection enabled'
        : 'Protect with passkey';
  }

  const remove =
    $('removePasskey');

  if(remove){
    remove.disabled =
      !stored &&
      !corrupt;
  }

  setText(
    'passkeyState',
    corrupt
      ? 'Encrypted wallet data is present but invalid. Remove it before creating new passkey protection.'
      : stored
        ? 'Passkey-protected wallet data is stored locally on this device.'
        : 'No passkey-protected wallet is stored on this device.'
  );
}


async function createWalletPasskey(
  prfInput,
  rpId
){
  const userId =
    randomBytes(32);

  const challenge =
    randomBytes(32);

  try{
    const credential =
      await navigator
        .credentials
        .create({
          publicKey:{
            rp:{
              id:
                rpId,
              name:
                'ATANATUS Wallet'
            },

            user:{
              id:
                userId,
              name:
                'atanatus-wallet-local',
              displayName:
                'ATANATUS Wallet'
            },

            challenge,

            pubKeyCredParams:[
              {
                type:
                  'public-key',
                alg:
                  -7
              },
              {
                type:
                  'public-key',
                alg:
                  -257
              }
            ],

            timeout:
              120000,

            attestation:
              'none',

            authenticatorSelection:{
              residentKey:
                'required',
              requireResidentKey:
                true,
              userVerification:
                'required'
            },

            extensions:{
              prf:{
                eval:{
                  first:
                    prfInput
                }
              }
            }
          }
        });

    if(!credential){
      throw new Error(
        'PASSKEY_CREATE_NULL'
      );
    }

    const ext =
      credential
        .getClientExtensionResults?.() ||
      {};

    if(
      ext?.prf?.enabled !==
        true &&
      !ext?.prf?.results?.first
    ){
      throw new Error(
        'PASSKEY_PRF_NOT_ENABLED'
      );
    }

    return credential;
  }
  finally{
    wipeBytes(
      userId
    );

    wipeBytes(
      challenge
    );
  }
}


async function requestWalletPasskeyPrf(
  credentialRawId,
  prfInput,
  rpId
){
  const challenge =
    randomBytes(32);

  try{
    const assertion =
      await navigator
        .credentials
        .get({
          publicKey:{
            challenge,

            rpId,

            allowCredentials:[
              {
                type:
                  'public-key',
                id:
                  credentialRawId
              }
            ],

            userVerification:
              'required',

            timeout:
              120000,

            extensions:{
              prf:{
                eval:{
                  first:
                    prfInput
                }
              }
            }
          }
        });

    if(!assertion){
      throw new Error(
        'PASSKEY_ASSERTION_NULL'
      );
    }

    const ext =
      assertion
        .getClientExtensionResults?.() ||
      {};

    const first =
      ext?.prf?.results?.first;

    if(!first){
      throw new Error(
        'PASSKEY_PRF_RESULT_MISSING'
      );
    }

    const prfOutput =
      new Uint8Array(
        first
      );

    if(
      prfOutput.byteLength !==
        CRYPTO_POLICY.prfOutputBytes
    ){
      wipeBytes(
        prfOutput
      );

      throw new Error(
        'PASSKEY_PRF_OUTPUT_LENGTH_INVALID'
      );
    }

    return prfOutput;
  }
  finally{
    wipeBytes(
      challenge
    );
  }
}


async function protectWalletWithPasskey(){
  if(!state.wallet){
    throw new Error(
      'WALLET_LOCKED'
    );
  }

  if(
    readStoredPasskeyEnvelope() !==
      null
  ){
    throw new Error(
      'PASSKEY_PROTECTION_ALREADY_EXISTS_REMOVE_FIRST'
    );
  }

  const environment =
    assertPasskeyEnvironment();

  const mnemonic =
    normalizeMnemonic(
      state.wallet.mnemonic
    );

  const prfInput =
    randomBytes(
      CRYPTO_POLICY.prfInputBytes
    );

  let credential =
    null;

  let credentialRawId =
    null;

  let prfOutput =
    null;

  let secretBytes =
    null;

  try{
    credential =
      await createWalletPasskey(
        prfInput,
        environment.rpId
      );

    credentialRawId =
      new Uint8Array(
        credential.rawId
      );

    if(
      credentialRawId.byteLength <
        1
    ){
      throw new Error(
        'PASSKEY_CREDENTIAL_ID_EMPTY'
      );
    }

    prfOutput =
      await requestWalletPasskeyPrf(
        credentialRawId,
        prfInput,
        environment.rpId
      );

    secretBytes =
      new TextEncoder()
        .encode(
          mnemonic
        );

    const credentialId =
      bytesToB64Url(
        credentialRawId
      );

    const envelope =
      await encryptSecretBytes({
        secretBytes,
        prfOutput,
        prfInput,
        origin:
          environment.origin,
        rpId:
          environment.rpId,
        walletPathPrefix:
          PASSKEY_WALLET_PATH_PREFIX,
        credentialId
      });

    if(
      envelope.kdf.prfInput !==
        bytesToB64Url(
          prfInput
        )
    ){
      throw new Error(
        'PASSKEY_ENVELOPE_PRF_INPUT_BINDING_FAILED'
      );
    }

    const serialized =
      JSON.stringify(
        envelope
      );

    if(
      serialized.includes(
        mnemonic
      )
    ){
      throw new Error(
        'PLAINTEXT_MNEMONIC_PERSISTENCE_BLOCKED'
      );
    }

    if(
      serialized.includes(
        bytesToB64Url(
          prfOutput
        )
      )
    ){
      throw new Error(
        'PRF_OUTPUT_PERSISTENCE_BLOCKED'
      );
    }

    persistPasskeyEnvelope(
      envelope
    );

    refreshPasskeyUi();

    setStatus(
      'Passkey protection enabled · encrypted wallet data stored locally'
    );
  }
  finally{
    wipeBytes(
      prfInput
    );

    if(credentialRawId){
      wipeBytes(
        credentialRawId
      );
    }

    if(prfOutput){
      wipeBytes(
        prfOutput
      );
    }

    if(secretBytes){
      wipeBytes(
        secretBytes
      );
    }
  }
}


async function unlockWalletWithPasskey(){
  const environment =
    assertPasskeyEnvironment();

  const envelope =
    readStoredPasskeyEnvelope();

  if(!envelope){
    throw new Error(
      'PASSKEY_ENVELOPE_NOT_FOUND'
    );
  }

  if(
    envelope.binding.origin !==
      environment.origin
  ){
    throw new Error(
      'PASSKEY_ENVELOPE_ORIGIN_MISMATCH'
    );
  }

  if(
    envelope.binding.rpId !==
      environment.rpId
  ){
    throw new Error(
      'PASSKEY_ENVELOPE_RPID_MISMATCH'
    );
  }

  if(
    envelope
      .binding
      .walletPathPrefix !==
        PASSKEY_WALLET_PATH_PREFIX
  ){
    throw new Error(
      'PASSKEY_ENVELOPE_WALLET_PATH_MISMATCH'
    );
  }

  const credentialRawId =
    b64UrlToBytes(
      envelope
        .binding
        .credentialId
    );

  const prfInput =
    b64UrlToBytes(
      envelope
        .kdf
        .prfInput
    );

  if(
    prfInput.byteLength !==
      CRYPTO_POLICY.prfInputBytes
  ){
    wipeBytes(
      credentialRawId
    );

    wipeBytes(
      prfInput
    );

    throw new Error(
      'PASSKEY_STORED_PRF_INPUT_LENGTH_INVALID'
    );
  }

  let prfOutput =
    null;

  let secretBytes =
    null;

  try{
    prfOutput =
      await requestWalletPasskeyPrf(
        credentialRawId,
        prfInput,
        environment.rpId
      );

    secretBytes =
      await decryptSecretBytes({
        envelope,
        prfOutput,
        expectedBinding:{
          origin:
            environment.origin,
          rpId:
            environment.rpId,
          walletPathPrefix:
            PASSKEY_WALLET_PATH_PREFIX,
          credentialId:
            envelope
              .binding
              .credentialId
        }
      });

    const mnemonic =
      new TextDecoder()
        .decode(
          secretBytes
        );

    await activateWallet(
      mnemonic,
      false
    );

    refreshPasskeyUi();

    setStatus(
      'Wallet unlocked with passkey'
    );
  }
  finally{
    wipeBytes(
      credentialRawId
    );

    wipeBytes(
      prfInput
    );

    if(prfOutput){
      wipeBytes(
        prfOutput
      );
    }

    if(secretBytes){
      wipeBytes(
        secretBytes
      );
    }
  }
}


function removePasskeyProtection(){
  const stored =
    localStorage.getItem(
      PASSKEY_STORAGE_KEY
    );

  if(stored === null){
    refreshPasskeyUi();
    return;
  }

  if(
    !confirm(
      'Remove the locally stored encrypted wallet record? Your recovery phrase remains the ultimate recovery method.'
    )
  ){
    return;
  }

  removeStoredPasskeyEnvelope();

  refreshPasskeyUi();

  setStatus(
    'Passkey protection removed from this browser'
  );
}

/* ATAN_W63F_P1_PASSKEY_BLOB_END */


async function loadMainnet(){
  if(
    !globalThis.__mainnetPromise
  ){
    throw new Error(
      'MAINNET_JS_NOT_LOADED'
    );
  }

  const library =
    await globalThis.__mainnetPromise;

  for(
    const name of [
      'Wallet',
      'SendRequest',
      'TokenSendRequest',
      'Config',
      'toCashaddr',
      'toTokenaddr',
      'libauth'
    ]
  ){
    if(
      library[name] ===
      undefined
    ){
      throw new Error(
        'MAINNET_JS_EXPORT_MISSING_' +
        name
      );
    }
  }

  library
    .Config
    .EnforceCashTokenReceiptAddresses =
      true;

  state.mainnet =
    library;

  return library;
}


function normalizeMnemonic(
  value
){
  const mnemonic =
    String(
      value ||
      ''
    )
      .trim()
      .toLowerCase()
      .replace(
        /\s+/g,
        ' '
      );

  const words =
    mnemonic.split(' ');

  if(words.length !== 12){
    throw new Error(
      'RECOVERY_PHRASE_MUST_HAVE_12_WORDS'
    );
  }

  return mnemonic;
}


async function deriveWallet(
  mnemonic
){
  const wallet =
    await state
      .mainnet
      .Wallet
      .fromSeed(
        normalizeMnemonic(
          mnemonic
        ),
        DERIVATION_PATH
      );

  if(
    !wallet.cashaddr ||
    !String(
      wallet.cashaddr
    ).startsWith(
      'bitcoincash:'
    )
  ){
    throw new Error(
      'BCH_ADDRESS_DERIVATION_FAILED'
    );
  }

  if(
    !wallet.tokenaddr ||
    !String(
      wallet.tokenaddr
    ).startsWith(
      'bitcoincash:'
    )
  ){
    wipeWallet(
      wallet
    );

    throw new Error(
      'ATAN_ADDRESS_DERIVATION_FAILED'
    );
  }

  return wallet;
}


async function deriveChangeWallet(
  mnemonic
){
  const wallet =
    await state
      .mainnet
      .Wallet
      .fromSeed(
        normalizeMnemonic(
          mnemonic
        ),
        BCH_CHANGE_DERIVATION_PATH
      );

  if(
    !wallet.cashaddr ||
    !String(
      wallet.cashaddr
    ).startsWith(
      'bitcoincash:'
    )
  ){
    wipeWallet(
      wallet
    );

    throw new Error(
      'BCH_CHANGE_ADDRESS_DERIVATION_FAILED'
    );
  }

  return wallet;
}


function showWallet(){
  requireElement(
    'lockedView'
  ).hidden =
    true;

  const recovery =
    $('recoveryView');

  if(recovery){
    recovery.hidden =
      true;
  }

  requireElement(
    'walletView'
  ).hidden =
    false;

  setText(
    'walletAddress',
    state.wallet.cashaddr
  );

  setText(
    'tokenAddress',
    state.wallet.tokenaddr
  );

  refreshPasskeyUi();
}


function showRecovery(
  mnemonic
){
  requireElement(
    'lockedView'
  ).hidden =
    true;

  requireElement(
    'walletView'
  ).hidden =
    true;

  const recovery =
    requireElement(
      'recoveryView'
    );

  recovery.hidden =
    false;

  setText(
    'generatedMnemonic',
    mnemonic
  );
}


async function activateWallet(
  mnemonic,
  revealRecovery
){
  setStatus(
    'Opening wallet…'
  );

  const wallet =
    await deriveWallet(
      mnemonic
    );

  let changeWallet =
    null;

  try{
    changeWallet =
      await deriveChangeWallet(
        mnemonic
      );
  }
  catch(error){
    wipeWallet(
      wallet
    );

    throw error;
  }

  if(state.wallet){
    wipeWallet(
      state.wallet
    );
  }

  if(state.changeWallet){
    wipeWallet(
      state.changeWallet
    );
  }

  state.wallet =
    wallet;

  state.changeWallet =
    changeWallet;

  state.pending =
    null;

  const input =
    $('mnemonicInput');

  if(input){
    input.value =
      '';
  }

  if(revealRecovery){
    showRecovery(
      mnemonic
    );

    setStatus(
      'Save your recovery phrase securely'
    );

    return;
  }

  showWallet();

  await refreshWallet();
}


async function createWallet(){
  const temporary =
    await state
      .mainnet
      .Wallet
      .newRandom();

  try{
    const mnemonic =
      normalizeMnemonic(
        temporary.mnemonic
      );

    await activateWallet(
      mnemonic,
      true
    );
  }
  finally{
    wipeWallet(
      temporary
    );
  }
}


async function refreshWallet(){
  if(!state.wallet){
    return;
  }

  setStatus(
    'Synchronizing with Bitcoin Cash mainnet…'
  );

  if(!state.changeWallet){
    throw new Error(
      'BCH_CHANGE_WALLET_NOT_DERIVED'
    );
  }

  const [
    primaryBchSats,
    changeBchSats,
    atanBase,
    height
  ] =
    await Promise.all([
      state.wallet.getBalance(),

      state.changeWallet.getBalance(),

      state.wallet.getTokenBalance(
        ATAN_CATEGORY
      ),

      state.wallet
        .provider
        .getBlockHeight()
    ]);

  const bchSats =
    BigInt(primaryBchSats) +
    BigInt(changeBchSats);

  setText(
    'bchBalance',
    formatFixed8(
      bchSats
    )
  );

  setText(
    'atanBalance',
    formatFixed8(
      atanBase
    )
  );

  setText(
    'height',
    '#' +
      String(height)
  );

  setText(
    'fieldState',
    'On-chain wallet'
  );

  setText(
    'fieldBalance',
    formatFixed8(
      atanBase
    ) +
      ' ATAN'
  );

  setText(
    'fieldEligibility',
    'Field is a separate protocol'
  );

  setText(
    'fieldEntitlement',
    '—'
  );

  setText(
    'fieldSnapshot',
    'Balances are read directly from Bitcoin Cash mainnet.'
  );

  setStatus(
    'BCH mainnet · synchronized'
  );
}


function tokenAmount(
  utxo
){
  return BigInt(
    utxo?.token?.amount ??
      0
  );
}


function utxoSats(
  utxo
){
  return BigInt(
    utxo?.satoshis ??
      0
  );
}


function isAtan(
  utxo
){
  return (
    !!utxo?.token &&
    String(
      utxo.token.category ||
        ''
    ).toLowerCase() ===
      ATAN_CATEGORY &&
    utxo.token.nft ===
      undefined &&
    tokenAmount(
      utxo
    ) > 0n
  );
}


function isPlainBch(
  utxo
){
  return !utxo?.token;
}


function sortBySatsDesc(
  a,
  b
){
  const left =
    utxoSats(a);

  const right =
    utxoSats(b);

  if(left > right){
    return -1;
  }

  if(left < right){
    return 1;
  }

  return 0;
}


function sortByTokenDesc(
  a,
  b
){
  const left =
    tokenAmount(a);

  const right =
    tokenAmount(b);

  if(left > right){
    return -1;
  }

  if(left < right){
    return 1;
  }

  return 0;
}


function sponsoredControllerEntry(
  utxo,
  controller,
  derivationPath
){
  return {
    utxo,
    controller,
    derivationPath,
    sats:
      utxoSats(
        utxo
      )
  };
}


async function collectW62cSponsoredInventory(
  paymentAmount
){
  if(
    !state.wallet ||
    !state.changeWallet
  ){
    throw new Error(
      'W62C_DUAL_DERIVATION_WALLETS_REQUIRED'
    );
  }

  const [
    primaryUtxos,
    changeUtxos
  ] =
    await Promise.all([
      state.wallet.getUtxos(),
      state.changeWallet.getUtxos()
    ]);

  const primaryPlain =
    primaryUtxos
      .filter(
        isPlainBch
      )
      .map(
        utxo =>
          sponsoredControllerEntry(
            utxo,
            'USER_PRIMARY_0_0',
            DERIVATION_PATH
          )
      );

  const changePlain =
    changeUtxos
      .filter(
        isPlainBch
      )
      .map(
        utxo =>
          sponsoredControllerEntry(
            utxo,
            'USER_CHANGE_0_1',
            BCH_CHANGE_DERIVATION_PATH
          )
      );

  const plain =
    [
      ...primaryPlain,
      ...changePlain
    ]
      .sort(
        (a,b) =>
          sortBySatsDesc(
            a.utxo,
            b.utxo
          )
      );

  const token =
    primaryUtxos
      .filter(
        isAtan
      )
      .sort(
        sortByTokenDesc
      );

  if(plain.length === 0){
    throw new Error(
      'W62C_NO_USER_PLAIN_BCH_INPUT_AVAILABLE'
    );
  }

  if(token.length === 0){
    throw new Error(
      'W62C_NO_USER_ATAN_INPUT_AVAILABLE'
    );
  }

  const requested =
    BigInt(
      paymentAmount
    );

  /*
    Current settlement-plan module is intentionally 3-input:
      USER_BCH + USER_TOKEN + SPONSOR_BCH

    W62C therefore selects exactly ONE user BCH input.
    If no single primary/change UTXO can carry the requested payment,
    fail closed rather than silently changing transaction topology.
  */
  const selectedBch =
    plain.find(
      entry =>
        entry.sats >
        requested
    );

  if(!selectedBch){
    throw new Error(
      'W62C_SINGLE_USER_BCH_INPUT_INSUFFICIENT_REQUIRES_FUTURE_TOPOLOGY_EXTENSION'
    );
  }

  const selectedToken =
    token[0];

  const allUtxos =
    [
      ...primaryUtxos,
      ...changeUtxos
    ];

  return {
    primaryUtxoCount:
      primaryUtxos.length,

    changeUtxoCount:
      changeUtxos.length,

    primaryPlainCount:
      primaryPlain.length,

    changePlainCount:
      changePlain.length,

    atanInputCount:
      token.length,

    selectedBch,

    selectedToken,

    selectedTokenAmountBase:
      tokenAmount(
        selectedToken
      ),

    selectedTokenCarrierSats:
      utxoSats(
        selectedToken
      ),

    allUtxos
  };
}


async function getW62dSponsorTransportHealth(){
  const client =
    createSponsorHttpsClient({
      baseUrl:
        W62D_STAGED_SPONSOR_BASE_URL,

      allowInsecureLoopback:
        true
    });

  const health =
    await client.health();

  if(
    health.payload?.ok !== true ||
    health.payload?.mode !==
      'W62D_NO_SIGNING_NO_BROADCAST' ||
    health.payload?.quote_enabled !==
      false ||
    health.payload?.sponsor_sign_enabled !==
      false ||
    health.payload?.broadcast_enabled !==
      false
  ){
    throw new Error(
      'W62D_SPONSOR_HEALTH_POLICY_INVALID'
    );
  }

  return {
    ready:
      true,

    baseUrl:
      client.baseUrl,

    productionOrigin:
      client.productionOrigin,

    mode:
      health.payload.mode,

    quoteEnabled:
      false,

    sponsorSignEnabled:
      false,

    broadcastEnabled:
      false
  };
}


async function buildW62cExactSponsoredPreflight(
  paymentAmount
){
  const inventory =
    await collectW62cSponsoredInventory(
      paymentAmount
    );

  const envelope =
    await createExactSponsoredFeeEnvelopeV2({
      user_bch_input_count:
        1,

      user_token_input_count:
        1,

      fee_rate_sats_per_kb:
        W62C_STAGED_EXACT_FEE_RATE_SATS_PER_KB,

      ordinary_output_count:
        3,

      token_output_count:
        2,

      safety_margin_bytes:
        0
    });

  await validateExactSponsoredFeeEnvelopeV2(
    envelope
  );

  if(
    envelope.shape.input_count !== 3 ||
    envelope.shape.output_count !== 5
  ){
    throw new Error(
      'W62C_EXACT_FEE_TOPOLOGY_NOT_3X5'
    );
  }

  const sponsorTransport =
    await getW62dSponsorTransportHealth();

  return {
    inventory,
    envelope,
    sponsorTransport,
    feeRateSource:
      W62C_STAGED_FEE_RATE_SOURCE,

    sponsorQuoteStatus:
      'NOT_REQUESTED_W62D_TRANSPORT_ONLY',

    settlementPlanStatus:
      'BLOCKED_UNTIL_AUTHENTICATED_SPONSOR_QUOTE',

    unsignedTransactionStatus:
      'BLOCKED_UNTIL_SPONSOR_QUOTE_RESERVATION_AND_ACCEPTANCE',

    signingAllowed:
      false,

    broadcastAllowed:
      false
  };
}


function calculateFee(
  prepared
){
  const libauth =
    state.mainnet.libauth;

  const decoded =
    libauth.decodeTransaction(
      libauth.hexToBin(
        prepared
          .unsignedTransaction
      )
    );

  if(
    !decoded ||
    typeof decoded ===
      'string' ||
    !Array.isArray(
      decoded.outputs
    )
  ){
    throw new Error(
      'UNSIGNED_TRANSACTION_DECODE_FAILED'
    );
  }

  const inputs =
    prepared
      .sourceOutputs
      .reduce(
        (
          total,
          output
        ) =>
          total +
          BigInt(
            output.valueSatoshis
          ),
        0n
      );

  const outputs =
    decoded
      .outputs
      .reduce(
        (
          total,
          output
        ) =>
          total +
          BigInt(
            output.valueSatoshis
          ),
        0n
      );

  const fee =
    inputs -
    outputs;

  if(fee < 0n){
    throw new Error(
      'TRANSACTION_FEE_INVALID'
    );
  }

  return fee;
}


async function buildUnsigned(
  requests,
  utxos
){
  const prepared =
    await state.wallet.send(
      requests,
      {
        buildUnsigned:
          true,

        queryBalance:
          false,

        awaitTransactionPropagation:
          false,

        utxoIds:
          utxos
      }
    );

  if(
    !prepared ||
    typeof prepared
      .unsignedTransaction !==
      'string' ||
    !Array.isArray(
      prepared.sourceOutputs
    ) ||
    prepared
      .sourceOutputs
      .length ===
      0
  ){
    throw new Error(
      'UNSIGNED_TRANSACTION_MISSING'
    );
  }

  return prepared;
}


async function buildBchPlan(
  recipient,
  amount
){
  const {
    SendRequest,
    TokenSendRequest,
    toCashaddr
  } =
    state.mainnet;

  const destination =
    toCashaddr(
      recipient
    );

  const all =
    await state.wallet
      .getUtxos();

  const plain =
    all
      .filter(
        isPlainBch
      )
      .sort(
        sortBySatsDesc
      );

  const atan =
    all
      .filter(
        isAtan
      )
      .sort(
        sortBySatsDesc
      );

  const payment =
    new SendRequest({
      cashaddr:
        destination,

      value:
        amount
    });

  /*
    First try ordinary BCH only.
  */
  if(plain.length > 0){
    try{
      const prepared =
        await buildUnsigned(
          [
            payment
          ],
          plain
        );

      return {
        asset:
          'BCH',

        amount,

        recipient:
          destination,

        prepared,

        fee:
          calculateFee(
            prepared
          ),

        atanPreserved:
          0n,

        usedAtanCarrier:
          false
      };
    }
    catch{
    }
  }

  /*
    If the only BCH available is attached to ATAN,
    selected ATAN inputs are allowed only while returning
    EXACTLY the selected amount of ATAN to this wallet.

    Foreign tokens: excluded.
    NFTs: excluded.
  */
  const selected = [];

  let preserve =
    0n;

  let finalError =
    null;

  for(const utxo of atan){

    selected.push(
      utxo
    );

    preserve +=
      tokenAmount(
        utxo
      );

    const tokenReturn =
      new TokenSendRequest({
        cashaddr:
          state.wallet.tokenaddr,

        category:
          ATAN_CATEGORY,

        amount:
          preserve,

        value:
          1000n
      });

    try{
      const prepared =
        await buildUnsigned(
          [
            payment,
            tokenReturn
          ],
          [
            ...plain,
            ...selected
          ]
        );

      return {
        asset:
          'BCH',

        amount,

        recipient:
          destination,

        prepared,

        fee:
          calculateFee(
            prepared
          ),

        atanPreserved:
          preserve,

        usedAtanCarrier:
          true
      };
    }
    catch(error){
      finalError =
        error;
    }
  }

  if(finalError){
    throw finalError;
  }

  throw new Error(
    'INSUFFICIENT_BCH'
  );
}


async function buildAtanPlan(
  recipient,
  amount
){
  const {
    TokenSendRequest,
    toTokenaddr
  } =
    state.mainnet;

  const destination =
    toTokenaddr(
      recipient
    );

  const all =
    await state.wallet
      .getUtxos();

  const plain =
    all
      .filter(
        isPlainBch
      )
      .sort(
        sortBySatsDesc
      );

  const atan =
    all
      .filter(
        isAtan
      )
      .sort(
        sortByTokenDesc
      );

  const selected = [];

  let available =
    0n;

  for(const utxo of atan){

    selected.push(
      utxo
    );

    available +=
      tokenAmount(
        utxo
      );

    if(available >= amount){
      break;
    }
  }

  if(available < amount){
    throw new Error(
      'INSUFFICIENT_ATAN'
    );
  }

  const transfer =
    new TokenSendRequest({
      cashaddr:
        destination,

      category:
        ATAN_CATEGORY,

      amount,

      value:
        1000n
    });

  const prepared =
    await buildUnsigned(
      [
        transfer
      ],
      [
        ...plain,
        ...selected
      ]
    );

  return {
    asset:
      'ATAN',

    amount,

    recipient:
      destination,

    prepared,

    fee:
      calculateFee(
        prepared
      ),

    atanPreserved:
      available -
      amount,

    usedAtanCarrier:
      true
  };
}


async function prepareSend(){
  if(!state.wallet){
    throw new Error(
      'WALLET_LOCKED'
    );
  }

  state.pending =
    null;

  requireElement(
    'sendBroadcast'
  ).disabled =
    true;

  requireElement(
    'sendBroadcast'
  ).textContent =
    'Broadcast transaction';

  const asset =
    String(
      requireElement(
        'sendAsset'
      ).value
    ).toUpperCase();

  const feeMode =
    String(
      requireElement(
        'sendFeeMode'
      ).value
    ).toUpperCase();

  const recipient =
    String(
      requireElement(
        'sendRecipient'
      ).value ||
        ''
    ).trim();

  const amountText =
    String(
      requireElement(
        'sendAmount'
      ).value ||
        ''
    ).trim();

  if(!recipient){
    throw new Error(
      'RECIPIENT_REQUIRED'
    );
  }

  const amount =
    parseFixed8(
      amountText,
      asset
    );
  if(
    feeMode !== 'BCH_STANDARD' &&
    feeMode !==
      ATAN_SPONSORED_FEE_SHADOW_MODE
  ){
    throw new Error(
      'FEE_MODE_INVALID'
    );
  }

  if(
    feeMode ===
    ATAN_SPONSORED_FEE_SHADOW_MODE
  ){
    if(asset !== 'BCH'){
      throw new Error(
        'ATAN_SPONSORED_FEES_CURRENTLY_REQUIRE_BCH_ASSET'
      );
    }

    setStatus(
      'Building authenticated ATAN Sponsored Fees preview...'
    );

    const preview =
      await createW62JUnsignedSettlementComposition({
        recipient,
        amount,
        wallet:
          state.wallet,
        changeWallet:
          state.changeWallet,
        mainnet:
          state.mainnet,
        atanCategory:
          ATAN_CATEGORY,
        sponsorOrigin:
          'http://127.0.0.1:18794'
      });

    state.pending = {
      feeMode:
        'ATAN_SPONSORED_UNSIGNED_ATOMIC_SETTLEMENT',
      ...preview
    };

    const lines = [
      'Bitcoin Cash mainnet',
      '',
      'Fee mode: ATAN Sponsored Fees',
      'Stage: UNSIGNED ATOMIC SETTLEMENT (W62J)',
      '',
      'Asset: BCH',
      'Amount: ' +
        formatFixed8(
          BigInt(
            preview.payment_sats
          )
        ) +
        ' BCH',
      '',
      'Recipient:',
      preview.recipient,
      '',
      'User BCH network fee target: 0 sats',
      'Exact network fee: ' +
        preview.network_fee_sats +
        ' sats',
      'ATAN fee cost: ' +
        formatFixed8(
          BigInt(
            preview.token_cost_base
          )
        ) +
        ' ATAN',
      '',
      'Quote ID:',
      preview.quote_id,
      '',
      'Sponsor signer:',
      preview.signer_address,
      '',
      'Sponsor funding:',
      preview.sponsor_funding_outpoint,
      '',
      'Exact fee envelope:',
      preview.exact_fee_envelope_id,
      '',
      'Max signed envelope: ' +
        String(
          preview.max_signed_bytes
        ) +
        ' bytes',
      '',
      'User BCH input:',
      preview.user_bch_input_outpoint,
      'Derivation: ' +
        preview.user_bch_input_derivation,
      '',
      'User ATAN input:',
      preview.user_token_input_outpoint,
      'Derivation: ' +
        preview.user_token_input_derivation,
      '',
      'Authenticated quote: VALID',
      'Exact fee binding: VALID',
      'Dual-derivation inventory: CONNECTED',
      '',
      'Candidate ID:',
      preview.candidate_id,
      '',
      'Unsigned transaction SHA256:',
      preview.unsigned_transaction_sha256,
      'Unsigned transaction bytes: ' + String(preview.unsigned_transaction_bytes),
      'Projected signed bytes: ' + String(preview.projected_signed_bytes),
      'Pre-sign freshness revalidation: REQUIRED',
      '',
      'Status: COMPOSED / UNSIGNED',
      'Transaction signing: LOCKED',
      'Broadcast: LOCKED',
      '',
      'No transaction has been signed or broadcast.'
    ];

    setText(
      'sendReviewText',
      lines.join('\n')
    );

    requireElement(
      'sendReview'
    ).hidden =
      false;

    const broadcast =
      requireElement(
        'sendBroadcast'
      );

    broadcast.disabled =
      true;

    broadcast.textContent =
      'Sponsored broadcast locked (W62J)';

    const result =
      $('sendResult');

    if(result){
      result.hidden =
        false;

      result.textContent =
        'Authenticated sponsor quote verified in-browser. Exact fee = 689 sats; ATAN fee = 1.00000000. Preview only — signing and broadcast remain locked.';
    }

    setStatus(
      'ATAN Sponsored Fees - unsigned atomic settlement composed'
    );

    const proofResponse =
      await fetch(
        '/w62j-preview-proof',
        {
          method:
            'POST',

          headers: {
            'content-type':
              'application/json'
          },

          cache:
            'no-store',

          credentials:
            'omit',

          body:
            JSON.stringify({
              schema:
                'ATAN_FEE_V2_W62J_BROWSER_UNSIGNED_SETTLEMENT_PREVIEW_PROOF',

              version:
                '1.0.0',

              quote_id:
                preview.quote_id,

              recipient:
                preview.recipient,

              payment_sats:
                preview.payment_sats,

              network_fee_sats:
                preview.network_fee_sats,

              token_cost_base:
                preview.token_cost_base,

              user_bch_input_derivation:
                preview.user_bch_input_derivation,

              user_token_input_derivation:
                preview.user_token_input_derivation,

              quote_authentication_valid:
                preview.quote_authentication_valid,

              exact_fee_binding_valid:
                preview.exact_fee_binding_valid,

              dual_derivation_inventory_connected:
                preview.dual_derivation_inventory_connected,

              transaction_signing:
                false,

              testmempoolaccept:
                false,

              submitTransaction:
                false,

              sendrawtransaction:
                false,

              transaction_broadcast:
                false
            })
        }
      );

    if(!proofResponse.ok){
      throw new Error(
        'W62I_BROWSER_PROOF_SUBMISSION_FAILED'
      );
    }

    return;
  }

  setStatus(
    'Building unsigned transaction…'
  );

  const plan =
    asset === 'BCH'
      ? await buildBchPlan(
          recipient,
          amount
        )
      : asset === 'ATAN'
        ? await buildAtanPlan(
            recipient,
            amount
          )
        : (() => {
            throw new Error(
              'ASSET_MUST_BE_BCH_OR_ATAN'
            );
          })();

  /*
    REVIEW STATE:
    No signature exists yet.
  */
  state.pending =
    plan;

  const lines = [
    'Bitcoin Cash mainnet',
    '',
    'Asset: ' +
      plan.asset,

    'Amount: ' +
      formatFixed8(
        plan.amount
      ) +
      ' ' +
      plan.asset,

    '',
    'Recipient:',
    plan.recipient,

    '',
    'Network fee: ' +
      plan.fee.toString() +
      ' sats'
  ];

  if(
    plan.asset === 'BCH' &&
    plan.usedAtanCarrier
  ){
    lines.push(
      '',
      'ATAN preserved in your wallet: ' +
        formatFixed8(
          plan.atanPreserved
        ) +
        ' ATAN'
    );
  }

  if(plan.asset === 'ATAN'){
    lines.push(
      '',
      'ATAN change: ' +
        formatFixed8(
          plan.atanPreserved
        ) +
        ' ATAN'
    );
  }

  lines.push(
    '',
    'Status: UNSIGNED',
    'Nothing has been broadcast.',
    '',
    'Press “Broadcast transaction” to sign locally',
    'and send this transaction.'
  );

  setText(
    'sendReviewText',
    lines.join('\n')
  );

  requireElement(
    'sendReview'
  ).hidden =
    false;

  requireElement(
    'sendBroadcast'
  ).disabled =
    false;

  const result =
    $('sendResult');

  if(result){
    result.hidden =
      true;

    result.textContent =
      '';
  }

  setStatus(
    'Unsigned transaction ready for review'
  );
}


async function broadcastSend(){
  throw new Error(
    'W61K_R2_STAGED_BROADCAST_LOCKED'
  );

  if(
    !state.wallet ||
    !state.pending
  ){
    throw new Error(
      'NO_PREPARED_TRANSACTION'
    );
  }

  if(
    state.pending.feeMode ===
    ATAN_SPONSORED_FEE_SHADOW_MODE
  ){
    throw new Error(
      'SPONSORED_FEES_SHADOW_MODE_BROADCAST_LOCKED'
    );
  }

  const button =
    requireElement(
      'sendBroadcast'
    );

  button.disabled =
    true;

  setStatus(
    'Signing locally in this browser…'
  );

  try{
    /*
      Private key never leaves this browser.
    */
    const signed =
      await state.wallet
        .signUnsignedTransaction(
          state.pending
            .prepared
            .unsignedTransaction,

          state.pending
            .prepared
            .sourceOutputs
        );

    setStatus(
      'Broadcasting to Bitcoin Cash mainnet…'
    );

    /*
      This is the ONLY broadcast path,
      reached by explicit user click.
    */
    const txid =
      await state.wallet
        .submitTransaction(
          signed,
          true
        );

    const result =
      requireElement(
        'sendResult'
      );

    result.hidden =
      false;

    result.textContent =
      'Broadcast successful · TXID: ' +
      txid;

    requireElement(
      'sendReview'
    ).hidden =
      true;

    state.pending =
      null;

    setStatus(
      'Transaction broadcast successfully'
    );

    await new Promise(
      resolve =>
        setTimeout(
          resolve,
          1200
        )
    );

    await refreshWallet();
  }
  catch(error){
    button.disabled =
      false;

    throw error;
  }
}


function clearSend(){
  state.pending =
    null;

  const panel =
    $('sendPanel');

  if(panel){
    panel.hidden =
      true;
  }

  const review =
    $('sendReview');

  if(review){
    review.hidden =
      true;
  }

  const result =
    $('sendResult');

  if(result){
    result.hidden =
      true;

    result.textContent =
      '';
  }

  const recipient =
    $('sendRecipient');

  if(recipient){
    recipient.value =
      '';
  }

  const amount =
    $('sendAmount');

  if(amount){
    amount.value =
      '';
  }

  const feeMode =
    $('sendFeeMode');

  if(feeMode){
    feeMode.value =
      'BCH_STANDARD';
  }

  const broadcast =
    $('sendBroadcast');

  if(broadcast){
    broadcast.disabled =
      true;

    broadcast.textContent =
      'Broadcast transaction';
  }
}


async function copyText(
  value
){
  await navigator
    .clipboard
    .writeText(
      String(value)
    );
}


function lockWallet(){
  if(state.wallet){
    wipeWallet(
      state.wallet
    );
  }

  if(state.changeWallet){
    wipeWallet(
      state.changeWallet
    );
  }

  state.wallet =
    null;

  state.changeWallet =
    null;

  state.pending =
    null;

  clearSend();

  requireElement(
    'walletView'
  ).hidden =
    true;

  const recovery =
    $('recoveryView');

  if(recovery){
    recovery.hidden =
      true;
  }

  requireElement(
    'lockedView'
  ).hidden =
    false;

  setText(
    'walletAddress',
    '—'
  );

  setText(
    'tokenAddress',
    '—'
  );

  setText(
    'bchBalance',
    '—'
  );

  setText(
    'atanBalance',
    '—'
  );

  setText(
    'generatedMnemonic',
    ''
  );

  setStatus(
    'Wallet locked'
  );

  refreshPasskeyUi();
}


function wireUi(){
  const required = [
    'globalStatus',
    'lockedView',
    'walletView',
    'recoveryView',
    'createWallet',
    'recoverWallet',
    'passkeyUnlockPanel',
    'unlockPasskey',
    'protectPasskey',
    'removePasskey',
    'passkeyState',
    'mnemonicInput',
    'generatedMnemonic',
    'walletAddress',
    'tokenAddress',
    'bchBalance',
    'atanBalance',
    'refreshWallet',
    'lockWallet',
    'sendOpen',
    'sendPanel',
    'sendAsset',
    'sendFeeMode',
    'sendRecipient',
    'sendAmount',
    'sendPrepare',
    'sendCancel',
    'sendReview',
    'sendReviewText',
    'sendBroadcast',
    'sendResult'
  ];

  for(const id of required){
    requireElement(id);
  }

  $('createWallet')
    .addEventListener(
      'click',
      async () => {
        try{
          await createWallet();
        }
        catch(error){
          setStatus(
            error?.message ||
              String(error),
            false
          );
        }
      }
    );

  $('recoverWallet')
    .addEventListener(
      'click',
      async () => {
        try{
          await activateWallet(
            $('mnemonicInput')
              .value,
            false
          );
        }
        catch(error){
          setStatus(
            error?.message ||
              String(error),
            false
          );
        }
      }
    );

  $('unlockPasskey')
    .addEventListener(
      'click',
      async () => {
        try{
          await unlockWalletWithPasskey();
        }
        catch(error){
          setStatus(
            error?.message ||
              String(error),
            false
          );
        }
      }
    );

  $('protectPasskey')
    .addEventListener(
      'click',
      async () => {
        try{
          await protectWalletWithPasskey();
        }
        catch(error){
          setStatus(
            error?.message ||
              String(error),
            false
          );
        }
      }
    );

  $('removePasskey')
    .addEventListener(
      'click',
      () => {
        try{
          removePasskeyProtection();
        }
        catch(error){
          setStatus(
            error?.message ||
              String(error),
            false
          );
        }
      }
    );

  $('hideRecovery')
    ?.addEventListener(
      'click',
      async () => {
        try{
          setText(
            'generatedMnemonic',
            ''
          );

          showWallet();

          await refreshWallet();
        }
        catch(error){
          setStatus(
            error?.message ||
              String(error),
            false
          );
        }
      }
    );

  $('refreshWallet')
    .addEventListener(
      'click',
      async () => {
        try{
          await refreshWallet();
        }
        catch(error){
          setStatus(
            error?.message ||
              String(error),
            false
          );
        }
      }
    );

  $('lockWallet')
    .addEventListener(
      'click',
      lockWallet
    );

  $('walletAddress')
    .addEventListener(
      'click',
      async () => {
        if(state.wallet){
          await copyText(
            state.wallet.cashaddr
          );
        }
      }
    );

  $('tokenAddress')
    .addEventListener(
      'click',
      async () => {
        if(state.wallet){
          await copyText(
            state.wallet.tokenaddr
          );
        }
      }
    );

  $('copyReceive')
    ?.addEventListener(
      'click',
      async () => {
        if(state.wallet){
          await copyText(
            state.wallet.cashaddr
          );
        }
      }
    );

  $('copyTokenReceive')
    ?.addEventListener(
      'click',
      async () => {
        if(state.wallet){
          await copyText(
            state.wallet.tokenaddr
          );
        }
      }
    );

  $('sendOpen')
    .addEventListener(
      'click',
      () => {
        $('sendPanel').hidden =
          false;

        $('sendReview').hidden =
          true;

        $('sendResult').hidden =
          true;
      }
    );

  $('sendCancel')
    .addEventListener(
      'click',
      clearSend
    );

  $('sendPrepare')
    .addEventListener(
      'click',
      async () => {
        try{
          await prepareSend();
        }
        catch(error){
          const message =
            error?.message ||
            String(error);

          setStatus(
            message,
            false
          );

          $('sendResult').hidden =
            false;

          $('sendResult').textContent =
            message;
        }
      }
    );

  $('sendBroadcast')
    .addEventListener(
      'click',
      async () => {
        try{
          await broadcastSend();
        }
        catch(error){
          const message =
            error?.message ||
            String(error);

          setStatus(
            message,
            false
          );

          $('sendResult').hidden =
            false;

          $('sendResult').textContent =
            message;
        }
      }
    );

  window.addEventListener(
    'beforeunload',
    () => {
      if(state.wallet){
        wipeWallet(
          state.wallet
        );
      }

      if(state.changeWallet){
        wipeWallet(
          state.changeWallet
        );
      }
    }
  );
}


async function smokeTest(){
  document
    .documentElement
    .dataset
    .smoke =
      'RUNNING';

  let randomWallet =
    null;

  let watchWallet =
    null;

  try{
    /*
      Prove wallet creation locally without publishing
      or using a fixed private seed.
    */
    randomWallet =
      await state
        .mainnet
        .Wallet
        .newRandom();

    if(
      !randomWallet.mnemonic ||
      randomWallet
        .mnemonic
        .trim()
        .split(/\s+/)
        .length !== 12
    ){
      throw new Error(
        'SMOKE_RANDOM_WALLET_FAILED'
      );
    }

    wipeWallet(
      randomWallet
    );

    randomWallet =
      null;

    /*
      Network smoke uses a PUBLIC watch-only address.
      No private key exists for this query.
    */
    watchWallet =
      await state
        .mainnet
        .Wallet
        .watchOnly(
          PUBLIC_SMOKE_ADDRESS
        );

    const [
      bch,
      atan,
      height
    ] =
      await Promise.all([
        watchWallet.getBalance(),

        watchWallet.getTokenBalance(
          ATAN_CATEGORY
        ),

        watchWallet
          .provider
          .getBlockHeight()
      ]);

    if(
      typeof bch !==
        'bigint' ||
      typeof atan !==
        'bigint' ||
      !Number.isFinite(
        Number(height)
      )
    ){
      throw new Error(
        'SMOKE_MAINNET_RESPONSE_INVALID'
      );
    }

    document
      .documentElement
      .dataset
      .smoke =
        'PASS';

    document
      .documentElement
      .dataset
      .smokeNetwork =
        'BITCOIN_CASH_MAINNET';

    document
      .documentElement
      .dataset
      .smokeHeight =
        String(height);

    setStatus(
      'Browser mainnet smoke test · PASS'
    );
  }
  catch(error){
    document
      .documentElement
      .dataset
      .smoke =
        'FAIL';

    document
      .documentElement
      .dataset
      .smokeError =
        String(
          error?.message ||
            error
        )
          .replace(
            /[^A-Za-z0-9_.:-]/g,
            '_'
          )
          .slice(
            0,
            160
          );

    throw error;
  }
  finally{
    wipeWallet(
      randomWallet
    );

    wipeWallet(
      watchWallet
    );
  }
}


async function main(){
  try{
    await loadMainnet();

    wireUi();

    refreshPasskeyUi();

    document
      .documentElement
      .dataset
      .atanWalletRelease =
        'ATAN_WALLET_STATIC_V1';

    document
      .documentElement
      .dataset
      .boot =
        'PASS';

    const params =
      new URLSearchParams(
        location.search
      );

    if(
      params.get(
        'smoke'
      ) ===
        '1'
    ){
      await smokeTest();
      return;
    }

    setStatus(
      'BCH mainnet · browser wallet ready'
    );
  }
  catch(error){
    document
      .documentElement
      .dataset
      .boot =
        'FAIL';

    setStatus(
      error?.message ||
        String(error),
      false
    );

    console.error(error);
  }
}


main();