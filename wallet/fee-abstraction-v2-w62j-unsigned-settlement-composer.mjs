import {
  createExactSponsoredFeeEnvelopeV2
} from './fee-abstraction-v2-exact-fee-planner.mjs';

import {
  validateSponsorQuoteV2,
  verifySponsorQuoteSignatureV2
} from './fee-abstraction-v2-sponsor-protocol.mjs';

const EXACT_QUOTE_ID='8ecf6b79f3be7cc3d9d621448f4dd4263c8e941c06c2d698e3e1b28d8abb35ec';
const EXACT_MESSAGE='ATAN_FEE_ABSTRACTION_V2_QUOTE:8ecf6b79f3be7cc3d9d621448f4dd4263c8e941c06c2d698e3e1b28d8abb35ec';
const EXACT_SIGNER='bitcoincash:qrxkkqkshdyzvr556me77p3m7grpjppd8s68kdrmkc';
const EXACT_TXID='6fb26fc091839059480ad0d0982d1c65885d422dd8f34823d3d9e3a04129439e';
const USER_BCH_OUTPOINT='6fb26fc091839059480ad0d0982d1c65885d422dd8f34823d3d9e3a04129439e:1';
const USER_TOKEN_OUTPOINT='6fb26fc091839059480ad0d0982d1c65885d422dd8f34823d3d9e3a04129439e:2';
const SPONSOR_OUTPOINT='6fb26fc091839059480ad0d0982d1c65885d422dd8f34823d3d9e3a04129439e:4';
const EXPECTED_RECIPIENT='bitcoincash:qpue0pja34hemgz7h5zexlx8n36suy74lv83kkknxv';
const ATAN_CATEGORY='3c9af04021c731219908a6c1f9e900ce988d481d40463845e7f5befe61e0362b';
const EXPECTED_USER_BCH_SATS=438266n;
const EXPECTED_USER_TOKEN_SATS=1000n;
const EXPECTED_USER_TOKEN_AMOUNT=82789660660864n;
const EXPECTED_SPONSOR_SATS=44132n;
const PAYMENT_SATS=1000n;
const NETWORK_FEE_SATS=689n;
const ATAN_COST_BASE=100000000n;
const USER_BCH_CHANGE_SATS=437266n;
const USER_TOKEN_CHANGE_BASE=82789560660864n;
const SPONSOR_TOKEN_CARRIER_SATS=1000n;
const SPONSOR_BCH_CHANGE_SATS=42443n;
const PRIMARY_DERIVATION="m/44'/145'/0'/0/0";
const CHANGE_DERIVATION="m/44'/145'/0'/0/1";

function fail(code){ throw new Error(code); }
function bytesToHex(bytes){ return Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join(''); }
function tokenAmount(utxo){ return BigInt(utxo?.token?.amount ?? 0); }
function sats(utxo){ return BigInt(utxo?.satoshis ?? 0); }
function isAtan(utxo){
  return !!utxo?.token &&
    String(utxo.token.category || '').toLowerCase()===ATAN_CATEGORY &&
    utxo.token.nft===undefined && tokenAmount(utxo)>0n;
}
function outpointOf(utxo){
  const txid=String(utxo?.txid ?? utxo?.tx_hash ?? utxo?.txHash ?? '');
  const vout=utxo?.vout ?? utxo?.tx_pos ?? utxo?.txPos ?? utxo?.outputIndex;
  if(!txid || vout===undefined || vout===null) return 'OUTPOINT_UNAVAILABLE';
  return `${txid}:${vout}`;
}
function p2pkh(mainnet,address){
  if(typeof mainnet.derivePublicKeyHash!=='function') fail('W62J_DERIVE_PUBLIC_KEY_HASH_MISSING');
  const pkh=mainnet.derivePublicKeyHash(address);
  if(!(pkh instanceof Uint8Array) || pkh.length!==20) fail('W62J_P2PKH_DERIVATION_FAILED');
  return Uint8Array.from([0x76,0xa9,0x14,...pkh,0x88,0xac]);
}
function parseOutpoint(value){
  const m=/^([0-9a-f]{64}):([0-9]+)$/.exec(value);
  if(!m) fail('W62J_OUTPOINT_INVALID');
  return {txid:m[1],index:Number(m[2])};
}
async function sha256HexBytes(bytes){
  const digest=await globalThis.crypto.subtle.digest('SHA-256',bytes);
  return bytesToHex(new Uint8Array(digest));
}
async function sha256HexText(text){
  return sha256HexBytes(new TextEncoder().encode(String(text)));
}
async function postJson(path,body){
  const response=await fetch(path,{
    method:'POST',headers:{'content-type':'application/json'},cache:'no-store',credentials:'omit',body:JSON.stringify(body)
  });
  const text=await response.text();
  let payload=null; if(text) payload=JSON.parse(text);
  return {ok:response.ok,status:response.status,payload};
}

export async function createW62JUnsignedSettlementComposition({
  recipient, amount, wallet, changeWallet, mainnet, atanCategory, sponsorOrigin='http://127.0.0.1:18794'
}){
  if(!wallet || !changeWallet || !mainnet) fail('W62J_WALLET_STATE_REQUIRED');
  if(String(atanCategory).toLowerCase()!==ATAN_CATEGORY) fail('W62J_ATAN_CATEGORY_MISMATCH');
  const normalizedRecipient=mainnet.toCashaddr(recipient);
  if(normalizedRecipient!==EXPECTED_RECIPIENT) fail('W62J_CANARY_RECIPIENT_MISMATCH');
  if(BigInt(amount)!==PAYMENT_SATS) fail('W62J_CANARY_PAYMENT_MISMATCH');

  const bundleResponse=await fetch('./ATAN_W62H_AUTHENTICATED_QUOTE_BUNDLE.json',{cache:'no-store',credentials:'omit'});
  if(!bundleResponse.ok) fail('W62J_AUTHENTICATED_BUNDLE_FETCH_FAILED');
  const bundle=await bundleResponse.json();
  if(bundle?.quote_id!==EXACT_QUOTE_ID || bundle?.signing_message!==EXACT_MESSAGE || bundle?.signer_address!==EXACT_SIGNER || bundle?.cryptographic_authentication_validated!==true){
    fail('W62J_AUTHENTICATED_BUNDLE_BINDING_FAILED');
  }

  const envelope=await createExactSponsoredFeeEnvelopeV2({
    user_bch_input_count:1,user_token_input_count:1,fee_rate_sats_per_kb:'1000'
  });
  if(envelope.network_fee_sats!==NETWORK_FEE_SATS.toString()) fail('W62J_EXACT_FEE_ENVELOPE_MISMATCH');

  const [primaryUtxos,changeUtxos,height]=await Promise.all([
    wallet.getUtxos(),changeWallet.getUtxos(),wallet.provider.getBlockHeight()
  ]);

  if(Number(height)>Number(bundle.request.valid_until_height) || Number(height)>Number(bundle.quote.valid_until_height)){
    fail('W62J_AUTHENTICATED_QUOTE_EXPIRED');
  }

  const userBchInput=changeUtxos.find(u=>outpointOf(u)===USER_BCH_OUTPOINT);
  if(!userBchInput || userBchInput.token!==undefined || sats(userBchInput)!==EXPECTED_USER_BCH_SATS){
    fail('W62J_USER_BCH_INPUT_STATE_MISMATCH');
  }

  const userTokenInput=primaryUtxos.find(u=>outpointOf(u)===USER_TOKEN_OUTPOINT);
  if(!userTokenInput || !isAtan(userTokenInput) || sats(userTokenInput)!==EXPECTED_USER_TOKEN_SATS || tokenAmount(userTokenInput)!==EXPECTED_USER_TOKEN_AMOUNT){
    fail('W62J_USER_TOKEN_INPUT_STATE_MISMATCH');
  }

  const quoteResponse=await fetch(sponsorOrigin+'/v2/quote',{
    method:'POST',headers:{'content-type':'application/json'},cache:'no-store',credentials:'omit',body:JSON.stringify(bundle.request)
  });
  const quoteText=await quoteResponse.text();
  const quotePayload=quoteText ? JSON.parse(quoteText) : null;
  if(!quoteResponse.ok) fail(quotePayload?.code || `W62J_SPONSOR_QUOTE_HTTP_${quoteResponse.status}`);
  const quote=quotePayload?.quote;
  if(!quote) fail('W62J_SPONSOR_QUOTE_MISSING');

  await validateSponsorQuoteV2(bundle.request,quote);
  if(quote.quote_id!==EXACT_QUOTE_ID || quote.sponsor_signer_address!==EXACT_SIGNER || quote.sponsor_funding_outpoint!==SPONSOR_OUTPOINT){
    fail('W62J_SPONSOR_QUOTE_EXACT_BINDING_FAILED');
  }
  if(quote.network_fee_sats!==NETWORK_FEE_SATS.toString() || quote.token_cost_base!==ATAN_COST_BASE.toString()){
    fail('W62J_SPONSOR_ECONOMIC_BINDING_FAILED');
  }
  if(verifySponsorQuoteSignatureV2({quote,mainnet})!==true) fail('W62J_SPONSOR_SIGNATURE_INVALID');

  const libauth=mainnet.libauth;
  if(typeof libauth?.encodeTransaction!=='function' || typeof libauth?.decodeTransaction!=='function' || typeof libauth?.hexToBin!=='function'){
    fail('W62J_LIBAUTH_CAPABILITY_MISSING');
  }

  const tokenCategoryBin=libauth.hexToBin(ATAN_CATEGORY);
  const userBchOut=parseOutpoint(USER_BCH_OUTPOINT);
  const userTokenOut=parseOutpoint(USER_TOKEN_OUTPOINT);
  const sponsorOut=parseOutpoint(SPONSOR_OUTPOINT);

  const transaction={
    version:2,
    inputs:[
      {outpointTransactionHash:libauth.hexToBin(userBchOut.txid),outpointIndex:userBchOut.index,sequenceNumber:0xffffffff,unlockingBytecode:new Uint8Array()},
      {outpointTransactionHash:libauth.hexToBin(userTokenOut.txid),outpointIndex:userTokenOut.index,sequenceNumber:0xffffffff,unlockingBytecode:new Uint8Array()},
      {outpointTransactionHash:libauth.hexToBin(sponsorOut.txid),outpointIndex:sponsorOut.index,sequenceNumber:0xffffffff,unlockingBytecode:new Uint8Array()}
    ],
    outputs:[
      {lockingBytecode:p2pkh(mainnet,normalizedRecipient),valueSatoshis:PAYMENT_SATS},
      {lockingBytecode:p2pkh(mainnet,changeWallet.cashaddr),valueSatoshis:USER_BCH_CHANGE_SATS},
      {lockingBytecode:p2pkh(mainnet,wallet.cashaddr),valueSatoshis:EXPECTED_USER_TOKEN_SATS,token:{category:tokenCategoryBin,amount:USER_TOKEN_CHANGE_BASE}},
      {lockingBytecode:p2pkh(mainnet,quote.sponsor_token_address),valueSatoshis:SPONSOR_TOKEN_CARRIER_SATS,token:{category:tokenCategoryBin,amount:ATAN_COST_BASE}},
      {lockingBytecode:p2pkh(mainnet,quote.sponsor_bch_change_address),valueSatoshis:SPONSOR_BCH_CHANGE_SATS}
    ],
    locktime:0
  };

  const sourceOutputs=[
    {lockingBytecode:p2pkh(mainnet,changeWallet.cashaddr),valueSatoshis:EXPECTED_USER_BCH_SATS},
    {lockingBytecode:p2pkh(mainnet,wallet.cashaddr),valueSatoshis:EXPECTED_USER_TOKEN_SATS,token:{category:tokenCategoryBin,amount:EXPECTED_USER_TOKEN_AMOUNT}},
    {lockingBytecode:p2pkh(mainnet,quote.sponsor_signer_address),valueSatoshis:EXPECTED_SPONSOR_SATS}
  ];

  const encoded=libauth.encodeTransaction(transaction);
  const decoded=libauth.decodeTransaction(encoded);
  if(typeof decoded==='string') fail('W62J_LIBAUTH_DECODE_FAILED:'+decoded);
  if(decoded.inputs.length!==3 || decoded.outputs.length!==5) fail('W62J_TRANSACTION_GEOMETRY_INVALID');
  if(decoded.inputs.some(i=>!(i.unlockingBytecode instanceof Uint8Array) || i.unlockingBytecode.length!==0)) fail('W62J_UNSIGNED_INPUT_UNLOCKING_BYTECODE_NONEMPTY');
  const reencoded=libauth.encodeTransaction(decoded);
  if(bytesToHex(reencoded)!==bytesToHex(encoded)) fail('W62J_DECODE_REENCODE_MISMATCH');

  const totalInput=EXPECTED_USER_BCH_SATS+EXPECTED_USER_TOKEN_SATS+EXPECTED_SPONSOR_SATS;
  const totalOutput=PAYMENT_SATS+USER_BCH_CHANGE_SATS+EXPECTED_USER_TOKEN_SATS+SPONSOR_TOKEN_CARRIER_SATS+SPONSOR_BCH_CHANGE_SATS;
  if(totalInput-totalOutput!==NETWORK_FEE_SATS) fail('W62J_ACCOUNTING_FEE_MISMATCH');
  const projectedSignedBytes=encoded.length+(3*100);
  if(projectedSignedBytes>Number(envelope.shape.max_signed_bytes)) fail('W62J_EXACT_FEE_ENVELOPE_EXCEEDED');

  const unsignedHex=bytesToHex(encoded);
  const unsignedSha=await sha256HexBytes(encoded);
  const candidateId=await sha256HexText(
    ['W62J',bundle.request.request_id,quote.quote_id,unsignedSha,USER_BCH_OUTPOINT,USER_TOKEN_OUTPOINT,SPONSOR_OUTPOINT].join(':')
  );

  const composition={
    schema:'ATAN_FEE_V2_W62J_UNSIGNED_ATOMIC_SETTLEMENT_COMPOSITION',
    version:'1.0.0',
    candidate_id:candidateId,
    request_id:bundle.request.request_id,
    quote_id:quote.quote_id,
    signing_message:EXACT_MESSAGE,
    signer_address:quote.sponsor_signer_address,
    exact_fee_envelope_id:envelope.envelope_id,
    fee_rate_sats_per_kb:envelope.fee_rate_sats_per_kb,
    max_signed_bytes:envelope.shape.max_signed_bytes,
    projected_signed_bytes:projectedSignedBytes,
    unsigned_transaction_bytes:encoded.length,
    unsigned_transaction_hex:unsignedHex,
    unsigned_transaction_sha256:unsignedSha,
    input_order:['USER_BCH','USER_TOKEN','SPONSOR_BCH'],
    output_order:['RECIPIENT_BCH','USER_BCH_CHANGE','USER_TOKEN_CHANGE','SPONSOR_TOKEN_RECEIVER','SPONSOR_BCH_CHANGE'],
    source_outputs:[
      {role:'USER_BCH',outpoint:USER_BCH_OUTPOINT,value_sats:EXPECTED_USER_BCH_SATS.toString(),address:changeWallet.cashaddr,derivation:CHANGE_DERIVATION},
      {role:'USER_TOKEN',outpoint:USER_TOKEN_OUTPOINT,value_sats:EXPECTED_USER_TOKEN_SATS.toString(),address:wallet.cashaddr,derivation:PRIMARY_DERIVATION,token_category:ATAN_CATEGORY,token_amount_base:EXPECTED_USER_TOKEN_AMOUNT.toString()},
      {role:'SPONSOR_BCH',outpoint:SPONSOR_OUTPOINT,value_sats:EXPECTED_SPONSOR_SATS.toString(),address:quote.sponsor_signer_address,freshness:'LAST_CERTIFIED_W62F_R2_REVALIDATION'}
    ],
    outputs:[
      {role:'RECIPIENT_BCH',address:normalizedRecipient,value_sats:PAYMENT_SATS.toString()},
      {role:'USER_BCH_CHANGE',address:changeWallet.cashaddr,value_sats:USER_BCH_CHANGE_SATS.toString()},
      {role:'USER_TOKEN_CHANGE',address:wallet.tokenaddr,value_sats:EXPECTED_USER_TOKEN_SATS.toString(),token_category:ATAN_CATEGORY,token_amount_base:USER_TOKEN_CHANGE_BASE.toString()},
      {role:'SPONSOR_TOKEN_RECEIVER',address:quote.sponsor_token_address,value_sats:SPONSOR_TOKEN_CARRIER_SATS.toString(),token_category:ATAN_CATEGORY,token_amount_base:ATAN_COST_BASE.toString()},
      {role:'SPONSOR_BCH_CHANGE',address:quote.sponsor_bch_change_address,value_sats:SPONSOR_BCH_CHANGE_SATS.toString()}
    ],
    accounting:{
      total_input_sats:totalInput.toString(),total_output_sats:totalOutput.toString(),network_fee_sats:NETWORK_FEE_SATS.toString(),
      user_payment_sats:PAYMENT_SATS.toString(),user_bch_network_fee_target_sats:'0',user_atan_fee_base:ATAN_COST_BASE.toString(),
      sponsor_bch_input_sats:EXPECTED_SPONSOR_SATS.toString(),sponsor_bch_change_sats:SPONSOR_BCH_CHANGE_SATS.toString(),sponsor_atan_received_base:ATAN_COST_BASE.toString()
    },
    current_height:Number(height),
    quote_authentication_valid:true,
    exact_fee_binding_valid:true,
    dual_derivation_inventory_connected:true,
    sponsor_funding_freshness:'LAST_CERTIFIED_W62F_R2_REVALIDATION',
    pre_sign_freshness_required:true,
    user_signature_present:false,
    sponsor_signature_present:false,
    transaction_signed:false,
    message_signing:false,
    transaction_signing:false,
    testmempoolaccept:false,
    submitTransaction:false,
    sendrawtransaction:false,
    transaction_broadcast:false
  };

  const stored=await postJson('/w62j-composition',composition);
  if(!stored.ok || stored.payload?.accepted!==true) fail(stored.payload?.code || `W62J_COMPOSITION_POST_FAILED_${stored.status}`);

  return Object.freeze({
    mode:'ATAN_SPONSORED_UNSIGNED_ATOMIC_SETTLEMENT',stage:'W62J',
    quote_id:quote.quote_id,request_id:bundle.request.request_id,signer_address:quote.sponsor_signer_address,
    sponsor_funding_outpoint:quote.sponsor_funding_outpoint,sponsor_token_address:quote.sponsor_token_address,sponsor_bch_change_address:quote.sponsor_bch_change_address,
    recipient:normalizedRecipient,payment_sats:PAYMENT_SATS.toString(),network_fee_sats:NETWORK_FEE_SATS.toString(),token_cost_base:ATAN_COST_BASE.toString(),
    fee_rate_sats_per_kb:envelope.fee_rate_sats_per_kb,exact_fee_envelope_id:envelope.envelope_id,max_signed_bytes:envelope.shape.max_signed_bytes,
    user_bch_input_outpoint:USER_BCH_OUTPOINT,user_bch_input_sats:EXPECTED_USER_BCH_SATS.toString(),user_bch_input_derivation:CHANGE_DERIVATION,
    user_token_input_outpoint:USER_TOKEN_OUTPOINT,user_token_input_atan_base:EXPECTED_USER_TOKEN_AMOUNT.toString(),user_token_input_derivation:PRIMARY_DERIVATION,
    unsigned_transaction_sha256:unsignedSha,unsigned_transaction_bytes:encoded.length,projected_signed_bytes:projectedSignedBytes,candidate_id:candidateId,
    user_bch_network_fee_target_sats:'0',quote_authentication_valid:true,exact_fee_binding_valid:true,dual_derivation_inventory_connected:true,
    current_height:Number(height),pre_sign_freshness_required:true,transaction_signing:false,testmempoolaccept:false,submitTransaction:false,sendrawtransaction:false,transaction_broadcast:false
  });
}
