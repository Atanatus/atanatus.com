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
const EXPECTED_RECIPIENT='bitcoincash:qpue0pja34hemgz7h5zexlx8n36suy74lv83kkknxv';
const EXPECTED_PAYMENT_SATS='1000';
const EXPECTED_NETWORK_FEE_SATS='689';
const EXPECTED_ATAN_COST_BASE='100000000';
const PRIMARY_DERIVATION="m/44'/145'/0'/0/0";
const CHANGE_DERIVATION="m/44'/145'/0'/0/1";

function fail(code){
  throw new Error(code);
}

function tokenAmount(utxo){
  return BigInt(utxo?.token?.amount ?? 0);
}

function sats(utxo){
  return BigInt(utxo?.satoshis ?? 0);
}

function isAtan(utxo,category){
  return !!utxo?.token &&
    String(utxo.token.category || '').toLowerCase() === category &&
    utxo.token.nft === undefined &&
    tokenAmount(utxo) > 0n;
}

function isPlain(utxo){
  return !utxo?.token;
}

function outpointOf(utxo){
  const txid=String(
    utxo?.txid ??
    utxo?.tx_hash ??
    utxo?.txHash ??
    ''
  );

  const vout=(
    utxo?.vout ??
    utxo?.tx_pos ??
    utxo?.txPos ??
    utxo?.outputIndex
  );

  if(!txid || vout === undefined || vout === null){
    return 'OUTPOINT_UNAVAILABLE';
  }

  return `${txid}:${vout}`;
}

async function postJson(url,body){
  const response=await fetch(url,{
    method:'POST',
    headers:{'content-type':'application/json'},
    cache:'no-store',
    credentials:'omit',
    redirect:'error',
    body:JSON.stringify(body)
  });

  const text=await response.text();
  let payload=null;
  if(text) payload=JSON.parse(text);

  return {ok:response.ok,status:response.status,payload};
}

export async function createW62IAuthenticatedSponsoredPreview({
  recipient,
  amount,
  wallet,
  changeWallet,
  mainnet,
  atanCategory,
  sponsorOrigin='http://127.0.0.1:18792'
}){
  if(!wallet || !changeWallet || !mainnet){
    fail('W62I_WALLET_STATE_REQUIRED');
  }

  if(String(atanCategory).toLowerCase()!=='3c9af04021c731219908a6c1f9e900ce988d481d40463845e7f5befe61e0362b'){
    fail('W62I_ATAN_CATEGORY_MISMATCH');
  }

  const normalizedRecipient=mainnet.toCashaddr(recipient);
  const paymentSats=BigInt(amount).toString();

  const bundleResponse=await fetch(
    './ATAN_W62H_AUTHENTICATED_QUOTE_BUNDLE.json',
    {cache:'no-store',credentials:'omit'}
  );

  if(!bundleResponse.ok){
    fail('W62I_AUTHENTICATED_BUNDLE_FETCH_FAILED');
  }

  const bundle=await bundleResponse.json();

  if(
    bundle?.quote_id!==EXACT_QUOTE_ID ||
    bundle?.signing_message!==EXACT_MESSAGE ||
    bundle?.signer_address!==EXACT_SIGNER ||
    bundle?.cryptographic_authentication_validated!==true
  ){
    fail('W62I_AUTHENTICATED_BUNDLE_BINDING_FAILED');
  }

  if(
    normalizedRecipient!==EXPECTED_RECIPIENT ||
    paymentSats!==EXPECTED_PAYMENT_SATS ||
    bundle.request?.recipient!==EXPECTED_RECIPIENT ||
    bundle.request?.payment_sats!==EXPECTED_PAYMENT_SATS
  ){
    fail('W62I_AUTHENTICATED_CANARY_REQUEST_MISMATCH');
  }

  const envelope=await createExactSponsoredFeeEnvelopeV2({
    user_bch_input_count:1,
    user_token_input_count:1,
    fee_rate_sats_per_kb:'1000'
  });

  if(
    envelope.network_fee_sats!==EXPECTED_NETWORK_FEE_SATS ||
    bundle.request?.fee_policy?.network_fee_sats!==EXPECTED_NETWORK_FEE_SATS ||
    bundle.quote?.network_fee_sats!==EXPECTED_NETWORK_FEE_SATS
  ){
    fail('W62I_EXACT_FEE_BINDING_FAILED');
  }

  if(bundle.quote?.token_cost_base!==EXPECTED_ATAN_COST_BASE){
    fail('W62I_ATAN_COST_BINDING_FAILED');
  }

  const [primaryUtxos,changeUtxos,height]=await Promise.all([
    wallet.getUtxos(),
    changeWallet.getUtxos(),
    wallet.provider.getBlockHeight()
  ]);

  if(
    Number(height)>Number(bundle.request.valid_until_height) ||
    Number(height)>Number(bundle.quote.valid_until_height)
  ){
    fail('W62I_AUTHENTICATED_QUOTE_EXPIRED');
  }

  const changePlain=changeUtxos
    .filter(isPlain)
    .sort((a,b)=>sats(a)>sats(b)?-1:sats(a)<sats(b)?1:0);

  const primaryPlain=primaryUtxos
    .filter(isPlain)
    .sort((a,b)=>sats(a)>sats(b)?-1:sats(a)<sats(b)?1:0);

  const userBchInput=changePlain[0] || primaryPlain[0];

  if(!userBchInput){
    fail('W62I_USER_BCH_INPUT_NOT_FOUND');
  }

  if(sats(userBchInput)<BigInt(EXPECTED_PAYMENT_SATS)){
    fail('W62I_USER_BCH_INPUT_INSUFFICIENT');
  }

  const userBchDerivation=changePlain[0]===userBchInput
    ? CHANGE_DERIVATION
    : PRIMARY_DERIVATION;

  const atanInputs=primaryUtxos
    .filter(utxo=>isAtan(utxo,String(atanCategory).toLowerCase()))
    .sort((a,b)=>tokenAmount(a)>tokenAmount(b)?-1:tokenAmount(a)<tokenAmount(b)?1:0);

  const userTokenInput=atanInputs.find(
    utxo=>tokenAmount(utxo)>=BigInt(EXPECTED_ATAN_COST_BASE)
  );

  if(!userTokenInput){
    fail('W62I_USER_ATAN_INPUT_NOT_FOUND_OR_INSUFFICIENT');
  }

  const quoteResponse=await postJson(
    sponsorOrigin+'/v2/quote',
    bundle.request
  );

  if(!quoteResponse.ok){
    fail(
      quoteResponse.payload?.code ||
      `W62I_SPONSOR_QUOTE_HTTP_${quoteResponse.status}`
    );
  }

  const quote=quoteResponse.payload?.quote;

  if(!quote){
    fail('W62I_SPONSOR_QUOTE_MISSING');
  }

  await validateSponsorQuoteV2(
    bundle.request,
    quote
  );

  if(
    quote.quote_id!==EXACT_QUOTE_ID ||
    quote.sponsor_signer_address!==EXACT_SIGNER ||
    quote.authentication?.signer_address!==EXACT_SIGNER
  ){
    fail('W62I_TRANSPORTED_QUOTE_EXACT_BINDING_FAILED');
  }

  if(
    verifySponsorQuoteSignatureV2({quote,mainnet})!==true
  ){
    fail('W62I_TRANSPORTED_QUOTE_SIGNATURE_INVALID');
  }

  return Object.freeze({
    mode:'ATAN_SPONSORED_AUTHENTICATED_PREVIEW',
    stage:'W62I',
    quote_id:quote.quote_id,
    request_id:bundle.request.request_id,
    signer_address:quote.sponsor_signer_address,
    sponsor_funding_outpoint:quote.sponsor_funding_outpoint,
    sponsor_token_address:quote.sponsor_token_address,
    sponsor_bch_change_address:quote.sponsor_bch_change_address,
    recipient:normalizedRecipient,
    payment_sats:paymentSats,
    network_fee_sats:quote.network_fee_sats,
    token_cost_base:quote.token_cost_base,
    fee_rate_sats_per_kb:envelope.fee_rate_sats_per_kb,
    exact_fee_envelope_id:envelope.envelope_id,
    max_signed_bytes:envelope.shape.max_signed_bytes,
    user_bch_input_outpoint:outpointOf(userBchInput),
    user_bch_input_sats:sats(userBchInput).toString(),
    user_bch_input_derivation:userBchDerivation,
    user_token_input_outpoint:outpointOf(userTokenInput),
    user_token_input_atan_base:tokenAmount(userTokenInput).toString(),
    user_token_input_derivation:PRIMARY_DERIVATION,
    user_bch_network_fee_target_sats:'0',
    quote_authentication_valid:true,
    exact_fee_binding_valid:true,
    dual_derivation_inventory_connected:true,
    current_height:Number(height),
    transaction_signing:false,
    testmempoolaccept:false,
    submitTransaction:false,
    sendrawtransaction:false,
    transaction_broadcast:false
  });
}
