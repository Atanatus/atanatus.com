export const ATAN_FEE_V2_SPONSOR_FACTS_OBSERVER_VERSION =
  '1.0.0';

export const ATAN_FEE_V2_SPONSOR_FACTS_OBSERVATION_SCHEMA =
  'ATAN_FEE_V2_SPONSOR_FACTS_OBSERVATION';

function fail(code){
  throw new Error(code);
}

function requireObject(value, field){
  if(
    !value ||
    typeof value !== 'object' ||
    Array.isArray(value)
  ){
    fail(`SPONSOR_FACTS_OBJECT_REQUIRED:${field}`);
  }
}

function requireString(value, field){
  if(
    typeof value !== 'string' ||
    value.length === 0
  ){
    fail(`SPONSOR_FACTS_STRING_REQUIRED:${field}`);
  }

  return value;
}

function requireHeight(value, field){
  if(
    !Number.isSafeInteger(value) ||
    value < 0
  ){
    fail(`SPONSOR_FACTS_HEIGHT_INVALID:${field}`);
  }
}

function normalizeAddress(value, field){
  return requireString(
    value,
    field
  ).toLowerCase();
}

function normalizeHex(value, field){
  const text =
    requireString(
      value,
      field
    ).toLowerCase();

  if(
    text.length % 2 !== 0 ||
    !/^[0-9a-f]+$/.test(text)
  ){
    fail(`SPONSOR_FACTS_HEX_INVALID:${field}`);
  }

  return text;
}

export function normalizeSponsorFundingOutpointV2(value){
  if(typeof value === 'string'){
    const match =
      /^([0-9a-fA-F]{64}):([0-9]+)$/.exec(
        value
      );

    if(!match){
      fail('SPONSOR_FUNDING_OUTPOINT_INVALID');
    }

    const vout =
      Number(match[2]);

    if(
      !Number.isSafeInteger(vout) ||
      vout < 0 ||
      vout > 0xffffffff
    ){
      fail('SPONSOR_FUNDING_VOUT_INVALID');
    }

    return {
      txid:
        match[1].toLowerCase(),

      vout,

      canonical:
        `${match[1].toLowerCase()}:${vout}`
    };
  }

  requireObject(
    value,
    'sponsor_funding_outpoint'
  );

  const txid =
    requireString(
      value.txid,
      'sponsor_funding_outpoint.txid'
    ).toLowerCase();

  if(!/^[0-9a-f]{64}$/.test(txid)){
    fail('SPONSOR_FUNDING_TXID_INVALID');
  }

  const vout =
    value.vout;

  if(
    !Number.isSafeInteger(vout) ||
    vout < 0 ||
    vout > 0xffffffff
  ){
    fail('SPONSOR_FUNDING_VOUT_INVALID');
  }

  return {
    txid,
    vout,
    canonical:
      `${txid}:${vout}`
  };
}

function p2pkhValidation(value, field){
  requireObject(value, field);

  if(value.isvalid !== true){
    fail(`SPONSOR_FACTS_ADDRESS_INVALID:${field}`);
  }

  if(value.isscript !== false){
    fail(`SPONSOR_FACTS_P2PKH_REQUIRED:${field}`);
  }

  const address =
    normalizeAddress(
      value.address,
      `${field}.address`
    );

  const scriptPubKey =
    normalizeHex(
      value.scriptPubKey,
      `${field}.scriptPubKey`
    );

  if(
    !/^76a914[0-9a-f]{40}88ac$/.test(
      scriptPubKey
    )
  ){
    fail(`SPONSOR_FACTS_P2PKH_SCRIPT_INVALID:${field}`);
  }

  return {
    address,
    scriptPubKey,
    tokenAware:
      value.istokenaware === true
  };
}

export function deriveSponsorQuoteFactsV2({
  quote,
  observation
}){
  requireObject(
    quote,
    'quote'
  );

  requireObject(
    observation,
    'observation'
  );

  if(
    observation.schema !==
    ATAN_FEE_V2_SPONSOR_FACTS_OBSERVATION_SCHEMA
  ){
    fail('SPONSOR_FACTS_OBSERVATION_SCHEMA_INVALID');
  }

  if(
    observation.version !==
    ATAN_FEE_V2_SPONSOR_FACTS_OBSERVER_VERSION
  ){
    fail('SPONSOR_FACTS_OBSERVATION_VERSION_INVALID');
  }

  if(
    observation.source !==
    'BCHN_MAINNET_READONLY_OBSERVER'
  ){
    fail('SPONSOR_FACTS_OBSERVATION_SOURCE_INVALID');
  }

  if(observation.chain !== 'main'){
    fail('SPONSOR_FACTS_CHAIN_NOT_MAINNET');
  }

  if(observation.initial_block_download !== false){
    fail('SPONSOR_FACTS_NODE_IN_IBD');
  }

  requireHeight(
    observation.observed_height,
    'observed_height'
  );

  const quoteOutpoint =
    normalizeSponsorFundingOutpointV2(
      quote.sponsor_funding_outpoint
    );

  const observedOutpoint =
    normalizeSponsorFundingOutpointV2(
      observation.funding_outpoint
    );

  if(
    quoteOutpoint.canonical !==
    observedOutpoint.canonical
  ){
    fail('SPONSOR_FACTS_OUTPOINT_BINDING_MISMATCH');
  }

  const signerAddress =
    normalizeAddress(
      quote.sponsor_signer_address,
      'quote.sponsor_signer_address'
    );

  const tokenAddress =
    normalizeAddress(
      quote.sponsor_token_address,
      'quote.sponsor_token_address'
    );

  const changeAddress =
    normalizeAddress(
      quote.sponsor_bch_change_address,
      'quote.sponsor_bch_change_address'
    );

  const signerValidation =
    p2pkhValidation(
      observation.signer_validation,
      'signer_validation'
    );

  const tokenValidation =
    p2pkhValidation(
      observation.token_receive_validation,
      'token_receive_validation'
    );

  const changeValidation =
    p2pkhValidation(
      observation.bch_change_validation,
      'bch_change_validation'
    );

  if(
    signerValidation.address !==
    signerAddress
  ){
    fail('SPONSOR_FACTS_SIGNER_ADDRESS_BINDING_MISMATCH');
  }

  if(
    tokenValidation.address !==
    tokenAddress
  ){
    fail('SPONSOR_FACTS_TOKEN_ADDRESS_BINDING_MISMATCH');
  }

  if(
    changeValidation.address !==
    changeAddress
  ){
    fail('SPONSOR_FACTS_CHANGE_ADDRESS_BINDING_MISMATCH');
  }

  if(tokenValidation.tokenAware !== true){
    fail('SPONSOR_TOKEN_RECEIVE_ADDRESS_NOT_TOKEN_AWARE');
  }

  if(
    tokenValidation.scriptPubKey ===
    changeValidation.scriptPubKey
  ){
    fail('SPONSOR_TOKEN_AND_BCH_CHANGE_SCRIPTS_MUST_DIFFER');
  }

  const fundingUtxo =
    observation.funding_utxo;

  const fundingOutpointUnspent =
    fundingUtxo !== null &&
    fundingUtxo !== undefined;

  if(!fundingOutpointUnspent){
    return Object.freeze({
      observer_version:
        ATAN_FEE_V2_SPONSOR_FACTS_OBSERVER_VERSION,

      observed_height:
        observation.observed_height,

      funding_outpoint:
        quoteOutpoint.canonical,

      funding_value_sats:
        null,

      funding_bch_only:
        false,

      signer_address_matches_funding_script:
        false,

      bch_change_address_valid:
        true,

      token_and_bch_change_scripts_distinct:
        true,

      protocol_facts:
        Object.freeze({
          funding_outpoint_unspent:
            false,

          signer_controls_funding_outpoint:
            false,

          token_receive_address_token_aware:
            true
        })
    });
  }

  requireObject(
    fundingUtxo,
    'funding_utxo'
  );

  requireObject(
    fundingUtxo.scriptPubKey,
    'funding_utxo.scriptPubKey'
  );

  if(
    fundingUtxo.tokenData !== null &&
    fundingUtxo.tokenData !== undefined
  ){
    fail('SPONSOR_FUNDING_OUTPOINT_CONTAINS_TOKEN');
  }

  const fundingScript =
    normalizeHex(
      fundingUtxo.scriptPubKey.hex,
      'funding_utxo.scriptPubKey.hex'
    );

  if(
    fundingUtxo.scriptPubKey.type !==
    'pubkeyhash'
  ){
    fail('SPONSOR_FUNDING_OUTPOINT_NOT_P2PKH');
  }

  const scriptAddresses =
    Array.isArray(
      fundingUtxo.scriptPubKey.addresses
    )
      ? fundingUtxo.scriptPubKey.addresses
          .map(
            value =>
              String(value).toLowerCase()
          )
      : [];

  const signerAddressMatchesFundingScript =
    fundingScript ===
      signerValidation.scriptPubKey &&
    scriptAddresses.includes(
      signerAddress
    );

  const valueSats =
    observation.funding_value_sats;

  if(
    !Number.isSafeInteger(valueSats) ||
    valueSats <= 0
  ){
    fail('SPONSOR_FUNDING_VALUE_SATS_INVALID');
  }

  return Object.freeze({
    observer_version:
      ATAN_FEE_V2_SPONSOR_FACTS_OBSERVER_VERSION,

    observed_height:
      observation.observed_height,

    funding_outpoint:
      quoteOutpoint.canonical,

    funding_value_sats:
      valueSats,

    funding_bch_only:
      true,

    signer_address_matches_funding_script:
      signerAddressMatchesFundingScript,

    bch_change_address_valid:
      true,

    token_and_bch_change_scripts_distinct:
      true,

    protocol_facts:
      Object.freeze({
        funding_outpoint_unspent:
          true,

        signer_controls_funding_outpoint:
          signerAddressMatchesFundingScript,

        token_receive_address_token_aware:
          true
      })
  });
}
