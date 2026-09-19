export const ATAN_FEE_V2_EXACT_FEE_PLANNER_VERSION =
  '1.0.0';

export const ATAN_FEE_V2_SIGHASH_BYTE =
  0x61;

export const ATAN_FEE_V2_P2PKH_UNLOCKING_BYTES =
  100;

export const ATAN_FEE_V2_P2PKH_SIGNED_INPUT_BYTES =
  141;

export const ATAN_FEE_V2_P2PKH_OUTPUT_BYTES =
  34;

export const ATAN_FEE_V2_MAX_FUNGIBLE_TOKEN_P2PKH_OUTPUT_BYTES =
  77;

function fail(code){
  throw new Error(code);
}

function requireSafeInteger(
  value,
  field,
  minimum = 0
){
  if(
    !Number.isSafeInteger(value) ||
    value < minimum
  ){
    fail(
      `INVALID_SAFE_INTEGER:${field}`
    );
  }
}

function requireDecimalUint(
  value,
  field,
  allowZero = false
){
  if(
    typeof value !== 'string' ||
    !/^[0-9]+$/.test(value)
  ){
    fail(
      `INVALID_UINT_STRING:${field}`
    );
  }

  const parsed =
    BigInt(value);

  if(
    allowZero
      ? parsed < 0n
      : parsed <= 0n
  ){
    fail(
      `INVALID_UINT_RANGE:${field}`
    );
  }

  return parsed;
}

function varIntBytes(value){
  requireSafeInteger(
    value,
    'varint_value',
    0
  );

  if(value <= 0xfc){
    return 1;
  }

  if(value <= 0xffff){
    return 3;
  }

  if(value <= 0xffffffff){
    return 5;
  }

  return 9;
}

function bytesToHex(bytes){
  return Array
    .from(bytes)
    .map(
      value =>
        value
          .toString(16)
          .padStart(2,'0')
    )
    .join('');
}

function canonicalValue(value){
  if(value === null){
    return 'null';
  }

  if(Array.isArray(value)){
    return (
      '[' +
      value
        .map(canonicalValue)
        .join(',') +
      ']'
    );
  }

  if(
    typeof value ===
      'object'
  ){
    return (
      '{' +
      Object
        .keys(value)
        .sort()
        .map(
          key =>
            JSON.stringify(key) +
            ':' +
            canonicalValue(
              value[key]
            )
        )
        .join(',') +
      '}'
    );
  }

  if(
    typeof value === 'number'
  ){
    if(!Number.isSafeInteger(value)){
      fail(
        'FLOAT_OR_UNSAFE_NUMBER_FORBIDDEN'
      );
    }

    return String(value);
  }

  if(
    typeof value === 'string' ||
    typeof value === 'boolean'
  ){
    return JSON.stringify(value);
  }

  fail(
    `UNSUPPORTED_CANONICAL_TYPE:${typeof value}`
  );
}

async function sha256Hex(text){
  const subtle =
    globalThis.crypto?.subtle;

  if(!subtle){
    fail(
      'WEBCRYPTO_SUBTLE_REQUIRED'
    );
  }

  const bytes =
    new TextEncoder()
      .encode(
        String(text)
      );

  const digest =
    await subtle.digest(
      'SHA-256',
      bytes
    );

  return bytesToHex(
    new Uint8Array(digest)
  );
}

function ceilDiv(
  numerator,
  denominator
){
  if(denominator <= 0n){
    fail(
      'CEIL_DIV_DENOMINATOR_INVALID'
    );
  }

  return (
    numerator +
    denominator -
    1n
  ) / denominator;
}

export function calculateSponsoredEnvelopeBytesV2({
  user_bch_input_count,
  user_token_input_count,
  ordinary_output_count = 3,
  token_output_count = 2,
  safety_margin_bytes = 0
}){
  requireSafeInteger(
    user_bch_input_count,
    'user_bch_input_count',
    1
  );

  requireSafeInteger(
    user_token_input_count,
    'user_token_input_count',
    1
  );

  requireSafeInteger(
    ordinary_output_count,
    'ordinary_output_count',
    1
  );

  requireSafeInteger(
    token_output_count,
    'token_output_count',
    1
  );

  requireSafeInteger(
    safety_margin_bytes,
    'safety_margin_bytes',
    0
  );

  const sponsorBchInputCount =
    1;

  const inputCount =
    user_bch_input_count +
    user_token_input_count +
    sponsorBchInputCount;

  const outputCount =
    ordinary_output_count +
    token_output_count;

  const transactionOverheadBytes =
    4 +
    varIntBytes(inputCount) +
    varIntBytes(outputCount) +
    4;

  const inputBytes =
    inputCount *
    ATAN_FEE_V2_P2PKH_SIGNED_INPUT_BYTES;

  const ordinaryOutputBytes =
    ordinary_output_count *
    ATAN_FEE_V2_P2PKH_OUTPUT_BYTES;

  const tokenOutputBytes =
    token_output_count *
    ATAN_FEE_V2_MAX_FUNGIBLE_TOKEN_P2PKH_OUTPUT_BYTES;

  const maxSignedBytes =
    transactionOverheadBytes +
    inputBytes +
    ordinaryOutputBytes +
    tokenOutputBytes +
    safety_margin_bytes;

  return {
    user_bch_input_count,
    user_token_input_count,

    sponsor_bch_input_count:
      sponsorBchInputCount,

    input_count:
      inputCount,

    ordinary_output_count,

    token_output_count,

    output_count:
      outputCount,

    p2pkh_unlocking_bytes:
      ATAN_FEE_V2_P2PKH_UNLOCKING_BYTES,

    p2pkh_signed_input_bytes:
      ATAN_FEE_V2_P2PKH_SIGNED_INPUT_BYTES,

    ordinary_p2pkh_output_bytes:
      ATAN_FEE_V2_P2PKH_OUTPUT_BYTES,

    max_fungible_token_p2pkh_output_bytes:
      ATAN_FEE_V2_MAX_FUNGIBLE_TOKEN_P2PKH_OUTPUT_BYTES,

    transaction_overhead_bytes:
      transactionOverheadBytes,

    safety_margin_bytes,

    max_signed_bytes:
      maxSignedBytes
  };
}

export async function createExactSponsoredFeeEnvelopeV2({
  user_bch_input_count,
  user_token_input_count,
  fee_rate_sats_per_kb,
  ordinary_output_count = 3,
  token_output_count = 2,
  safety_margin_bytes = 0
}){
  const feeRate =
    requireDecimalUint(
      fee_rate_sats_per_kb,
      'fee_rate_sats_per_kb'
    );

  const shape =
    calculateSponsoredEnvelopeBytesV2({
      user_bch_input_count,
      user_token_input_count,
      ordinary_output_count,
      token_output_count,
      safety_margin_bytes
    });

  const feeSats =
    ceilDiv(
      BigInt(
        shape.max_signed_bytes
      ) *
      feeRate,
      1000n
    );

  const envelope = {
    planner_version:
      ATAN_FEE_V2_EXACT_FEE_PLANNER_VERSION,

    sighash:
      'ALL|FORKID|UTXOS',

    sighash_byte:
      '0x61',

    fee_policy:
      'EXACT_COMMITTED_FEE_FROM_SIGNED_SIZE_ENVELOPE',

    fee_rate_sats_per_kb:
      feeRate.toString(),

    network_fee_sats:
      feeSats.toString(),

    shape
  };

  return {
    ...envelope,

    envelope_id:
      await sha256Hex(
        canonicalValue(
          envelope
        )
      )
  };
}

export async function validateExactSponsoredFeeEnvelopeV2(
  envelope
){
  if(
    !envelope ||
    typeof envelope !== 'object' ||
    Array.isArray(envelope)
  ){
    fail(
      'FEE_ENVELOPE_OBJECT_REQUIRED'
    );
  }

  if(
    envelope.planner_version !==
    ATAN_FEE_V2_EXACT_FEE_PLANNER_VERSION
  ){
    fail(
      'FEE_ENVELOPE_VERSION_INVALID'
    );
  }

  if(
    envelope.sighash !==
      'ALL|FORKID|UTXOS' ||
    envelope.sighash_byte !==
      '0x61'
  ){
    fail(
      'FEE_ENVELOPE_SIGHASH_INVALID'
    );
  }

  if(
    envelope.fee_policy !==
    'EXACT_COMMITTED_FEE_FROM_SIGNED_SIZE_ENVELOPE'
  ){
    fail(
      'FEE_ENVELOPE_POLICY_INVALID'
    );
  }

  const feeRate =
    requireDecimalUint(
      envelope.fee_rate_sats_per_kb,
      'fee_rate_sats_per_kb'
    );

  const fee =
    requireDecimalUint(
      envelope.network_fee_sats,
      'network_fee_sats'
    );

  if(
    !envelope.shape ||
    typeof envelope.shape !== 'object'
  ){
    fail(
      'FEE_ENVELOPE_SHAPE_REQUIRED'
    );
  }

  const rebuiltShape =
    calculateSponsoredEnvelopeBytesV2({
      user_bch_input_count:
        envelope.shape
          .user_bch_input_count,

      user_token_input_count:
        envelope.shape
          .user_token_input_count,

      ordinary_output_count:
        envelope.shape
          .ordinary_output_count,

      token_output_count:
        envelope.shape
          .token_output_count,

      safety_margin_bytes:
        envelope.shape
          .safety_margin_bytes
    });

  if(
    JSON.stringify(rebuiltShape) !==
    JSON.stringify(envelope.shape)
  ){
    fail(
      'FEE_ENVELOPE_SHAPE_MISMATCH'
    );
  }

  const expectedFee =
    ceilDiv(
      BigInt(
        rebuiltShape.max_signed_bytes
      ) *
      feeRate,
      1000n
    );

  if(fee !== expectedFee){
    fail(
      'FEE_ENVELOPE_FEE_MISMATCH'
    );
  }

  const commitment = {
    planner_version:
      envelope.planner_version,

    sighash:
      envelope.sighash,

    sighash_byte:
      envelope.sighash_byte,

    fee_policy:
      envelope.fee_policy,

    fee_rate_sats_per_kb:
      envelope.fee_rate_sats_per_kb,

    network_fee_sats:
      envelope.network_fee_sats,

    shape:
      envelope.shape
  };

  const expectedId =
    await sha256Hex(
      canonicalValue(
        commitment
      )
    );

  if(
    envelope.envelope_id !==
    expectedId
  ){
    fail(
      'FEE_ENVELOPE_ID_MISMATCH'
    );
  }

  return true;
}

export async function assertFinalSponsoredTransactionFitsEnvelopeV2({
  envelope,
  signed_transaction_bytes,
  actual_network_fee_sats
}){
  await validateExactSponsoredFeeEnvelopeV2(
    envelope
  );

  requireSafeInteger(
    signed_transaction_bytes,
    'signed_transaction_bytes',
    1
  );

  const actualFee =
    requireDecimalUint(
      actual_network_fee_sats,
      'actual_network_fee_sats'
    );

  if(
    signed_transaction_bytes >
    envelope.shape.max_signed_bytes
  ){
    fail(
      'SIGNED_TRANSACTION_EXCEEDS_FEE_ENVELOPE'
    );
  }

  if(
    actualFee !==
    BigInt(
      envelope.network_fee_sats
    )
  ){
    fail(
      'FINAL_NETWORK_FEE_DOES_NOT_MATCH_COMMITMENT'
    );
  }

  return {
    fits:
      true,

    signed_transaction_bytes,

    max_signed_bytes:
      envelope.shape
        .max_signed_bytes,

    actual_network_fee_sats:
      actualFee.toString(),

    committed_network_fee_sats:
      envelope.network_fee_sats
  };
}
