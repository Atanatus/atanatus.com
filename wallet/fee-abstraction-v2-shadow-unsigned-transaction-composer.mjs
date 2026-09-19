import {
  validateShadowSettlementPlanV2
} from './fee-abstraction-v2-shadow-settlement-plan-r1.mjs';

export const ATAN_FEE_V2_UNSIGNED_COMPOSER_VERSION =
  '1.0.0';

export const ATAN_FEE_V2_UNSIGNED_COMPOSER_SCHEMA =
  'ATAN_FEE_ABSTRACTION_V2_UNSIGNED_TRANSACTION_SHADOW';

function fail(code){
  throw new Error(code);
}

function requireObject(value, name){
  if(
    !value ||
    typeof value !== 'object' ||
    Array.isArray(value)
  ){
    fail(
      `${name.toUpperCase()}_OBJECT_REQUIRED`
    );
  }
}

function requireString(value, name){
  if(
    typeof value !== 'string' ||
    value.length === 0
  ){
    fail(
      `${name.toUpperCase()}_STRING_REQUIRED`
    );
  }

  return value;
}

function hexToBin(hex, name){
  const value =
    requireString(
      hex,
      name
    ).toLowerCase();

  if(
    value.length % 2 !== 0 ||
    !/^[0-9a-f]+$/.test(value)
  ){
    fail(
      `${name.toUpperCase()}_HEX_INVALID`
    );
  }

  return Uint8Array.from(
    Buffer.from(
      value,
      'hex'
    )
  );
}

function binToHex(bytes, name){
  if(!(bytes instanceof Uint8Array)){
    fail(
      `${name.toUpperCase()}_UINT8ARRAY_REQUIRED`
    );
  }

  return Buffer
    .from(bytes)
    .toString('hex');
}

function parseOutpoint(value, name){
  const text =
    requireString(
      value,
      name
    ).toLowerCase();

  const match =
    /^([0-9a-f]{64}):([0-9]+)$/
      .exec(text);

  if(!match){
    fail(
      `${name.toUpperCase()}_INVALID`
    );
  }

  const index =
    Number(match[2]);

  if(
    !Number.isSafeInteger(index) ||
    index < 0 ||
    index > 0xffffffff
  ){
    fail(
      `${name.toUpperCase()}_INDEX_INVALID`
    );
  }

  return {
    txid:
      match[1],

    index
  };
}

function requireSats(value, name){
  const text =
    String(value);

  if(!/^[0-9]+$/.test(text)){
    fail(
      `${name.toUpperCase()}_INVALID`
    );
  }

  return BigInt(text);
}

function tokenFromPlan(token){
  if(token === undefined){
    return undefined;
  }

  requireObject(
    token,
    'token'
  );

  const category =
    hexToBin(
      token.category,
      'token_category'
    );

  if(category.length !== 32){
    fail(
      'TOKEN_CATEGORY_LENGTH_INVALID'
    );
  }

  const amount =
    requireSats(
      token.amount_base,
      'token_amount_base'
    );

  if(amount <= 0n){
    fail(
      'TOKEN_AMOUNT_MUST_BE_POSITIVE'
    );
  }

  return {
    category,
    amount
  };
}

function inputFromPlan(input){
  requireObject(
    input,
    'plan_input'
  );

  const outpoint =
    parseOutpoint(
      input.outpoint,
      'plan_input_outpoint'
    );

  return {
    outpointTransactionHash:
      hexToBin(
        outpoint.txid,
        'plan_input_txid'
      ),

    outpointIndex:
      outpoint.index,

    sequenceNumber:
      0xffffffff,

    unlockingBytecode:
      new Uint8Array()
  };
}

function sourceOutputFromPlan(input){
  const source = {
    lockingBytecode:
      hexToBin(
        input.locking_bytecode,
        'source_output_locking_bytecode'
      ),

    valueSatoshis:
      requireSats(
        input.value_sats,
        'source_output_value_sats'
      )
  };

  const token =
    tokenFromPlan(
      input.token
    );

  if(token !== undefined){
    source.token =
      token;
  }

  return source;
}

function outputFromPlan(output){
  const target = {
    lockingBytecode:
      hexToBin(
        output.locking_bytecode,
        'transaction_output_locking_bytecode'
      ),

    valueSatoshis:
      requireSats(
        output.value_sats,
        'transaction_output_value_sats'
      )
  };

  const token =
    tokenFromPlan(
      output.token
    );

  if(token !== undefined){
    target.token =
      token;
  }

  return target;
}

function compareToken(
  actual,
  planned,
  label
){
  if(planned === undefined){
    if(actual !== undefined){
      fail(
        `${label}_UNEXPECTED_TOKEN`
      );
    }

    return;
  }

  if(actual === undefined){
    fail(
      `${label}_TOKEN_MISSING`
    );
  }

  if(
    binToHex(
      actual.category,
      `${label}_TOKEN_CATEGORY`
    ) !==
    planned.category
  ){
    fail(
      `${label}_TOKEN_CATEGORY_MISMATCH`
    );
  }

  if(
    actual.amount !==
    BigInt(
      planned.amount_base
    )
  ){
    fail(
      `${label}_TOKEN_AMOUNT_MISMATCH`
    );
  }

  if(actual.nft !== undefined){
    fail(
      `${label}_UNEXPECTED_NFT`
    );
  }
}

function assertTransactionMatchesPlan({
  transaction,
  plan
}){
  if(
    transaction.version !== 2 ||
    transaction.locktime !== 0
  ){
    fail(
      'UNSIGNED_TRANSACTION_VERSION_OR_LOCKTIME_INVALID'
    );
  }

  if(
    transaction.inputs.length !==
      plan.inputs.length ||
    transaction.outputs.length !==
      plan.outputs.length
  ){
    fail(
      'UNSIGNED_TRANSACTION_GEOMETRY_MISMATCH'
    );
  }

  for(
    let index = 0;
    index < plan.inputs.length;
    index += 1
  ){
    const actual =
      transaction.inputs[index];

    const planned =
      plan.inputs[index];

    const outpoint =
      parseOutpoint(
        planned.outpoint,
        `plan_input_${index}_outpoint`
      );

    if(
      binToHex(
        actual.outpointTransactionHash,
        `input_${index}_outpoint_hash`
      ) !==
      outpoint.txid
    ){
      fail(
        `INPUT_${index}_TXID_MISMATCH`
      );
    }

    if(
      actual.outpointIndex !==
      outpoint.index
    ){
      fail(
        `INPUT_${index}_VOUT_MISMATCH`
      );
    }

    if(
      actual.sequenceNumber !==
      0xffffffff
    ){
      fail(
        `INPUT_${index}_SEQUENCE_INVALID`
      );
    }

    if(
      !(actual.unlockingBytecode instanceof Uint8Array) ||
      actual.unlockingBytecode.length !== 0
    ){
      fail(
        `INPUT_${index}_MUST_BE_UNSIGNED`
      );
    }
  }

  for(
    let index = 0;
    index < plan.outputs.length;
    index += 1
  ){
    const actual =
      transaction.outputs[index];

    const planned =
      plan.outputs[index];

    if(
      binToHex(
        actual.lockingBytecode,
        `output_${index}_locking_bytecode`
      ) !==
      planned.locking_bytecode
    ){
      fail(
        `OUTPUT_${index}_SCRIPT_MISMATCH`
      );
    }

    if(
      actual.valueSatoshis !==
      BigInt(
        planned.value_sats
      )
    ){
      fail(
        `OUTPUT_${index}_VALUE_MISMATCH`
      );
    }

    compareToken(
      actual.token,
      planned.token,
      `OUTPUT_${index}`
    );
  }

  return true;
}

function assertSourceOutputsMatchPlan({
  sourceOutputs,
  plan
}){
  if(
    sourceOutputs.length !==
    plan.inputs.length
  ){
    fail(
      'SOURCE_OUTPUT_COUNT_MISMATCH'
    );
  }

  for(
    let index = 0;
    index < sourceOutputs.length;
    index += 1
  ){
    const actual =
      sourceOutputs[index];

    const planned =
      plan.inputs[index];

    if(
      binToHex(
        actual.lockingBytecode,
        `source_${index}_locking_bytecode`
      ) !==
      planned.locking_bytecode
    ){
      fail(
        `SOURCE_${index}_SCRIPT_MISMATCH`
      );
    }

    if(
      actual.valueSatoshis !==
      BigInt(
        planned.value_sats
      )
    ){
      fail(
        `SOURCE_${index}_VALUE_MISMATCH`
      );
    }

    compareToken(
      actual.token,
      planned.token,
      `SOURCE_${index}`
    );
  }

  return true;
}

function binsEqual(a, b){
  return (
    a.length === b.length &&
    a.every(
      (value, index) =>
        value === b[index]
    )
  );
}

export async function createUnsignedTransactionFromShadowSettlementPlanV2({
  plan,
  pre_sign_attestation,
  libauth
}){
  await validateShadowSettlementPlanV2(
    plan
  );

  requireObject(
    pre_sign_attestation,
    'pre_sign_attestation'
  );

  if(
    pre_sign_attestation.status !==
      'PRE_SIGN_VALIDATED'
  ){
    fail(
      'UNSIGNED_COMPOSER_PRE_SIGN_STATUS_INVALID'
    );
  }

  if(
    pre_sign_attestation
      .settlement_plan_id !==
      plan.settlement_plan_id
  ){
    fail(
      'UNSIGNED_COMPOSER_PRE_SIGN_PLAN_BINDING_MISMATCH'
    );
  }

  if(
    pre_sign_attestation
      .signing_allowed !==
      false ||
    pre_sign_attestation
      .broadcast_allowed !==
      false
  ){
    fail(
      'UNSIGNED_COMPOSER_PRE_SIGN_AUTHORITY_INVALID'
    );
  }

  requireObject(
    libauth,
    'libauth'
  );

  if(
    typeof libauth.encodeTransaction !==
      'function' ||
    typeof libauth.decodeTransaction !==
      'function'
  ){
    fail(
      'UNSIGNED_COMPOSER_LIBAUTH_ENCODER_DECODER_REQUIRED'
    );
  }

  if(
    plan.inputs.length !== 3 ||
    plan.outputs.length !== 5
  ){
    fail(
      'UNSIGNED_COMPOSER_PLAN_TOPOLOGY_INVALID'
    );
  }

  const transaction = {
    version:
      2,

    inputs:
      plan.inputs.map(
        input =>
          inputFromPlan(
            input
          )
      ),

    outputs:
      plan.outputs.map(
        output =>
          outputFromPlan(
            output
          )
      ),

    locktime:
      0
  };

  const sourceOutputs =
    plan.inputs.map(
      input =>
        sourceOutputFromPlan(
          input
        )
    );

  assertTransactionMatchesPlan({
    transaction,
    plan
  });

  assertSourceOutputsMatchPlan({
    sourceOutputs,
    plan
  });

  const encoded =
    libauth.encodeTransaction(
      transaction
    );

  const decoded =
    libauth.decodeTransaction(
      encoded
    );

  if(typeof decoded === 'string'){
    fail(
      'UNSIGNED_COMPOSER_LIBAUTH_DECODE_FAILED:' +
      decoded
    );
  }

  assertTransactionMatchesPlan({
    transaction:
      decoded,

    plan
  });

  const reencoded =
    libauth.encodeTransaction(
      decoded
    );

  if(
    !binsEqual(
      encoded,
      reencoded
    )
  ){
    fail(
      'UNSIGNED_COMPOSER_DECODE_REENCODE_MISMATCH'
    );
  }

  const w1UnlockingBytesPerInput =
    100;

  const projectedSignedBytes =
    encoded.length +
    (
      plan.inputs.length *
      w1UnlockingBytesPerInput
    );

  const w7MaxSignedBytes =
    Number(
      plan.accounting
        .max_signed_bytes
    );

  if(
    !Number.isSafeInteger(
      w7MaxSignedBytes
    ) ||
    projectedSignedBytes >
      w7MaxSignedBytes
  ){
    fail(
      'UNSIGNED_COMPOSER_W7_ENVELOPE_EXCEEDED'
    );
  }

  const headroom =
    w7MaxSignedBytes -
    projectedSignedBytes;

  return Object.freeze({
    schema:
      ATAN_FEE_V2_UNSIGNED_COMPOSER_SCHEMA,

    version:
      ATAN_FEE_V2_UNSIGNED_COMPOSER_VERSION,

    settlement_plan_id:
      plan.settlement_plan_id,

    request_id:
      plan.bindings
        .request_id,

    quote_id:
      plan.bindings
        .quote_id,

    reservation_id:
      plan.bindings
        .reservation_id,

    durable_reservation_id:
      plan.bindings
        .durable_reservation_id,

    acceptance_id:
      plan.bindings
        .acceptance_id,

    envelope_id:
      plan.bindings
        .envelope_id,

    transaction,

    source_outputs:
      sourceOutputs,

    encoded_transaction:
      encoded,

    unsigned_transaction_bytes:
      encoded.length,

    projected_w1_signed_bytes:
      projectedSignedBytes,

    w7_max_signed_bytes:
      w7MaxSignedBytes,

    w7_size_headroom_bytes:
      headroom,

    committed_network_fee_sats:
      plan.accounting
        .network_fee_sats,

    unsigned_transaction_created:
      true,

    user_signature_present:
      false,

    sponsor_signature_present:
      false,

    transaction_signed:
      false,

    signing_allowed:
      false,

    broadcast_allowed:
      false
  });
}

export async function validateUnsignedCompositionAgainstPlanV2({
  composition,
  plan,
  libauth
}){
  requireObject(
    composition,
    'composition'
  );

  await validateShadowSettlementPlanV2(
    plan
  );

  if(
    composition.schema !==
      ATAN_FEE_V2_UNSIGNED_COMPOSER_SCHEMA ||
    composition.version !==
      ATAN_FEE_V2_UNSIGNED_COMPOSER_VERSION
  ){
    fail(
      'UNSIGNED_COMPOSITION_SCHEMA_OR_VERSION_INVALID'
    );
  }

  if(
    composition
      .settlement_plan_id !==
      plan.settlement_plan_id
  ){
    fail(
      'UNSIGNED_COMPOSITION_PLAN_BINDING_MISMATCH'
    );
  }

  if(
    composition.transaction_signed !==
      false ||
    composition.user_signature_present !==
      false ||
    composition.sponsor_signature_present !==
      false ||
    composition.signing_allowed !==
      false ||
    composition.broadcast_allowed !==
      false
  ){
    fail(
      'UNSIGNED_COMPOSITION_AUTHORITY_INVALID'
    );
  }

  assertTransactionMatchesPlan({
    transaction:
      composition.transaction,

    plan
  });

  assertSourceOutputsMatchPlan({
    sourceOutputs:
      composition.source_outputs,

    plan
  });

  const encoded =
    libauth.encodeTransaction(
      composition.transaction
    );

  if(
    !binsEqual(
      encoded,
      composition
        .encoded_transaction
    )
  ){
    fail(
      'UNSIGNED_COMPOSITION_ENCODED_BYTES_MISMATCH'
    );
  }

  return true;
}

export function describeUnsignedTransactionComposerV2(){
  return Object.freeze({
    version:
      ATAN_FEE_V2_UNSIGNED_COMPOSER_VERSION,

    schema:
      ATAN_FEE_V2_UNSIGNED_COMPOSER_SCHEMA,

    transaction_version:
      2,

    locktime:
      0,

    sequence_number:
      0xffffffff,

    topology:
      '3_INPUTS_5_OUTPUTS',

    input_order:
      'USER_BCH>USER_TOKEN>SPONSOR_BCH',

    output_order:
      'RECIPIENT_BCH>USER_BCH_CHANGE>USER_TOKEN_CHANGE>SPONSOR_TOKEN_RECEIVER>SPONSOR_BCH_CHANGE',

    source_outputs_complete:
      true,

    outpoint_hash_representation:
      'LIBAUTH_UI_BIG_ENDIAN',

    token_category_representation:
      'LIBAUTH_UI_BIG_ENDIAN',

    unsigned_transaction_created:
      true,

    signing_authority:
      'NONE',

    broadcast_authority:
      'NONE'
  });
}
