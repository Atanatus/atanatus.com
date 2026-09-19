import {
  validateShadowSettlementPlanV2,
  preSignRevalidateShadowSettlementPlanV2
} from './fee-abstraction-v2-shadow-settlement-plan-r1.mjs';

import {
  validateUnsignedCompositionAgainstPlanV2
} from './fee-abstraction-v2-shadow-unsigned-transaction-composer.mjs';

import {
  assertFinalSponsoredTransactionFitsEnvelopeV2
} from './fee-abstraction-v2-exact-fee-planner.mjs';

import {
  sha256HexV2
} from './fee-abstraction-v2-sponsor-protocol.mjs';

import {
  computeTwoPartySigningCommitmentV2
} from './fee-abstraction-v2-synthetic-two-party-signing-shadow.mjs';

export const ATAN_FEE_V2_PRE_BROADCAST_GUARD_VERSION =
  '1.0.0';

export const ATAN_FEE_V2_PRE_BROADCAST_GUARD_SCHEMA =
  'ATAN_FEE_ABSTRACTION_V2_PRE_BROADCAST_SHADOW_GUARD';

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

function requireHeight(value, name){
  if(
    !Number.isSafeInteger(value) ||
    value < 0
  ){
    fail(
      `${name.toUpperCase()}_HEIGHT_INVALID`
    );
  }

  return value;
}

function requireBin(value, name){
  if(!(value instanceof Uint8Array)){
    fail(
      `${name.toUpperCase()}_UINT8ARRAY_REQUIRED`
    );
  }

  return value;
}

function binToHex(value){
  return Buffer
    .from(
      requireBin(
        value,
        'binary_value'
      )
    )
    .toString('hex');
}

function equalBins(a, b){
  return (
    a.length === b.length &&
    a.every(
      (value, index) =>
        value === b[index]
    )
  );
}

function classifyW1Unlocking(unlocking){
  requireBin(
    unlocking,
    'unlocking_bytecode'
  );

  if(unlocking.length !== 100){
    fail(
      'PRE_BROADCAST_UNLOCKING_BYTES_NOT_100'
    );
  }

  const signaturePushBytes =
    unlocking[0];

  if(signaturePushBytes !== 65){
    fail(
      'PRE_BROADCAST_SIGNATURE_PUSH_NOT_65'
    );
  }

  const signaturePayload =
    unlocking.slice(
      1,
      1 + signaturePushBytes
    );

  const cryptoSignatureBytes =
    signaturePayload.length - 1;

  const sighashByte =
    signaturePayload[
      signaturePayload.length - 1
    ];

  const publicKeyPushIndex =
    1 +
    signaturePushBytes;

  const publicKeyPushBytes =
    unlocking[
      publicKeyPushIndex
    ];

  const publicKeyBytes =
    unlocking.length -
    publicKeyPushIndex -
    1;

  if(
    cryptoSignatureBytes !== 64 ||
    sighashByte !== 0x61 ||
    publicKeyPushBytes !== 33 ||
    publicKeyBytes !== 33
  ){
    fail(
      'PRE_BROADCAST_W1_SIGNATURE_GEOMETRY_INVALID'
    );
  }

  return Object.freeze({
    unlocking_bytes:
      unlocking.length,

    schnorr_signature_bytes:
      cryptoSignatureBytes,

    sighash_byte:
      sighashByte,

    public_key_bytes:
      publicKeyBytes
  });
}

function sumSats(outputs){
  if(!Array.isArray(outputs)){
    fail(
      'PRE_BROADCAST_OUTPUT_ARRAY_REQUIRED'
    );
  }

  return outputs.reduce(
    (sum, output) =>
      sum +
      BigInt(
        output.valueSatoshis
      ),
    0n
  );
}

function guardCommitmentPayload({
  settlement_plan_id,
  durable_reservation_id,
  signed_transaction_sha256,
  economic_core_commitment,
  signed_transaction_bytes,
  network_fee_sats,
  current_height
}){
  return {
    settlement_plan_id,
    durable_reservation_id,
    signed_transaction_sha256,
    economic_core_commitment,
    signed_transaction_bytes,
    network_fee_sats,
    current_height
  };
}

async function inspectFinalSignedPackage({
  plan,
  orchestration,
  unsigned_composition,
  fully_signed_package,
  mainnet
}){
  requireObject(
    unsigned_composition,
    'unsigned_composition'
  );

  requireObject(
    fully_signed_package,
    'fully_signed_package'
  );

  requireObject(
    mainnet,
    'mainnet'
  );

  if(
    !mainnet.libauth ||
    typeof mainnet.libauth.encodeTransaction !==
      'function' ||
    typeof mainnet.libauth.decodeTransaction !==
      'function'
  ){
    fail(
      'PRE_BROADCAST_LIBAUTH_REQUIRED'
    );
  }

  if(
    fully_signed_package
      .stage !==
      'FULLY_SIGNED_SYNTHETIC' ||
    fully_signed_package
      .synthetic_only !==
      true ||
    fully_signed_package
      .transaction_fully_signed !==
      true ||
    fully_signed_package
      .real_transaction_signed !==
      false ||
    fully_signed_package
      .broadcast_allowed !==
      false
  ){
    fail(
      'PRE_BROADCAST_SIGNED_PACKAGE_AUTHORITY_INVALID'
    );
  }

  await validateUnsignedCompositionAgainstPlanV2({
    composition:
      unsigned_composition,

    plan,

    libauth:
      mainnet.libauth
  });

  if(
    !Array.isArray(
      fully_signed_package
        .transaction
        .inputs
    ) ||
    fully_signed_package
      .transaction
      .inputs
      .length !== 3 ||
    !Array.isArray(
      fully_signed_package
        .transaction
        .outputs
    ) ||
    fully_signed_package
      .transaction
      .outputs
      .length !== 5 ||
    !Array.isArray(
      fully_signed_package
        .source_outputs
    ) ||
    fully_signed_package
      .source_outputs
      .length !== 3
  ){
    fail(
      'PRE_BROADCAST_FINAL_GEOMETRY_INVALID'
    );
  }

  const signatureFacts =
    fully_signed_package
      .transaction
      .inputs
      .map(
        input =>
          classifyW1Unlocking(
            input.unlockingBytecode
          )
      );

  const referenceEconomicCommitment =
    await computeTwoPartySigningCommitmentV2({
      transaction:
        unsigned_composition
          .transaction,

      source_outputs:
        unsigned_composition
          .source_outputs
    });

  const finalEconomicCommitment =
    await computeTwoPartySigningCommitmentV2({
      transaction:
        fully_signed_package
          .transaction,

      source_outputs:
        fully_signed_package
          .source_outputs
    });

  if(
    finalEconomicCommitment !==
      referenceEconomicCommitment ||
    fully_signed_package
      .economic_core_commitment !==
      referenceEconomicCommitment
  ){
    fail(
      'PRE_BROADCAST_ECONOMIC_CORE_MISMATCH'
    );
  }

  const encoded =
    mainnet.libauth
      .encodeTransaction(
        fully_signed_package
          .transaction
      );

  if(
    !(
      fully_signed_package
        .encoded_transaction
        instanceof Uint8Array
    ) ||
    !equalBins(
      encoded,
      fully_signed_package
        .encoded_transaction
    )
  ){
    fail(
      'PRE_BROADCAST_ENCODED_TRANSACTION_MISMATCH'
    );
  }

  if(
    encoded.length !==
      fully_signed_package
        .encoded_transaction_bytes
  ){
    fail(
      'PRE_BROADCAST_SIGNED_BYTE_COUNT_MISMATCH'
    );
  }

  const decoded =
    mainnet.libauth
      .decodeTransaction(
        encoded
      );

  if(typeof decoded === 'string'){
    fail(
      'PRE_BROADCAST_SIGNED_DECODE_FAILED:' +
      decoded
    );
  }

  const reencoded =
    mainnet.libauth
      .encodeTransaction(
        decoded
      );

  if(
    !equalBins(
      encoded,
      reencoded
    )
  ){
    fail(
      'PRE_BROADCAST_SIGNED_DECODE_REENCODE_MISMATCH'
    );
  }

  const inputSats =
    sumSats(
      fully_signed_package
        .source_outputs
    );

  const outputSats =
    sumSats(
      fully_signed_package
        .transaction
        .outputs
    );

  const actualNetworkFee =
    inputSats -
    outputSats;

  if(actualNetworkFee <= 0n){
    fail(
      'PRE_BROADCAST_NETWORK_FEE_INVALID'
    );
  }

  if(
    actualNetworkFee.toString() !==
      plan.accounting
        .network_fee_sats
  ){
    fail(
      'PRE_BROADCAST_NETWORK_FEE_PLAN_MISMATCH'
    );
  }

  await assertFinalSponsoredTransactionFitsEnvelopeV2({
    envelope:
      orchestration
        .exact_fee_envelope,

    signed_transaction_bytes:
      encoded.length,

    actual_network_fee_sats:
      actualNetworkFee.toString()
  });

  if(
    encoded.length >
      Number(
        plan.accounting
          .max_signed_bytes
      )
  ){
    fail(
      'PRE_BROADCAST_SIGNED_SIZE_EXCEEDS_PLAN'
    );
  }

  const signedTransactionSha256 =
    await sha256HexV2(
      binToHex(
        encoded
      )
    );

  return Object.freeze({
    signature_facts:
      signatureFacts,

    economic_core_commitment:
      referenceEconomicCommitment,

    encoded_transaction:
      encoded,

    signed_transaction_bytes:
      encoded.length,

    signed_transaction_sha256:
      signedTransactionSha256,

    network_fee_sats:
      actualNetworkFee.toString(),

    decode_reencode_exact:
      true,

    w7_envelope_valid:
      true
  });
}

export async function createPreBroadcastShadowGuardV2({
  plan,
  orchestration,
  durableTransportBridge,
  mainnet,
  fresh_sponsor_observation,
  fresh_user_inputs,
  current_height,
  unsigned_composition,
  fully_signed_package
}){
  requireHeight(
    current_height,
    'current_height'
  );

  await validateShadowSettlementPlanV2(
    plan
  );

  const freshRevalidation =
    await preSignRevalidateShadowSettlementPlanV2({
      plan,
      orchestration,
      durableTransportBridge,
      mainnet,
      fresh_sponsor_observation,
      fresh_user_inputs,
      current_height
    });

  if(
    freshRevalidation.status !==
      'PRE_SIGN_VALIDATED' ||
    freshRevalidation
      .durable_reservation_revalidated !==
      true ||
    freshRevalidation
      .user_bch_input_revalidated !==
      true ||
    freshRevalidation
      .user_token_input_revalidated !==
      true
  ){
    fail(
      'PRE_BROADCAST_FRESH_REVALIDATION_FAILED'
    );
  }

  const finalInspection =
    await inspectFinalSignedPackage({
      plan,
      orchestration,
      unsigned_composition,
      fully_signed_package,
      mainnet
    });

  const guardPayload =
    guardCommitmentPayload({
      settlement_plan_id:
        plan.settlement_plan_id,

      durable_reservation_id:
        orchestration
          .durable_reservation
          .durable_reservation_id,

      signed_transaction_sha256:
        finalInspection
          .signed_transaction_sha256,

      economic_core_commitment:
        finalInspection
          .economic_core_commitment,

      signed_transaction_bytes:
        finalInspection
          .signed_transaction_bytes,

      network_fee_sats:
        finalInspection
          .network_fee_sats,

      current_height
    });

  const guardId =
    await sha256HexV2(
      JSON.stringify(
        guardPayload
      )
    );

  return Object.freeze({
    schema:
      ATAN_FEE_V2_PRE_BROADCAST_GUARD_SCHEMA,

    version:
      ATAN_FEE_V2_PRE_BROADCAST_GUARD_VERSION,

    status:
      'PRE_BROADCAST_VALIDATED',

    guard_id:
      guardId,

    settlement_plan_id:
      plan.settlement_plan_id,

    durable_reservation_id:
      orchestration
        .durable_reservation
        .durable_reservation_id,

    current_height,

    signed_transaction_sha256:
      finalInspection
        .signed_transaction_sha256,

    economic_core_commitment:
      finalInspection
        .economic_core_commitment,

    signed_transaction_bytes:
      finalInspection
        .signed_transaction_bytes,

    network_fee_sats:
      finalInspection
        .network_fee_sats,

    signature_count:
      finalInspection
        .signature_facts
        .length,

    all_signatures_schnorr_64:
      finalInspection
        .signature_facts
        .every(
          facts =>
            facts.schnorr_signature_bytes ===
              64
        ),

    all_sighash_0x61:
      finalInspection
        .signature_facts
        .every(
          facts =>
            facts.sighash_byte ===
              0x61
        ),

    durable_reservation_revalidated:
      true,

    sponsor_facts_revalidated:
      true,

    user_inputs_revalidated:
      true,

    final_envelope_revalidated:
      true,

    decode_reencode_exact:
      true,

    transaction_signed:
      true,

    real_transaction_signed:
      false,

    broadcast_allowed:
      false,

    explicit_real_broadcast_authorization_required:
      true
  });
}

export async function validatePreBroadcastShadowGuardV2({
  guard,
  plan,
  orchestration,
  durableTransportBridge,
  mainnet,
  fresh_sponsor_observation,
  fresh_user_inputs,
  current_height,
  unsigned_composition,
  fully_signed_package
}){
  requireObject(
    guard,
    'pre_broadcast_guard'
  );

  if(
    guard.schema !==
      ATAN_FEE_V2_PRE_BROADCAST_GUARD_SCHEMA ||
    guard.version !==
      ATAN_FEE_V2_PRE_BROADCAST_GUARD_VERSION ||
    guard.status !==
      'PRE_BROADCAST_VALIDATED' ||
    guard.broadcast_allowed !==
      false ||
    guard.explicit_real_broadcast_authorization_required !==
      true
  ){
    fail(
      'PRE_BROADCAST_GUARD_HEADER_INVALID'
    );
  }

  const rebuilt =
    await createPreBroadcastShadowGuardV2({
      plan,
      orchestration,
      durableTransportBridge,
      mainnet,
      fresh_sponsor_observation,
      fresh_user_inputs,
      current_height,
      unsigned_composition,
      fully_signed_package
    });

  if(
    guard.guard_id !==
      rebuilt.guard_id
  ){
    fail(
      'PRE_BROADCAST_GUARD_ID_MISMATCH'
    );
  }

  if(
    guard.signed_transaction_sha256 !==
      rebuilt
        .signed_transaction_sha256
  ){
    fail(
      'PRE_BROADCAST_SIGNED_TRANSACTION_HASH_CHANGED'
    );
  }

  if(
    guard.economic_core_commitment !==
      rebuilt
        .economic_core_commitment
  ){
    fail(
      'PRE_BROADCAST_ECONOMIC_COMMITMENT_CHANGED'
    );
  }

  if(
    guard.signed_transaction_bytes !==
      rebuilt
        .signed_transaction_bytes ||
    guard.network_fee_sats !==
      rebuilt
        .network_fee_sats
  ){
    fail(
      'PRE_BROADCAST_FINAL_ACCOUNTING_CHANGED'
    );
  }

  return true;
}

export function describePreBroadcastShadowGuardV2(){
  return Object.freeze({
    version:
      ATAN_FEE_V2_PRE_BROADCAST_GUARD_VERSION,

    schema:
      ATAN_FEE_V2_PRE_BROADCAST_GUARD_SCHEMA,

    fresh_sponsor_authentication_required:
      true,

    fresh_sponsor_chain_facts_required:
      true,

    fresh_user_input_truth_required:
      true,

    durable_reservation_health_required:
      true,

    final_signed_transaction_hash_required:
      true,

    economic_core_and_source_outputs_required:
      true,

    all_signatures_schnorr_64_required:
      true,

    sighash_0x61_required:
      true,

    exact_fee_required:
      true,

    w7_envelope_required:
      true,

    broadcast_implementation:
      false,

    real_signing_authority:
      'NONE',

    broadcast_authority:
      'NONE'
  });
}
