import {
  canonicalizeV2,
  sha256HexV2
} from './fee-abstraction-v2-sponsor-protocol.mjs';

export const ATAN_FEE_V2_OWNER_AUTH_PREFLIGHT_VERSION =
  '1.0.0';

export const ATAN_FEE_V2_OWNER_AUTHORIZATION_SCHEMA =
  'ATAN_FEE_ABSTRACTION_V2_OWNER_PREFLIGHT_AUTHORIZATION';

export const ATAN_FEE_V2_OWNER_AUTH_MESSAGE_PREFIX =
  'ATAN_FEE_ABSTRACTION_V2_OWNER_PREFLIGHT_AUTH:';

export const ATAN_FEE_V2_LIVE_PREFLIGHT_CONTRACT_SCHEMA =
  'ATAN_FEE_ABSTRACTION_V2_LIVE_BROADCAST_PREFLIGHT_CONTRACT';

export const ATAN_FEE_V2_PREFLIGHT_RECEIPT_SCHEMA =
  'ATAN_FEE_ABSTRACTION_V2_PREFLIGHT_RECEIPT_SHADOW';

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

function requireHash(value, name){
  const text =
    requireString(
      value,
      name
    ).toLowerCase();

  if(!/^[0-9a-f]{64}$/.test(text)){
    fail(
      `${name.toUpperCase()}_HASH_INVALID`
    );
  }

  return text;
}

function requireGuardAndHandoff({
  guard,
  handoff
}){
  requireObject(
    guard,
    'pre_broadcast_guard'
  );

  requireObject(
    handoff,
    'broadcast_handoff'
  );

  if(
    guard.status !==
      'PRE_BROADCAST_VALIDATED' ||
    guard.broadcast_allowed !==
      false ||
    guard.explicit_real_broadcast_authorization_required !==
      true
  ){
    fail(
      'OWNER_AUTH_GUARD_NOT_READY'
    );
  }

  if(
    handoff.status !==
      'DISCONNECTED_SHADOW' ||
    handoff.broadcast_allowed !==
      false ||
    handoff.broadcast_attempted !==
      false ||
    handoff.broadcast_authority !==
      'NONE'
  ){
    fail(
      'OWNER_AUTH_HANDOFF_NOT_SHADOW_LOCKED'
    );
  }

  const guardId =
    requireHash(
      guard.guard_id,
      'guard_id'
    );

  const txHash =
    requireHash(
      guard.signed_transaction_sha256,
      'signed_transaction_sha256'
    );

  if(
    handoff.guard_id !==
      guardId ||
    handoff.signed_transaction_sha256 !==
      txHash ||
    handoff.economic_core_commitment !==
      guard.economic_core_commitment ||
    handoff.signed_transaction_bytes !==
      guard.signed_transaction_bytes ||
    handoff.network_fee_sats !==
      guard.network_fee_sats
  ){
    fail(
      'OWNER_AUTH_GUARD_HANDOFF_BINDING_MISMATCH'
    );
  }
}

function authorizationPayload(
  authorization
){
  return {
    schema:
      authorization.schema,

    version:
      authorization.version,

    scope:
      authorization.scope,

    network:
      authorization.network,

    guard_id:
      authorization.guard_id,

    settlement_plan_id:
      authorization.settlement_plan_id,

    durable_reservation_id:
      authorization.durable_reservation_id,

    signed_transaction_sha256:
      authorization.signed_transaction_sha256,

    economic_core_commitment:
      authorization.economic_core_commitment,

    signed_transaction_bytes:
      authorization.signed_transaction_bytes,

    network_fee_sats:
      authorization.network_fee_sats,

    owner_signer_address:
      authorization.owner_signer_address,

    created_height:
      authorization.created_height,

    valid_until_height:
      authorization.valid_until_height,

    authorization_nonce:
      authorization.authorization_nonce
  };
}

export function ownerAuthorizationMessageV2(
  authorizationId
){
  return (
    ATAN_FEE_V2_OWNER_AUTH_MESSAGE_PREFIX +
    requireHash(
      authorizationId,
      'authorization_id'
    )
  );
}

export async function createOwnerPreflightAuthorizationV2({
  guard,
  handoff,
  network,
  owner_signer_address,
  created_height,
  valid_until_height,
  authorization_nonce,
  signature_base64
}){
  requireGuardAndHandoff({
    guard,
    handoff
  });

  const createdHeight =
    requireHeight(
      created_height,
      'created_height'
    );

  const validUntilHeight =
    requireHeight(
      valid_until_height,
      'valid_until_height'
    );

  if(validUntilHeight <= createdHeight){
    fail(
      'OWNER_AUTH_EXPIRY_MUST_BE_AFTER_CREATION'
    );
  }

  const authorization = {
    schema:
      ATAN_FEE_V2_OWNER_AUTHORIZATION_SCHEMA,

    version:
      ATAN_FEE_V2_OWNER_AUTH_PREFLIGHT_VERSION,

    scope:
      'LIVE_BROADCAST_PREFLIGHT_ONLY',

    network:
      requireString(
        network,
        'network'
      ),

    guard_id:
      requireHash(
        guard.guard_id,
        'guard_id'
      ),

    settlement_plan_id:
      requireHash(
        guard.settlement_plan_id,
        'settlement_plan_id'
      ),

    durable_reservation_id:
      requireHash(
        guard.durable_reservation_id,
        'durable_reservation_id'
      ),

    signed_transaction_sha256:
      requireHash(
        guard.signed_transaction_sha256,
        'signed_transaction_sha256'
      ),

    economic_core_commitment:
      requireHash(
        guard.economic_core_commitment,
        'economic_core_commitment'
      ),

    signed_transaction_bytes:
      Number(
        guard.signed_transaction_bytes
      ),

    network_fee_sats:
      String(
        guard.network_fee_sats
      ),

    owner_signer_address:
      requireString(
        owner_signer_address,
        'owner_signer_address'
      ),

    created_height:
      createdHeight,

    valid_until_height:
      validUntilHeight,

    authorization_nonce:
      requireString(
        authorization_nonce,
        'authorization_nonce'
      )
  };

  authorization.authorization_id =
    await sha256HexV2(
      canonicalizeV2(
        authorizationPayload(
          authorization
        )
      )
    );

  authorization.authentication = {
    scheme:
      'BCH_SIGNMESSAGE_P2PKH_V1',

    signer_address:
      authorization.owner_signer_address,

    signature_base64:
      requireString(
        signature_base64,
        'signature_base64'
      )
  };

  authorization.broadcast_allowed =
    false;

  authorization.broadcast_authority =
    'NONE';

  return Object.freeze(
    structuredClone(
      authorization
    )
  );
}

export async function verifyOwnerPreflightAuthorizationV2({
  authorization,
  guard,
  handoff,
  mainnet,
  current_height
}){
  requireObject(
    authorization,
    'authorization'
  );

  requireGuardAndHandoff({
    guard,
    handoff
  });

  requireObject(
    mainnet,
    'mainnet'
  );

  if(
    authorization.schema !==
      ATAN_FEE_V2_OWNER_AUTHORIZATION_SCHEMA ||
    authorization.version !==
      ATAN_FEE_V2_OWNER_AUTH_PREFLIGHT_VERSION ||
    authorization.scope !==
      'LIVE_BROADCAST_PREFLIGHT_ONLY' ||
    authorization.broadcast_allowed !==
      false ||
    authorization.broadcast_authority !==
      'NONE'
  ){
    fail(
      'OWNER_AUTH_HEADER_INVALID'
    );
  }

  const currentHeight =
    requireHeight(
      current_height,
      'current_height'
    );

  if(
    currentHeight <
      authorization.created_height ||
    currentHeight >
      authorization.valid_until_height
  ){
    fail(
      'OWNER_AUTH_EXPIRED_OR_NOT_YET_VALID'
    );
  }

  const expectedBindings = [
    [
      authorization.guard_id,
      guard.guard_id
    ],
    [
      authorization.settlement_plan_id,
      guard.settlement_plan_id
    ],
    [
      authorization.durable_reservation_id,
      guard.durable_reservation_id
    ],
    [
      authorization.signed_transaction_sha256,
      guard.signed_transaction_sha256
    ],
    [
      authorization.economic_core_commitment,
      guard.economic_core_commitment
    ],
    [
      authorization.signed_transaction_bytes,
      guard.signed_transaction_bytes
    ],
    [
      authorization.network_fee_sats,
      guard.network_fee_sats
    ]
  ];

  if(
    expectedBindings.some(
      ([a,b]) => a !== b
    )
  ){
    fail(
      'OWNER_AUTH_GUARD_BINDING_MISMATCH'
    );
  }

  const expectedId =
    await sha256HexV2(
      canonicalizeV2(
        authorizationPayload(
          authorization
        )
      )
    );

  if(
    authorization.authorization_id !==
      expectedId
  ){
    fail(
      'OWNER_AUTH_ID_MISMATCH'
    );
  }

  requireObject(
    authorization.authentication,
    'authentication'
  );

  if(
    authorization.authentication.scheme !==
      'BCH_SIGNMESSAGE_P2PKH_V1' ||
    authorization.authentication.signer_address !==
      authorization.owner_signer_address
  ){
    fail(
      'OWNER_AUTH_AUTHENTICATION_HEADER_INVALID'
    );
  }

  if(
    !mainnet.SignedMessage ||
    typeof mainnet.SignedMessage.verify !==
      'function'
  ){
    fail(
      'OWNER_AUTH_SIGNEDMESSAGE_VERIFY_REQUIRED'
    );
  }

  const result =
    mainnet.SignedMessage.verify(
      ownerAuthorizationMessageV2(
        authorization.authorization_id
      ),
      authorization.authentication.signature_base64,
      authorization.owner_signer_address
    );

  if(
    !result ||
    result.valid !==
      true
  ){
    fail(
      'OWNER_AUTH_SIGNATURE_INVALID'
    );
  }

  return true;
}

export function createInjectedLiveBroadcastPreflightContractV2({
  check_preflight
}){
  if(typeof check_preflight !== 'function'){
    fail(
      'LIVE_PREFLIGHT_CHECK_FUNCTION_REQUIRED'
    );
  }

  return Object.freeze({
    schema:
      ATAN_FEE_V2_LIVE_PREFLIGHT_CONTRACT_SCHEMA,

    version:
      ATAN_FEE_V2_OWNER_AUTH_PREFLIGHT_VERSION,

    mode:
      'INJECTED_PREFLIGHT_CONTRACT_SHADOW',

    live:
      false,

    connected:
      false,

    transport_agnostic:
      true,

    preflight_implementation_injected:
      true,

    network_implementation_embedded:
      false,

    rpc_implementation_embedded:
      false,

    broadcast_implementation_embedded:
      false,

    broadcast_authority:
      'NONE',

    async preflight(context){
      return check_preflight(
        context
      );
    }
  });
}

export async function executeOwnerAuthorizedPreflightV2({
  authorization,
  guard,
  handoff,
  mainnet,
  current_height,
  preflight_contract
}){
  await verifyOwnerPreflightAuthorizationV2({
    authorization,
    guard,
    handoff,
    mainnet,
    current_height
  });

  requireObject(
    preflight_contract,
    'preflight_contract'
  );

  if(
    preflight_contract.schema !==
      ATAN_FEE_V2_LIVE_PREFLIGHT_CONTRACT_SCHEMA ||
    preflight_contract.mode !==
      'INJECTED_PREFLIGHT_CONTRACT_SHADOW' ||
    preflight_contract.live !==
      false ||
    preflight_contract.connected !==
      false ||
    preflight_contract.network_implementation_embedded !==
      false ||
    preflight_contract.rpc_implementation_embedded !==
      false ||
    preflight_contract.broadcast_implementation_embedded !==
      false ||
    preflight_contract.broadcast_authority !==
      'NONE'
  ){
    fail(
      'LIVE_PREFLIGHT_CONTRACT_NOT_SHADOW_ISOLATED'
    );
  }

  if(typeof preflight_contract.preflight !== 'function'){
    fail(
      'LIVE_PREFLIGHT_METHOD_REQUIRED'
    );
  }

  const result =
    await preflight_contract.preflight({
      authorization_id:
        authorization.authorization_id,

      guard_id:
        guard.guard_id,

      signed_transaction_sha256:
        handoff.signed_transaction_sha256,

      signed_transaction_bytes:
        handoff.signed_transaction_bytes,

      network_fee_sats:
        handoff.network_fee_sats,

      encoded_transaction:
        Uint8Array.from(
          handoff.encoded_transaction
        )
    });

  requireObject(
    result,
    'preflight_result'
  );

  if(
    result.status !==
      'ACCEPTED' ||
    result.guard_id !==
      guard.guard_id ||
    result.signed_transaction_sha256 !==
      handoff.signed_transaction_sha256
  ){
    fail(
      'LIVE_PREFLIGHT_RESULT_REJECTED_OR_MISMATCHED'
    );
  }

  return Object.freeze({
    schema:
      ATAN_FEE_V2_PREFLIGHT_RECEIPT_SCHEMA,

    version:
      ATAN_FEE_V2_OWNER_AUTH_PREFLIGHT_VERSION,

    status:
      'PREFLIGHT_ACCEPTED_SHADOW',

    authorization_id:
      authorization.authorization_id,

    guard_id:
      guard.guard_id,

    signed_transaction_sha256:
      handoff.signed_transaction_sha256,

    signed_transaction_bytes:
      handoff.signed_transaction_bytes,

    network_fee_sats:
      handoff.network_fee_sats,

    preflight_contract_mode:
      preflight_contract.mode,

    preflight_result_status:
      result.status,

    owner_authorization_verified:
      true,

    owner_authorization_scope:
      authorization.scope,

    live_transport_connected:
      false,

    network_request_performed:
      false,

    broadcast_attempted:
      false,

    broadcast_allowed:
      false,

    broadcast_authority:
      'NONE'
  });
}

export function describeOwnerAuthorizationPreflightContractV2(){
  return Object.freeze({
    version:
      ATAN_FEE_V2_OWNER_AUTH_PREFLIGHT_VERSION,

    authorization_scope:
      'LIVE_BROADCAST_PREFLIGHT_ONLY',

    authorization_scheme:
      'BCH_SIGNMESSAGE_P2PKH_V1',

    binds_guard_id:
      true,

    binds_settlement_plan_id:
      true,

    binds_durable_reservation_id:
      true,

    binds_signed_transaction_sha256:
      true,

    binds_economic_core_commitment:
      true,

    binds_signed_transaction_bytes:
      true,

    binds_network_fee_sats:
      true,

    height_expiry_required:
      true,

    preflight_contract_transport_agnostic:
      true,

    live_transport_connected_in_w20:
      false,

    network_implementation_embedded:
      false,

    rpc_implementation_embedded:
      false,

    broadcast_implementation_embedded:
      false,

    preflight_authorization_is_broadcast_authorization:
      false,

    real_transaction_signing_authority:
      'NONE',

    broadcast_authority:
      'NONE'
  });
}
