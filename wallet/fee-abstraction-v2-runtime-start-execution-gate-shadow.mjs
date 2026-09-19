import crypto from 'node:crypto';

export const ATAN_FEE_V2_W37_VERSION =
  '1.0.0';

export const ATAN_FEE_V2_W37_GATE_SCHEMA =
  'ATAN_FEE_ABSTRACTION_V2_RUNTIME_START_EXECUTION_GATE_SHADOW';

export const ATAN_FEE_V2_W37_AUTH_SCOPE =
  'START_LIVE_BROADCAST_RUNTIME_ONLY';

export const ATAN_FEE_V2_W37_SIGNATURE_SCHEME =
  'BCH_SIGNMESSAGE_P2PKH_V1';

function fail(code){
  throw new Error(code);
}

function requireObject(value, name){
  if(!value || typeof value !== 'object' || Array.isArray(value)){
    fail(`${name.toUpperCase()}_OBJECT_REQUIRED`);
  }
}

function requireString(value, name){
  if(typeof value !== 'string' || value.length === 0){
    fail(`${name.toUpperCase()}_STRING_REQUIRED`);
  }

  return value;
}

function requireHash(value, name){
  const text =
    requireString(value, name).toLowerCase();

  if(!/^[0-9a-f]{64}$/.test(text)){
    fail(`${name.toUpperCase()}_HASH_INVALID`);
  }

  return text;
}

function requireHeight(value, name){
  const n = Number(value);

  if(!Number.isSafeInteger(n) || n < 0){
    fail(`${name.toUpperCase()}_HEIGHT_INVALID`);
  }

  return n;
}

function canonicalValue(value){
  if(value === null){
    return null;
  }

  if(typeof value === 'string' || typeof value === 'boolean'){
    return value;
  }

  if(typeof value === 'number'){
    if(!Number.isFinite(value)){
      fail('W37_NONFINITE_NUMBER_FORBIDDEN');
    }
    return value;
  }

  if(Array.isArray(value)){
    return value.map(canonicalValue);
  }

  if(value && typeof value === 'object'){
    const result = {};

    for(const key of Object.keys(value).sort()){
      if(value[key] === undefined){
        fail('W37_UNDEFINED_FORBIDDEN');
      }
      result[key] = canonicalValue(value[key]);
    }

    return result;
  }

  fail('W37_CANONICAL_TYPE_FORBIDDEN');
}

function canonicalize(value){
  return JSON.stringify(canonicalValue(value));
}

function sha256Hex(value){
  return crypto
    .createHash('sha256')
    .update(Buffer.from(String(value), 'utf8'))
    .digest('hex');
}

function authorizationPayload(auth){
  return {
    schema:
      'ATAN_FEE_ABSTRACTION_V2_LIVE_TRANSPORT_START_AUTHORIZATION',

    version:
      '1.0.0',

    scope:
      ATAN_FEE_V2_W37_AUTH_SCOPE,

    signature_scheme:
      ATAN_FEE_V2_W37_SIGNATURE_SCHEME,

    runtime_root:
      auth.runtime_root,

    runtime_config_sha256:
      auth.runtime_config_sha256,

    runtime_identity_sha256:
      auth.runtime_identity_sha256,

    w35_wrapper_sha256:
      auth.w35_wrapper_sha256,

    owner_signer_address:
      auth.owner_signer_address,

    created_height:
      auth.created_height,

    valid_until_height:
      auth.valid_until_height,

    authorization_nonce:
      auth.authorization_nonce
  };
}

export async function createRuntimeStartExecutionGateShadowV2({
  authorization,
  expected,
  current_height,
  runtime_process_count,
  rpc_port_open,
  verify_owner_signature
}){
  requireObject(authorization, 'authorization');
  requireObject(expected, 'expected');

  if(typeof verify_owner_signature !== 'function'){
    fail('W37_OWNER_SIGNATURE_VERIFIER_REQUIRED');
  }

  if(
    authorization.schema !==
      'ATAN_FEE_ABSTRACTION_V2_LIVE_TRANSPORT_START_AUTHORIZATION' ||
    authorization.version !==
      '1.0.0' ||
    authorization.scope !==
      ATAN_FEE_V2_W37_AUTH_SCOPE ||
    authorization.signature_scheme !==
      ATAN_FEE_V2_W37_SIGNATURE_SCHEME
  ){
    fail('W37_START_AUTHORIZATION_SHAPE_INVALID');
  }

  const runtimeRoot =
    requireString(
      authorization.runtime_root,
      'runtime_root'
    );

  const runtimeConfigHash =
    requireHash(
      authorization.runtime_config_sha256,
      'runtime_config_sha256'
    );

  const runtimeIdentityHash =
    requireHash(
      authorization.runtime_identity_sha256,
      'runtime_identity_sha256'
    );

  const w35WrapperHash =
    requireHash(
      authorization.w35_wrapper_sha256,
      'w35_wrapper_sha256'
    );

  if(
    runtimeRoot !== expected.runtime_root ||
    runtimeConfigHash !==
      requireHash(
        expected.runtime_config_sha256,
        'expected_runtime_config_sha256'
      ) ||
    runtimeIdentityHash !==
      requireHash(
        expected.runtime_identity_sha256,
        'expected_runtime_identity_sha256'
      ) ||
    w35WrapperHash !==
      requireHash(
        expected.w35_wrapper_sha256,
        'expected_w35_wrapper_sha256'
      )
  ){
    fail('W37_RUNTIME_BINDING_MISMATCH');
  }

  const createdHeight =
    requireHeight(
      authorization.created_height,
      'created_height'
    );

  const validUntilHeight =
    requireHeight(
      authorization.valid_until_height,
      'valid_until_height'
    );

  const currentHeight =
    requireHeight(
      current_height,
      'current_height'
    );

  if(
    currentHeight < createdHeight ||
    currentHeight > validUntilHeight
  ){
    fail('W37_START_AUTHORIZATION_EXPIRED_OR_NOT_YET_VALID');
  }

  const processCount =
    Number(runtime_process_count);

  if(
    !Number.isSafeInteger(processCount) ||
    processCount !== 0
  ){
    fail('W37_RUNTIME_PROCESS_COUNT_MUST_BE_ZERO');
  }

  if(rpc_port_open !== false){
    fail('W37_RPC_PORT_MUST_BE_CLOSED');
  }

  requireString(
    authorization.owner_signer_address,
    'owner_signer_address'
  );

  requireString(
    authorization.authorization_nonce,
    'authorization_nonce'
  );

  const payload =
    authorizationPayload({
      ...authorization,
      runtime_config_sha256:
        runtimeConfigHash,
      runtime_identity_sha256:
        runtimeIdentityHash,
      w35_wrapper_sha256:
        w35WrapperHash,
      created_height:
        createdHeight,
      valid_until_height:
        validUntilHeight
    });

  const message =
    canonicalize(payload);

  const authorizationId =
    sha256Hex(message);

  if(
    authorization.authorization_id !==
      authorizationId
  ){
    fail('W37_START_AUTHORIZATION_ID_MISMATCH');
  }

  const signature =
    requireString(
      authorization.owner_signature,
      'owner_signature'
    );

  const signatureOk =
    await verify_owner_signature({
      scheme:
        ATAN_FEE_V2_W37_SIGNATURE_SCHEME,

      owner_signer_address:
        authorization.owner_signer_address,

      message,

      signature
    });

  if(signatureOk !== true){
    fail('W37_OWNER_START_AUTH_SIGNATURE_INVALID');
  }

  const gateCore = {
    schema:
      ATAN_FEE_V2_W37_GATE_SCHEMA,

    version:
      ATAN_FEE_V2_W37_VERSION,

    authorization_id:
      authorizationId,

    runtime_root:
      runtimeRoot,

    runtime_config_sha256:
      runtimeConfigHash,

    runtime_identity_sha256:
      runtimeIdentityHash,

    w35_wrapper_sha256:
      w35WrapperHash,

    current_height:
      currentHeight,

    status:
      'READY_FOR_EXPLICIT_RUNTIME_START_EXECUTION_SHADOW'
  };

  const gateId =
    sha256Hex(
      canonicalize(gateCore)
    );

  return Object.freeze({
    ...gateCore,

    gate_id:
      gateId,

    owner_signature_verified:
      true,

    runtime_process_count:
      0,

    rpc_port_open:
      false,

    runtime_started:
      false,

    network_implementation:
      false,

    real_mainnet_rpc_requests:
      0,

    sendrawtransaction_implementation:
      false,

    transaction_broadcast:
      false,

    broadcast_allowed:
      false,

    broadcast_authority:
      'NONE',

    execution_gate_grants_broadcast_authority:
      false,

    next_boundary:
      'REAL_RUNTIME_START_REQUIRES_NEW_EXPLICIT_OWNER_AUTHORIZATION'
  });
}

export function verifyRuntimeStartExecutionGateShadowV2(gate){
  requireObject(gate, 'gate');

  if(
    gate.schema !==
      ATAN_FEE_V2_W37_GATE_SCHEMA ||
    gate.version !==
      ATAN_FEE_V2_W37_VERSION ||
    gate.status !==
      'READY_FOR_EXPLICIT_RUNTIME_START_EXECUTION_SHADOW' ||
    gate.owner_signature_verified !== true ||
    gate.runtime_process_count !== 0 ||
    gate.rpc_port_open !== false ||
    gate.runtime_started !== false ||
    gate.network_implementation !== false ||
    gate.real_mainnet_rpc_requests !== 0 ||
    gate.sendrawtransaction_implementation !== false ||
    gate.transaction_broadcast !== false ||
    gate.broadcast_allowed !== false ||
    gate.broadcast_authority !== 'NONE' ||
    gate.execution_gate_grants_broadcast_authority !== false ||
    gate.next_boundary !==
      'REAL_RUNTIME_START_REQUIRES_NEW_EXPLICIT_OWNER_AUTHORIZATION'
  ){
    fail('W37_GATE_STATE_INVALID');
  }

  requireHash(gate.gate_id, 'gate_id');
  requireHash(gate.authorization_id, 'authorization_id');
  requireHash(gate.runtime_config_sha256, 'runtime_config_sha256');
  requireHash(gate.runtime_identity_sha256, 'runtime_identity_sha256');
  requireHash(gate.w35_wrapper_sha256, 'w35_wrapper_sha256');

  return true;
}

export async function startRuntimeFromGateV2(gate){
  verifyRuntimeStartExecutionGateShadowV2(gate);
  fail('W37_RUNTIME_START_NOT_IMPLEMENTED');
}
