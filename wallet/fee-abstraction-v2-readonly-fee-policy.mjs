export const ATAN_FEE_V2_READONLY_FEE_POLICY_VERSION =
  '1.0.0';

export const ATAN_FEE_V2_READONLY_FEE_POLICY_SCHEMA =
  'ATAN_FEE_V2_READONLY_FEE_POLICY_SNAPSHOT';

export const ATAN_FEE_V2_READONLY_FEE_SOURCE_CLASS =
  'LOCAL_RELAY_POLICY_FLOOR';

function fail(code){
  throw new Error(code);
}

function requireObject(value, field){
  if(
    !value ||
    typeof value !== 'object' ||
    Array.isArray(value)
  ){
    fail(`FEE_POLICY_OBJECT_REQUIRED:${field}`);
  }
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
    fail(`FEE_POLICY_SAFE_INTEGER_INVALID:${field}`);
  }
}

function requirePositiveUintString(
  value,
  field
){
  if(
    typeof value !== 'string' ||
    !/^[0-9]+$/.test(value)
  ){
    fail(`FEE_POLICY_UINT_STRING_INVALID:${field}`);
  }

  const parsed = BigInt(value);

  if(parsed <= 0n){
    fail(`FEE_POLICY_UINT_NOT_POSITIVE:${field}`);
  }

  return parsed;
}

export function validateReadOnlyFeePolicySnapshotV2(
  snapshot,
  {
    nowUnixMs = Date.now(),
    maxAgeMs = 300000
  } = {}
){
  requireObject(snapshot, 'snapshot');

  if(
    snapshot.schema !==
    ATAN_FEE_V2_READONLY_FEE_POLICY_SCHEMA
  ){
    fail('FEE_POLICY_SCHEMA_INVALID');
  }

  if(
    snapshot.version !==
    ATAN_FEE_V2_READONLY_FEE_POLICY_VERSION
  ){
    fail('FEE_POLICY_VERSION_INVALID');
  }

  if(
    snapshot.source !==
    'BCHN_MAINNET_READONLY_OBSERVER'
  ){
    fail('FEE_POLICY_SOURCE_INVALID');
  }

  if(
    snapshot.source_class !==
    ATAN_FEE_V2_READONLY_FEE_SOURCE_CLASS
  ){
    fail('FEE_POLICY_SOURCE_CLASS_INVALID');
  }

  if(
    snapshot.fee_estimator !== false ||
    snapshot.congestion_signal !== false
  ){
    fail('FEE_POLICY_SOURCE_SEMANTICS_INVALID');
  }

  if(snapshot.chain !== 'main'){
    fail('FEE_POLICY_CHAIN_NOT_MAINNET');
  }

  if(snapshot.initial_block_download !== false){
    fail('FEE_POLICY_IBD_FORBIDDEN');
  }

  requireSafeInteger(
    snapshot.blocks,
    'blocks',
    1
  );

  requireSafeInteger(
    snapshot.headers,
    'headers',
    1
  );

  if(snapshot.blocks !== snapshot.headers){
    fail('FEE_POLICY_NODE_NOT_CAUGHT_UP');
  }

  if(
    typeof snapshot.observed_at_utc !== 'string' ||
    snapshot.observed_at_utc.length === 0
  ){
    fail('FEE_POLICY_OBSERVED_AT_REQUIRED');
  }

  requireSafeInteger(
    nowUnixMs,
    'nowUnixMs',
    0
  );

  requireSafeInteger(
    maxAgeMs,
    'maxAgeMs',
    1
  );

  const observedMs =
    Date.parse(
      snapshot.observed_at_utc
    );

  if(!Number.isSafeInteger(observedMs)){
    fail('FEE_POLICY_OBSERVED_AT_INVALID');
  }

  const ageMs =
    nowUnixMs -
    observedMs;

  if(ageMs < -30000){
    fail('FEE_POLICY_SNAPSHOT_FROM_FUTURE');
  }

  if(ageMs > maxAgeMs){
    fail('FEE_POLICY_SNAPSHOT_STALE');
  }

  requireObject(
    snapshot.rates_sats_per_kb,
    'rates_sats_per_kb'
  );

  const relay =
    requirePositiveUintString(
      snapshot.rates_sats_per_kb.relayfee,
      'relayfee'
    );

  const mempoolMin =
    requirePositiveUintString(
      snapshot.rates_sats_per_kb.mempoolminfee,
      'mempoolminfee'
    );

  const minRelay =
    requirePositiveUintString(
      snapshot.rates_sats_per_kb.minrelaytxfee,
      'minrelaytxfee'
    );

  const selected =
    requirePositiveUintString(
      snapshot.selected_fee_rate_sats_per_kb,
      'selected_fee_rate_sats_per_kb'
    );

  const expected =
    [relay, mempoolMin, minRelay]
      .reduce(
        (a,b) => a > b ? a : b
      );

  if(selected !== expected){
    fail('FEE_POLICY_SELECTED_RATE_NOT_MAX_FLOOR');
  }

  if(
    snapshot.selection_policy !==
    'MAX_LOCAL_RELAY_POLICY_FLOOR'
  ){
    fail('FEE_POLICY_SELECTION_POLICY_INVALID');
  }

  return Object.freeze({
    valid:
      true,

    source:
      snapshot.source,

    sourceClass:
      snapshot.source_class,

    feeEstimator:
      false,

    congestionSignal:
      false,

    observedAtUtc:
      snapshot.observed_at_utc,

    observedHeight:
      snapshot.blocks,

    ageMs,

    selectedFeeRateSatsPerKb:
      selected.toString(),

    relayfeeSatsPerKb:
      relay.toString(),

    mempoolminfeeSatsPerKb:
      mempoolMin.toString(),

    minrelaytxfeeSatsPerKb:
      minRelay.toString(),

    selectionPolicy:
      snapshot.selection_policy
  });
}
