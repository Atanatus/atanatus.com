import {
  canonicalizeV2,
  sha256HexV2
} from './fee-abstraction-v2-sponsor-protocol.mjs';

import {
  deriveAuthenticatedSponsorQuoteFactsV2
} from './fee-abstraction-v2-sponsor-auth-facts-bridge.mjs';

export const ATAN_FEE_V2_SHADOW_SETTLEMENT_PLAN_VERSION =
  '1.0.0';

export const ATAN_FEE_V2_SHADOW_SETTLEMENT_PLAN_SCHEMA =
  'ATAN_FEE_ABSTRACTION_V2_SHADOW_SETTLEMENT_PLAN';

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

function normalizeHex(value, name){
  const text =
    requireString(
      value,
      name
    ).toLowerCase();

  if(
    text.length % 2 !== 0 ||
    !/^[0-9a-f]+$/.test(text)
  ){
    fail(
      `${name.toUpperCase()}_HEX_INVALID`
    );
  }

  return text;
}

function canonicalOutpoint(value, name){
  const text =
    requireString(
      value,
      name
    ).toLowerCase();

  const match =
    /^([0-9a-f]{64}):([0-9]+)$/
      .exec(
        text
      );

  if(!match){
    fail(
      `${name.toUpperCase()}_OUTPOINT_INVALID`
    );
  }

  const vout =
    Number(
      match[2]
    );

  if(
    !Number.isSafeInteger(vout) ||
    vout < 0 ||
    vout > 0xffffffff
  ){
    fail(
      `${name.toUpperCase()}_VOUT_INVALID`
    );
  }

  return (
    match[1] +
    ':' +
    String(vout)
  );
}

function requirePositiveIntegerString(
  value,
  name,
  {
    allowZero = false
  } = {}
){
  const text =
    String(
      value
    );

  if(!/^[0-9]+$/.test(text)){
    fail(
      `${name.toUpperCase()}_INTEGER_STRING_INVALID`
    );
  }

  const amount =
    BigInt(
      text
    );

  if(
    allowZero
      ? amount < 0n
      : amount <= 0n
  ){
    fail(
      `${name.toUpperCase()}_AMOUNT_INVALID`
    );
  }

  return text;
}

function binToHex(bytes){
  if(!(bytes instanceof Uint8Array)){
    fail(
      'P2PKH_PUBLIC_KEY_HASH_NOT_UINT8ARRAY'
    );
  }

  return Array
    .from(
      bytes,
      byte =>
        byte
          .toString(16)
          .padStart(2, '0')
    )
    .join('');
}

function p2pkhScriptForAddress(
  mainnet,
  address,
  name
){
  requireObject(
    mainnet,
    'mainnet'
  );

  if(
    typeof mainnet
      .derivePublicKeyHash !==
    'function'
  ){
    fail(
      'MAINNET_DERIVE_PUBLIC_KEY_HASH_REQUIRED'
    );
  }

  const normalizedAddress =
    requireString(
      address,
      name
    ).toLowerCase();

  const pkh =
    mainnet
      .derivePublicKeyHash(
        normalizedAddress
      );

  if(
    !(pkh instanceof Uint8Array) ||
    pkh.length !== 20
  ){
    fail(
      `${name.toUpperCase()}_NOT_P2PKH`
    );
  }

  return (
    '76a914' +
    binToHex(pkh) +
    '88ac'
  );
}

function requireOrchestration(
  orchestration
){
  requireObject(
    orchestration,
    'orchestration'
  );

  if(
    orchestration.shadow !==
      true ||
    orchestration
      .ready_for_shadow_settlement_planning !==
      true
  ){
    fail(
      'SETTLEMENT_PLAN_ORCHESTRATION_NOT_READY'
    );
  }

  if(
    orchestration.signing_allowed !==
      false ||
    orchestration.broadcast_allowed !==
      false ||
    orchestration
      .live_sponsor_transport_connected !==
      false
  ){
    fail(
      'SETTLEMENT_PLAN_ORCHESTRATION_AUTHORITY_INVALID'
    );
  }

  for(const field of [
    'exact_fee_envelope',
    'request',
    'selected_quote',
    'selected_facts',
    'selected_observation',
    'reservation',
    'durable_reservation',
    'acceptance',
    'acknowledgement'
  ]){
    requireObject(
      orchestration[field],
      `orchestration_${field}`
    );
  }

  if(
    orchestration
      .durable_reservation
      .status !==
      'ACTIVE'
  ){
    fail(
      'SETTLEMENT_PLAN_DURABLE_RESERVATION_NOT_ACTIVE'
    );
  }

  if(
    orchestration
      .acknowledgement
      .status !==
      'ACKNOWLEDGED'
  ){
    fail(
      'SETTLEMENT_PLAN_ACCEPTANCE_NOT_ACKNOWLEDGED'
    );
  }
}

function requireUserBchInput(
  input
){
  requireObject(
    input,
    'user_bch_input'
  );

  return {
    role:
      'USER_BCH',

    outpoint:
      canonicalOutpoint(
        input.outpoint,
        'user_bch_input'
      ),

    value_sats:
      requirePositiveIntegerString(
        input.value_sats,
        'user_bch_input_value_sats'
      ),

    locking_bytecode:
      normalizeHex(
        input.locking_bytecode,
        'user_bch_input_locking_bytecode'
      ),

  };
}

function requireUserTokenInput(
  input,
  tokenCategory
){
  requireObject(
    input,
    'user_token_input'
  );

  const category =
    normalizeHex(
      input.token_category,
      'user_token_input_category'
    );

  if(
    category.length !== 64 ||
    category !==
      tokenCategory
  ){
    fail(
      'USER_TOKEN_INPUT_CATEGORY_MISMATCH'
    );
  }

  return {
    role:
      'USER_TOKEN',

    outpoint:
      canonicalOutpoint(
        input.outpoint,
        'user_token_input'
      ),

    value_sats:
      requirePositiveIntegerString(
        input.value_sats,
        'user_token_input_value_sats'
      ),

    locking_bytecode:
      normalizeHex(
        input.locking_bytecode,
        'user_token_input_locking_bytecode'
      ),

    token: {
      category,

      amount_base:
        requirePositiveIntegerString(
          input.token_amount_base,
          'user_token_input_amount_base'
        )
    }
  };
}

function planPayload(plan){
  return {
    schema:
      plan.schema,

    version:
      plan.version,

    network:
      plan.network,

    bindings:
      plan.bindings,

    input_order:
      plan.input_order,

    output_order:
      plan.output_order,

    inputs:
      plan.inputs,

    outputs:
      plan.outputs,

    accounting:
      plan.accounting
  };
}

async function computePlanId(
  plan
){
  return sha256HexV2(
    canonicalizeV2(
      planPayload(
        plan
      )
    )
  );
}

function assertUnique(
  values,
  code
){
  if(
    new Set(
      values
    ).size !==
    values.length
  ){
    fail(code);
  }
}

function requireProtocolFactsHealthy(
  facts
){
  requireObject(
    facts,
    'protocol_facts'
  );

  if(
    facts.authentication_valid !==
      true
  ){
    fail(
      'PRE_SIGN_AUTHENTICATION_INVALID'
    );
  }

  if(
    facts.funding_outpoint_unspent !==
      true
  ){
    fail(
      'PRE_SIGN_SPONSOR_FUNDING_SPENT'
    );
  }

  if(
    facts
      .signer_controls_funding_outpoint !==
      true
  ){
    fail(
      'PRE_SIGN_SPONSOR_SIGNER_CONTROL_INVALID'
    );
  }

  if(
    facts
      .token_receive_address_token_aware !==
      true
  ){
    fail(
      'PRE_SIGN_SPONSOR_TOKEN_ADDRESS_NOT_TOKEN_AWARE'
    );
  }
}

function compareFreshUserInput({
  planned,
  fresh,
  token
}){
  requireObject(
    fresh,
    token
      ? 'fresh_user_token_input'
      : 'fresh_user_bch_input'
  );

  if(fresh.unspent !== true){
    fail(
      token
        ? 'PRE_SIGN_USER_TOKEN_INPUT_SPENT'
        : 'PRE_SIGN_USER_BCH_INPUT_SPENT'
    );
  }

  if(
    canonicalOutpoint(
      fresh.outpoint,
      token
        ? 'fresh_user_token_input'
        : 'fresh_user_bch_input'
    ) !==
    planned.outpoint
  ){
    fail(
      token
        ? 'PRE_SIGN_USER_TOKEN_OUTPOINT_CHANGED'
        : 'PRE_SIGN_USER_BCH_OUTPOINT_CHANGED'
    );
  }

  if(
    requirePositiveIntegerString(
      fresh.value_sats,
      token
        ? 'fresh_user_token_value_sats'
        : 'fresh_user_bch_value_sats'
    ) !==
    planned.value_sats
  ){
    fail(
      token
        ? 'PRE_SIGN_USER_TOKEN_VALUE_CHANGED'
        : 'PRE_SIGN_USER_BCH_VALUE_CHANGED'
    );
  }

  if(
    normalizeHex(
      fresh.locking_bytecode,
      token
        ? 'fresh_user_token_locking_bytecode'
        : 'fresh_user_bch_locking_bytecode'
    ) !==
    planned.locking_bytecode
  ){
    fail(
      token
        ? 'PRE_SIGN_USER_TOKEN_SCRIPT_CHANGED'
        : 'PRE_SIGN_USER_BCH_SCRIPT_CHANGED'
    );
  }

  if(token){
    if(
      normalizeHex(
        fresh.token_category,
        'fresh_user_token_category'
      ) !==
      planned.token.category
    ){
      fail(
        'PRE_SIGN_USER_TOKEN_CATEGORY_CHANGED'
      );
    }

    if(
      requirePositiveIntegerString(
        fresh.token_amount_base,
        'fresh_user_token_amount_base'
      ) !==
      planned.token.amount_base
    ){
      fail(
        'PRE_SIGN_USER_TOKEN_AMOUNT_CHANGED'
      );
    }
  }
}

export async function validateShadowSettlementPlanV2(
  plan
){
  requireObject(
    plan,
    'settlement_plan'
  );

  if(
    plan.schema !==
    ATAN_FEE_V2_SHADOW_SETTLEMENT_PLAN_SCHEMA
  ){
    fail(
      'SETTLEMENT_PLAN_SCHEMA_INVALID'
    );
  }

  if(
    plan.version !==
    ATAN_FEE_V2_SHADOW_SETTLEMENT_PLAN_VERSION
  ){
    fail(
      'SETTLEMENT_PLAN_VERSION_INVALID'
    );
  }

  requireString(
    plan.settlement_plan_id,
    'settlement_plan_id'
  );

  if(
    plan.signing_allowed !==
      false ||
    plan.broadcast_allowed !==
      false
  ){
    fail(
      'SETTLEMENT_PLAN_AUTHORITY_INVALID'
    );
  }

  const expected =
    await computePlanId(
      plan
    );

  if(
    expected !==
    plan.settlement_plan_id
  ){
    fail(
      'SETTLEMENT_PLAN_ID_MISMATCH'
    );
  }

  return true;
}

export async function createShadowSettlementPlanV2({
  orchestration,
  mainnet,
  user_bch_input,
  user_token_input,
  user_bch_change_address,
  user_token_change_address,
  user_token_change_output_sats,
  sponsor_token_output_sats
}){
  requireOrchestration(
    orchestration
  );

  requireObject(
    mainnet,
    'mainnet'
  );

  const {
    request,
    selected_quote:
      quote,
    selected_observation:
      observation,
    reservation,
    durable_reservation:
      durable,
    acceptance,
    acknowledgement,
    exact_fee_envelope:
      envelope
  } =
    orchestration;

  const tokenCategory =
    normalizeHex(
      request.token_category,
      'request_token_category'
    );

  if(tokenCategory.length !== 64){
    fail(
      'REQUEST_TOKEN_CATEGORY_LENGTH_INVALID'
    );
  }

  if(
    envelope.shape
      .input_count !==
      3 ||
    envelope.shape
      .output_count !==
      5
  ){
    fail(
      'SETTLEMENT_PLAN_TOPOLOGY_NOT_3X5'
    );
  }

  if(
    envelope.network_fee_sats !==
      request
        .fee_policy
        .network_fee_sats ||
    envelope.network_fee_sats !==
      quote.network_fee_sats
  ){
    fail(
      'SETTLEMENT_PLAN_NETWORK_FEE_BINDING_MISMATCH'
    );
  }

  if(
    quote.quote_id !==
      reservation.quote_id ||
    request.request_id !==
      reservation.request_id ||
    reservation.reservation_id !==
      acceptance.reservation_id ||
    acceptance.acceptance_id !==
      acknowledgement.acceptance_id
  ){
    fail(
      'SETTLEMENT_PLAN_PROTOCOL_BINDING_MISMATCH'
    );
  }

  if(
    durable
      .protocol_reservation_id !==
      reservation.reservation_id ||
    acknowledgement
      .durable_reservation_id !==
      durable.durable_reservation_id
  ){
    fail(
      'SETTLEMENT_PLAN_DURABLE_BINDING_MISMATCH'
    );
  }

  const userBch =
    requireUserBchInput(
      user_bch_input
    );

  const userToken =
    requireUserTokenInput(
      user_token_input,
      tokenCategory
    );

  const sponsorOutpoint =
    canonicalOutpoint(
      quote.sponsor_funding_outpoint,
      'sponsor_funding_outpoint'
    );

  if(
    sponsorOutpoint !==
      canonicalOutpoint(
        observation.funding_outpoint,
        'observed_sponsor_funding_outpoint'
      )
  ){
    fail(
      'SETTLEMENT_PLAN_SPONSOR_OUTPOINT_OBSERVATION_MISMATCH'
    );
  }

  assertUnique(
    [
      userBch.outpoint,
      userToken.outpoint,
      sponsorOutpoint
    ],
    'SETTLEMENT_PLAN_INPUT_OUTPOINT_COLLISION'
  );

  const sponsorValue =
    requirePositiveIntegerString(
      observation.funding_value_sats,
      'sponsor_funding_value_sats'
    );

  const sponsorSignerScript =
    p2pkhScriptForAddress(
      mainnet,
      quote.sponsor_signer_address,
      'sponsor_signer_address'
    );

  const sponsorTokenScript =
    p2pkhScriptForAddress(
      mainnet,
      quote.sponsor_token_address,
      'sponsor_token_address'
    );

  const sponsorChangeScript =
    p2pkhScriptForAddress(
      mainnet,
      quote.sponsor_bch_change_address,
      'sponsor_bch_change_address'
    );

  const recipientScript =
    p2pkhScriptForAddress(
      mainnet,
      request.recipient,
      'recipient'
    );

  const userBchChangeScript =
    p2pkhScriptForAddress(
      mainnet,
      user_bch_change_address,
      'user_bch_change_address'
    );

  if(
    typeof mainnet.isTokenaddr !==
      'function' ||
    mainnet.isTokenaddr(
      user_token_change_address
    ) !== true
  ){
    fail(
      'USER_TOKEN_CHANGE_ADDRESS_NOT_TOKEN_AWARE'
    );
  }

  const userTokenChangeScript =
    p2pkhScriptForAddress(
      mainnet,
      user_token_change_address,
      'user_token_change_address'
    );

  if(
    normalizeHex(
      observation
        .signer_validation
        .scriptPubKey,
      'observation_signer_script'
    ) !==
      sponsorSignerScript ||
    normalizeHex(
      observation
        .token_receive_validation
        .scriptPubKey,
      'observation_token_script'
    ) !==
      sponsorTokenScript ||
    normalizeHex(
      observation
        .bch_change_validation
        .scriptPubKey,
      'observation_change_script'
    ) !==
      sponsorChangeScript ||
    normalizeHex(
      observation
        .funding_utxo
        .scriptPubKey
        .hex,
      'observation_funding_script'
    ) !==
      sponsorSignerScript
  ){
    fail(
      'SETTLEMENT_PLAN_SPONSOR_SCRIPT_BINDING_MISMATCH'
    );
  }

  if(
    observation
      .token_receive_validation
      .istokenaware !==
      true
  ){
    fail(
      'SETTLEMENT_PLAN_SPONSOR_TOKEN_ADDRESS_NOT_TOKEN_AWARE'
    );
  }

  if(
    observation
      .funding_utxo
      .tokenData !==
      undefined &&
    observation
      .funding_utxo
      .tokenData !==
      null
  ){
    fail(
      'SETTLEMENT_PLAN_SPONSOR_FUNDING_MUST_BE_BCH_ONLY'
    );
  }

  assertUnique(
    [
      recipientScript,
      userBchChangeScript,
      userTokenChangeScript,
      sponsorTokenScript,
      sponsorChangeScript
    ],
    'SETTLEMENT_PLAN_OUTPUT_SCRIPT_COLLISION'
  );

  const payment =
    BigInt(
      requirePositiveIntegerString(
        request.payment_sats,
        'payment_sats'
      )
    );

  const fee =
    BigInt(
      requirePositiveIntegerString(
        envelope.network_fee_sats,
        'network_fee_sats'
      )
    );

  const tokenCost =
    BigInt(
      requirePositiveIntegerString(
        quote.token_cost_base,
        'token_cost_base'
      )
    );

  const userTokenAmount =
    BigInt(
      userToken.token
        .amount_base
    );

  if(userTokenAmount <= tokenCost){
    fail(
      'SETTLEMENT_PLAN_USER_TOKEN_CHANGE_MUST_BE_POSITIVE'
    );
  }

  const tokenChange =
    userTokenAmount -
    tokenCost;

  const userTokenChangeSats =
    BigInt(
      requirePositiveIntegerString(
        user_token_change_output_sats,
        'user_token_change_output_sats'
      )
    );

  const sponsorTokenSats =
    BigInt(
      requirePositiveIntegerString(
        sponsor_token_output_sats,
        'sponsor_token_output_sats'
      )
    );

  const userBchValue =
    BigInt(
      userBch.value_sats
    );

  const userTokenValue =
    BigInt(
      userToken.value_sats
    );

  const sponsorFunding =
    BigInt(
      sponsorValue
    );

  const totalUserInputs =
    userBchValue +
    userTokenValue;

  if(
    totalUserInputs <=
    payment +
    userTokenChangeSats
  ){
    fail(
      'SETTLEMENT_PLAN_USER_BCH_CHANGE_NON_POSITIVE'
    );
  }

  const userBchChange =
    totalUserInputs -
    payment -
    userTokenChangeSats;

  if(
    sponsorFunding <=
    fee +
    sponsorTokenSats
  ){
    fail(
      'SETTLEMENT_PLAN_SPONSOR_CHANGE_NON_POSITIVE'
    );
  }

  const sponsorBchChange =
    sponsorFunding -
    fee -
    sponsorTokenSats;

  const totalInputs =
    totalUserInputs +
    sponsorFunding;

  const totalOutputs =
    payment +
    userBchChange +
    userTokenChangeSats +
    sponsorTokenSats +
    sponsorBchChange;

  const actualFee =
    totalInputs -
    totalOutputs;

  const userExtraBchCost =
    totalUserInputs -
    payment -
    userBchChange -
    userTokenChangeSats;

  const sponsorNetBchCost =
    sponsorFunding -
    sponsorBchChange -
    sponsorTokenSats;

  const tokenOutputTotal =
    tokenChange +
    tokenCost;

  if(actualFee !== fee){
    fail(
      'SETTLEMENT_PLAN_GLOBAL_FEE_ACCOUNTING_MISMATCH'
    );
  }

  if(userExtraBchCost !== 0n){
    fail(
      'SETTLEMENT_PLAN_USER_EXTRA_BCH_COST_NOT_ZERO'
    );
  }

  if(sponsorNetBchCost !== fee){
    fail(
      'SETTLEMENT_PLAN_SPONSOR_DOES_NOT_FUND_EXACT_FEE'
    );
  }

  if(tokenOutputTotal !== userTokenAmount){
    fail(
      'SETTLEMENT_PLAN_TOKEN_CONSERVATION_FAILED'
    );
  }

  const plan = {
    schema:
      ATAN_FEE_V2_SHADOW_SETTLEMENT_PLAN_SCHEMA,

    version:
      ATAN_FEE_V2_SHADOW_SETTLEMENT_PLAN_VERSION,

    network:
      request.network,

    bindings: {
      request_id:
        request.request_id,

      quote_id:
        quote.quote_id,

      reservation_id:
        reservation.reservation_id,

      durable_reservation_id:
        durable.durable_reservation_id,

      acceptance_id:
        acceptance.acceptance_id,

      envelope_id:
        envelope.envelope_id,

      wallet_id:
        durable.wallet_id
    },

    input_order: [
      'USER_BCH',
      'USER_TOKEN',
      'SPONSOR_BCH'
    ],

    output_order: [
      'RECIPIENT_BCH',
      'USER_BCH_CHANGE',
      'USER_TOKEN_CHANGE',
      'SPONSOR_TOKEN_RECEIVER',
      'SPONSOR_BCH_CHANGE'
    ],

    inputs: [
      userBch,

      userToken,

      {
        role:
          'SPONSOR_BCH',

        outpoint:
          sponsorOutpoint,

        value_sats:
          sponsorValue,

        locking_bytecode:
          sponsorSignerScript,

      }
    ],

    outputs: [
      {
        role:
          'RECIPIENT_BCH',

        address:
          request.recipient,

        value_sats:
          payment.toString(),

        locking_bytecode:
          recipientScript,

      },

      {
        role:
          'USER_BCH_CHANGE',

        address:
          user_bch_change_address,

        value_sats:
          userBchChange.toString(),

        locking_bytecode:
          userBchChangeScript,

      },

      {
        role:
          'USER_TOKEN_CHANGE',

        address:
          user_token_change_address,

        value_sats:
          userTokenChangeSats.toString(),

        locking_bytecode:
          userTokenChangeScript,

        token: {
          category:
            tokenCategory,

          amount_base:
            tokenChange.toString()
        }
      },

      {
        role:
          'SPONSOR_TOKEN_RECEIVER',

        address:
          quote.sponsor_token_address,

        value_sats:
          sponsorTokenSats.toString(),

        locking_bytecode:
          sponsorTokenScript,

        token: {
          category:
            tokenCategory,

          amount_base:
            tokenCost.toString()
        }
      },

      {
        role:
          'SPONSOR_BCH_CHANGE',

        address:
          quote.sponsor_bch_change_address,

        value_sats:
          sponsorBchChange.toString(),

        locking_bytecode:
          sponsorChangeScript,

      }
    ],

    accounting: {
      input_count:
        3,

      output_count:
        5,

      max_signed_bytes:
        envelope.shape
          .max_signed_bytes,

      network_fee_sats:
        fee.toString(),

      user_payment_sats:
        payment.toString(),

      user_extra_bch_cost_sats:
        userExtraBchCost.toString(),

      sponsor_net_bch_cost_sats:
        sponsorNetBchCost.toString(),

      token_input_base:
        userTokenAmount.toString(),

      sponsor_token_cost_base:
        tokenCost.toString(),

      user_token_change_base:
        tokenChange.toString(),

      token_output_total_base:
        tokenOutputTotal.toString(),

      total_input_sats:
        totalInputs.toString(),

      total_output_sats:
        totalOutputs.toString()
    }
  };

  plan.settlement_plan_id =
    await computePlanId(
      plan
    );

  plan.signing_allowed =
    false;

  plan.broadcast_allowed =
    false;

  plan.unsigned_transaction_created =
    false;

  await validateShadowSettlementPlanV2(
    plan
  );

  return Object.freeze(
    structuredClone(
      plan
    )
  );
}

export async function preSignRevalidateShadowSettlementPlanV2({
  plan,
  orchestration,
  durableTransportBridge,
  mainnet,
  fresh_sponsor_observation,
  fresh_user_inputs,
  current_height
}){
  await validateShadowSettlementPlanV2(
    plan
  );

  requireOrchestration(
    orchestration
  );

  requireObject(
    durableTransportBridge,
    'durable_transport_bridge'
  );

  requireObject(
    durableTransportBridge.transport,
    'durable_transport'
  );

  if(
    durableTransportBridge.live !==
      false ||
    durableTransportBridge
      .transport
      .live !==
      false
  ){
    fail(
      'PRE_SIGN_LIVE_TRANSPORT_FORBIDDEN'
    );
  }

  requireHeight(
    current_height,
    'current_height'
  );

  const {
    request,
    selected_quote:
      quote,
    reservation,
    acceptance,
    durable_reservation:
      durable
  } =
    orchestration;

  if(
    current_height >
      request.valid_until_height ||
    current_height >
      quote.valid_until_height ||
    current_height >
      reservation.valid_until_height
  ){
    fail(
      'PRE_SIGN_PROTOCOL_OBJECT_EXPIRED'
    );
  }

  const bindingChecks = [
    [
      plan.bindings.request_id,
      request.request_id
    ],
    [
      plan.bindings.quote_id,
      quote.quote_id
    ],
    [
      plan.bindings.reservation_id,
      reservation.reservation_id
    ],
    [
      plan.bindings.durable_reservation_id,
      durable.durable_reservation_id
    ],
    [
      plan.bindings.acceptance_id,
      acceptance.acceptance_id
    ],
    [
      plan.bindings.envelope_id,
      orchestration
        .exact_fee_envelope
        .envelope_id
    ],
    [
      plan.bindings.wallet_id,
      durable.wallet_id
    ]
  ];

  if(
    bindingChecks.some(
      ([a,b]) => a !== b
    )
  ){
    fail(
      'PRE_SIGN_SETTLEMENT_BINDING_MISMATCH'
    );
  }

  const freshSponsorFacts =
    deriveAuthenticatedSponsorQuoteFactsV2({
      quote,
      observation:
        fresh_sponsor_observation,
      mainnet
    });

  requireProtocolFactsHealthy(
    freshSponsorFacts
  );

  const sponsorPlanned =
    plan.inputs.find(
      input =>
        input.role ===
        'SPONSOR_BCH'
    );

  if(!sponsorPlanned){
    fail(
      'PRE_SIGN_SPONSOR_INPUT_MISSING'
    );
  }

  if(
    canonicalOutpoint(
      fresh_sponsor_observation
        .funding_outpoint,
      'fresh_sponsor_funding_outpoint'
    ) !==
    sponsorPlanned.outpoint
  ){
    fail(
      'PRE_SIGN_SPONSOR_OUTPOINT_CHANGED'
    );
  }

  if(
    requirePositiveIntegerString(
      fresh_sponsor_observation
        .funding_value_sats,
      'fresh_sponsor_funding_value_sats'
    ) !==
    sponsorPlanned.value_sats
  ){
    fail(
      'PRE_SIGN_SPONSOR_VALUE_CHANGED'
    );
  }

  requireObject(
    fresh_user_inputs,
    'fresh_user_inputs'
  );

  const userBchPlanned =
    plan.inputs.find(
      input =>
        input.role ===
        'USER_BCH'
    );

  const userTokenPlanned =
    plan.inputs.find(
      input =>
        input.role ===
        'USER_TOKEN'
    );

  if(
    !userBchPlanned ||
    !userTokenPlanned
  ){
    fail(
      'PRE_SIGN_USER_INPUTS_MISSING'
    );
  }

  compareFreshUserInput({
    planned:
      userBchPlanned,

    fresh:
      fresh_user_inputs.user_bch,

    token:
      false
  });

  compareFreshUserInput({
    planned:
      userTokenPlanned,

    fresh:
      fresh_user_inputs.user_token,

    token:
      true
  });

  if(
    typeof durableTransportBridge
      .transport
      .acknowledgeAcceptance !==
    'function'
  ){
    fail(
      'PRE_SIGN_DURABLE_HEALTH_GATE_MISSING'
    );
  }

  const acknowledgement =
    await durableTransportBridge
      .transport
      .acknowledgeAcceptance({
        request,
        quote,
        reservation,
        acceptance,
        wallet_id:
          durable.wallet_id
      });

  if(
    acknowledgement.status !==
      'ACKNOWLEDGED' ||
    acknowledgement
      .durable_reservation_id !==
      durable.durable_reservation_id
  ){
    fail(
      'PRE_SIGN_DURABLE_RESERVATION_NOT_HEALTHY'
    );
  }

  return Object.freeze({
    schema:
      'ATAN_FEE_ABSTRACTION_V2_PRE_SIGN_SHADOW_REVALIDATION',

    version:
      '1.0.0',

    settlement_plan_id:
      plan.settlement_plan_id,

    request_id:
      request.request_id,

    quote_id:
      quote.quote_id,

    reservation_id:
      reservation.reservation_id,

    durable_reservation_id:
      durable.durable_reservation_id,

    acceptance_id:
      acceptance.acceptance_id,

    current_height,

    sponsor_facts: {
      authentication_valid:
        freshSponsorFacts
          .authentication_valid,

      funding_outpoint_unspent:
        freshSponsorFacts
          .funding_outpoint_unspent,

      signer_controls_funding_outpoint:
        freshSponsorFacts
          .signer_controls_funding_outpoint,

      token_receive_address_token_aware:
        freshSponsorFacts
          .token_receive_address_token_aware
    },

    user_bch_input_revalidated:
      true,

    user_token_input_revalidated:
      true,

    durable_reservation_revalidated:
      true,

    status:
      'PRE_SIGN_VALIDATED',

    signing_allowed:
      false,

    broadcast_allowed:
      false
  });
}

export function describeShadowSettlementPlanV2(){
  return Object.freeze({
    version:
      ATAN_FEE_V2_SHADOW_SETTLEMENT_PLAN_VERSION,

    schema:
      ATAN_FEE_V2_SHADOW_SETTLEMENT_PLAN_SCHEMA,

    topology:
      '3_INPUTS_5_OUTPUTS',

    input_order: [
      'USER_BCH',
      'USER_TOKEN',
      'SPONSOR_BCH'
    ],

    output_order: [
      'RECIPIENT_BCH',
      'USER_BCH_CHANGE',
      'USER_TOKEN_CHANGE',
      'SPONSOR_TOKEN_RECEIVER',
      'SPONSOR_BCH_CHANGE'
    ],

    user_extra_bch_cost_required:
      '0',

    sponsor_net_bch_cost_required:
      'EXACT_NETWORK_FEE',

    token_conservation_required:
      true,

    fresh_sponsor_authentication_required_pre_sign:
      true,

    fresh_sponsor_chain_facts_required_pre_sign:
      true,

    fresh_user_inputs_required_pre_sign:
      true,

    durable_reservation_health_required_pre_sign:
      true,

    unsigned_transaction_created:
      false,

    signing_authority:
      'NONE',

    broadcast_authority:
      'NONE'
  });
}
