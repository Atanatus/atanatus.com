import {
  ATAN_FEE_V2_PROTOCOL_VERSION,
  ATAN_FEE_V2_AUTH_SCHEME,
  createFeeRequestV2,
  validateSponsorQuoteV2,
  verifySponsorQuoteSignatureV2,
  selectSponsorQuoteV2,
  createReservationV2,
  createAcceptanceV2
} from './fee-abstraction-v2-sponsor-protocol.mjs';

export const ATAN_FEE_V2_SHADOW_PROTOCOL_STAGE =
  'SPONSOR_PROTOCOL_CONNECTED';

function fail(code){
  throw new Error(code);
}

function requirePreview(preview){
  if(
    !preview ||
    typeof preview !== 'object' ||
    preview.shadow !== true ||
    preview.feeMode !== 'ATAN_SPONSORED_SHADOW'
  ){
    fail('SPONSOR_SHADOW_PREVIEW_INVALID');
  }

  if(
    preview.signingAllowed !== false ||
    preview.broadcastAllowed !== false
  ){
    fail('SPONSOR_SHADOW_SAFETY_LOCK_INVALID');
  }

  if(
    typeof preview.recipient !== 'string' ||
    preview.recipient.length === 0
  ){
    fail('SPONSOR_SHADOW_RECIPIENT_INVALID');
  }

  if(
    typeof preview.amount !== 'bigint' ||
    preview.amount <= 0n
  ){
    fail('SPONSOR_SHADOW_PAYMENT_INVALID');
  }
}

function requireCategory(category){
  const normalized =
    String(category || '').toLowerCase();

  if(!/^[0-9a-f]{64}$/.test(normalized)){
    fail('SPONSOR_SHADOW_ATAN_CATEGORY_INVALID');
  }

  return normalized;
}

function baseState(preview){
  return {
    stage:
      ATAN_FEE_V2_SHADOW_PROTOCOL_STAGE,

    protocolVersion:
      ATAN_FEE_V2_PROTOCOL_VERSION,

    authenticationScheme:
      ATAN_FEE_V2_AUTH_SCHEME,

    requestStatus:
      'AWAITING_EXACT_NETWORK_FEE',

    quoteStatus:
      'NOT_REQUESTED',

    selectionStatus:
      'NOT_SELECTED',

    reservationStatus:
      'NOT_CREATED',

    acceptanceStatus:
      'NOT_CREATED',

    exactFeePlannerConnected:
      false,

    liveSponsorTransportConnected:
      false,

    request:
      null,

    selectedQuote:
      null,

    reservation:
      null,

    acceptance:
      null,

    networkFeeSats:
      null,

    atanCostBase:
      null,

    signingAllowed:
      false,

    broadcastAllowed:
      false,

    targetUserExtraBchCostSats:
      preview.targetUserExtraBchCostSats
  };
}

function normalizeFee(value){
  if(value === null || value === undefined){
    return null;
  }

  const result = BigInt(value);

  if(result <= 0n){
    fail('SPONSOR_SHADOW_EXACT_NETWORK_FEE_INVALID');
  }

  return result;
}

function requireHeight(value, field){
  if(
    !Number.isSafeInteger(value) ||
    value < 0
  ){
    fail(`SPONSOR_SHADOW_HEIGHT_INVALID:${field}`);
  }
}

export async function createSponsorProtocolShadowState({
  preview,
  atanCategory,
  exactNetworkFeeSats = null,
  currentHeight = null,
  requestValidUntilHeight = null,
  requestNonce = null,
  quotes = null,
  factsByQuoteId = null,
  mainnet = null,
  reservationValidUntilHeight = null,
  reservationNonce = null,
  acceptanceNonce = null
}){
  requirePreview(preview);

  const category =
    requireCategory(atanCategory);

  const result =
    baseState(preview);

  const exactFee =
    normalizeFee(exactNetworkFeeSats);

  if(exactFee === null){
    return result;
  }

  requireHeight(
    currentHeight,
    'currentHeight'
  );

  requireHeight(
    requestValidUntilHeight,
    'requestValidUntilHeight'
  );

  if(requestValidUntilHeight < currentHeight){
    fail('SPONSOR_SHADOW_REQUEST_ALREADY_EXPIRED');
  }

  if(
    typeof requestNonce !== 'string' ||
    requestNonce.length === 0
  ){
    fail('SPONSOR_SHADOW_REQUEST_NONCE_REQUIRED');
  }

  const request =
    await createFeeRequestV2({
      network:
        'mainnet',

      token_category:
        category,

      recipient:
        preview.recipient,

      payment_sats:
        preview.amount.toString(),

      network_fee_sats:
        exactFee.toString(),

      valid_until_height:
        requestValidUntilHeight,

      request_nonce:
        requestNonce
    });

  result.exactFeePlannerConnected =
    true;

  result.request =
    request;

  result.requestStatus =
    'CREATED';

  result.networkFeeSats =
    exactFee;

  if(
    quotes === null ||
    quotes === undefined
  ){
    result.quoteStatus =
      'AWAITING_SPONSOR_QUOTES';

    return result;
  }

  if(
    !Array.isArray(quotes) ||
    quotes.length === 0
  ){
    fail('SPONSOR_SHADOW_QUOTES_REQUIRED_WHEN_CONNECTED');
  }

  if(
    !factsByQuoteId ||
    typeof factsByQuoteId !== 'object' ||
    Array.isArray(factsByQuoteId)
  ){
    fail('SPONSOR_SHADOW_QUOTE_FACTS_REQUIRED');
  }

  if(
    !mainnet ||
    !mainnet.SignedMessage ||
    typeof mainnet.SignedMessage.verify !== 'function'
  ){
    fail('SPONSOR_SHADOW_SIGNEDMESSAGE_REQUIRED');
  }

  const effectiveFacts = {};

  for(const quote of quotes){
    await validateSponsorQuoteV2(
      request,
      quote
    );

    const authenticationValid =
      verifySponsorQuoteSignatureV2({
        quote,
        mainnet
      });

    const supplied =
      factsByQuoteId[
        quote.quote_id
      ];

    if(
      !supplied ||
      typeof supplied !== 'object'
    ){
      fail(
        `SPONSOR_SHADOW_QUOTE_FACTS_MISSING:${quote.quote_id}`
      );
    }

    effectiveFacts[
      quote.quote_id
    ] = {
      authentication_valid:
        authenticationValid,

      funding_outpoint_unspent:
        supplied.funding_outpoint_unspent === true,

      signer_controls_funding_outpoint:
        supplied.signer_controls_funding_outpoint === true,

      token_receive_address_token_aware:
        supplied.token_receive_address_token_aware === true
    };
  }

  const selection =
    await selectSponsorQuoteV2({
      request,
      quotes,
      factsByQuoteId:
        effectiveFacts,
      currentHeight
    });

  result.liveSponsorTransportConnected =
    true;

  result.quoteStatus =
    'VALIDATED';

  result.selectionStatus =
    'SELECTED';

  result.selectedQuote =
    selection.selected_quote;

  result.atanCostBase =
    BigInt(
      selection
        .selected_quote
        .token_cost_base
    );

  if(
    reservationValidUntilHeight === null ||
    reservationValidUntilHeight === undefined ||
    reservationNonce === null ||
    reservationNonce === undefined
  ){
    return result;
  }

  requireHeight(
    reservationValidUntilHeight,
    'reservationValidUntilHeight'
  );

  const selectedFacts =
    effectiveFacts[
      selection
        .selected_quote
        .quote_id
    ];

  const reservation =
    await createReservationV2({
      request,
      quote:
        selection.selected_quote,
      current_height:
        currentHeight,
      valid_until_height:
        reservationValidUntilHeight,
      reservation_nonce:
        String(reservationNonce),
      facts:
        selectedFacts
    });

  result.reservation =
    reservation;

  result.reservationStatus =
    'CREATED';

  if(
    acceptanceNonce === null ||
    acceptanceNonce === undefined
  ){
    return result;
  }

  const acceptance =
    await createAcceptanceV2({
      request,
      quote:
        selection.selected_quote,
      reservation,
      current_height:
        currentHeight,
      acceptance_nonce:
        String(acceptanceNonce),
      facts:
        selectedFacts
    });

  result.acceptance =
    acceptance;

  result.acceptanceStatus =
    'CREATED';

  return result;
}