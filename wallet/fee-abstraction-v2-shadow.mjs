import {
  ATAN_FEE_ABSTRACTION_SIGHASH_BYTE,
  ATAN_FEE_ABSTRACTION_SIGHASH_NAME
} from './fee-abstraction-v2-kernel.mjs';


export const ATAN_SPONSORED_FEE_SHADOW_MODE =
  'ATAN_SPONSORED_SHADOW';


function tokenAmount(
  utxo
){
  return BigInt(
    utxo?.token?.amount ??
    0
  );
}


function satoshis(
  utxo
){
  return BigInt(
    utxo?.satoshis ??
    0
  );
}


function isSpendableAtan(
  utxo,
  atanCategory
){
  return (
    utxo?.token &&
    String(
      utxo.token.category ||
      ''
    ).toLowerCase() ===
      atanCategory &&
    utxo.token.nft ===
      undefined &&
    tokenAmount(
      utxo
    ) > 0n
  );
}


export function createSponsoredFeeShadowPreview({
  recipient,
  amount,
  utxos,
  atanCategory,
  normalizeRecipient
}){
  const category =
    String(
      atanCategory ||
      ''
    ).toLowerCase();

  if(
    !/^[0-9a-f]{64}$/.test(
      category
    )
  ){
    throw new Error(
      'SPONSORED_FEES_ATAN_CATEGORY_INVALID'
    );
  }

  const requested =
    BigInt(
      amount
    );

  if(requested <= 0n){
    throw new Error(
      'SPONSORED_FEES_BCH_AMOUNT_MUST_BE_POSITIVE'
    );
  }

  if(
    !Array.isArray(
      utxos
    )
  ){
    throw new Error(
      'SPONSORED_FEES_UTXOS_REQUIRED'
    );
  }

  if(
    typeof normalizeRecipient !==
    'function'
  ){
    throw new Error(
      'SPONSORED_FEES_RECIPIENT_NORMALIZER_REQUIRED'
    );
  }

  const destination =
    normalizeRecipient(
      String(
        recipient ||
        ''
      ).trim()
    );

  const atanUtxos =
    utxos.filter(
      utxo =>
        isSpendableAtan(
          utxo,
          category
        )
    );

  const availableAtanBase =
    atanUtxos.reduce(
      (
        total,
        utxo
      ) =>
        total +
        tokenAmount(
          utxo
        ),
      0n
    );

  const atanCarrierSats =
    atanUtxos.reduce(
      (
        total,
        utxo
      ) =>
        total +
        satoshis(
          utxo
        ),
      0n
    );

  if(availableAtanBase <= 0n){
    throw new Error(
      'SPONSORED_FEES_REQUIRE_REAL_ATAN'
    );
  }

  return {
    feeMode:
      ATAN_SPONSORED_FEE_SHADOW_MODE,

    shadow:
      true,

    asset:
      'BCH',

    recipient:
      destination,

    amount:
      requested,

    availableAtanBase,

    atanCarrierSats,

    targetUserExtraBchCostSats:
      0n,

    networkFeeSats:
      null,

    atanCostBase:
      null,

    quoteStatus:
      'REQUIRED',

    reservationStatus:
      'NOT_CREATED',

    settlementPlanStatus:
      'NOT_CREATED',

    signingAllowed:
      false,

    broadcastAllowed:
      false,

    sighashName:
      ATAN_FEE_ABSTRACTION_SIGHASH_NAME,

    sighashByte:
      ATAN_FEE_ABSTRACTION_SIGHASH_BYTE
  };
}