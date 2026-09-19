import {
  ATAN_SPONSORED_FEE_SHADOW_MODE,
  createSponsoredFeeShadowPreview
} from './fee-abstraction-v2-shadow.mjs';

import {
  createSponsorProtocolShadowState
} from './fee-abstraction-v2-sponsor-shadow-controller.mjs';

const ATAN_CATEGORY =
  '3c9af04021c731219908a6c1f9e900ce988d481d40463845e7f5befe61e0362b';

const DERIVATION_PATH =
  "m/44'/145'/0'/0/0";

const BCH_CHANGE_DERIVATION_PATH =
  "m/44'/145'/0'/0/1";

const PUBLIC_SMOKE_ADDRESS =
  'bitcoincash:qpue0pja34hemgz7h5zexlx8n36suy74lv83kkknxv';

const $ =
  id =>
    document.getElementById(id);

const state = {
  mainnet:
    null,

  wallet:
    null,

  changeWallet:
    null,

  pending:
    null
};


function requireElement(
  id
){
  const element =
    $(id);

  if(!element){
    throw new Error(
      'UI_ELEMENT_MISSING_' +
      id
    );
  }

  return element;
}


function setText(
  id,
  value
){
  const element =
    $(id);

  if(element){
    element.textContent =
      String(value);
  }
}


function setStatus(
  message,
  good = true
){
  const element =
    $('globalStatus');

  if(!element){
    return;
  }

  element.textContent =
    String(message);

  element.dataset.state =
    good
      ? 'ok'
      : 'error';
}


function formatFixed8(
  value
){
  const amount =
    BigInt(value);

  const whole =
    amount /
    100000000n;

  const fraction =
    (
      amount %
      100000000n
    )
      .toString()
      .padStart(
        8,
        '0'
      );

  return (
    whole.toString() +
    '.' +
    fraction
  );
}


function parseFixed8(
  value,
  label
){
  const text =
    String(
      value ||
      ''
    ).trim();

  const match =
    /^([0-9]+)(?:\.([0-9]{1,8}))?$/
      .exec(text);

  if(!match){
    throw new Error(
      label +
      '_INVALID_AMOUNT'
    );
  }

  const whole =
    BigInt(
      match[1]
    );

  const fraction =
    BigInt(
      (
        match[2] ||
        ''
      ).padEnd(
        8,
        '0'
      )
    );

  const result =
    whole *
      100000000n +
    fraction;

  if(result <= 0n){
    throw new Error(
      label +
      '_AMOUNT_MUST_BE_POSITIVE'
    );
  }

  return result;
}


function wipeWallet(
  wallet
){
  if(!wallet){
    return;
  }

  try{
    wallet.privateKey?.fill(0);
  }
  catch{
  }

  try{
    wallet.mnemonic = '';
  }
  catch{
  }
}


async function loadMainnet(){
  if(
    !globalThis.__mainnetPromise
  ){
    throw new Error(
      'MAINNET_JS_NOT_LOADED'
    );
  }

  const library =
    await globalThis.__mainnetPromise;

  for(
    const name of [
      'Wallet',
      'SendRequest',
      'TokenSendRequest',
      'Config',
      'toCashaddr',
      'toTokenaddr',
      'libauth'
    ]
  ){
    if(
      library[name] ===
      undefined
    ){
      throw new Error(
        'MAINNET_JS_EXPORT_MISSING_' +
        name
      );
    }
  }

  library
    .Config
    .EnforceCashTokenReceiptAddresses =
      true;

  state.mainnet =
    library;

  return library;
}


function normalizeMnemonic(
  value
){
  const mnemonic =
    String(
      value ||
      ''
    )
      .trim()
      .toLowerCase()
      .replace(
        /\s+/g,
        ' '
      );

  const words =
    mnemonic.split(' ');

  if(words.length !== 12){
    throw new Error(
      'RECOVERY_PHRASE_MUST_HAVE_12_WORDS'
    );
  }

  return mnemonic;
}


async function deriveWallet(
  mnemonic
){
  const wallet =
    await state
      .mainnet
      .Wallet
      .fromSeed(
        normalizeMnemonic(
          mnemonic
        ),
        DERIVATION_PATH
      );

  if(
    !wallet.cashaddr ||
    !String(
      wallet.cashaddr
    ).startsWith(
      'bitcoincash:'
    )
  ){
    throw new Error(
      'BCH_ADDRESS_DERIVATION_FAILED'
    );
  }

  if(
    !wallet.tokenaddr ||
    !String(
      wallet.tokenaddr
    ).startsWith(
      'bitcoincash:'
    )
  ){
    wipeWallet(
      wallet
    );

    throw new Error(
      'ATAN_ADDRESS_DERIVATION_FAILED'
    );
  }

  return wallet;
}


async function deriveChangeWallet(
  mnemonic
){
  const wallet =
    await state
      .mainnet
      .Wallet
      .fromSeed(
        normalizeMnemonic(
          mnemonic
        ),
        BCH_CHANGE_DERIVATION_PATH
      );

  if(
    !wallet.cashaddr ||
    !String(
      wallet.cashaddr
    ).startsWith(
      'bitcoincash:'
    )
  ){
    wipeWallet(
      wallet
    );

    throw new Error(
      'BCH_CHANGE_ADDRESS_DERIVATION_FAILED'
    );
  }

  return wallet;
}


function showWallet(){
  requireElement(
    'lockedView'
  ).hidden =
    true;

  const recovery =
    $('recoveryView');

  if(recovery){
    recovery.hidden =
      true;
  }

  requireElement(
    'walletView'
  ).hidden =
    false;

  setText(
    'walletAddress',
    state.wallet.cashaddr
  );

  setText(
    'tokenAddress',
    state.wallet.tokenaddr
  );
}


function showRecovery(
  mnemonic
){
  requireElement(
    'lockedView'
  ).hidden =
    true;

  requireElement(
    'walletView'
  ).hidden =
    true;

  const recovery =
    requireElement(
      'recoveryView'
    );

  recovery.hidden =
    false;

  setText(
    'generatedMnemonic',
    mnemonic
  );
}


async function activateWallet(
  mnemonic,
  revealRecovery
){
  setStatus(
    'Opening wallet…'
  );

  const wallet =
    await deriveWallet(
      mnemonic
    );

  let changeWallet =
    null;

  try{
    changeWallet =
      await deriveChangeWallet(
        mnemonic
      );
  }
  catch(error){
    wipeWallet(
      wallet
    );

    throw error;
  }

  if(state.wallet){
    wipeWallet(
      state.wallet
    );
  }

  if(state.changeWallet){
    wipeWallet(
      state.changeWallet
    );
  }

  state.wallet =
    wallet;

  state.changeWallet =
    changeWallet;

  state.pending =
    null;

  const input =
    $('mnemonicInput');

  if(input){
    input.value =
      '';
  }

  if(revealRecovery){
    showRecovery(
      mnemonic
    );

    setStatus(
      'Save your recovery phrase securely'
    );

    return;
  }

  showWallet();

  await refreshWallet();
}


async function createWallet(){
  const temporary =
    await state
      .mainnet
      .Wallet
      .newRandom();

  try{
    const mnemonic =
      normalizeMnemonic(
        temporary.mnemonic
      );

    await activateWallet(
      mnemonic,
      true
    );
  }
  finally{
    wipeWallet(
      temporary
    );
  }
}


async function refreshWallet(){
  if(!state.wallet){
    return;
  }

  setStatus(
    'Synchronizing with Bitcoin Cash mainnet…'
  );

  if(!state.changeWallet){
    throw new Error(
      'BCH_CHANGE_WALLET_NOT_DERIVED'
    );
  }

  const [
    primaryBchSats,
    changeBchSats,
    atanBase,
    height
  ] =
    await Promise.all([
      state.wallet.getBalance(),

      state.changeWallet.getBalance(),

      state.wallet.getTokenBalance(
        ATAN_CATEGORY
      ),

      state.wallet
        .provider
        .getBlockHeight()
    ]);

  const bchSats =
    BigInt(primaryBchSats) +
    BigInt(changeBchSats);

  setText(
    'bchBalance',
    formatFixed8(
      bchSats
    )
  );

  setText(
    'atanBalance',
    formatFixed8(
      atanBase
    )
  );

  setText(
    'height',
    '#' +
      String(height)
  );

  setText(
    'fieldState',
    'On-chain wallet'
  );

  setText(
    'fieldBalance',
    formatFixed8(
      atanBase
    ) +
      ' ATAN'
  );

  setText(
    'fieldEligibility',
    'Field is a separate protocol'
  );

  setText(
    'fieldEntitlement',
    '—'
  );

  setText(
    'fieldSnapshot',
    'Balances are read directly from Bitcoin Cash mainnet.'
  );

  setStatus(
    'BCH mainnet · synchronized'
  );
}


function tokenAmount(
  utxo
){
  return BigInt(
    utxo?.token?.amount ??
      0
  );
}


function utxoSats(
  utxo
){
  return BigInt(
    utxo?.satoshis ??
      0
  );
}


function isAtan(
  utxo
){
  return (
    !!utxo?.token &&
    String(
      utxo.token.category ||
        ''
    ).toLowerCase() ===
      ATAN_CATEGORY &&
    utxo.token.nft ===
      undefined &&
    tokenAmount(
      utxo
    ) > 0n
  );
}


function isPlainBch(
  utxo
){
  return !utxo?.token;
}


function sortBySatsDesc(
  a,
  b
){
  const left =
    utxoSats(a);

  const right =
    utxoSats(b);

  if(left > right){
    return -1;
  }

  if(left < right){
    return 1;
  }

  return 0;
}


function sortByTokenDesc(
  a,
  b
){
  const left =
    tokenAmount(a);

  const right =
    tokenAmount(b);

  if(left > right){
    return -1;
  }

  if(left < right){
    return 1;
  }

  return 0;
}


function calculateFee(
  prepared
){
  const libauth =
    state.mainnet.libauth;

  const decoded =
    libauth.decodeTransaction(
      libauth.hexToBin(
        prepared
          .unsignedTransaction
      )
    );

  if(
    !decoded ||
    typeof decoded ===
      'string' ||
    !Array.isArray(
      decoded.outputs
    )
  ){
    throw new Error(
      'UNSIGNED_TRANSACTION_DECODE_FAILED'
    );
  }

  const inputs =
    prepared
      .sourceOutputs
      .reduce(
        (
          total,
          output
        ) =>
          total +
          BigInt(
            output.valueSatoshis
          ),
        0n
      );

  const outputs =
    decoded
      .outputs
      .reduce(
        (
          total,
          output
        ) =>
          total +
          BigInt(
            output.valueSatoshis
          ),
        0n
      );

  const fee =
    inputs -
    outputs;

  if(fee < 0n){
    throw new Error(
      'TRANSACTION_FEE_INVALID'
    );
  }

  return fee;
}


async function buildUnsigned(
  requests,
  utxos
){
  const prepared =
    await state.wallet.send(
      requests,
      {
        buildUnsigned:
          true,

        queryBalance:
          false,

        awaitTransactionPropagation:
          false,

        utxoIds:
          utxos
      }
    );

  if(
    !prepared ||
    typeof prepared
      .unsignedTransaction !==
      'string' ||
    !Array.isArray(
      prepared.sourceOutputs
    ) ||
    prepared
      .sourceOutputs
      .length ===
      0
  ){
    throw new Error(
      'UNSIGNED_TRANSACTION_MISSING'
    );
  }

  return prepared;
}


async function buildBchPlan(
  recipient,
  amount
){
  const {
    SendRequest,
    TokenSendRequest,
    toCashaddr
  } =
    state.mainnet;

  const destination =
    toCashaddr(
      recipient
    );

  const all =
    await state.wallet
      .getUtxos();

  const plain =
    all
      .filter(
        isPlainBch
      )
      .sort(
        sortBySatsDesc
      );

  const atan =
    all
      .filter(
        isAtan
      )
      .sort(
        sortBySatsDesc
      );

  const payment =
    new SendRequest({
      cashaddr:
        destination,

      value:
        amount
    });

  /*
    First try ordinary BCH only.
  */
  if(plain.length > 0){
    try{
      const prepared =
        await buildUnsigned(
          [
            payment
          ],
          plain
        );

      return {
        asset:
          'BCH',

        amount,

        recipient:
          destination,

        prepared,

        fee:
          calculateFee(
            prepared
          ),

        atanPreserved:
          0n,

        usedAtanCarrier:
          false
      };
    }
    catch{
    }
  }

  /*
    If the only BCH available is attached to ATAN,
    selected ATAN inputs are allowed only while returning
    EXACTLY the selected amount of ATAN to this wallet.

    Foreign tokens: excluded.
    NFTs: excluded.
  */
  const selected = [];

  let preserve =
    0n;

  let finalError =
    null;

  for(const utxo of atan){

    selected.push(
      utxo
    );

    preserve +=
      tokenAmount(
        utxo
      );

    const tokenReturn =
      new TokenSendRequest({
        cashaddr:
          state.wallet.tokenaddr,

        category:
          ATAN_CATEGORY,

        amount:
          preserve,

        value:
          1000n
      });

    try{
      const prepared =
        await buildUnsigned(
          [
            payment,
            tokenReturn
          ],
          [
            ...plain,
            ...selected
          ]
        );

      return {
        asset:
          'BCH',

        amount,

        recipient:
          destination,

        prepared,

        fee:
          calculateFee(
            prepared
          ),

        atanPreserved:
          preserve,

        usedAtanCarrier:
          true
      };
    }
    catch(error){
      finalError =
        error;
    }
  }

  if(finalError){
    throw finalError;
  }

  throw new Error(
    'INSUFFICIENT_BCH'
  );
}


async function buildAtanPlan(
  recipient,
  amount
){
  const {
    TokenSendRequest,
    toTokenaddr
  } =
    state.mainnet;

  const destination =
    toTokenaddr(
      recipient
    );

  const all =
    await state.wallet
      .getUtxos();

  const plain =
    all
      .filter(
        isPlainBch
      )
      .sort(
        sortBySatsDesc
      );

  const atan =
    all
      .filter(
        isAtan
      )
      .sort(
        sortByTokenDesc
      );

  const selected = [];

  let available =
    0n;

  for(const utxo of atan){

    selected.push(
      utxo
    );

    available +=
      tokenAmount(
        utxo
      );

    if(available >= amount){
      break;
    }
  }

  if(available < amount){
    throw new Error(
      'INSUFFICIENT_ATAN'
    );
  }

  const transfer =
    new TokenSendRequest({
      cashaddr:
        destination,

      category:
        ATAN_CATEGORY,

      amount,

      value:
        1000n
    });

  const prepared =
    await buildUnsigned(
      [
        transfer
      ],
      [
        ...plain,
        ...selected
      ]
    );

  return {
    asset:
      'ATAN',

    amount,

    recipient:
      destination,

    prepared,

    fee:
      calculateFee(
        prepared
      ),

    atanPreserved:
      available -
      amount,

    usedAtanCarrier:
      true
  };
}


async function prepareSend(){
  if(!state.wallet){
    throw new Error(
      'WALLET_LOCKED'
    );
  }

  state.pending =
    null;

  requireElement(
    'sendBroadcast'
  ).disabled =
    true;

  requireElement(
    'sendBroadcast'
  ).textContent =
    'Broadcast transaction';

  const asset =
    String(
      requireElement(
        'sendAsset'
      ).value
    ).toUpperCase();

  const feeMode =
    String(
      requireElement(
        'sendFeeMode'
      ).value
    ).toUpperCase();

  const recipient =
    String(
      requireElement(
        'sendRecipient'
      ).value ||
        ''
    ).trim();

  const amountText =
    String(
      requireElement(
        'sendAmount'
      ).value ||
        ''
    ).trim();

  if(!recipient){
    throw new Error(
      'RECIPIENT_REQUIRED'
    );
  }

  const amount =
    parseFixed8(
      amountText,
      asset
    );
  if(
    feeMode !== 'BCH_STANDARD' &&
    feeMode !==
      ATAN_SPONSORED_FEE_SHADOW_MODE
  ){
    throw new Error(
      'FEE_MODE_INVALID'
    );
  }

  if(
    feeMode ===
    ATAN_SPONSORED_FEE_SHADOW_MODE
  ){
    if(asset !== 'BCH'){
      throw new Error(
        'ATAN_SPONSORED_FEES_CURRENTLY_REQUIRE_BCH_ASSET'
      );
    }

    setStatus(
      'Building ATAN Sponsored Fees shadow previewâ€¦'
    );

    const preview =
      createSponsoredFeeShadowPreview({
        recipient,
        amount,
        utxos:
          await state.wallet
            .getUtxos(),
        atanCategory:
          ATAN_CATEGORY,
        normalizeRecipient:
          state.mainnet
            .toCashaddr
      });

    const sponsorProtocol =
      await createSponsorProtocolShadowState({
        preview,
        atanCategory:
          ATAN_CATEGORY
      });

    state.pending = {
      ...preview,
      sponsorProtocol
    };

    const lines = [
      'Bitcoin Cash mainnet',
      '',
      'Fee mode: ATAN Sponsored Fees',
      'Stage: SHADOW MODE',
      '',
      'Asset: BCH',
      'Amount: ' +
        formatFixed8(
          preview.amount
        ) +
        ' BCH',
      '',
      'Recipient:',
      preview.recipient,
      '',
      'User BCH network fee target: 0 sats',
      'Sponsor protocol: CONNECTED',
      'Protocol version: ' +
        sponsorProtocol.protocolVersion,
      'Authentication: ' +
        sponsorProtocol.authenticationScheme,
      'Request: ' +
        sponsorProtocol.requestStatus,
      'Exact sponsored network fee: REQUIRED',
      'Sponsor quote: NOT REQUESTED',
      'ATAN fee cost: NOT QUOTED',
      'Network fee: NOT COMMITTED',
      '',
      'Available ATAN: ' +
        formatFixed8(
          preview.availableAtanBase
        ) +
        ' ATAN',
      '',
      'Signature policy: ' +
        preview.sighashName +
        ' (0x' +
        preview.sighashByte
          .toString(16)
          .padStart(2,'0') +
        ')',
      '',
      'Quote reservation: ' +
        sponsorProtocol.reservationStatus,
      'Acceptance: ' +
        sponsorProtocol.acceptanceStatus,
      'Settlement plan: NOT CREATED',
      '',
      'Status: SHADOW / UNSIGNED',
      'Signing: LOCKED',
      'Broadcast: LOCKED',
      '',
      'No sponsored transaction has been signed or broadcast.'
    ];

    setText(
      'sendReviewText',
      lines.join('\n')
    );

    requireElement(
      'sendReview'
    ).hidden =
      false;

    const broadcast =
      requireElement(
        'sendBroadcast'
      );

    broadcast.disabled =
      true;

    broadcast.textContent =
      'Sponsored broadcast locked (shadow)';

    const result =
      $('sendResult');

    if(result){
      result.hidden =
        false;

      result.textContent =
        'Shadow preview only Â· sponsor protocol connected; exact fee planner and live sponsor transport are not connected yet.';
    }

    setStatus(
      'ATAN Sponsored Fees Â· shadow preview ready'
    );

    return;
  }

  setStatus(
    'Building unsigned transaction…'
  );

  const plan =
    asset === 'BCH'
      ? await buildBchPlan(
          recipient,
          amount
        )
      : asset === 'ATAN'
        ? await buildAtanPlan(
            recipient,
            amount
          )
        : (() => {
            throw new Error(
              'ASSET_MUST_BE_BCH_OR_ATAN'
            );
          })();

  /*
    REVIEW STATE:
    No signature exists yet.
  */
  state.pending =
    plan;

  const lines = [
    'Bitcoin Cash mainnet',
    '',
    'Asset: ' +
      plan.asset,

    'Amount: ' +
      formatFixed8(
        plan.amount
      ) +
      ' ' +
      plan.asset,

    '',
    'Recipient:',
    plan.recipient,

    '',
    'Network fee: ' +
      plan.fee.toString() +
      ' sats'
  ];

  if(
    plan.asset === 'BCH' &&
    plan.usedAtanCarrier
  ){
    lines.push(
      '',
      'ATAN preserved in your wallet: ' +
        formatFixed8(
          plan.atanPreserved
        ) +
        ' ATAN'
    );
  }

  if(plan.asset === 'ATAN'){
    lines.push(
      '',
      'ATAN change: ' +
        formatFixed8(
          plan.atanPreserved
        ) +
        ' ATAN'
    );
  }

  lines.push(
    '',
    'Status: UNSIGNED',
    'Nothing has been broadcast.',
    '',
    'Press “Broadcast transaction” to sign locally',
    'and send this transaction.'
  );

  setText(
    'sendReviewText',
    lines.join('\n')
  );

  requireElement(
    'sendReview'
  ).hidden =
    false;

  requireElement(
    'sendBroadcast'
  ).disabled =
    false;

  const result =
    $('sendResult');

  if(result){
    result.hidden =
      true;

    result.textContent =
      '';
  }

  setStatus(
    'Unsigned transaction ready for review'
  );
}


async function broadcastSend(){
  throw new Error(
    'W61K_R2_STAGED_BROADCAST_LOCKED'
  );

  if(
    !state.wallet ||
    !state.pending
  ){
    throw new Error(
      'NO_PREPARED_TRANSACTION'
    );
  }

  if(
    state.pending.feeMode ===
    ATAN_SPONSORED_FEE_SHADOW_MODE
  ){
    throw new Error(
      'SPONSORED_FEES_SHADOW_MODE_BROADCAST_LOCKED'
    );
  }

  const button =
    requireElement(
      'sendBroadcast'
    );

  button.disabled =
    true;

  setStatus(
    'Signing locally in this browser…'
  );

  try{
    /*
      Private key never leaves this browser.
    */
    const signed =
      await state.wallet
        .signUnsignedTransaction(
          state.pending
            .prepared
            .unsignedTransaction,

          state.pending
            .prepared
            .sourceOutputs
        );

    setStatus(
      'Broadcasting to Bitcoin Cash mainnet…'
    );

    /*
      This is the ONLY broadcast path,
      reached by explicit user click.
    */
    const txid =
      await state.wallet
        .submitTransaction(
          signed,
          true
        );

    const result =
      requireElement(
        'sendResult'
      );

    result.hidden =
      false;

    result.textContent =
      'Broadcast successful · TXID: ' +
      txid;

    requireElement(
      'sendReview'
    ).hidden =
      true;

    state.pending =
      null;

    setStatus(
      'Transaction broadcast successfully'
    );

    await new Promise(
      resolve =>
        setTimeout(
          resolve,
          1200
        )
    );

    await refreshWallet();
  }
  catch(error){
    button.disabled =
      false;

    throw error;
  }
}


function clearSend(){
  state.pending =
    null;

  const panel =
    $('sendPanel');

  if(panel){
    panel.hidden =
      true;
  }

  const review =
    $('sendReview');

  if(review){
    review.hidden =
      true;
  }

  const result =
    $('sendResult');

  if(result){
    result.hidden =
      true;

    result.textContent =
      '';
  }

  const recipient =
    $('sendRecipient');

  if(recipient){
    recipient.value =
      '';
  }

  const amount =
    $('sendAmount');

  if(amount){
    amount.value =
      '';
  }

  const feeMode =
    $('sendFeeMode');

  if(feeMode){
    feeMode.value =
      'BCH_STANDARD';
  }

  const broadcast =
    $('sendBroadcast');

  if(broadcast){
    broadcast.disabled =
      true;

    broadcast.textContent =
      'Broadcast transaction';
  }
}


async function copyText(
  value
){
  await navigator
    .clipboard
    .writeText(
      String(value)
    );
}


function lockWallet(){
  if(state.wallet){
    wipeWallet(
      state.wallet
    );
  }

  if(state.changeWallet){
    wipeWallet(
      state.changeWallet
    );
  }

  state.wallet =
    null;

  state.changeWallet =
    null;

  state.pending =
    null;

  clearSend();

  requireElement(
    'walletView'
  ).hidden =
    true;

  const recovery =
    $('recoveryView');

  if(recovery){
    recovery.hidden =
      true;
  }

  requireElement(
    'lockedView'
  ).hidden =
    false;

  setText(
    'walletAddress',
    '—'
  );

  setText(
    'tokenAddress',
    '—'
  );

  setText(
    'bchBalance',
    '—'
  );

  setText(
    'atanBalance',
    '—'
  );

  setText(
    'generatedMnemonic',
    ''
  );

  setStatus(
    'Wallet locked'
  );
}


function wireUi(){
  const required = [
    'globalStatus',
    'lockedView',
    'walletView',
    'recoveryView',
    'createWallet',
    'recoverWallet',
    'mnemonicInput',
    'generatedMnemonic',
    'walletAddress',
    'tokenAddress',
    'bchBalance',
    'atanBalance',
    'refreshWallet',
    'lockWallet',
    'sendOpen',
    'sendPanel',
    'sendAsset',
    'sendFeeMode',
    'sendRecipient',
    'sendAmount',
    'sendPrepare',
    'sendCancel',
    'sendReview',
    'sendReviewText',
    'sendBroadcast',
    'sendResult'
  ];

  for(const id of required){
    requireElement(id);
  }

  $('createWallet')
    .addEventListener(
      'click',
      async () => {
        try{
          await createWallet();
        }
        catch(error){
          setStatus(
            error?.message ||
              String(error),
            false
          );
        }
      }
    );

  $('recoverWallet')
    .addEventListener(
      'click',
      async () => {
        try{
          await activateWallet(
            $('mnemonicInput')
              .value,
            false
          );
        }
        catch(error){
          setStatus(
            error?.message ||
              String(error),
            false
          );
        }
      }
    );

  $('hideRecovery')
    ?.addEventListener(
      'click',
      async () => {
        try{
          setText(
            'generatedMnemonic',
            ''
          );

          showWallet();

          await refreshWallet();
        }
        catch(error){
          setStatus(
            error?.message ||
              String(error),
            false
          );
        }
      }
    );

  $('refreshWallet')
    .addEventListener(
      'click',
      async () => {
        try{
          await refreshWallet();
        }
        catch(error){
          setStatus(
            error?.message ||
              String(error),
            false
          );
        }
      }
    );

  $('lockWallet')
    .addEventListener(
      'click',
      lockWallet
    );

  $('walletAddress')
    .addEventListener(
      'click',
      async () => {
        if(state.wallet){
          await copyText(
            state.wallet.cashaddr
          );
        }
      }
    );

  $('tokenAddress')
    .addEventListener(
      'click',
      async () => {
        if(state.wallet){
          await copyText(
            state.wallet.tokenaddr
          );
        }
      }
    );

  $('copyReceive')
    ?.addEventListener(
      'click',
      async () => {
        if(state.wallet){
          await copyText(
            state.wallet.cashaddr
          );
        }
      }
    );

  $('copyTokenReceive')
    ?.addEventListener(
      'click',
      async () => {
        if(state.wallet){
          await copyText(
            state.wallet.tokenaddr
          );
        }
      }
    );

  $('sendOpen')
    .addEventListener(
      'click',
      () => {
        $('sendPanel').hidden =
          false;

        $('sendReview').hidden =
          true;

        $('sendResult').hidden =
          true;
      }
    );

  $('sendCancel')
    .addEventListener(
      'click',
      clearSend
    );

  $('sendPrepare')
    .addEventListener(
      'click',
      async () => {
        try{
          await prepareSend();
        }
        catch(error){
          const message =
            error?.message ||
            String(error);

          setStatus(
            message,
            false
          );

          $('sendResult').hidden =
            false;

          $('sendResult').textContent =
            message;
        }
      }
    );

  $('sendBroadcast')
    .addEventListener(
      'click',
      async () => {
        try{
          await broadcastSend();
        }
        catch(error){
          const message =
            error?.message ||
            String(error);

          setStatus(
            message,
            false
          );

          $('sendResult').hidden =
            false;

          $('sendResult').textContent =
            message;
        }
      }
    );

  window.addEventListener(
    'beforeunload',
    () => {
      if(state.wallet){
        wipeWallet(
          state.wallet
        );
      }

      if(state.changeWallet){
        wipeWallet(
          state.changeWallet
        );
      }
    }
  );
}


async function smokeTest(){
  document
    .documentElement
    .dataset
    .smoke =
      'RUNNING';

  let randomWallet =
    null;

  let watchWallet =
    null;

  try{
    /*
      Prove wallet creation locally without publishing
      or using a fixed private seed.
    */
    randomWallet =
      await state
        .mainnet
        .Wallet
        .newRandom();

    if(
      !randomWallet.mnemonic ||
      randomWallet
        .mnemonic
        .trim()
        .split(/\s+/)
        .length !== 12
    ){
      throw new Error(
        'SMOKE_RANDOM_WALLET_FAILED'
      );
    }

    wipeWallet(
      randomWallet
    );

    randomWallet =
      null;

    /*
      Network smoke uses a PUBLIC watch-only address.
      No private key exists for this query.
    */
    watchWallet =
      await state
        .mainnet
        .Wallet
        .watchOnly(
          PUBLIC_SMOKE_ADDRESS
        );

    const [
      bch,
      atan,
      height
    ] =
      await Promise.all([
        watchWallet.getBalance(),

        watchWallet.getTokenBalance(
          ATAN_CATEGORY
        ),

        watchWallet
          .provider
          .getBlockHeight()
      ]);

    if(
      typeof bch !==
        'bigint' ||
      typeof atan !==
        'bigint' ||
      !Number.isFinite(
        Number(height)
      )
    ){
      throw new Error(
        'SMOKE_MAINNET_RESPONSE_INVALID'
      );
    }

    document
      .documentElement
      .dataset
      .smoke =
        'PASS';

    document
      .documentElement
      .dataset
      .smokeNetwork =
        'BITCOIN_CASH_MAINNET';

    document
      .documentElement
      .dataset
      .smokeHeight =
        String(height);

    setStatus(
      'Browser mainnet smoke test · PASS'
    );
  }
  catch(error){
    document
      .documentElement
      .dataset
      .smoke =
        'FAIL';

    document
      .documentElement
      .dataset
      .smokeError =
        String(
          error?.message ||
            error
        )
          .replace(
            /[^A-Za-z0-9_.:-]/g,
            '_'
          )
          .slice(
            0,
            160
          );

    throw error;
  }
  finally{
    wipeWallet(
      randomWallet
    );

    wipeWallet(
      watchWallet
    );
  }
}


async function main(){
  try{
    await loadMainnet();

    wireUi();

    document
      .documentElement
      .dataset
      .atanWalletRelease =
        'ATAN_WALLET_STATIC_V1';

    document
      .documentElement
      .dataset
      .boot =
        'PASS';

    const params =
      new URLSearchParams(
        location.search
      );

    if(
      params.get(
        'smoke'
      ) ===
        '1'
    ){
      await smokeTest();
      return;
    }

    setStatus(
      'BCH mainnet · browser wallet ready'
    );
  }
  catch(error){
    document
      .documentElement
      .dataset
      .boot =
        'FAIL';

    setStatus(
      error?.message ||
        String(error),
      false
    );

    console.error(error);
  }
}


main();