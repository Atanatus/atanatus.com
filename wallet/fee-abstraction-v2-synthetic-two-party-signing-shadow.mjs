import {
  signFeeAbstractionUserInputs
} from './fee-abstraction-v2-signing-adapter.mjs';

import {
  sha256HexV2
} from './fee-abstraction-v2-sponsor-protocol.mjs';

export const ATAN_FEE_V2_TWO_PARTY_SIGNING_SHADOW_VERSION =
  '1.0.0';

export const ATAN_FEE_V2_TWO_PARTY_SIGNING_SHADOW_SCHEMA =
  'ATAN_FEE_ABSTRACTION_V2_TWO_PARTY_SIGNING_SHADOW';

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

function requireUint8Array(value, name){
  if(!(value instanceof Uint8Array)){
    fail(
      `${name.toUpperCase()}_UINT8ARRAY_REQUIRED`
    );
  }

  return value;
}

function requirePrivateKey(value, name){
  requireUint8Array(
    value,
    name
  );

  if(value.length !== 32){
    fail(
      `${name.toUpperCase()}_32_BYTES_REQUIRED`
    );
  }

  return value;
}

function binToHex(value){
  requireUint8Array(
    value,
    'binary_value'
  );

  return Buffer
    .from(value)
    .toString('hex');
}

function cloneBin(value){
  return Uint8Array.from(
    requireUint8Array(
      value,
      'binary_value'
    )
  );
}

function cloneToken(token){
  if(token === undefined){
    return undefined;
  }

  const cloned = {
    category:
      cloneBin(
        token.category
      ),

    amount:
      BigInt(
        token.amount
      )
  };

  if(token.nft !== undefined){
    cloned.nft =
      structuredClone(
        token.nft
      );
  }

  return cloned;
}

function cloneOutput(output){
  const cloned = {
    lockingBytecode:
      cloneBin(
        output.lockingBytecode
      ),

    valueSatoshis:
      BigInt(
        output.valueSatoshis
      )
  };

  const token =
    cloneToken(
      output.token
    );

  if(token !== undefined){
    cloned.token =
      token;
  }

  return cloned;
}

function cloneTransaction(transaction){
  requireObject(
    transaction,
    'transaction'
  );

  if(
    !Array.isArray(transaction.inputs) ||
    !Array.isArray(transaction.outputs)
  ){
    fail(
      'TWO_PARTY_TRANSACTION_SHAPE_INVALID'
    );
  }

  return {
    version:
      Number(
        transaction.version
      ),

    inputs:
      transaction.inputs.map(
        input => ({
          outpointTransactionHash:
            cloneBin(
              input.outpointTransactionHash
            ),

          outpointIndex:
            Number(
              input.outpointIndex
            ),

          sequenceNumber:
            Number(
              input.sequenceNumber
            ),

          unlockingBytecode:
            cloneBin(
              input.unlockingBytecode
            )
        })
      ),

    outputs:
      transaction.outputs.map(
        output =>
          cloneOutput(
            output
          )
      ),

    locktime:
      Number(
        transaction.locktime
      )
  };
}

function cloneSourceOutputs(sourceOutputs){
  if(!Array.isArray(sourceOutputs)){
    fail(
      'TWO_PARTY_SOURCE_OUTPUTS_REQUIRED'
    );
  }

  return sourceOutputs.map(
    output =>
      cloneOutput(
        output
      )
  );
}

function outputCommitment(output){
  const result = {
    locking_bytecode:
      binToHex(
        output.lockingBytecode
      ),

    value_satoshis:
      BigInt(
        output.valueSatoshis
      ).toString()
  };

  if(output.token !== undefined){
    result.token = {
      category:
        binToHex(
          output.token.category
        ),

      amount:
        BigInt(
          output.token.amount
        ).toString()
    };

    if(output.token.nft !== undefined){
      result.token.nft =
        structuredClone(
          output.token.nft
        );
    }
  }

  return result;
}

function economicCommitmentPayload({
  transaction,
  sourceOutputs
}){
  requireObject(
    transaction,
    'transaction'
  );

  if(
    !Array.isArray(transaction.inputs) ||
    !Array.isArray(transaction.outputs)
  ){
    fail(
      'TWO_PARTY_TRANSACTION_SHAPE_INVALID'
    );
  }

  if(
    !Array.isArray(sourceOutputs) ||
    sourceOutputs.length !==
      transaction.inputs.length
  ){
    fail(
      'TWO_PARTY_SOURCE_OUTPUT_COUNT_MISMATCH'
    );
  }

  return {
    version:
      Number(
        transaction.version
      ),

    inputs:
      transaction.inputs.map(
        input => ({
          outpoint_transaction_hash:
            binToHex(
              input.outpointTransactionHash
            ),

          outpoint_index:
            Number(
              input.outpointIndex
            ),

          sequence_number:
            Number(
              input.sequenceNumber
            )
        })
      ),

    outputs:
      transaction.outputs.map(
        output =>
          outputCommitment(
            output
          )
      ),

    locktime:
      Number(
        transaction.locktime
      ),

    source_outputs:
      sourceOutputs.map(
        output =>
          outputCommitment(
            output
          )
      )
  };
}

export async function computeTwoPartySigningCommitmentV2({
  transaction,
  source_outputs
}){
  return sha256HexV2(
    JSON.stringify(
      economicCommitmentPayload({
        transaction,
        sourceOutputs:
          source_outputs
      })
    )
  );
}

function extractSignedTransaction(
  signingResult,
  libauth
){
  if(
    signingResult &&
    Array.isArray(
      signingResult.inputs
    ) &&
    Array.isArray(
      signingResult.outputs
    )
  ){
    return signingResult;
  }

  for(const key of [
    'transaction',
    'signedTransaction',
    'signed_transaction'
  ]){
    const value =
      signingResult?.[key];

    if(
      value &&
      Array.isArray(value.inputs) &&
      Array.isArray(value.outputs)
    ){
      return value;
    }
  }

  for(const key of [
    'encodedTransaction',
    'encoded_transaction',
    'bytes'
  ]){
    const value =
      signingResult?.[key];

    if(value instanceof Uint8Array){
      const decoded =
        libauth
          .decodeTransaction(
            value
          );

      if(typeof decoded === 'string'){
        fail(
          'TWO_PARTY_SIGNED_RESULT_DECODE_FAILED:' +
          decoded
        );
      }

      return decoded;
    }
  }

  if(signingResult instanceof Uint8Array){
    const decoded =
      libauth
        .decodeTransaction(
          signingResult
        );

    if(typeof decoded === 'string'){
      fail(
        'TWO_PARTY_DIRECT_SIGNED_RESULT_DECODE_FAILED:' +
        decoded
      );
    }

    return decoded;
  }

  fail(
    'TWO_PARTY_SIGNING_RESULT_TRANSACTION_NOT_FOUND'
  );
}

function classifyUnlocking(
  unlocking
){
  requireUint8Array(
    unlocking,
    'unlocking_bytecode'
  );

  if(unlocking.length !== 100){
    fail(
      'TWO_PARTY_UNLOCKING_BYTES_NOT_100'
    );
  }

  const signaturePushBytes =
    unlocking[0];

  if(signaturePushBytes !== 65){
    fail(
      'TWO_PARTY_SIGNATURE_PUSH_NOT_65'
    );
  }

  const signaturePayload =
    unlocking.slice(
      1,
      1 + signaturePushBytes
    );

  const sighashByte =
    signaturePayload[
      signaturePayload.length - 1
    ];

  const cryptoSignatureBytes =
    signaturePayload.length - 1;

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
    sighashByte !== 0x61 ||
    cryptoSignatureBytes !== 64 ||
    publicKeyPushBytes !== 33 ||
    publicKeyBytes !== 33
  ){
    fail(
      'TWO_PARTY_W1_SCHNORR_GEOMETRY_INVALID'
    );
  }

  return Object.freeze({
    unlocking_bytes:
      unlocking.length,

    signature_push_bytes:
      signaturePushBytes,

    crypto_signature_bytes:
      cryptoSignatureBytes,

    sighash_byte:
      sighashByte,

    public_key_push_bytes:
      publicKeyPushBytes,

    public_key_bytes:
      publicKeyBytes
  });
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

function requireLibauth(libauth){
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
      'TWO_PARTY_LIBAUTH_ENCODER_DECODER_REQUIRED'
    );
  }
}

function assertUnsignedSponsorInput(
  transaction,
  sponsorInputIndex
){
  const input =
    transaction.inputs[
      sponsorInputIndex
    ];

  if(
    !input ||
    !(input.unlockingBytecode instanceof Uint8Array) ||
    input.unlockingBytecode.length !== 0
  ){
    fail(
      'TWO_PARTY_SPONSOR_INPUT_NOT_UNSIGNED'
    );
  }
}

function assertAllInitiallyUnsigned(
  transaction
){
  if(
    !transaction.inputs.every(
      input =>
        input.unlockingBytecode instanceof Uint8Array &&
        input.unlockingBytecode.length === 0
    )
  ){
    fail(
      'TWO_PARTY_INITIAL_TRANSACTION_NOT_UNSIGNED'
    );
  }
}

function requireSyntheticOnly(value){
  if(value !== true){
    fail(
      'TWO_PARTY_SYNTHETIC_ONLY_REQUIRED'
    );
  }
}

export async function createUserPartialSignaturePackageV2({
  libauth,
  transaction,
  source_outputs,
  user_signers,
  sponsor_input_index,
  synthetic_only
}){
  requireSyntheticOnly(
    synthetic_only
  );

  requireLibauth(
    libauth
  );

  const working =
    cloneTransaction(
      transaction
    );

  const sources =
    cloneSourceOutputs(
      source_outputs
    );

  assertAllInitiallyUnsigned(
    working
  );

  if(
    !Array.isArray(user_signers) ||
    user_signers.length !== 2
  ){
    fail(
      'TWO_PARTY_EXACTLY_TWO_USER_SIGNERS_REQUIRED'
    );
  }

  if(
    sponsor_input_index !== 2
  ){
    fail(
      'TWO_PARTY_SPONSOR_INPUT_INDEX_MUST_BE_2'
    );
  }

  const indexes =
    user_signers.map(
      signer =>
        Number(
          signer.input_index
        )
    );

  if(
    indexes.length !== 2 ||
    indexes[0] !== 0 ||
    indexes[1] !== 1
  ){
    fail(
      'TWO_PARTY_USER_INPUT_ORDER_MUST_BE_0_1'
    );
  }

  const commitment =
    await computeTwoPartySigningCommitmentV2({
      transaction:
        working,

      source_outputs:
        sources
    });

  let signed =
    working;

  const userSignatureFacts = [];

  for(
    let signerIndex = 0;
    signerIndex < user_signers.length;
    signerIndex += 1
  ){
    const signer =
      user_signers[
        signerIndex
      ];

    requireObject(
      signer,
      `user_signer_${signerIndex}`
    );

    const inputIndex =
      Number(
        signer.input_index
      );

    const privateKey =
      requirePrivateKey(
        signer.private_key,
        `user_signer_${signerIndex}_private_key`
      );

    const beforeUntouched =
      signed.inputs.map(
        input =>
          cloneBin(
            input.unlockingBytecode
          )
      );

    const signingResult =
      await signFeeAbstractionUserInputs({
        libauth,

        transaction:
          signed,

        sourceOutputs:
          sources,

        inputIndexes: [
          inputIndex
        ],

        privateKey
      });

    const next =
      extractSignedTransaction(
        signingResult,
        libauth
      );

    const nextCommitment =
      await computeTwoPartySigningCommitmentV2({
        transaction:
          next,

        source_outputs:
          sources
      });

    if(nextCommitment !== commitment){
      fail(
        'TWO_PARTY_ECONOMIC_CORE_CHANGED_DURING_USER_SIGNING'
      );
    }

    for(
      let index = 0;
      index < next.inputs.length;
      index += 1
    ){
      if(index === inputIndex){
        continue;
      }

      if(
        !equalBins(
          beforeUntouched[index],
          next.inputs[index]
            .unlockingBytecode
        )
      ){
        fail(
          `TWO_PARTY_USER_SIGNING_MUTATED_INPUT_${index}`
        );
      }
    }

    userSignatureFacts.push(
      classifyUnlocking(
        next.inputs[
          inputIndex
        ].unlockingBytecode
      )
    );

    signed =
      next;
  }

  assertUnsignedSponsorInput(
    signed,
    sponsor_input_index
  );

  for(const index of [0,1]){
    classifyUnlocking(
      signed.inputs[index]
        .unlockingBytecode
    );
  }

  const encoded =
    libauth
      .encodeTransaction(
        signed
      );

  return Object.freeze({
    schema:
      ATAN_FEE_V2_TWO_PARTY_SIGNING_SHADOW_SCHEMA,

    version:
      ATAN_FEE_V2_TWO_PARTY_SIGNING_SHADOW_VERSION,

    stage:
      'USER_PARTIAL_SIGNATURES',

    synthetic_only:
      true,

    economic_core_commitment:
      commitment,

    transaction:
      signed,

    source_outputs:
      sources,

    user_input_indexes: [
      0,
      1
    ],

    sponsor_input_index:
      sponsor_input_index,

    user_signature_facts:
      userSignatureFacts,

    encoded_transaction:
      encoded,

    encoded_transaction_bytes:
      encoded.length,

    user_signature_count:
      2,

    sponsor_signature_present:
      false,

    transaction_fully_signed:
      false,

    broadcast_allowed:
      false
  });
}

export async function applySponsorSignatureShadowV2({
  libauth,
  user_package,
  sponsor_private_key,
  synthetic_only
}){
  requireSyntheticOnly(
    synthetic_only
  );

  requireLibauth(
    libauth
  );

  requireObject(
    user_package,
    'user_package'
  );

  if(
    user_package.schema !==
      ATAN_FEE_V2_TWO_PARTY_SIGNING_SHADOW_SCHEMA ||
    user_package.version !==
      ATAN_FEE_V2_TWO_PARTY_SIGNING_SHADOW_VERSION ||
    user_package.stage !==
      'USER_PARTIAL_SIGNATURES' ||
    user_package.synthetic_only !==
      true
  ){
    fail(
      'TWO_PARTY_USER_PACKAGE_INVALID'
    );
  }

  const sponsorPrivateKey =
    requirePrivateKey(
      sponsor_private_key,
      'sponsor_private_key'
    );

  const transaction =
    cloneTransaction(
      user_package.transaction
    );

  const sources =
    cloneSourceOutputs(
      user_package.source_outputs
    );

  const currentCommitment =
    await computeTwoPartySigningCommitmentV2({
      transaction,
      source_outputs:
        sources
    });

  if(
    currentCommitment !==
    user_package
      .economic_core_commitment
  ){
    fail(
      'TWO_PARTY_PRE_SPONSOR_COMMITMENT_MISMATCH'
    );
  }

  const sponsorInputIndex =
    Number(
      user_package
        .sponsor_input_index
    );

  if(sponsorInputIndex !== 2){
    fail(
      'TWO_PARTY_SPONSOR_INPUT_INDEX_INVALID'
    );
  }

  assertUnsignedSponsorInput(
    transaction,
    sponsorInputIndex
  );

  const exactUserUnlockings =
    [
      cloneBin(
        transaction.inputs[0]
          .unlockingBytecode
      ),
      cloneBin(
        transaction.inputs[1]
          .unlockingBytecode
      )
    ];

  classifyUnlocking(
    exactUserUnlockings[0]
  );

  classifyUnlocking(
    exactUserUnlockings[1]
  );

  const signingResult =
    await signFeeAbstractionUserInputs({
      libauth,

      transaction,

      sourceOutputs:
        sources,

      inputIndexes: [
        sponsorInputIndex
      ],

      privateKey:
        sponsorPrivateKey
  });

  const fullySigned =
    extractSignedTransaction(
      signingResult,
      libauth
    );

  const afterCommitment =
    await computeTwoPartySigningCommitmentV2({
      transaction:
        fullySigned,

      source_outputs:
        sources
    });

  if(
    afterCommitment !==
    user_package
      .economic_core_commitment
  ){
    fail(
      'TWO_PARTY_ECONOMIC_CORE_CHANGED_DURING_SPONSOR_SIGNING'
    );
  }

  for(const index of [0,1]){
    if(
      !equalBins(
        exactUserUnlockings[index],
        fullySigned.inputs[index]
          .unlockingBytecode
      )
    ){
      fail(
        `TWO_PARTY_SPONSOR_MUTATED_USER_SIGNATURE_${index}`
      );
    }
  }

  const sponsorSignatureFacts =
    classifyUnlocking(
      fullySigned.inputs[
        sponsorInputIndex
      ].unlockingBytecode
    );

  const allSignatureFacts =
    fullySigned.inputs.map(
      input =>
        classifyUnlocking(
          input.unlockingBytecode
        )
    );

  const encoded =
    libauth
      .encodeTransaction(
        fullySigned
      );

  const decoded =
    libauth
      .decodeTransaction(
        encoded
      );

  if(typeof decoded === 'string'){
    fail(
      'TWO_PARTY_FULLY_SIGNED_DECODE_FAILED:' +
      decoded
    );
  }

  const reencoded =
    libauth
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
      'TWO_PARTY_FULLY_SIGNED_DECODE_REENCODE_MISMATCH'
    );
  }

  return Object.freeze({
    schema:
      ATAN_FEE_V2_TWO_PARTY_SIGNING_SHADOW_SCHEMA,

    version:
      ATAN_FEE_V2_TWO_PARTY_SIGNING_SHADOW_VERSION,

    stage:
      'FULLY_SIGNED_SYNTHETIC',

    synthetic_only:
      true,

    economic_core_commitment:
      afterCommitment,

    transaction:
      fullySigned,

    source_outputs:
      sources,

    encoded_transaction:
      encoded,

    encoded_transaction_bytes:
      encoded.length,

    user_input_indexes: [
      0,
      1
    ],

    sponsor_input_index:
      sponsorInputIndex,

    all_signature_facts:
      allSignatureFacts,

    sponsor_signature_facts:
      sponsorSignatureFacts,

    user_signature_count:
      2,

    sponsor_signature_count:
      1,

    transaction_fully_signed:
      true,

    real_transaction_signed:
      false,

    broadcast_allowed:
      false
  });
}

export function describeTwoPartySigningShadowV2(){
  return Object.freeze({
    version:
      ATAN_FEE_V2_TWO_PARTY_SIGNING_SHADOW_VERSION,

    schema:
      ATAN_FEE_V2_TWO_PARTY_SIGNING_SHADOW_SCHEMA,

    mode:
      'SYNTHETIC_ONLY',

    user_inputs: [
      0,
      1
    ],

    sponsor_input:
      2,

    sighash:
      'ALL|FORKID|UTXOS',

    sighash_byte:
      '0x61',

    schnorr_signature_bytes:
      64,

    unlocking_bytecode_bytes:
      100,

    user_partial_package:
      true,

    sponsor_must_preserve_user_signatures:
      true,

    economic_core_commitment_includes_source_outputs:
      true,

    real_signing_authority:
      'NONE',

    broadcast_authority:
      'NONE'
  });
}
