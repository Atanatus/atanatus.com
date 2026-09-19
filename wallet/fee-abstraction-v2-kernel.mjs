/*
 * ATANATUS :: FEE ABSTRACTION V2
 * Browser SIGHASH_UTXOS Kernel
 *
 * This module intentionally contains no network access,
 * no sponsor identity, no private key storage and no
 * transaction broadcast path.
 *
 * The signing primitive is supplied by the Libauth instance
 * already bundled with the wallet.
 */

export const ATAN_FEE_ABSTRACTION_SIGHASH_BYTE =
  0x61;

export const ATAN_FEE_ABSTRACTION_SIGHASH_NAME =
  'ALL|FORKID|UTXOS';

export const ATAN_FEE_ABSTRACTION_SIGNATURE_IDENTIFIER =
  'all_outputs_all_utxos';


function requireLibauth(
  libauth
){
  if(
    !libauth ||
    typeof libauth.walletTemplateToCompilerBCH !==
      'function' ||
    !libauth.walletTemplateP2pkhNonHd
  ){
    throw new Error(
      'FEE_V2_REQUIRED_LIBAUTH_CAPABILITIES_MISSING'
    );
  }
}


function deepClone(
  value
){
  return JSON.parse(
    JSON.stringify(
      value
    )
  );
}


export function createFeeAbstractionP2pkhTemplate(
  libauth
){
  requireLibauth(
    libauth
  );

  const template =
    deepClone(
      libauth.walletTemplateP2pkhNonHd
    );

  if(
    !template.scripts ||
    !template.scripts.unlock
  ){
    throw new Error(
      'FEE_V2_P2PKH_UNLOCK_TEMPLATE_MISSING'
    );
  }

  /*
   * Standard Mainnet-js P2PKH:
   *
   *   key.schnorr_signature.all_outputs
   *   => ALL|FORKID
   *   => 0x41
   *
   * ATAN Fee Abstraction V2:
   *
   *   key.schnorr_signature.all_outputs_all_utxos
   *   => ALL|UTXOS|FORKID
   *   => 0x61
   */
  template.name =
    'ATAN Fee Abstraction V2 P2PKH';

  template.description =
    'P2PKH using ALL|FORKID|UTXOS for atomic multi-entity BCH/ATAN settlement.';

  template.scripts.unlock.script =
    '<key.schnorr_signature.all_outputs_all_utxos>\n' +
    '<key.public_key>';

  return template;
}


export async function createFeeAbstractionCompiler(
  libauth
){
  const template =
    createFeeAbstractionP2pkhTemplate(
      libauth
    );

  const compiler =
    await libauth
      .walletTemplateToCompilerBCH(
        template
      );

  if(
    typeof compiler ===
    'string'
  ){
    throw new Error(
      'FEE_V2_COMPILER_CREATION_FAILED:' +
      compiler
    );
  }

  if(
    !compiler ||
    typeof compiler.generateScenario !==
      'function'
  ){
    throw new Error(
      'FEE_V2_COMPILER_INVALID'
    );
  }

  return compiler;
}


function readFirstPush(
  unlockingBytecode
){
  if(
    !(unlockingBytecode instanceof Uint8Array) ||
    unlockingBytecode.length < 2
  ){
    throw new Error(
      'FEE_V2_UNLOCKING_BYTECODE_INVALID'
    );
  }

  const opcode =
    unlockingBytecode[0];

  let dataStart;
  let dataLength;

  if(
    opcode >= 1 &&
    opcode <= 75
  ){
    dataStart=1;
    dataLength=opcode;
  }
  else if(opcode === 76){

    if(unlockingBytecode.length < 3){
      throw new Error(
        'FEE_V2_PUSHDATA1_TRUNCATED'
      );
    }

    dataStart=2;
    dataLength=
      unlockingBytecode[1];
  }
  else{
    throw new Error(
      'FEE_V2_UNEXPECTED_SIGNATURE_PUSH_OPCODE_' +
      opcode
    );
  }

  if(
    dataLength < 2 ||
    unlockingBytecode.length <
      dataStart + dataLength
  ){
    throw new Error(
      'FEE_V2_SIGNATURE_PUSH_INVALID'
    );
  }

  return unlockingBytecode.slice(
    dataStart,
    dataStart + dataLength
  );
}


export function getP2pkhSignatureSighashByte(
  unlockingBytecode
){
  const signature =
    readFirstPush(
      unlockingBytecode
    );

  return signature[
    signature.length - 1
  ];
}


export function assertFeeAbstractionSighash(
  unlockingBytecode
){
  const actual =
    getP2pkhSignatureSighashByte(
      unlockingBytecode
    );

  if(
    actual !==
    ATAN_FEE_ABSTRACTION_SIGHASH_BYTE
  ){
    throw new Error(
      'FEE_V2_SIGHASH_MISMATCH_0x' +
      actual
        .toString(16)
        .padStart(2,'0')
    );
  }

  return true;
}