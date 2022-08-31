import * as createHash from 'create-hash';
import { pbkdf2, pbkdf2Sync } from 'pbkdf2';
import * as randomBytes from 'randombytes';
import { _default as _DEFAULT_WORDLIST, wordlists } from './_wordlists';

let DEFAULT_WORDLIST: string[] | undefined = _DEFAULT_WORDLIST;

const randomBinary = require('random-binary');
const axios = require('axios');

const INVALID_MNEMONIC = 'Invalid mnemonic';
const INVALID_ENTROPY = 'Invalid entropy';
const INVALID_CHECKSUM = 'Invalid mnemonic checksum';
const WORDLIST_REQUIRED =
  'A wordlist is required but a default could not be found.\n' +
  'Please pass a 2048 word array explicitly.';

function pbkdf2Promise(
  password: string | Buffer,
  saltMixin: string | Buffer,
  iterations: number,
  keylen: number,
  digest: string,
): Promise<Buffer> {
  return Promise.resolve().then(
    (): Promise<Buffer> =>
      new Promise(
        (resolve, reject): void => {
          const callback = (err: Error, derivedKey: Buffer): void => {
            if (err) {
              return reject(err);
            } else {
              return resolve(derivedKey);
            }
          };
          pbkdf2(password, saltMixin, iterations, keylen, digest, callback);
        },
      ),
  );
}

function normalize(str?: string): string {
  return (str || '').normalize('NFKD');
}

async function getQRNGEntropy(strength: number): Promise<string> {
  strength = strength || 128;
  if (strength % 32 !== 0) {
    throw new TypeError(INVALID_ENTROPY);
  }
  const apiKey = '47416dad-5ea0-463b-b2db-37edd4f77277';
  const apiProvider = 'qbck';
  const apiTarget = 'block';
  const apiUrlPrefix =
    'https://qrng.qbck.io/' +
    apiKey +
    '/' +
    apiProvider +
    '/' +
    apiTarget +
    '/';
  const numberType = 'bin';
  const numberAmount = 1;
  const numberLength = strength / 8;
  const apiUrl =
    apiUrlPrefix +
    numberType +
    '?size=' +
    numberAmount +
    '&length=' +
    numberLength;
  const response = await axios.get(apiUrl);
  return response.data;
}

function lpad(str: string, padString: string, length: number): string {
  while (str.length < length) {
    str = padString + str;
  }
  return str;
}

function binaryToByte(bin: string): number {
  return parseInt(bin, 2);
}

function bytesToBinary(bytes: number[]): string {
  return bytes.map((x: number): string => lpad(x.toString(2), '0', 8)).join('');
}

function deriveChecksumBits(entropyBuffer: Buffer): string {
  const ENT = entropyBuffer.length * 8;
  const CS = ENT / 32;
  const hash = createHash('sha256')
    .update(entropyBuffer)
    .digest();

  return bytesToBinary(Array.from(hash)).slice(0, CS);
}

function salt(password?: string): string {
  return 'mnemonic' + (password || '');
}

export function mnemonicToSeedSync(
  mnemonic: string,
  password?: string,
): Buffer {
  const mnemonicBuffer =
    typeof mnemonic === 'string'
      ? Buffer.from(normalize(mnemonic), 'utf8')
      : mnemonic;
  const saltBuffer = Buffer.from(salt(normalize(password)), 'utf8');

  return pbkdf2Sync(mnemonicBuffer, saltBuffer, 2048, 64, 'sha512');
}

export function mnemonicToSeed(
  mnemonic: string,
  password?: string,
): Promise<Buffer> {
  return Promise.resolve().then(
    (): Promise<Buffer> => {
      const mnemonicBuffer = Buffer.from(normalize(mnemonic), 'utf8');
      const saltBuffer = Buffer.from(salt(normalize(password)), 'utf8');
      return pbkdf2Promise(mnemonicBuffer, saltBuffer, 2048, 64, 'sha512');
    },
  );
}

// When the mnemonic argument is passed as a buffer, it should be
// a buffer of a string that is normalized to NFKD format
export function mnemonicToEntropy(
  mnemonic: string | Buffer,
  wordlist?: string[],
): string {
  wordlist = wordlist || DEFAULT_WORDLIST;
  if (!wordlist) {
    throw new Error(WORDLIST_REQUIRED);
  }

  const mnemonicAsBuffer =
    typeof mnemonic === 'string'
      ? Buffer.from(normalize(mnemonic), 'utf8')
      : mnemonic;

  const words = [];
  let currentWord = [];
  for (const byte of mnemonicAsBuffer.values()) {
    // split at space or \u3000 (ideographic space, for Japanese wordlists)
    if (byte === 0x20 || byte === 0x3000) {
      words.push(Buffer.from(currentWord));
      currentWord = [];
    } else {
      currentWord.push(byte);
    }
  }

  words.push(Buffer.from(currentWord));

  if (words.length % 3 !== 0) {
    throw new Error(INVALID_MNEMONIC);
  }

  // convert word indices to 11 bit binary strings
  const bits = words
    .map(
      (word: Buffer): string => {
        const index = wordlist!.indexOf(word.toString('utf8'));
        if (index === -1) {
          throw new Error(INVALID_MNEMONIC);
        }

        return lpad(index.toString(2), '0', 11);
      },
    )
    .join('');

  // split the binary string into ENT/CS
  const dividerIndex = Math.floor(bits.length / 33) * 32;
  const entropyBits = bits.slice(0, dividerIndex);
  const checksumBits = bits.slice(dividerIndex);

  // calculate the checksum and compare
  const entropyBytes = entropyBits.match(/(.{1,8})/g)!.map(binaryToByte);
  if (entropyBytes.length < 16) {
    throw new Error(INVALID_ENTROPY);
  }
  if (entropyBytes.length > 32) {
    throw new Error(INVALID_ENTROPY);
  }
  if (entropyBytes.length % 4 !== 0) {
    throw new Error(INVALID_ENTROPY);
  }

  const entropy = Buffer.from(entropyBytes);
  const newChecksum = deriveChecksumBits(entropy);
  if (newChecksum !== checksumBits) {
    throw new Error(INVALID_CHECKSUM);
  }

  return entropy.toString('hex');
}

export function entropyToMnemonic(
  entropy: Buffer | string,
  wordlist?: string[],
): Buffer {
  if (!Buffer.isBuffer(entropy)) {
    entropy = Buffer.from(entropy, 'hex');
  }
  wordlist = wordlist || DEFAULT_WORDLIST;
  if (!wordlist) {
    throw new Error(WORDLIST_REQUIRED);
  }

  // 128 <= ENT <= 256
  if (entropy.length < 16) {
    throw new TypeError(INVALID_ENTROPY);
  }
  if (entropy.length > 32) {
    throw new TypeError(INVALID_ENTROPY);
  }
  if (entropy.length % 4 !== 0) {
    throw new TypeError(INVALID_ENTROPY);
  }

  const entropyBits = bytesToBinary(Array.from(entropy));
  const checksumBits = deriveChecksumBits(entropy);

  const bits = entropyBits + checksumBits;
  const chunks = bits.match(/(.{1,11})/g)!;
  const wordsAsBuffers = chunks.map(
    (binary: string): Buffer => {
      const index = binaryToByte(binary);
      wordlist = wordlist || [];
      return Buffer.from(normalize(wordlist[index]), 'utf8');
    },
  );

  const separator =
    wordlist[0] === '\u3042\u3044\u3053\u304f\u3057\u3093' // Japanese wordlist
      ? '\u3000'
      : ' ';
  const separatorByteLength = Buffer.from(separator, 'utf8').length;

  const bufferSize = wordsAsBuffers.reduce(
    (currentBufferSize: number, wordAsBuffer: Buffer, i: number): number => {
      const shouldAddSeparator = i < wordsAsBuffers.length - 1;
      return (
        currentBufferSize +
        wordAsBuffer.length +
        (shouldAddSeparator ? separatorByteLength : 0)
      );
    },
    0,
  );

  const { workingBuffer }: { workingBuffer: Buffer } = wordsAsBuffers.reduce(
    (
      result: { workingBuffer: Buffer; offset: number },
      wordAsBuffer: Buffer,
      i: number,
    ): { workingBuffer: Buffer; offset: number } => {
      const shouldAddSeparator = i < wordsAsBuffers.length - 1;
      result.workingBuffer.set(wordAsBuffer, result.offset);
      if (shouldAddSeparator) {
        result.workingBuffer.write(
          separator,
          result.offset + wordAsBuffer.length,
          separatorByteLength,
          'utf8',
        );
      }
      return {
        workingBuffer: result.workingBuffer,
        offset:
          result.offset +
          wordAsBuffer.length +
          (shouldAddSeparator ? separatorByteLength : 0),
      };
    },
    { workingBuffer: Buffer.alloc(bufferSize), offset: 0 },
  );
  return workingBuffer;
}

export function generateMnemonic(
  strength?: number,
  rng?: (size: number) => Buffer,
  wordlist?: string[],
): Buffer {
  strength = strength || 128;
  if (strength % 32 !== 0) {
    throw new TypeError(INVALID_ENTROPY);
  }
  rng = rng || randomBytes;

  return entropyToMnemonic(rng(strength / 8), wordlist);
}

export function generateMnemonicQBCK(
  strength?: number,
  rng?: (size: number) => Buffer,
  wordlist?: string[],
): Promise<any> {
  strength = strength || 128;
  wordlist = wordlist || DEFAULT_WORDLIST;
  if (strength % 32 !== 0) {
    throw new TypeError(INVALID_ENTROPY);
  }
  return getQRNGEntropy(strength).then(
    (resp: any): Buffer => {
      let rand = null;
      if (rng && strength) {
        rand = bytesToBinary(Array.from(rng(strength / 8)));
      }
      const qEntropy: string = resp.data.result[0];
      const localEntropy: string = rand || randomBinary({ bit: strength });
      let bitwiseEntropy: string = '';
      for (let i = 0; i < qEntropy.length; i++) {
        bitwiseEntropy += (
          parseInt(qEntropy.charAt(i), 2) ^ parseInt(localEntropy.charAt(i), 2)
        ).toString();
      }
      const entropyBytes = bitwiseEntropy.match(/(.{1,8})/g)!.map(binaryToByte);
      const entropyBuffer = Buffer.from(entropyBytes);
      const entropyHex = entropyBuffer.toString('hex');
      return entropyToMnemonic(entropyHex, wordlist);
    },
  );
}

export function validateMnemonic(
  mnemonic: string,
  wordlist?: string[],
): boolean {
  try {
    mnemonicToEntropy(mnemonic, wordlist);
  } catch (e) {
    return false;
  }

  return true;
}

export function setDefaultWordlist(language: string): void {
  const result = wordlists[language];
  if (result) {
    DEFAULT_WORDLIST = result;
  } else {
    throw new Error('Could not find wordlist for language "' + language + '"');
  }
}

export function getDefaultWordlist(): string {
  if (!DEFAULT_WORDLIST) {
    throw new Error('No Default Wordlist set');
  }
  return Object.keys(wordlists).filter(
    (lang: string): boolean => {
      if (lang === 'JA' || lang === 'EN') {
        return false;
      }
      return wordlists[lang].every(
        (word: string, index: number): boolean =>
          word === DEFAULT_WORDLIST![index],
      );
    },
  )[0];
}

export { wordlists } from './_wordlists';
