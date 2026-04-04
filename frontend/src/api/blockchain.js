import { PeraWalletConnect } from '@perawallet/connect';

const peraWallet = new PeraWalletConnect();
const DEFAULT_EXPLORER_BASE =
  import.meta.env.VITE_ALGO_EXPLORER_TX_BASE ||
  'https://testnet.explorer.perawallet.app/tx/';

export const DEMO_WALLET =
  'SAHBJDRHHRR72JHTWSXZR5VHQQUVC7S757TJZI656FWSDO3TZZWV3IGJV4';
export const DEMO_LOGIN_SIGNATURE = `0x${'a'.repeat(130)}`;
export const DEMO_STEP_UP_SIGNATURE = `0x${'b'.repeat(130)}`;
export { peraWallet };

function toUint8Array(value) {
  if (value instanceof Uint8Array) {
    return value;
  }

  if (value instanceof ArrayBuffer) {
    return new Uint8Array(value);
  }

  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }

  if (Array.isArray(value)) {
    return Uint8Array.from(value);
  }

  if (typeof value === 'string') {
    try {
      const decoded = atob(value);
      return Uint8Array.from(decoded, (char) => char.charCodeAt(0));
    } catch {
      return new TextEncoder().encode(value);
    }
  }

  if (value && typeof value === 'object') {
    const nestedValues = [
      value.signature,
      value.signedData,
      value.data,
      value.result,
    ];

    for (const nestedValue of nestedValues) {
      if (nestedValue == null) {
        continue;
      }

      try {
        return toUint8Array(nestedValue);
      } catch {
        // Try the next known field.
      }
    }
  }

  throw new Error('Unable to read signed payload from Pera Wallet.');
}

export function bytesToBase64(bytes) {
  const chunks = [];
  const chunkSize = 0x8000;

  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    const slice = bytes.subarray(offset, offset + chunkSize);
    chunks.push(String.fromCharCode(...slice));
  }

  return btoa(chunks.join(''));
}

export function buildSignInMessage({ walletAddress, nonce, issuedAt, origin }) {
  const normalizedWallet = (walletAddress || '').trim().toUpperCase();
  const originLine = origin ? `Origin: ${origin}\n` : '';

  return (
    'Sign in to SentinelX\n' +
    `Address: ${normalizedWallet}\n` +
    originLine +
    `Nonce: ${nonce}\n` +
    `Issued At: ${issuedAt}`
  );
}

export async function connectPeraWallet(expectedAddress) {
  let accounts = [];

  try {
    accounts = await peraWallet.reconnectSession();
  } catch {
    accounts = [];
  }

  if (!accounts?.length) {
    accounts = await peraWallet.connect();
  }

  if (!accounts?.length) {
    throw new Error('No Algorand account connected in Pera Wallet.');
  }

  if (!expectedAddress) {
    return accounts[0];
  }

  const normalizedExpected = expectedAddress.trim().toUpperCase();
  const matchingAccount = accounts.find(
    (account) => account.trim().toUpperCase() === normalizedExpected,
  );

  if (!matchingAccount) {
    throw new Error('Please connect the same Algorand account in Pera Wallet to continue.');
  }

  return matchingAccount;
}

export async function signMessageWithPera(message, signerAddress) {
  const activeAddress = await connectPeraWallet(signerAddress);
  const encodedMessage = new TextEncoder().encode(message);
  const signedPayload = await peraWallet.signData(
    [
      {
        data: encodedMessage,
        message: 'SentinelX authentication',
      },
    ],
    activeAddress,
  );

  const signatureBytes = toUint8Array(Array.isArray(signedPayload) ? signedPayload[0] : signedPayload);
  return bytesToBase64(signatureBytes);
}

export function getAlgorandExplorerUrl(txHash) {
  if (!txHash) {
    return null;
  }

  return `${DEFAULT_EXPLORER_BASE.replace(/\/+$/, '')}/${txHash}/`;
}
