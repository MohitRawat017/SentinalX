const DEFAULT_EXPLORER_BASE =
  import.meta.env.VITE_ALGO_EXPLORER_TX_BASE ||
  'https://testnet.explorer.perawallet.app/tx/';
const DEFAULT_PERA_CHAIN_ID = 416002;
const VALID_PERA_CHAIN_IDS = new Set([4160, 416001, 416002, 416003]);
const PERA_MODAL_WRAPPER_ID = 'pera-wallet-connect-modal-wrapper';
const WEB_WALLET_OPTION_ID = 'web-wallet-option';
const MOBILE_WALLET_OPTION_ID = 'mobile-wallet-option';

function resolvePeraChainId() {
  const configuredChainId = Number(import.meta.env.VITE_ALGO_CHAIN_ID || DEFAULT_PERA_CHAIN_ID);

  return VALID_PERA_CHAIN_IDS.has(configuredChainId)
    ? configuredChainId
    : DEFAULT_PERA_CHAIN_ID;
}

let peraWalletPromise = null;

export const DEMO_WALLET =
  'SAHBJDRHHRR72JHTWSXZR5VHQQUVC7S757TJZI656FWSDO3TZZWV3IGJV4';
export const DEMO_LOGIN_SIGNATURE = `0x${'a'.repeat(130)}`;
export const DEMO_STEP_UP_SIGNATURE = `0x${'b'.repeat(130)}`;

export function isMobilePeraFlow() {
  if (typeof navigator === 'undefined') {
    return false;
  }

  const userAgent = navigator.userAgent || navigator.vendor || '';
  const isTouchMac = /Macintosh/i.test(userAgent) && navigator.maxTouchPoints > 1;

  return (
    /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini|Mobile/i.test(userAgent) ||
    isTouchMac
  );
}

function promoteDesktopQrFlow() {
  if (typeof document === 'undefined' || isMobilePeraFlow()) {
    return () => {};
  }

  const applyQrOnlyMode = () => {
    const modalWrapper = document.getElementById(PERA_MODAL_WRAPPER_ID);
    const modal = modalWrapper?.querySelector('pera-wallet-connect-modal');
    const desktopMode = modal?.shadowRoot?.querySelector('pera-wallet-modal-desktop-mode');
    const desktopRoot = desktopMode?.shadowRoot;

    if (!desktopRoot) {
      return false;
    }

    const webWalletOption = desktopRoot.getElementById(WEB_WALLET_OPTION_ID);
    const mobileWalletOption = desktopRoot.getElementById(MOBILE_WALLET_OPTION_ID);

    webWalletOption?.remove();
    mobileWalletOption?.classList.add('pera-wallet-accordion-item--active');
    desktopRoot
      .querySelectorAll('.pera-wallet-accordion-item')
      .forEach((item) => {
        if (item.id !== MOBILE_WALLET_OPTION_ID) {
          item.classList.remove('pera-wallet-accordion-item--active');
        }
      });

    const downloadDescription = desktopRoot.querySelector(
      '.pera-wallet-connect-modal-desktop-mode__download-pera-description',
    );

    if (downloadDescription) {
      downloadDescription.textContent = 'Scan this QR code with Pera Wallet on your phone.';
    }

    return true;
  };

  if (applyQrOnlyMode()) {
    return () => {};
  }

  const observer = new MutationObserver(() => {
    if (applyQrOnlyMode()) {
      observer.disconnect();
    }
  });

  observer.observe(document.body, { childList: true, subtree: true });

  const timeoutId = window.setTimeout(() => {
    observer.disconnect();
  }, 10000);

  return () => {
    window.clearTimeout(timeoutId);
    observer.disconnect();
  };
}

async function getPeraWallet() {
  if (!peraWalletPromise) {
    peraWalletPromise = import('@perawallet/connect').then(
      ({ PeraWalletConnect }) =>
        new PeraWalletConnect({
          chainId: resolvePeraChainId(),
          singleAccount: true,
        }),
    );
  }

  return peraWalletPromise;
}

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

async function resetUnsupportedDesktopSession(peraWallet, accounts) {
  if (!accounts?.length || isMobilePeraFlow() || peraWallet.platform !== 'web') {
    return accounts;
  }

  await peraWallet.disconnect();
  return [];
}

export async function connectPeraWallet(expectedAddress) {
  const peraWallet = await getPeraWallet();
  let accounts = [];

  try {
    accounts = await peraWallet.reconnectSession();
  } catch {
    accounts = [];
  }

  accounts = await resetUnsupportedDesktopSession(peraWallet, accounts);

  if (!accounts?.length) {
    const stopQrPromotion = promoteDesktopQrFlow();

    try {
      accounts = await peraWallet.connect();
    } finally {
      stopQrPromotion();
    }
  }

  if (!accounts?.length) {
    throw new Error('No Algorand account connected in Pera Wallet.');
  }

  if (!isMobilePeraFlow() && peraWallet.platform === 'web') {
    await peraWallet.disconnect();
    throw new Error(
      'Desktop sign-in must be approved with Pera Wallet on your phone. Scan the QR code in the Pera modal to continue.',
    );
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
  const peraWallet = await getPeraWallet();
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
