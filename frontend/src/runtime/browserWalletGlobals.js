import { Buffer } from 'buffer';

let walletGlobalsReady = false;

function createProcessShim() {
  const nextTick = (callback, ...args) => {
    if (typeof callback !== 'function') {
      return;
    }

    if (typeof queueMicrotask === 'function') {
      queueMicrotask(() => callback(...args));
      return;
    }

    Promise.resolve().then(() => callback(...args));
  };

  return {
    browser: true,
    env: {},
    nextTick,
  };
}

function defineMutableGlobal(key, value) {
  if (typeof globalThis[key] !== 'undefined') {
    return globalThis[key];
  }

  Object.defineProperty(globalThis, key, {
    value,
    configurable: true,
    writable: true,
  });

  return value;
}

export function ensureBrowserWalletGlobals() {
  if (walletGlobalsReady || typeof globalThis === 'undefined') {
    return;
  }

  const runtime = globalThis;
  const processShim = defineMutableGlobal('process', createProcessShim());

  defineMutableGlobal('global', runtime);
  defineMutableGlobal('Buffer', Buffer);

  processShim.env ??= {};
  processShim.browser ??= true;
  processShim.nextTick ??= createProcessShim().nextTick;

  walletGlobalsReady = true;
}

ensureBrowserWalletGlobals();
