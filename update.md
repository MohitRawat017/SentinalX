# 🛡️ SentinelX – Audit Page Refactor (Demo-Friendly Version)

## 🎯 Objective

Refactor the existing **On-Chain Audit Trail** page to make it:

* Easy for non-technical judges to understand
* Demo-friendly
* One-click verifiable
* Less crypto-heavy in terminology

⚠️ Backend logic must remain unchanged.
Only UI and frontend logic should be updated.

---

# 1️⃣ Page Title Update

## Replace:

"On-Chain Audit Trail"

## With:

"Security Evidence & Blockchain Proofs"

### Subtitle:

"Tamper-proof security logs anchored on Ethereum"

### Example JSX Update

```jsx
<h1 className="text-2xl font-semibold">
  Security Evidence & Blockchain Proofs
</h1>
<p className="text-sm text-gray-400">
  Tamper-proof security logs anchored on Ethereum
</p>
```

---

# 2️⃣ Rename Confusing Labels

## Replace UI Labels

| Old Label              | New Label                   |
| ---------------------- | --------------------------- |
| Verify Event Inclusion | Verify Security Event Proof |
| Event Hash             | Event ID (Event Hash)       |
| Merkle Root            | Batch Proof Root            |
| Verify Inclusion Proof | Verify Proof                |

### JSX Example

```jsx
<h2 className="text-lg font-medium">
  Verify Security Event Proof
</h2>

<label>
  Event ID (Event Hash)
</label>

<label>
  Batch Proof Root
</label>

<button>
  Verify Proof
</button>
```

---

# 3️⃣ Add "Use Sample Event" Autofill Button

## Purpose

Allow judges to instantly verify an event without manual copy-paste.

## UI Requirements

* Secondary / outline style button
* Placed next to "Verify Proof" button

### Example Button (Tailwind)

```jsx
<button
  onClick={handleUseSample}
  className="border border-gray-500 text-gray-300 px-4 py-2 rounded-md hover:bg-gray-700"
>
  Use Sample Event
</button>
```

---

# 4️⃣ Autofill Logic Implementation

## State Assumptions

```jsx
const [eventHash, setEventHash] = useState("")
const [merkleRoot, setMerkleRoot] = useState("")
```

## Batches Data Structure (Assumed)

```js
batches = [
  {
    id: "batch_1",
    root: "0xabc...",
    events: [
      { hash: "0x123..." },
      { hash: "0x456..." }
    ]
  }
]
```

## Autofill Handler

```jsx
const handleUseSample = () => {
  if (!batches || batches.length === 0) return

  const firstBatch = batches[0]
  if (!firstBatch.events || firstBatch.events.length === 0) return

  const firstEvent = firstBatch.events[0]

  setEventHash(firstEvent.hash)
  setMerkleRoot(firstBatch.root)
}
```

## Graceful Empty Handling

If no batches exist:

* Disable button
* Or show toast: "No sample events available"

Example:

```jsx
disabled={!batches?.length}
```

---

# 5️⃣ Helper Text Under Inputs

## Under Event ID Input

"Unique fingerprint of a single security event"

## Under Batch Root Input

"Blockchain proof representing a batch of events"

### JSX Example

```jsx
<p className="text-xs text-gray-500 mt-1">
  Unique fingerprint of a single security event
</p>
```

---

# 6️⃣ Verification Result Messages

## Success Message

"✅ Event is cryptographically proven to exist on-chain"

## Failure Message

"❌ Event not found in this batch"

### Example State

```jsx
const [verificationResult, setVerificationResult] = useState(null)
```

### Render Feedback

```jsx
{verificationResult === 'success' && (
  <div className="text-green-400 mt-3">
    ✅ Event is cryptographically proven to exist on-chain
  </div>
)}

{verificationResult === 'failure' && (
  <div className="text-red-400 mt-3">
    ❌ Event not found in this batch
  </div>
)}
```

---

# 7️⃣ Demo Flow (Final Experience)

Judge Flow:

1. Click "Use Sample Event"
2. Fields auto-populate
3. Click "Verify Proof"
4. Instantly see success message

Zero crypto knowledge required.

---

# 8️⃣ Why This Improves Judge Experience

Before:

* Manual copy-paste
* Crypto-heavy terminology
* Confusing labels

After:

* One-click verification
* Clear explanations
* Professional terminology
* Immediate success feedback

This shifts perception from:
"Complex crypto page"
To:
"Security evidence system"

---

# 9️⃣ Important Constraints

* Do NOT modify backend proof logic
* Do NOT modify smart contract
* Do NOT modify proof validation function
* Only improve UI + add autofill helper

---

# 🔥 Final Outcome

The page becomes:

✔ Judge-friendly
✔ Self-explanatory
✔ Demo-safe
✔ Low-risk during presentation
✔ Emotionally satisfying (instant green checkmark)

---

End of Audit Page Refactor Plan.
