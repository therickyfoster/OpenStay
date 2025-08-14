# PART 1 — Architecture & Security Hardening

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    OpenStay Production Architecture             │
├─────────────────────────────────────────────────────────────────┤
│  UI Layer (Single HTML File)                                   │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐              │
│  │   Listing   │ │  Booking    │ │   Inbox     │              │
│  │  Manager    │ │  Calendar   │ │  Messages   │              │
│  └─────────────┘ └─────────────┘ └─────────────┘              │
├─────────────────────────────────────────────────────────────────┤
│  Security Layer                                                │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐              │
│  │  Input      │ │   Crypto    │ │  Receipt    │              │
│  │ Validation  │ │   Vault     │ │  Signing    │              │
│  └─────────────┘ └─────────────┘ └─────────────┘              │
├─────────────────────────────────────────────────────────────────┤
│  Data Layer                                                     │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐              │
│  │  IndexedDB  │ │    OPFS     │ │ BroadcastCh │              │
│  │  Structured │ │    Media    │ │  Multi-tab  │              │
│  └─────────────┘ └─────────────┘ └─────────────┘              │
├─────────────────────────────────────────────────────────────────┤
│  Sync Layer                                                     │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐              │
│  │   WebRTC    │ │  Firebase   │ │   Worker    │              │
│  │    P2P      │ │  Optional   │ │  Background │              │
│  └─────────────┘ └─────────────┘ └─────────────┘              │
└─────────────────────────────────────────────────────────────────┘
```

## Data Schema (IndexedDB Stores)

```javascript
// Store: users (keyPath: 'id')
{
  id: string,           // handle/username
  publicKey?: string,   // ECDSA P-256 for signatures
  created: number,      // timestamp
  profile: {
    name?: string,
    bio?: string,
    verified: boolean
  }
}

// Store: listings (keyPath: 'id')
{
  id: string,           // UUID
  host: string,         // user.id
  title: string,
  description: string,
  price: number,
  currency: string,
  location?: string,
  tags: string[],
  media: string[],      // media.id references
  availability: {       // per-date availability
    [date]: {           // YYYY-MM-DD
      available: boolean,
      maxGuests?: number,
      priceOverride?: number
    }
  },
  created: number,
  updated: number
}

// Store: bookings (keyPath: 'id')
{
  id: string,           // UUID
  listingId: string,
  host: string,
  guest: string,
  status: 'requested'|'confirmed'|'declined'|'canceled',
  checkIn: string,      // YYYY-MM-DD
  checkOut: string,     // YYYY-MM-DD
  guests: number,
  totalPrice: number,
  currency: string,
  created: number,
  confirmed?: number,   // timestamp
  hash?: string,        // SHA-256 for tamper detection
  signature?: string    // ECDSA signature (optional)
}

// Store: messages (keyPath: 'id')
{
  id: string,           // UUID
  from: string,         // user.id
  to: string,           // user.id
  subject: string,
  body: string,
  type: 'booking'|'system'|'chat',
  refId?: string,       // booking.id or listing.id
  unread: boolean,
  created: number
}

// Store: media (keyPath: 'id')
{
  id: string,           // UUID
  listingId?: string,
  name: string,
  mimeType: string,
  size: number,
  opfsHandle?: FileSystemFileHandle,  // OPFS when available
  blob?: Blob,          // IndexedDB fallback
  created: number
}

// Store: meta (keyPath: 'key')
{
  key: string,          // 'schema_version', 'last_sync', etc.
  value: any,
  updated: number
}
```

## Booking State Machine

```
┌─────────────┐    confirm()     ┌─────────────┐
│  requested  │─────────────────→│  confirmed  │
│             │                  │             │
└─────────────┘                  └─────────────┘
       │                                │
       │ decline()                      │ cancel()
       ↓                                ↓
┌─────────────┐                  ┌─────────────┐
│  declined   │                  │  canceled   │
│             │                  │             │
└─────────────┘                  └─────────────┘

Rules:
- Only host can confirm/decline requests
- Only guest can cancel confirmed bookings
- No state changes after declined/canceled
- All transitions logged with timestamps
```

## Security Considerations

### Content Security Policy
```html
<!-- CSP Headers (when served over HTTP) -->
<!-- 
default-src 'self'; 
script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; 
style-src 'self' 'unsafe-inline'; 
connect-src 'self' https://cdn.jsdelivr.net wss: https:; 
worker-src 'self' blob:; 
img-src 'self' blob: data:;
-->
```

**Tradeoffs:**
- `'unsafe-inline'` required for single-file execution
- Consider nonce-based CSP for production deployments
- blob: workers needed for inline worker construction

### Input Validation Strategy
```javascript
// Schema validation functions
function validateListing(data) {
  return {
    title: sanitizeText(data.title, 100),
    description: sanitizeText(data.description, 1000),
    price: Math.max(0, Number(data.price) || 0),
    tags: (data.tags || []).slice(0, 10).map(t => sanitizeText(t, 30))
  };
}

function sanitizeText(str, maxLength) {
  return String(str || '').trim().slice(0, maxLength)
    .replace(/[<>'"&]/g, ''); // Basic XSS prevention
}
```

### Cryptographic Security
- **Key Derivation**: PBKDF2-SHA256 (150k iterations) default; Argon2id WASM when online
- **Encryption**: AES-GCM-256 for data export/import
- **Signatures**: ECDSA P-256 for booking receipts (optional)
- **Hashing**: SHA-256 for booking integrity

## Sync Protocol & Conflict Resolution

### P2P Merge Rules
```javascript
// Conflict resolution by entity type
const MERGE_RULES = {
  listings: 'last-write-wins',      // by updated timestamp
  bookings: 'state-machine',        // respect booking state transitions
  messages: 'append-only',          // never overwrite, dedupe by ID
  users: 'merge-profiles'           // combine profile fields
};

// Idempotent merge function
function mergeBooking(local, remote) {
  // Booking state machine enforcement
  const validTransitions = {
    'requested': ['confirmed', 'declined'],
    'confirmed': ['canceled'],
    'declined': [],
    'canceled': []
  };
  
  if (local.updated > remote.updated) return local;
  if (validTransitions[local.status]?.includes(remote.status)) {
    return remote;
  }
  return local; // Invalid transition, keep local
}
```

### Rate Limiting (Client-Side)
```javascript
// Simple token bucket for API calls
class RateLimiter {
  constructor(maxTokens, refillRate) {
    this.maxTokens = maxTokens;
    this.tokens = maxTokens;
    this.refillRate = refillRate;
    this.lastRefill = Date.now();
  }
  
  tryConsume() {
    this.refill();
    if (this.tokens > 0) {
      this.tokens--;
      return true;
    }
    return false;
  }
  
  refill() {
    const now = Date.now();
    const elapsed = now - this.lastRefill;
    this.tokens = Math.min(this.maxTokens, 
      this.tokens + (elapsed * this.refillRate / 1000));
    this.lastRefill = now;
  }
}
```

## Threat Model & Mitigations

| Threat | Impact | Mitigation |
|--------|--------|------------|
| XSS | High | Input sanitization, textContent usage, CSP |
| Data tampering | Medium | Cryptographic hashing, optional signatures |
| Key theft | High | Client-side only storage, secure derivation |
| Phishing | Medium | URL verification prompts, education |
| Supply chain | High | Subresource integrity, lazy loading |
| Man-in-middle | Medium | HTTPS enforcement, certificate pinning notes |
| Replay attacks | Low | Timestamp validation, nonce usage |
| DoS (local) | Low | Rate limiting, input size limits |

## Performance Targets

- **LCP**: < 2.5s (single file advantage)
- **INP**: < 200ms (Web Workers for heavy tasks)
- **Memory**: < 50MB for 1000 listings + media
- **Storage**: Efficient OPFS usage, IndexedDB cleanup
- **Worker Tasks**: Offload hashing, parsing, crypto operations

## Browser Compatibility Matrix

| Feature | Chrome/Edge | Safari | Firefox | Fallback |
|---------|-------------|--------|---------|----------|
| IndexedDB | ✅ | ✅ | ✅ | localStorage (limited) |
| OPFS | ✅ | ❌ | ❌ | IndexedDB Blob |
| WebGPU | ✅ | ⚠️ | ❌ | CPU fallback |
| WebRTC | ✅ | ✅ | ✅ | Manual data transfer |
| Web Workers | ✅ | ✅ | ✅ | Main thread fallback |
| WebCrypto | ✅ | ✅ | ✅ | None (required) |

---

**Next**: PART 2 will contain the complete production-grade single-file HTML implementation with all security hardening, validation, and progressive enhancements described above.
