// Node.js request stack: undici `fetch` + a connect-time IP-filtering
// dispatcher (SSRF protection). Replaces the previous `node-fetch` v2 +
// `request-filtering-agent` pairing while preserving its public contract:
//
//   - `useAgent(url, options)` keeps its signature; returns a per-hop
//     undici Dispatcher instead of an http(s).Agent
//   - `fetch(url, opts)` accepts the node-fetch v2 options this package
//     has always passed: `agent`, `timeout`, `size`, `compress`,
//     `redirect: 'manual'`, plus standard fetch init
//   - errors keep node-fetch v2's FetchError shape (`type`, `code`,
//     `errno`) and message formats
//   - the SSRF filter keeps request-filtering-agent's option names,
//     defaults, and error messages
//
// Security properties carried over:
//   - every redirect hop re-validates: `main.js` issues a fresh fetch per
//     hop, and each fetch resolves + validates its target independently
//   - DNS answers are validated inside the connection's own `lookup`
//     callback, and Node's dialer only ever receives validated addresses —
//     the addresses validated are the only ones the connection can use
//     (DNS-rebinding safe by construction, no TOCTOU window)
//   - `size` caps the DEcompressed body mid-stream (gzip-bomb safe)
//   - `timeout` bounds time-to-headers per hop, as node-fetch v2 did

const dns = require('node:dns')
const net = require('node:net')
const tls = require('node:tls')
const ipaddr = require('ipaddr.js')
const { Agent, fetch: undiciFetch } = require('undici')

// ---------------------------------------------------------------------------
// FetchError — mirror of node-fetch v2's FetchError. Callers (and this
// package's own tests) rely on `type`, `code`/`errno`, and the exact
// message formats produced below.
// ---------------------------------------------------------------------------
class FetchError extends Error {
  constructor (message, type, systemError) {
    super(message)
    this.name = 'FetchError'
    this.type = type
    // when err.type is `system`, err.code contains the system error code
    if (systemError) {
      this.code = this.errno = systemError.code
    }
  }
}

// ---------------------------------------------------------------------------
// SSRF filter — port of request-filtering-agent's validation logic
// (https://www.npmjs.com/package/request-filtering-agent), same option
// names, defaults, and error messages.
// ---------------------------------------------------------------------------
const DefaultRequestFilteringAgentOptions = {
  allowPrivateIPAddress: false,
  allowMetaIPAddress: false,
  allowIPAddressList: [],
  denyIPAddressList: []
}

function normalizeFilterOptions (options) {
  const opts = options || {}
  return {
    allowPrivateIPAddress: opts.allowPrivateIPAddress !== undefined
      ? opts.allowPrivateIPAddress
      : DefaultRequestFilteringAgentOptions.allowPrivateIPAddress,
    allowMetaIPAddress: opts.allowMetaIPAddress !== undefined
      ? opts.allowMetaIPAddress
      : DefaultRequestFilteringAgentOptions.allowMetaIPAddress,
    allowIPAddressList: opts.allowIPAddressList || DefaultRequestFilteringAgentOptions.allowIPAddressList,
    denyIPAddressList: opts.denyIPAddressList || DefaultRequestFilteringAgentOptions.denyIPAddressList
  }
}

// Check if an IP address matches an IP or CIDR in the list.
function matchIPAddress ({ targetAddress, ipAddressList, listName }) {
  for (const ipOrCIDR of ipAddressList) {
    if (net.isIP(ipOrCIDR) !== 0) {
      // single IP address
      if (ipOrCIDR === targetAddress.raw) return true
    } else {
      // CIDR
      try {
        const cidr = ipaddr.parseCIDR(ipOrCIDR)
        if (targetAddress.parsed.match(cidr)) return true
      } catch (e) {
        // not a valid CIDR, show warning
        console.warn(new Error(`[url-metadata] Invalid CIDR in ${listName}: ${ipOrCIDR}`, { cause: e }))
      }
    }
  }
  return false
}

// Returns an Error when the address is blocked, undefined when allowed.
function validateIPAddress ({ address, host, family }, options) {
  // if it is not an IP address, skip it
  if (net.isIP(address) === 0) return
  try {
    const parsedAddr = ipaddr.parse(address)
    // prefer allowed list
    if (options.allowIPAddressList.length > 0) {
      if (matchIPAddress({
        targetAddress: { raw: address, parsed: parsedAddr },
        ipAddressList: options.allowIPAddressList,
        listName: 'allowIPAddressList'
      })) {
        return // It is allowed
      }
    }
    const range = parsedAddr.range()
    if (!options.allowMetaIPAddress) {
      // address === "0.0.0.0" || address === "::"
      if (range === 'unspecified') {
        return new Error(`DNS lookup ${address}(family:${family}, host:${host}) is not allowed. Because, It is meta IP address.`)
      }
    }
    if (!options.allowPrivateIPAddress && range !== 'unicast') {
      return new Error(`DNS lookup ${address}(family:${family}, host:${host}) is not allowed. Because, It is private IP address.`)
    }
    if (options.denyIPAddressList.length > 0) {
      if (matchIPAddress({
        targetAddress: { raw: address, parsed: parsedAddr },
        ipAddressList: options.denyIPAddressList,
        listName: 'denyIPAddressList'
      })) {
        return new Error(`DNS lookup ${address}(family:${family}, host:${host}) is not allowed. Because It is defined in denyIPAddressList.`)
      }
    }
  } catch (error) {
    return error // if can not parse IP address, throw error
  }
}

// ---------------------------------------------------------------------------
// Filtering connector — undici `connect` function. Validation happens inside
// a custom `lookup`: every resolved address is validated, and only validated
// addresses are handed back to Node's dialer — which then dials exactly
// those addresses (with Happy Eyeballs across families, so a stalled first
// address never blocks the rest). The addresses validated are the only ones
// the connection can use: no TOCTOU window, no DNS-rebinding.
// The callback contract mirrors undici's own connector
// (lib/core/connect.js): invoke the callback exactly once, with the socket
// only after it has connected.
// ---------------------------------------------------------------------------

// dns.lookup-compatible function that validates every resolved address
// before returning them (same structure as request-filtering-agent's
// makeLookup).
function makeValidatingLookup (filterOptions) {
  return function validatingLookup (hostname, options, callback) {
    dns.lookup(hostname, { ...options, all: true }, (lookupErr, addresses) => {
      if (lookupErr) return callback(lookupErr)
      for (const { address, family } of addresses) {
        const validationError = validateIPAddress({ address, family, host: hostname }, filterOptions)
        if (validationError) return callback(validationError)
      }
      if (options.all) return callback(null, addresses)
      const { address, family } = addresses[0]
      callback(null, address, family)
    })
  }
}

function makeFilteringConnect (filterOptions) {
  const lookup = makeValidatingLookup(filterOptions)
  return function filteringConnect (opts, callback) {
    // guard against a double callback (connect error after success)
    let called = false
    const done = (err, socket) => {
      if (called) return
      called = true
      callback(err, socket)
    }

    const hostname = opts.hostname
    const port = Number(opts.port) || (opts.protocol === 'https:' ? 443 : 80)

    // Direct-IP url (ex: http://127.0.0.1/...): no DNS lookup happens
    // inside connect, so validate the literal here.
    if (net.isIP(hostname) !== 0) {
      const validationError = validateIPAddress({ address: hostname, host: hostname }, filterOptions)
      if (validationError) return done(validationError)
    }

    let socket
    if (opts.protocol === 'https:') {
      socket = tls.connect({
        port,
        host: hostname,
        // SNI only makes sense for hostnames, never IP literals
        servername: net.isIP(hostname) ? undefined : (opts.servername || hostname),
        ALPNProtocols: ['http/1.1'],
        lookup
      })
      socket.once('secureConnect', () => done(null, socket))
    } else {
      socket = net.connect({ port, host: hostname, lookup })
      socket.once('connect', () => done(null, socket))
    }
    // stays attached after handoff (undici's own connector does the same);
    // the `called` guard makes post-handoff errors a no-op here
    socket.on('error', (err) => done(err))
  }
}

// ---------------------------------------------------------------------------
// useAgent — same signature as request-filtering-agent's. Default options
// share a process-wide dispatcher (like rfa's global agents); custom options
// get a fresh dispatcher per call, same as before.
// ---------------------------------------------------------------------------
let globalDispatcher
function useAgent (url, options) {
  if (!options) {
    if (!globalDispatcher) {
      globalDispatcher = new Agent({ connect: makeFilteringConnect(normalizeFilterOptions()) })
    }
    return globalDispatcher
  }
  return new Agent({ connect: makeFilteringConnect(normalizeFilterOptions(options)) })
}

// ---------------------------------------------------------------------------
// fetch — node-fetch v2-compatible wrapper around undici's fetch.
// ---------------------------------------------------------------------------

// Response statuses whose bodies are always null (Response constructor
// rejects a body for these).
const NULL_BODY_STATUS = new Set([101, 204, 205, 304])

// `size` cap on the DEcompressed body, enforced mid-stream: erroring the
// transform cancels the source stream (closing the socket), so an
// over-limit or gzip-bomb body stops downloading here instead of after
// being fully buffered. node-fetch v2 enforced the same semantics.
function limitBodySize (response, url, size) {
  let received = 0
  const limiter = new TransformStream({
    transform (chunk, controller) {
      received += chunk.byteLength
      if (received > size) {
        controller.error(new FetchError(`content size at ${url} over limit: ${size}`, 'max-size'))
        return
      }
      controller.enqueue(chunk)
    }
  })
  return new Response(response.body.pipeThrough(limiter), {
    status: response.status,
    statusText: response.statusText,
    headers: response.headers
  })
}

// Re-shape undici's errors into node-fetch v2's FetchError contract.
function translateError (err, url, timedOut) {
  if (timedOut) {
    return new FetchError(`network timeout at: ${url}`, 'request-timeout')
  }
  // undici wraps transport failures in `TypeError: fetch failed` with the
  // underlying error on `cause`; node-fetch v2 surfaced the cause directly.
  const cause = (err && err.cause) || err
  const message = cause && cause.message ? cause.message : String(err)
  return new FetchError(`request to ${url} failed, reason: ${message}`, 'system', cause)
}

async function nodeFetch (url, requestOpts = {}) {
  // node-fetch v2 rejected non-absolute/non-HTTP(S) urls up front (TypeError)
  let parsed
  try {
    parsed = new URL(url)
  } catch {
    throw new TypeError('Only absolute URLs are supported')
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new TypeError('Only HTTP(S) protocols are supported')
  }

  const {
    agent,
    timeout = 0,
    size = 0,
    compress = true,
    // Browser-only options main.js forwards for the browser entry; node-fetch
    // v2 silently ignored them, and forwarding them changes the request
    // fingerprint (undici would emit `sec-fetch-mode` / `cache-control`).
    cache: _cache,
    mode: _mode,
    ...init
  } = requestOpts

  // `agent` mirrors node-fetch v2: when a function, it is called with the
  // parsed URL and its return value is used; otherwise the value itself.
  // What changed is the type: an undici Dispatcher, not an http.Agent.
  const candidate = typeof agent === 'function' ? agent(parsed) : agent
  if (candidate) {
    if (typeof candidate.dispatch !== 'function') {
      throw new Error('`agent` must be an undici Dispatcher (or a function returning one); http.Agent instances are no longer supported')
    }
    init.dispatcher = candidate
  }

  // node-fetch v2's `timeout` bounded time-to-headers per hop (it cleared
  // the timer once response headers arrived); reproduce that with an
  // AbortController whose timer is cleared right after fetch() resolves.
  let timedOut = false
  let timer
  const controller = new AbortController()
  init.signal = controller.signal
  if (timeout > 0) {
    timer = setTimeout(() => {
      timedOut = true
      controller.abort()
    }, timeout)
    if (timer.unref) timer.unref()
  }

  // `compress: false` asked node-fetch to skip auto-decompression. undici
  // always decompresses per the fetch spec, so request an identity
  // encoding instead — servers then send the body uncompressed.
  if (compress === false) {
    const headers = new Headers(init.headers || {})
    if (!headers.has('accept-encoding')) headers.set('accept-encoding', 'identity')
    init.headers = headers
  }

  let response
  try {
    response = await undiciFetch(url, init)
  } catch (err) {
    throw translateError(err, url, timedOut)
  } finally {
    if (timer) clearTimeout(timer)
  }

  if (size > 0 && response.body && !NULL_BODY_STATUS.has(response.status)) {
    return limitBodySize(response, url, size)
  }
  return response
}

module.exports = {
  fetch: nodeFetch,
  useAgent,
  FetchError,
  // exported for tests
  validateIPAddress,
  normalizeFilterOptions,
  DefaultRequestFilteringAgentOptions
}
