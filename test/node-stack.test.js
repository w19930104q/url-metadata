// Acceptance tests for the undici-based Node request stack
// (lib/node-fetch-stack.js) against LOCAL HTTP servers — no live network.
//
// Covers the contract the migration from `node-fetch` v2 +
// `request-filtering-agent` must preserve:
//   - SSRF filter: same options/messages; every redirect hop re-validated;
//     connections dial the validated IP literal (rebind-proof)
//   - `size` caps the DEcompressed body (gzip-bomb safe)
//   - `timeout` bounds time-to-headers
//   - error shape: FetchError-compatible (`type`, `code`, `errno`) and
//     `error.responseHeaders` on HTTP errors
//   - credential stripping on cross-host redirect hops
//
// Note: local servers are private IPs, so most tests pass
// `allowPrivateIPAddress: true`. That does NOT disable the filter —
// deny-lists/meta-IP checks still apply, and the default-deny behavior is
// asserted explicitly below (and in test/ssrf.test.js).
const http = require('node:http')
const zlib = require('node:zlib')
const urlMetadata = require('../index')
const { validateIPAddress, normalizeFilterOptions } = require('../lib/node-fetch-stack')

const HTML = '<!DOCTYPE html><html><head><meta charset="utf-8"><title>local ok</title></head><body><h1>hi</h1></body></html>'
const ALLOW_LOCAL = { allowPrivateIPAddress: true }

const servers = []
function startServer (handler) {
  return new Promise((resolve) => {
    const server = http.createServer(handler)
    server.listen(0, '127.0.0.1', () => {
      servers.push(server)
      resolve({ server, url: `http://127.0.0.1:${server.address().port}` })
    })
  })
}

afterAll(async () => {
  for (const server of servers) {
    server.closeAllConnections()
    await new Promise((resolve) => server.close(resolve))
  }
})

// -- pure filter unit tests (same messages as request-filtering-agent) --

test('filter: default options block private/meta IPs with rfa-compatible messages', () => {
  const opts = normalizeFilterOptions()
  expect(validateIPAddress({ address: '127.0.0.1', family: 4, host: 'localhost' }, opts).message)
    .toContain('is private IP address.')
  expect(validateIPAddress({ address: '10.1.2.3', family: 4, host: 'x' }, opts).message)
    .toContain('is private IP address.')
  expect(validateIPAddress({ address: '0.0.0.0', family: 4, host: 'x' }, opts).message)
    .toContain('is meta IP address.')
  expect(validateIPAddress({ address: '8.8.8.8', family: 4, host: 'x' }, opts)).toBeUndefined()
})

test('filter: allow/deny lists compose with allowPrivateIPAddress', () => {
  // allowPrivateIPAddress opens ranges, denyIPAddressList still wins
  const opts = normalizeFilterOptions({ allowPrivateIPAddress: true, denyIPAddressList: ['10.0.0.0/8'] })
  expect(validateIPAddress({ address: '127.0.0.1', family: 4, host: 'x' }, opts)).toBeUndefined()
  expect(validateIPAddress({ address: '10.9.9.9', family: 4, host: 'x' }, opts).message)
    .toContain('denyIPAddressList')
  // allowIPAddressList is checked first and beats the private-range block
  const allowed = normalizeFilterOptions({ allowIPAddressList: ['192.168.1.0/24'] })
  expect(validateIPAddress({ address: '192.168.1.20', family: 4, host: 'x' }, allowed)).toBeUndefined()
  expect(validateIPAddress({ address: '192.168.2.20', family: 4, host: 'x' }, allowed).message)
    .toContain('is private IP address.')
})

// -- live local-server tests --

test('default filter blocks a local server (defaults not loosened)', async () => {
  const { url } = await startServer((req, res) => res.end(HTML))
  await expect(urlMetadata(url)).rejects.toThrow('is private IP address.')
})

test('local fetch + parse works with allowPrivateIPAddress', async () => {
  const { url } = await startServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' })
    res.end(HTML)
  })
  const metadata = await urlMetadata(url, { requestFilteringAgentOptions: ALLOW_LOCAL })
  expect(metadata.title).toBe('local ok')
  expect(metadata.responseStatusCode).toBe(200)
  expect(metadata.url).toBe(url)
  expect(metadata.redirects.count).toBe(0)
})

test('cross-host redirect hop strips credentials; chain shape preserved', async () => {
  let hop2Headers
  const dest = await startServer((req, res) => {
    hop2Headers = req.headers
    res.writeHead(200, { 'content-type': 'text/html' })
    res.end(HTML)
  })
  const entry = await startServer((req, res) => {
    res.writeHead(302, { location: `${dest.url}/final` })
    res.end()
  })
  const metadata = await urlMetadata(`${entry.url}/start`, {
    requestFilteringAgentOptions: ALLOW_LOCAL,
    requestHeaders: {
      'User-Agent': 'url-metadata test',
      Authorization: 'Bearer hunter2',
      Cookie: 'session=abc123'
    }
  })
  // different port = different host = credentials stripped on hop 2
  expect(metadata.redirects.count).toBe(1)
  expect(metadata.redirects.chain[0].order).toBe(1)
  expect(metadata.redirects.chain[0].statusCode).toBe(302)
  expect(metadata.redirects.chain[0].url).toBe(`${entry.url}/start`)
  expect(metadata.redirects.chain[0].location).toBe(`${dest.url}/final`)
  expect(metadata.url).toBe(`${dest.url}/final`)
  expect(hop2Headers.authorization).toBe(undefined)
  expect(hop2Headers.cookie).toBe(undefined)
  expect(hop2Headers['user-agent']).toBe('url-metadata test')
})

test('every redirect hop is re-validated: allowed hop 1, denied hop 2', async () => {
  // hop 1 (127.0.0.1) is allowed; hop 2 targets a deny-listed range.
  // If hop 2 were not re-validated, this would attempt a real connection
  // to 10.255.255.1 instead of failing with the filter error.
  const entry = await startServer((req, res) => {
    res.writeHead(302, { location: 'http://10.255.255.1/secret' })
    res.end()
  })
  try {
    await urlMetadata(`${entry.url}/start`, {
      requestFilteringAgentOptions: {
        allowPrivateIPAddress: true,
        denyIPAddressList: ['10.0.0.0/8']
      }
    })
    throw new Error('should not get here')
  } catch (err) {
    // hop 2 was refused by the filter BEFORE connecting (no redirects
    // object on transport errors — same contract as node-fetch era, see
    // fail.test.js 'fails gracefully on DNS errors')
    expect(err.message).toContain('denyIPAddressList')
    expect(err.redirects).toBeUndefined()
  }
})

test('DNS-path validation: hostname resolving to a deny-listed IP is refused', async () => {
  const { url } = await startServer((req, res) => res.end(HTML))
  const port = new URL(url).port
  try {
    // `localhost` resolves to 127.0.0.1 (and possibly ::1); the deny list
    // must be consulted on the resolved addresses, not the hostname
    await urlMetadata(`http://localhost:${port}/`, {
      requestFilteringAgentOptions: {
        allowPrivateIPAddress: true,
        denyIPAddressList: ['127.0.0.0/8', '::1/128']
      }
    })
    throw new Error('should not get here')
  } catch (err) {
    expect(err.message).toContain('denyIPAddressList')
  }
})

test('size option caps the DEcompressed body (gzip bomb cut off mid-stream)', async () => {
  const bigHtml = '<!DOCTYPE html><html><head><title>big</title></head><body>' + 'x'.repeat(100000) + '</body></html>'
  const gzipped = zlib.gzipSync(Buffer.from(bigHtml))
  // the wire bytes are well under the limit; only the decompressed body exceeds it
  expect(gzipped.length).toBeLessThan(1000)
  const { url } = await startServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/html', 'content-encoding': 'gzip' })
    res.end(gzipped)
  })
  try {
    await urlMetadata(url, { requestFilteringAgentOptions: ALLOW_LOCAL, size: 1000 })
    throw new Error('should not get here')
  } catch (err) {
    expect(err.message).toContain('over limit: 1000')
  }
})

test('gzip responses decompress transparently when under the size cap', async () => {
  const gzipped = zlib.gzipSync(Buffer.from(HTML))
  const { url } = await startServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/html', 'content-encoding': 'gzip' })
    res.end(gzipped)
  })
  const metadata = await urlMetadata(url, { requestFilteringAgentOptions: ALLOW_LOCAL })
  expect(metadata.title).toBe('local ok')
})

test('timeout option bounds time-to-headers', async () => {
  const { url } = await startServer((req, res) => {
    // never respond; hold the socket
    setTimeout(() => {}, 5000)
  })
  const start = Date.now()
  try {
    await urlMetadata(url, { requestFilteringAgentOptions: ALLOW_LOCAL, timeout: 300 })
    throw new Error('should not get here')
  } catch (err) {
    expect(err.message).toContain('network timeout at:')
    expect(Date.now() - start).toBeLessThan(4000)
  }
})

test('transport errors keep the FetchError contract (type/code/errno)', async () => {
  // nothing listens on this port (reserved by starting + closing a server)
  const { server, url } = await startServer((req, res) => res.end(HTML))
  server.closeAllConnections()
  await new Promise((resolve) => server.close(resolve))
  // The first connect right after close can race the OS releasing the
  // listen socket (accepted-then-reset -> ECONNRESET); flush it, then the
  // next attempt gets the stable ECONNREFUSED shape.
  await urlMetadata(url, { requestFilteringAgentOptions: ALLOW_LOCAL }).catch(() => {})
  try {
    await urlMetadata(url, { requestFilteringAgentOptions: ALLOW_LOCAL })
    throw new Error('should not get here')
  } catch (err) {
    expect(err.message).toContain('ECONNREFUSED')
    expect(err.type).toBe('system')
    expect(err.code).toBe('ECONNREFUSED')
    expect(err.errno).toBe('ECONNREFUSED')
  }
})

test('HTTP errors carry statusCode and whitelisted responseHeaders', async () => {
  const { url } = await startServer((req, res) => {
    res.writeHead(500, { 'content-type': 'text/html', 'x-custom-trace': 'abc123' })
    res.end('<html><title>err</title></html>')
  })
  try {
    await urlMetadata(url, { requestFilteringAgentOptions: ALLOW_LOCAL })
    throw new Error('should not get here')
  } catch (err) {
    expect(err.message).toContain('response code 500')
    expect(err.statusCode).toBe(500)
    expect(err.responseHeaders).toBeDefined()
    expect(err.responseHeaders['x-custom-trace']).toBe('abc123')
  }
})

test('maxRedirects: 0 errors with unfollowedRedirect and chain intact', async () => {
  const entry = await startServer((req, res) => {
    res.writeHead(301, { location: 'http://example.com/elsewhere' })
    res.end()
  })
  try {
    await urlMetadata(`${entry.url}/start`, {
      requestFilteringAgentOptions: ALLOW_LOCAL,
      maxRedirects: 0
    })
    throw new Error('should not get here')
  } catch (err) {
    expect(err.message).toBe('too many redirects')
    expect(err.unfollowedRedirect).toBe(true)
    expect(err.redirects.count).toBe(1)
    expect(err.redirects.chain[0].location).toBe('http://example.com/elsewhere')
  }
})

test('header-only `network` mode works against a local server (no hang on drain)', async () => {
  const { url } = await startServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/html', etag: '"local"' })
    res.end(HTML)
  })
  const metadata = await urlMetadata(url, {
    requestFilteringAgentOptions: ALLOW_LOCAL,
    fields: ['network']
  })
  expect(metadata.responseStatusCode).toBe(200)
  expect(metadata.responseHeaders.etag).toBe('"local"')
  expect('title' in metadata).toBe(false)
  expect(metadata.performance.ttfbMs).toBeDefined()
})

test('malformed url keeps the node-fetch v2 message', async () => {
  await expect(urlMetadata('XYZ')).rejects.toThrow('Only absolute URLs are supported')
})

test('option `agent`: user-supplied undici Dispatcher overrides the filter', async () => {
  // A user dispatcher replaces the SSRF-filtering one entirely (documented
  // override) — this fetch to a private IP succeeds with no filter options.
  const { Agent } = require('undici')
  const { url } = await startServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/html' })
    res.end(HTML)
  })
  const metadata = await urlMetadata(url, { agent: new Agent() })
  expect(metadata.title).toBe('local ok')
})

test('option `agent`: legacy http.Agent is rejected with a clear error', async () => {
  const { url } = await startServer((req, res) => res.end(HTML))
  await expect(urlMetadata(url, { agent: new (require('node:http').Agent)() }))
    .rejects.toThrow('undici Dispatcher')
})
