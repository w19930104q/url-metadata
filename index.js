// In Node.js, fetch via undici with SSRF protection from the filtering
// dispatcher in `lib/node-fetch-stack` (connect-time IP validation,
// DNS-rebinding safe). See that module for the preserved contract.
const { fetch: nodeFetch, useAgent } = require('./lib/node-fetch-stack')
const main = require('./main')
const resolveFields = require('./lib/resolve-fields')

module.exports = function (url, options) {
  return main(url, options, nodeFetch, useAgent)
}

// Result-shaping helpers, exposed on the public surface so consumers can
// filter an already-parsed result without re-fetching (single source of
// truth; used internally by the parser too):
//   resolveFields(fields) -> validate a `fields` selection (throws on bad input)
//   selectFields(metadata, fields) -> project a full result to the selection
//   isEmpty(value) -> the `omitEmpty` predicate
module.exports.resolveFields = resolveFields
module.exports.selectFields = resolveFields.selectFields
module.exports.isEmpty = resolveFields.isEmpty
