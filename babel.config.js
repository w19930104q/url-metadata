// Used by Jest only (via babel-jest) to compile ESM test files
// (ex: test/esm.test.js) to CommonJS for the test runner.
// Not published: excluded by the `files` whitelist in package.json.
module.exports = {
  presets: [['@babel/preset-env', { targets: { node: 'current' } }]]
}
