const defaultUrlRoot = '/file/'

/**
 * Creates a paka client that spends tokens from its pool on each request.
 * @param {string} urlRoot - Root URL of the file routes, e.g. '/file/' or 'https://host:9797/file/'.
 * @param {Iterable<string>} tokens - Tokens to start with.
 * @param {Object} h - Object to extend into the client.
 * @returns {Object} - The paka client.
 */
const paka = (urlRoot = defaultUrlRoot, tokens = [], h = Object.create(null)) => {
  tokens = [...tokens]
  const base = urlRoot.replace(/file\/?$/, '')
  const listeners = new Set()
  const url = (path, tk) => `${path}?tk=${encodeURIComponent(tk)}`
  const file = name => urlRoot + encodeURIComponent(name)

  /** Takes a token, throwing if the pool is empty. */
  const need = () => {
    const tk = h.takeToken()
    if (tk === undefined) throw new Error('paka: out of tokens')
    return tk
  }

  // defineProperties rather than Object.assign, which would freeze the tokens getter into a snapshot
  return Object.defineProperties(h, Object.getOwnPropertyDescriptors({
    /**
     * Downloads a file.
     * @param {string} name - The file name.
     * @returns {Promise<Response>}
     */
    get: name => fetch(url(file(name), need())),

    /**
     * Uploads (or overwrites) a file.
     * @param {string} name - The file name.
     * @param {BodyInit} data - The file contents.
     * @param {RequestInit} fetchOptions - Extra fetch options.
     * @returns {Promise<Response>}
     */
    post: (name, data, fetchOptions = {}) =>
      fetch(url(file(name), need()), { ...fetchOptions, method: 'POST', body: data }),

    /**
     * Deletes a file.
     * @param {string} name - The file name.
     * @returns {Promise<Response>}
     */
    delete: name => fetch(url(file(name), need()), { method: 'DELETE' }),

    /**
     * Gets {filename, size, modified} for a file.
     * @param {string} name - The file name.
     * @returns {Promise<Response>}
     */
    info: name => fetch(url(base + 'file-info/' + encodeURIComponent(name), need())),

    /**
     * Lists all files as [{filename, size, modified}].
     * @returns {Promise<Response>}
     */
    list: () => fetch(url(base + 'files', need())),

    /**
     * Gets a token's {exp, uses, file, ops, payload} without spending it.
     * @param {string} tk - The token, defaults to the next one in the pool.
     * @returns {Promise<Response>}
     */
    tokenInfo: (tk = tokens[0]) => fetch(url(base + 'token', tk ?? '')),

    /** A copy of the tokens left in the pool. */
    get tokens() { return [...tokens] },

    /**
     * Takes the next token from the pool.
     * @returns {string | undefined} - The token, or undefined if the pool is empty.
     */
    takeToken() {
      const token = tokens.shift()
      listeners.forEach(l => l(token))
      return token
    },

    /**
     * Adds a listener called whenever a token is taken.
     * @param {Function} fn - Called with the taken token.
     * @param {boolean} once - Remove the listener after its first call.
     * @returns {Function} - Removes the listener.
     * @example
     * client.ifTaking(token => console.log('Token taken:', token))
     */
    ifTaking(fn, once = false) {
      if (!(fn instanceof Function)) return () => {}
      const l = once ? (...args) => { listeners.delete(l); return fn(...args) } : fn
      listeners.add(l)
      return () => listeners.delete(l)
    },

    /**
     * Appends a token to a URL, e.g. for <img src>.
     * @param {string} u - The URL.
     * @returns {string} - The tokenated URL.
     */
    tokenate: u => url(u, need()),

    /**
     * Adds tokens to the pool.
     * @param {...string} tkns - Tokens to add.
     */
    feed(...tkns) {
      tokens.push(...tkns)
    },
  }))
}

/**
 * Creates a paka client from tokens.
 * @param {...string} tkns - Tokens for authentication.
 * @returns {Function} - Takes the URL root and returns the client.
 */
paka.fromTokens = (...tkns) => (urlRoot = defaultUrlRoot) => paka(urlRoot, tkns)

const admin = async (path, body, json = false) => {
  const res = await fetch(path, {
    method: 'POST',
    body: json ? JSON.stringify(body) : body,
    headers: json ? { 'Content-Type': 'application/json' } : {},
  })
  const out = await res.json().catch(() => null)
  if (!res.ok) throw new Error(out?.error || `paka: request failed with status ${res.status}`)
  return out
}

/**
 * Generates single use tokens with the default lifetime.
 * @param {string} pwd - The admin password.
 * @param {number} count - How many tokens to make (default: 1).
 * @returns {Promise<Array<string>>}
 */
paka.makeTokens = (pwd, count = 1) => admin('/make-tokens/' + count, pwd)

/**
 * Generates tokens with options.
 * @param {Object} opts
 * @param {string} opts.pwd - The admin password.
 * @param {number} [opts.count=1] - How many tokens to make.
 * @param {number} [opts.uses=1] - How many requests each token is good for.
 * @param {number} [opts.ttl] - Lifetime in seconds.
 * @param {number} [opts.exp] - Absolute expiry in unix seconds (overrides ttl).
 * @param {string} [opts.file] - Only allow this file name.
 * @param {Array<'read'|'write'|'delete'|'list'>} [opts.ops] - Only allow these operations.
 * @param {any} [opts.payload] - JSON handed back by tokenInfo.
 * @returns {Promise<Array<string>>}
 */
paka.makeTokenRequest = opts => admin('/mktn', opts, true)

/** Removes expired tokens. Resolves to {removed}. */
paka.expireTokens = pwd => admin('/expire-tokens', pwd)

/** Removes every token. Resolves to {removed}. */
paka.revokeTokens = pwd => admin('/revoke-tokens', pwd)

/** Changes the admin password. */
paka.changePassword = (pwd, newPwd) => admin('/admin/change-password', { pwd, new_pwd: newPwd }, true)

/** Clears the server's gzip cache of static files. */
paka.clearStaticCache = pwd => admin('/remove-gz-files', pwd)

export default paka
