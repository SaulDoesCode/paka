/**
 * Creates a paka object with HTTP request methods and token management.
 * @param {string} urlRoot - The root URL for the requests.
 * @param {Set} tokens - A set of tokens for authentication.
 * @param {Object} h - An object for extending the paka object.
 * @returns {Object} - The paka object.
 */
const paka = (urlRoot = '/', tokens = new Set(), h = Object.create(null)) => Object.assign(h, {
/**
 * Performs a GET request.
 * @param {string} file - The file path.
 * @returns {Promise<Response>} - A promise that resolves to the response object.
 */
async get(file) {
    return await fetch(urlRoot + file + '?tk=' + h.takeToken())
},

/**
 * Performs a POST request.
 * @param {string} file - The file path.
 * @param {any} data - The data to send in the request body.
 * @param {Object} fetchOptions - Additional fetch options.
 * @returns {Promise<Response>} - A promise that resolves to the response object.
 */
async post(file, data, fetchOptions = {}) {
    return await fetch(urlRoot + file + '?tk=' + h.takeToken(), Object.assign(fetchOptions, {
    method: 'POST',
    body: data
    }))
},

/**
 * Performs a DELETE request.
 * @param {string} file - The file path.
 * @returns {Promise<Response>} - A promise that resolves to the response object.
 */
async delete(file) {
    return await fetch(urlRoot + file + '?tk=' + h.takeToken(), {
    method: 'DELETE'
    })
},

/**
 * Takes a token from the available tokens set.
 * @returns {string | undefined} - The taken token, or undefined if no tokens are available.
 */
takeToken() {
    const token = tokens.values().next().value
    if (tokens.delete(token)) return token
},

/**
 * Appends the token parameter to the provided URL.
 * @param {string} url - The URL to tokenate.
 * @returns {string} - The tokenated URL.
 */
tokenate(url) {
    return `${url}?tk=${h.takeToken()}`
},

/**
 * Adds tokens to the available tokens set.
 * @param {...string} tkns - Tokens to add.
 */
feed(...tkns) {
    tokens.add(...tkns)
}
})
  
/**
 * Creates a paka object with pre-defined tokens.
 * @param {...string} tkns - Tokens for authentication.
 * @returns {Function} - The paka function that accepts the URL root.
 */
paka.fromTokens = (...tkns) => (urlRoot = '/') => paka(urlRoot, new Set(tkns))

  /**
 * Generates tokens by making a POST request to the server.
 * @param {string} pwd - The password to use for generating the tokens.
 * @param {number} count - The number of tokens to generate (default: 1).
 * @returns {Promise<Array<string>>} - A promise that resolves to an array of generated tokens.
 */
paka.makeTokens = async (pwd, count = 1) => {
 const res = await fetch('/make-tokens/' + count, { method: 'POST', body: pwd })
 if (!res.ok) {
    throw new Error('Failed to generate tokens. Status ' + response.status);
 }
 return await res.json()
}
  
export default paka
  