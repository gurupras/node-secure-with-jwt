const jwt = require('jsonwebtoken')
const cookieParser = require('cookie-parser')
const { pathToRegexp } = require('path-to-regexp')

const debugLogger = require('debug-logger')

const debug = debugLogger('secure-with-jwt')

function checkArrayTypes (name, arr, innerTypes) {
  if (typeof innerTypes === 'string') {
    innerTypes = [innerTypes]
  }
  if (!Array.isArray(arr)) {
    throw new Error(`${name} is expected to be of type ${innerTypes.join(' or ')} or Array. Received '${typeof arr}'`)
  }
  for (const entry of arr) {
    if (!innerTypes.includes(typeof entry)) {
      throw new Error(`All ${name} entries are expected to be ${innerTypes.join(' or ')}. Received '${typeof entry}'`)
    }
  }
}

function getAllKeyFunctions (getKey, jwksClients, log) {
  const keyFunctions = []

  if (jwksClients && jwksClients.length > 0) {
    if (getKey && getKey.length > 0) {
      log.warn('Both, jwksClient and getKey were specified.. jwksClient will be prioritized')
    }
    for (const jwksClient of jwksClients) {
      keyFunctions.push((header, callback) => {
        jwksClient.getSigningKey(header.kid, (err, key) => {
          if (err) {
            return callback(err, null)
          }
          var signingKey = key.publicKey || key.rsaPublicKey
          callback(null, signingKey)
        })
      })
    }
  }

  // Add all getKey functions to keyFunctions
  if (getKey) {
    keyFunctions.push(...getKey)
  }
  return keyFunctions
}

async function verifyJWT (token, keyFunctions) {
  const errors = []
  for (const keyFn of keyFunctions) {
    try {
      const decoded = await new Promise(function (resolve, reject) {
        jwt.verify(token, keyFn, (err, decoded) => {
          if (err) {
            return reject(err)
          }
          resolve(decoded)
        })
      })
      return decoded
    } catch (e) {
      errors.push(e.message)
    }
  }
  const err = new Error('Failed to verify token')
  err.errors = errors
  throw err
}

function secureExpressWithJWT (app, { getKey, jwksClient, paths = '/api', ignore = [], log = debug }) {
  if (typeof paths !== 'string' && !paths) {
    throw new Error('Must specify at least one path')
  } else {
    if (typeof paths === 'string') {
      paths = [paths]
    }
  }
  checkArrayTypes('paths', paths, 'string')

  if (ignore !== null && ignore !== undefined) {
    if (typeof ignore === 'string') {
      ignore = [ignore]
    }
  }
  checkArrayTypes('ignore', ignore, 'string')

  if (getKey) {
    if (typeof getKey === 'function') {
      getKey = [getKey]
    }
  }
  if (getKey !== undefined) {
    checkArrayTypes('getKey', getKey, ['function'])
  }

  if (jwksClient) {
    if (!(jwksClient instanceof Array) && typeof jwksClient === 'object') {
      jwksClient = [jwksClient]
    }
  }
  if (jwksClient !== undefined) {
    checkArrayTypes('jwksClient', jwksClient, 'object')
  }

  // We need to add cookieParser
  // TODO: Figure out a way to check if this has already been added by the app
  // and if it has, does it matter if we add it again?
  app.use(cookieParser())

  const ignorePatterns = ignore.map((x) => pathToRegexp(x))
  const keyFunctions = getAllKeyFunctions(getKey, jwksClient, log)

  async function decodeAuthorizationHeader (req) {
    const { headers: { authorization = '' } } = req
    if (!authorization.startsWith('Bearer ')) {
      throw new Error('Invalid token')
    }
    const accessToken = authorization.substr(7)
    return verifyJWT(accessToken, keyFunctions)
  }

  async function middleware (req, res, next) {
    const { originalUrl, headers: { authorization = '' } } = req
    const ignoreMatch = ignorePatterns.find(pattern => pattern.test(originalUrl))
    if (ignoreMatch) {
      log.debug(`Skipping ${originalUrl} since it was matched by ${ignoreMatch}`)
      return next()
    }

    function unauthorized (error) {
      log.error(`Failing request: ${req.url} due to token.`, { authorization, error })
      res.status(401).send('Unauthorized')
    }
    try {
      req.decoded = await decodeAuthorizationHeader(req)
    } catch (e) {
      log.error(e)
      return unauthorized(e)
    }
    next()
  }

  for (const path of paths) {
    app.use(path, middleware)
  }
}

function secureSocketIOWithJWT (io, { getKey, jwksClient, log = debug }) {
  if (getKey) {
    if (typeof getKey === 'function') {
      getKey = [getKey]
    }
  }
  if (getKey !== undefined) {
    checkArrayTypes('getKey', getKey, ['function'])
  }

  if (jwksClient !== undefined) {
    if (!(jwksClient instanceof Array) && typeof jwksClient === 'object') {
      jwksClient = [jwksClient]
    }
  }
  if (jwksClient !== undefined) {
    checkArrayTypes('jwksClient', jwksClient, 'object')
  }

  const keyFunctions = getAllKeyFunctions(getKey, jwksClient, log)
  if (keyFunctions.length === 0) {
    throw new Error('Must specify getKey or jwksClient')
  }

  io.use(async (socket, next) => {
    try {
      const { handshake: { query: { token } } } = socket
      socket.decoded = await verifyJWT(token, keyFunctions)
      next()
    } catch (e) {
      log.error(`Failed to decode token: ${e}`)
      return next(new Error('Authentication error: ' + e))
    }
  })
}

module.exports = {
  secureExpressWithJWT,
  secureSocketIOWithJWT
}
