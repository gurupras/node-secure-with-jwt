import jwt from 'jsonwebtoken'
import cookieParser from 'cookie-parser'
import { pathToRegexp } from 'path-to-regexp'
import { Application, Request, Response, NextFunction } from 'express'
import { Server, Socket } from 'socket.io'
import { Logger } from '@gurupras/log'

export type KeyFunction = (header: jwt.JwtHeader, callback: (err: Error | null, key?: string) => void) => void;

export interface SecureOptions {
  getKey?: KeyFunction | KeyFunction[];
  jwksClient?: any | any[];
  paths?: string | string[];
  ignore?: string | string[];
  log?: Logger;
}

interface SocketIOOptions {
  getKey?: KeyFunction | KeyFunction[];
  jwksClient?: any | any[];
  log?: Logger;
}

export interface AuthenticatedRequest extends Request {
  decoded: any
  token: string
}

const nullLogger: Logger = {
  debug () {},
  info () {},
  warn () {},
  error () {},
  fatal () {}
} as any

function checkArrayTypes (name: string, arr: any, innerTypes: string | string[]) {
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

export function getAllKeyFunctions (getKey: KeyFunction[] | undefined, jwksClients: any[] | undefined, log: Logger = nullLogger): KeyFunction[] {
  const keyFunctions: KeyFunction[] = []

  if (jwksClients && jwksClients.length > 0) {
    if (getKey && getKey.length > 0) {
      log.debug('Both, jwksClient and getKey were specified.. jwksClient will be prioritized')
    }
    for (const jwksClient of jwksClients) {
      keyFunctions.push((header, callback) => {
        jwksClient.getSigningKey(header.kid, (err: Error, key: any) => {
          if (err) {
            return callback(err, '')
          }
          const signingKey = key.publicKey || key.rsaPublicKey
          callback(null, signingKey)
        })
      })
    }
  }

  if (getKey) {
    keyFunctions.push(...getKey)
  }
  return keyFunctions
}

export async function verifyJWT (token: string, keyFunctions: KeyFunction[]): Promise<any> {
  const errors: string[] = []
  for (const keyFn of keyFunctions) {
    try {
      const decoded = await new Promise<any>((resolve, reject) => {
        jwt.verify(token, keyFn, (err, decoded) => {
          if (err) {
            return reject(err)
          }
          resolve(decoded)
        })
      })
      return decoded
    } catch (e: any) {
      errors.push(e.message)
    }
  }
  const err = new Error('Failed to verify token');
  (err as any).errors = errors
  throw err
}

export function secureExpressWithJWT (app: Application, options: SecureOptions) {
  let { getKey, jwksClient, paths = '/api', ignore = [], log = nullLogger } = options

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
  app.use(cookieParser())

  const ignorePatterns = ignore.map((x) => pathToRegexp(x, { end: false }))
  const keyFunctions = getAllKeyFunctions(getKey, jwksClient, log)

  function getAccessTokenFromAuthorizationHeader (req: Request): string {
    const { headers: { authorization = '' } } = req
    if (!authorization.startsWith('Bearer ')) {
      throw new Error('Invalid token')
    }
    return authorization.substring(7)
  }

  async function middleware (req: Request, res: Response, next: NextFunction) {
    const { originalUrl, headers: { authorization = '' } } = req
    const ignoreMatch = ignorePatterns.find(pattern => pattern.regexp.test(originalUrl))
    if (ignoreMatch) {
      log.debug(`Skipping ${originalUrl} since it was matched by ${ignoreMatch}`)
      return next()
    }

    function unauthorized (error: Error) {
      log.error(`Failing request: ${req.url} due to token.`, { authorization, error })
      res.status(401).send('Unauthorized')
    }
    try {
      const accessToken = getAccessTokenFromAuthorizationHeader(req)
      ;(req as AuthenticatedRequest).decoded = await verifyJWT(accessToken, keyFunctions)
      ;(req as AuthenticatedRequest).token = accessToken
    } catch (e: any) {
      log.error('Unexpected error in middleware', { error: { message: e.message, stack: e.stack } })
      return unauthorized(e)
    }
    next()
  }

  for (const path of paths) {
    app.use(path, middleware)
  }
}

export function secureSocketIOWithJWT (io: Server, options: SocketIOOptions) {
  let { getKey, jwksClient, log = nullLogger } = options

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

  io.use(async (socket: Socket, next) => {
    try {
      const { handshake: { query, auth } } = socket
      let token: string | undefined
      if (auth) {
        ;({ token } = auth)
      }
      if (!token) {
        token = query.token as string
      }
      ;(socket as any).decoded = await verifyJWT(token, keyFunctions)
      ;(socket as any).token = token
      next()
    } catch (e: any) {
      log.error('Failed to decode token', { error: { message: e.message, stack: e.stack } })
      next(new Error('Authentication error: ' + e))
    }
  })
}
