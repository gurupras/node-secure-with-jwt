import jwt from 'jsonwebtoken'
import cookieParser from 'cookie-parser'
import { pathToRegexp } from 'path-to-regexp'
import * as core from 'express-serve-static-core'
import express, { Application, Request, Response, NextFunction } from 'express'
import { Server, Socket } from 'socket.io'
import { Logger } from '@gurupras/log'
import { Options as JwksClientOptions, JwksClient } from 'jwks-rsa'

export type KeyFunction = (header: jwt.JwtHeader, callback: (err: Error | null, key?: string) => void) => void;

export interface BaseSecureOptions {
  getKey?: KeyFunction | KeyFunction[];
  jwksClientOpts?: Array<JwksClientOptions>
  jwksClient?: JwksClient | Array<JwksClient>
  log?: Logger;
}

export interface ExpressOptions extends BaseSecureOptions {
  paths?: string | string[];
  ignore?: string | string[];
}

interface SocketIOOptions extends BaseSecureOptions {
}

export interface AuthenticatedRequest<
      P = core.ParamsDictionary,
      ResBody = any,
      ReqBody = any,
      ReqQuery = core.Query,
      Locals extends Record<string, any> = Record<string, any>
    > extends Request<P, ResBody, ReqBody, ReqQuery, Locals> {
  decoded: any
  token: string
  userID: string
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

export function validateOptions (options: ExpressOptions, validationOptions: { requirePaths: boolean } = { requirePaths: true }): {
  getKey: KeyFunction[] | undefined
  jwksClient: JwksClient[] | undefined
  ignore: string[]
  log: Logger
  paths: string[]
  keyFunctions: KeyFunction[]
} {
  let { getKey, jwksClientOpts, jwksClient, ignore = [], log = nullLogger, paths = '/api' } = options

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

  if (jwksClientOpts !== undefined && Array.isArray(jwksClientOpts)) {
    for (const opts of jwksClientOpts) {
      const client = new JwksClient(opts)
      jwksClient = jwksClient || []
      jwksClient.push(client)
    }
  }

  if (validationOptions.requirePaths) {
    if (typeof paths !== 'string' && !paths) {
      throw new Error('Must specify at least one path')
    } else {
      if (typeof paths === 'string') {
        paths = [paths]
      }
    }
    checkArrayTypes('paths', paths, 'string')
  } else {
    // We can set it to an empty array
    paths = []
  }

  const keyFunctions = getAllKeyFunctions(getKey, jwksClient, log)
  if (keyFunctions.length === 0) {
    throw new Error('Must specify getKey or jwksClient')
  }

  return { getKey, jwksClient, ignore, log, paths, keyFunctions }
}

export function createSecurityMiddleware (options: ExpressOptions): express.Handler {
  const { ignore, log, keyFunctions } = validateOptions(options)

  const ignorePatterns = ignore.map((x) => pathToRegexp(x, { end: false }))

  function getAccessTokenFromAuthorizationHeader (req: Request): string {
    const { headers: { authorization = '' } } = req
    if (!authorization.startsWith('Bearer ')) {
      throw new Error('Invalid token')
    }
    return authorization.substring(7)
  }

  function getAccessTokenFromCookie (req: Request): string {
    const token = req.cookies?.access_token
    return token ?? ''
  }

  return async function middleware (req: Request, res: Response, next: NextFunction) {
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

    const validateTokenAndUpdateRequest = async (accessToken: string) => {
      const decoded = (req as AuthenticatedRequest).decoded = await verifyJWT(accessToken, keyFunctions)
      ;(req as AuthenticatedRequest).token = accessToken
      ;(req as AuthenticatedRequest).userID = decoded.sub
    }

    // First, try cookie
    try {
      const accessToken = getAccessTokenFromCookie(req)
      await validateTokenAndUpdateRequest(accessToken)
    } catch (_) {
      try {
        const accessToken = getAccessTokenFromAuthorizationHeader(req)
        await validateTokenAndUpdateRequest(accessToken)
      } catch (e: any) {
        log.error('Unexpected error in middleware', { error: { message: e.message, stack: e.stack } })
        return unauthorized(e)
      }
    }
    next()
  }
}

export function secureExpressWithJWT (app: Application, options: ExpressOptions) {
  const { paths } = validateOptions(options)

  // We need to add cookieParser
  app.use(cookieParser())

  const middleware = createSecurityMiddleware(options)
  for (const path of paths) {
    app.use(path, middleware)
  }
}

export function secureRouterWithJWT (router: express.Router, options: ExpressOptions) {
  const { paths } = validateOptions(options)

  const middleware = createSecurityMiddleware(options)
  for (const path of paths) {
    router.use(path, middleware)
  }
}

export function secureSocketIOWithJWT (io: Server, options: SocketIOOptions) {
  const { keyFunctions, log } = validateOptions(options, { requirePaths: false })

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
      if (!token) {
        throw new Error('No token found')
      }
      (socket as any).decoded = await verifyJWT(token, keyFunctions)
      ;(socket as any).token = token
      next()
    } catch (e: any) {
      log.error('Failed to decode token', { error: { message: e.message, stack: e.stack } })
      next(new Error('Authentication error: ' + e))
    }
  })
}
