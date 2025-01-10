import { addMinutes } from 'date-fns'
import jwt from 'jsonwebtoken'
import NodeRSA from 'node-rsa'
import { io } from 'socket.io-client'
// @ts-ignore
import { testForEvent } from '@gurupras/test-helpers'

const rsaKey = new NodeRSA({ b: 2048 })
const privateKey = rsaKey.exportKey('private')
const publicKey = rsaKey.exportKey('public')

type Opts = {
  withJWT?: boolean
  waitForConnect?: boolean
  noOpen?: boolean
}

type JWTArgs = {
  sub: string
  iss: string
  aud: string
  iat: number
  exp: number
}

export async function setupSocket (user = 'dummy', port: number, opts: Opts = {}) {
  let token
  const { withJWT = true, waitForConnect, noOpen = false } = opts
  const query: Record<string, string> = {}
  if (withJWT) {
    const jwtArgs: JWTArgs = {} as any
    if (typeof user === 'string') {
      // We treat this as iss
      jwtArgs.iss = user
    } else {
      Object.assign(jwtArgs, user)
    }
    token = createUserJWT(jwtArgs)
    query.token = token
  }
  const socket = io(`http://localhost:${port}`, {
    query,
    autoConnect: false
  })
  if (noOpen) {
    return socket
  }
  if (waitForConnect) {
    const promise = testForEvent(socket, waitForConnect, { timeout: 300 })
    socket.open()
    await promise
  } else {
    socket.open()
  }
  return socket
}

function createUserJWT (data: JWTArgs) {
  const {
    sub = 'test-helper-iss',
    iss,
    aud = 'test-helper-aud',
    iat = Math.floor(Date.now() / 1000),
    exp = Math.floor(addMinutes(new Date(), 5).getTime() / 1000)
  } = data
  if (!iss) {
    throw new Error('Must specify issuer (iss)')
  }
  const clientPayload = {
    iss,
    sub,
    aud,
    iat,
    exp
  }
  return jwt.sign(clientPayload, getJWTPrivateKey(), { algorithm: 'RS256' })
}

export function getJWTPrivateKey () {
  return privateKey
}

export function getJWTPublicKey () {
  return publicKey
}
