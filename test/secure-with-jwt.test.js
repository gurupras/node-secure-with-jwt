import http from 'http'
import express from 'express'
import jwt from 'jsonwebtoken'
import NodeRSA from 'node-rsa'
import request from 'supertest'
import SocketIOServer from 'socket.io'
import portfinder from 'portfinder'
import { initialize as LogInitialize, getRootLogger } from '@gurupras/log'
import { beforeEach, afterEach, describe, test, vitest, expect, beforeAll } from 'vitest'
import { setupSocket, testForNoEvent, getJWTPrivateKey, getJWTPublicKey } from '@gurupras/test-helpers'

import { secureExpressWithJWT, secureSocketIOWithJWT } from '../src/secure-with-jwt.js'

let log
let app

let key
let accessToken
const testAccountID = 'dummy'

beforeAll(() => {
  LogInitialize({
    file: false,
    stdout: {
      level: 'fatal'
    }
  })
  log = getRootLogger()
})

beforeEach(async () => {
  app = express()
  key = getJWTPrivateKey()
  accessToken = jwt.sign({
    sub: testAccountID,
    iat: Math.floor(Date.now() / 1000) - 30,
    exp: Math.floor(Date.now() / 1000) + 60
  },
  key, {
    algorithm: 'RS256'
  })

  secureExpressWithJWT(app, { getKey, log })
  app.get('/api/test', (req, res) => res.send('OK'))
})

const values = [
  ['null', null],
  ['boolean', false],
  ['boolean', true],
  ['function', () => {}],
  ['number', 4],
  ['number', 0],
  ['object', {}],
  ['string', 'bad'],
  ['string', '']
]
const fields = [
  ['paths', 'string'],
  ['ignore', 'string'],
  ['getKey', 'function']
]

describe('setupFakeJWT', () => {
  test('Test fake JWT', async () => {
    return new Promise((resolve, reject) => {
      jwt.verify(accessToken, getKey, (err, decoded) => {
        expect(err).toBeNil()
        expect(decoded).toMatchObject({
          sub: testAccountID,
          iat: expect.anything(),
          exp: expect.anything()
        })
        expect(decoded.iat).toBeBefore(Date.now() / 1e3)
        expect(decoded.exp).toBeAfter(Date.now() / 1e3)
        resolve()
      })
    })
  })

  test('Ensure (fake) public-private keys matter', async () => {
    const getKey = (headers, cb) =>
      cb(null, new NodeRSA({ b: 512 }).exportKey('public'))
    return new Promise((resolve, reject) => {
      jwt.verify(accessToken, getKey, (err, decoded) => {
        expect(err).not.toBeNil()
        resolve()
      })
    })
  })
})

describe('secureExpressWithJWT', () => {
  describe('Setup', () => {
    let data
    beforeEach(() => {
      data = { getKey }
    })
    describe.each(fields)('Property %s', (field, acceptedType) => {
      const badValues = values.filter(x => x[0] !== acceptedType)
      const goodValues = values.filter(x => x[0] === acceptedType)
      test.each(badValues)('Fails on %s(%p)', async (type, value) => {
        Object.assign(data, {
          [field]: value
        })
        expect(() => secureExpressWithJWT(app, data)).toThrow()
      })
      test.each(badValues)('Fails on [%s(%p)]', async (type, value) => {
        Object.assign(data, {
          [field]: [value]
        })
        expect(() => secureExpressWithJWT(app, data)).toThrow()
      })
      test.each(goodValues)('Passes on %s(%p)', async (type, value) => {
        Object.assign(data, {
          [field]: value
        })
        expect(() => secureExpressWithJWT(app, data)).not.toThrow()
      })
      test.each(goodValues)('Passes on [%s(%p)]', async (type, value) => {
        Object.assign(data, {
          [field]: [value]
        })
        expect(() => secureExpressWithJWT(app, data)).not.toThrow()
      })
    })
  })

  describe('jwksClient', () => {
    let jwksClient
    let badJwksClient
    let opts
    beforeEach(() => {
      badJwksClient = createMockJWKSClient(result => { result.rsaPublicKey = 'bad-string' })
      jwksClient = createMockJWKSClient()
      opts = { jwksClient, paths: '/jwks-test' }
    })

    function setupTestEndpoint () {
      app.get('/jwks-test/test', (req, res) => {
        res.send('OK')
      })
    }
    test('Works with jwksClient', async () => {
      app.get('/jwks-test/test', (req, res, next) => {
        next()
      })
      expect(() => secureExpressWithJWT(app, opts)).not.toThrow()
      setupTestEndpoint()
      let response = await request(app)
        .get('/jwks-test/test')
      expect(response.status).toBe(401)
      response = await request(app)
        .get('/jwks-test/test')
        .set('Authorization', `Bearer ${accessToken}`)
      expect(response.status).toBe(200)
    })

    test('Works with multiple jwksClients', async () => {
      opts.jwksClient = [badJwksClient, jwksClient]
      expect(() => secureExpressWithJWT(app, opts)).not.toThrow()
      setupTestEndpoint()
      let response = await request(app)
        .get('/jwks-test/test')
      expect(response.status).toBe(401)
      response = await request(app)
        .get('/jwks-test/test')
        .set('Authorization', `Bearer ${accessToken}`)
      expect(response.status).toBe(200)
    })
    test('Works with jwksClient and getKey', async () => {
      jwksClient.getSigningKey = vitest.fn().mockImplementation((header, cb) => {
        cb(new Error('bad'), null)
      })
      Object.assign(opts, { getKey })
      expect(() => secureExpressWithJWT(app, opts)).not.toThrow()
      setupTestEndpoint()
      let response = await request(app).get('/jwks-test/test')
      expect(response.status).toBe(401)
      response = await request(app)
        .get('/jwks-test/test')
        .set('Authorization', `Bearer ${accessToken}`)
      expect(response.status).toBe(200)
    })
    test('Works with multiple jwksClients and getKeys', async () => {
      const badGetKey = (headers, cb) => cb(null, 'bad-string')
      Object.assign(opts, {
        jwksClient: [badJwksClient, badJwksClient],
        getKey: [badGetKey, getKey]
      })
      expect(() => secureExpressWithJWT(app, opts)).not.toThrow()
      setupTestEndpoint()
      let response = await request(app).get('/jwks-test/test')
      expect(response.status).toBe(401)
      response = await request(app)
        .get('/jwks-test/test')
        .set('Authorization', `Bearer ${accessToken}`)
      expect(response.status).toBe(200)
    })
  })

  describe('Ignore patterns', () => {
    let paths
    let ignore
    beforeEach(() => {
      paths = ['/test', '/test/restricted']
      ignore = ['/test/avatar', '/test/restricted/avatar']
      secureExpressWithJWT(app, { paths, ignore, getKey })
      app.get('/test/*', (req, res) => {
        res.send('OK')
      })
    })
    test('Properly ignores specified patterns', async () => {
      let response
      // First, confirm that the blocking works
      response = await request(app).get('/test/test')
      expect(response.status).toBe(401)
      response = await request(app).get('/test/restricted')
      expect(response.status).toBe(401)

      response = await request(app)
        .get('/test/test')
        .set('Authorization', `Bearer ${accessToken}`)
      expect(response.status).toBe(200)
      response = await request(app)
        .get('/test/restricted')
        .set('Authorization', `Bearer ${accessToken}`)
      expect(response.status).toBe(200)

      // Now, test the ignore
      response = await request(app).get('/test/avatar')
      expect(response.status).toBe(200)
      response = await request(app).get('/test/restricted/avatar/test-user')
      expect(response.status).toBe(200)
    })
  })

  test('Fails on no token', async () => {
    const response = await request(app).get('/api/test')
    expect(response.status).toEqual(401) // unauthorized
  })

  test('Fails on invalid token', async () => {
    const response = await request(app)
      .get('/api/test')
      .set('Authorization', 'bad')
    expect(response.status).toEqual(401)
  })

  test('Fails on malformed token', async () => {
    let response = await request(app)
      .get('/api/test')
      .set('Authorization', 'Bearer bad')
    expect(response.status).toEqual(401)

    response = await request(app)
      .get('/api/test')
      .set('Authorization', `Bearer bad${accessToken.substr(3)}`)
    expect(response.status).toEqual(401)
  })

  test('Fails on expired token', async () => {
    const token = jwt.sign(
      {
        sub: testAccountID,
        iat: Math.floor(Date.now() / 1000) - 3000000,
        exp: Math.floor(Date.now() / 1000) - 3
      },
      key,
      {
        algorithm: 'RS256'
      }
    )
    const response = await request(app)
      .get('/api/test')
      .set('Authorization', `Bearer ${token}`)
    expect(response.status).toEqual(401)
  })

  test('Accepts valid token', async () => {
    const response = await request(app)
      .get('/api/test')
      .set('Authorization', `Bearer ${accessToken}`)
    expect(response.status).toBe(200)
  })
})

describe('secureSocketIOWithJWT', () => {
  let server
  let ioServer
  let port
  beforeEach(async () => {
    app = express()
    server = http.createServer(app)
    port = await portfinder.getPortPromise()
    ioServer = new SocketIOServer(server, {
      pingInterval: 10000,
      pingTimeout: 60000
    })
    ioServer.on('connection', socket => {
      log.debug('Received socket connection')
      socket.emit('ready')
    })

    server.listen(port)
  })
  afterEach(async () => {
    return new Promise(resolve => {
      server.close(resolve)
    })
  })

  function createSocket (user, opts) {
    const { waitForConnect = 'ready' } = opts
    Object.assign(opts, {
      waitForConnect
    })
    return setupSocket(user, port, opts)
  }

  async function testJWT (opts) {
    expect(() => secureSocketIOWithJWT(ioServer, opts)).not.toThrow()
    let socket = await createSocket('user', { withJWT: false, noOpen: true })
    const promise = testForNoEvent(socket, 'ready')
    socket.open()
    log.debug('Opened socket')
    await promise
    log.debug('Promise resolved')
    socket.close()
    socket = await createSocket('user', { withJWT: true })
    socket.close()
  }

  test('Throws on no getKey or jwtClient', async () => {
    expect(() => secureSocketIOWithJWT(ioServer, {})).toThrow()
  })

  describe('getKey', () => {
    const fields = [['getKey', 'function']]
    let data
    beforeEach(() => {
      data = {}
    })
    describe.each(fields)('Property %s', (field, acceptedType) => {
      const badValues = values.filter((x) => x[0] !== acceptedType)
      const goodValues = values.filter((x) => x[0] === acceptedType)
      test.each(badValues)('Fails on %s(%p)', async (type, value) => {
        Object.assign(data, {
          [field]: value
        })
        expect(() => secureSocketIOWithJWT(ioServer, data)).toThrow()
      })
      test.each(badValues)('Fails on [%s(%p)]', async (type, value) => {
        Object.assign(data, {
          [field]: [value]
        })
        expect(() => secureSocketIOWithJWT(ioServer, data)).toThrow()
      })
      test.each(goodValues)('Passes on %s(%p)', async (type, value) => {
        Object.assign(data, {
          [field]: value
        })
        expect(() => secureSocketIOWithJWT(ioServer, data)).not.toThrow()
      })
      test.each(goodValues)('Passes on [%s(%p)]', async (type, value) => {
        Object.assign(data, {
          [field]: [value]
        })
        expect(() => secureSocketIOWithJWT(ioServer, data)).not.toThrow()
      })
    })
  })

  test('Passing bad getKey throws error', async () => {
    await expect(testJWT({ getKey: 'bad' })).toReject()
  })
  test('Calling with getKey secures the socket.io server', async () => {
    await expect(testJWT({ getKey })).resolves.toBeUndefined()
  })
  test('Calling with jwksClient secures the socket.io server', async () => {
    const jwksClient = createMockJWKSClient()
    await expect(testJWT({ jwksClient })).resolves.toBeUndefined()
  })
  test('Calling with array of jwksClient secures the socket.io server', async () => {
    const badJwksClient = createMockJWKSClient(result => {
      result.rsaPublicKey = 'bad-string'
    })
    const validJwksClient = createMockJWKSClient()
    await expect(testJWT({ jwksClient: [badJwksClient, badJwksClient, validJwksClient] })).resolves.toBeUndefined()
  })
})

function getKey (headers, cb) {
  cb(null, getJWTPublicKey())
}

function createMockJWKSClient (customGetKeyModifier = () => { }) {
  return {
    getSigningKey: vitest.fn().mockImplementation(async (kid, cb) => {
      return getKey(null, (err, rsaPublicKey) => {
        const result = { rsaPublicKey }
        customGetKeyModifier(result)
        cb(err, result)
      })
    })
  }
}
