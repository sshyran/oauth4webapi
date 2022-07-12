import anyTest, { type TestFn } from 'ava'
import setup, { type Context, teardown, client, issuer, endpoint } from './_setup.js'
import * as jose from 'jose'
import * as lib from '../src/index.js'

const test = anyTest as TestFn<Context & { es256: CryptoKeyPair; rs256: CryptoKeyPair }>

const code =
  'YmJiZTAwYmYtMzgyOC00NzhkLTkyOTItNjJjNDM3MGYzOWIy9sFhvH8K_x8UIHj1osisS57f5DduL-ar_qw5jl3lthwpMjm283aVMQXDmoqqqydDSqJfbhptzw8rUVwkuQbolw'
const payload = {
  iss: issuer.issuer,
  aud: client.client_id,
  c_hash: 'x7vk7f6BvQj0jQHYFIk4ag',
  sub: 'subject',
  nonce: 'nonce-value',
}
const tIssuer: lib.AuthorizationServer = {
  ...issuer,
  jwks_uri: endpoint('jwks'),
}

test.before(setup)
test.after(teardown)

test.before(async (t) => {
  t.context.es256 = await lib.generateKeyPair('ES256')
  t.context.rs256 = await lib.generateKeyPair('RS256')

  t.context
    .intercept({
      path: '/jwks',
      method: 'GET',
    })
    .reply(200, {
      keys: [
        {
          kid: 'es256',
          ...(await jose.exportJWK(t.context.es256.publicKey)),
          use: 'sig',
        },
        {
          kid: 'rs256',
          ...(await jose.exportJWK(t.context.rs256.publicKey)),
          key_ops: ['verify'],
        },
      ],
    })
})

test('validateCodeIdTokenResponse() error conditions', async (t) => {
  await t.throwsAsync(() => lib.validateCodeIdTokenResponse(tIssuer, client, <any>null, 'nonce'), {
    message: '"parameters" must be an instance of URLSearchParams',
  })
  await t.throwsAsync(
    () => lib.validateCodeIdTokenResponse(tIssuer, client, new URLSearchParams(), 'nonce'),
    {
      message: '"parameters" does not contain a `code id_token` hybrid response',
    },
  )
  await t.throwsAsync(
    () =>
      lib.validateCodeIdTokenResponse(
        issuer,
        client,
        new URLSearchParams('code=foo&id_token=bar'),
        'nonce',
      ),
    {
      message: '"issuer.jwks_uri" must be a string',
    },
  )
  await t.throwsAsync(
    () =>
      lib.validateCodeIdTokenResponse(
        tIssuer,
        client,
        new URLSearchParams('code=foo&id_token=bar'),
        <any>null,
      ),
    {
      message: '"expectedNonce" must be a non-empty string',
    },
  )
  await t.throwsAsync(
    () =>
      lib.validateCodeIdTokenResponse(
        tIssuer,
        client,
        new URLSearchParams('code=foo&id_token=bar&token=baz'),
        'nonce',
      ),
    {
      message: '`code id_token token` response type is not supported',
    },
  )
  await t.throwsAsync(
    async () => {
      const kp = t.context.rs256

      const id_token = await new jose.SignJWT(payload)
        .setIssuedAt()
        .setExpirationTime('30s')
        .setProtectedHeader({ alg: 'RS256' })
        .sign(kp.privateKey)
      const params = new URLSearchParams({ id_token, code })
      await lib.validateCodeIdTokenResponse(
        tIssuer,
        { ...client, require_auth_time: true },
        params,
        'nonce-value',
      )
    },
    { message: 'invalid ID Token "auth_time"' },
  )
  await t.throwsAsync(
    async () => {
      const kp = t.context.rs256

      const id_token = await new jose.SignJWT(payload)
        .setIssuedAt()
        .setExpirationTime('30s')
        .setProtectedHeader({ alg: 'RS256' })
        .setAudience([client.client_id, 'another-audience'])
        .sign(kp.privateKey)
      const params = new URLSearchParams({ id_token, code })
      await lib.validateCodeIdTokenResponse(tIssuer, client, params, 'nonce-value')
    },
    { message: 'unexpected ID Token "azp" (authorized party)' },
  )
  await t.throwsAsync(
    async () => {
      const kp = t.context.rs256

      const id_token = await new jose.SignJWT({
        ...payload,
        azp: 'another-audience',
      })
        .setIssuedAt()
        .setExpirationTime('30s')
        .setProtectedHeader({ alg: 'RS256' })
        .setAudience([client.client_id, 'another-audience'])
        .sign(kp.privateKey)
      const params = new URLSearchParams({ id_token, code })
      await lib.validateCodeIdTokenResponse(tIssuer, client, params, 'nonce-value')
    },
    { message: 'unexpected ID Token "azp" (authorized party)' },
  )
  await t.throwsAsync(
    async () => {
      const kp = t.context.rs256

      const id_token = await new jose.SignJWT({
        ...payload,
        nonce: undefined,
      })
        .setIssuedAt()
        .setExpirationTime('30s')
        .setProtectedHeader({ alg: 'RS256' })
        .sign(kp.privateKey)
      const params = new URLSearchParams({ id_token, code })
      await lib.validateCodeIdTokenResponse(tIssuer, client, params, 'nonce-value')
    },
    { message: 'missing JWT "nonce" (nonce)' },
  )
  await t.throwsAsync(
    async () => {
      const kp = t.context.rs256

      const id_token = await new jose.SignJWT({
        ...payload,
        nonce: 'foo',
      })
        .setIssuedAt()
        .setExpirationTime('30s')
        .setProtectedHeader({ alg: 'RS256' })
        .sign(kp.privateKey)
      const params = new URLSearchParams({ id_token, code })
      await lib.validateCodeIdTokenResponse(tIssuer, client, params, 'nonce-value')
    },
    { message: 'unexpected ID Token "nonce" claim value received' },
  )
  await t.throwsAsync(
    async () => {
      const kp = t.context.rs256

      const id_token = await new jose.SignJWT({
        ...payload,
        c_hash: undefined,
      })
        .setIssuedAt()
        .setExpirationTime('30s')
        .setProtectedHeader({ alg: 'RS256' })
        .sign(kp.privateKey)
      const params = new URLSearchParams({ id_token, code })
      await lib.validateCodeIdTokenResponse(tIssuer, client, params, 'nonce-value')
    },
    { message: 'missing JWT "c_hash" (code hash value)' },
  )
  await t.throwsAsync(
    async () => {
      const kp = t.context.rs256

      const id_token = await new jose.SignJWT({
        ...payload,
        c_hash: 'foo',
      })
        .setIssuedAt()
        .setExpirationTime('30s')
        .setProtectedHeader({ alg: 'RS256' })
        .sign(kp.privateKey)
      const params = new URLSearchParams({ id_token, code })
      await lib.validateCodeIdTokenResponse(tIssuer, client, params, 'nonce-value')
    },
    { message: 'unexpected ID Token "c_hash" claim value received' },
  )
})

test('validateCodeIdTokenResponse()', async (t) => {
  const tIssuer: lib.AuthorizationServer = {
    ...issuer,
    jwks_uri: endpoint('jwks'),
  }
  const kp = t.context.rs256

  const id_token = await new jose.SignJWT(payload)
    .setIssuedAt()
    .setExpirationTime('30s')
    .setProtectedHeader({ alg: 'RS256', kid: 'rs256' })
    .sign(kp.privateKey)
  const params = new URLSearchParams({ id_token, code })
  await t.notThrowsAsync(async () => {
    const result = await lib.validateCodeIdTokenResponse(tIssuer, client, params, 'nonce-value')
    t.true(result instanceof URLSearchParams)
    const isError = lib.isOAuth2Error(result)
    if (isError) {
      t.fail()
      throw new Error()
    }
    t.is(result.constructor.name, 'CallbackParameters')
    t.deepEqual([...result.keys()], ['code'])
  })
})

test('validateCodeIdTokenResponse() - alg signalled', async (t) => {
  const tIssuer: lib.AuthorizationServer = {
    ...issuer,
    jwks_uri: endpoint('jwks'),
    id_token_signing_alg_values_supported: ['ES256'],
  }
  const kp = t.context.es256

  const id_token = await new jose.SignJWT(payload)
    .setIssuedAt()
    .setExpirationTime('30s')
    .setProtectedHeader({ alg: 'ES256', kid: 'es256' })
    .sign(kp.privateKey)
  const params = new URLSearchParams({ id_token, code })
  await t.notThrowsAsync(lib.validateCodeIdTokenResponse(tIssuer, client, params, 'nonce-value'))
})

test('validateCodeIdTokenResponse() - alg defined', async (t) => {
  const tIssuer: lib.AuthorizationServer = {
    ...issuer,
    jwks_uri: endpoint('jwks'),
  }
  const kp = t.context.es256

  const id_token = await new jose.SignJWT(payload)
    .setIssuedAt()
    .setExpirationTime('30s')
    .setProtectedHeader({ alg: 'ES256' })
    .sign(kp.privateKey)
  const params = new URLSearchParams({ id_token, code })
  await t.notThrowsAsync(
    lib.validateCodeIdTokenResponse(
      tIssuer,
      { ...client, id_token_signed_response_alg: 'ES256' },
      params,
      'nonce-value',
    ),
  )
})

test('validateCodeIdTokenResponse() - alg default', async (t) => {
  const tIssuer: lib.AuthorizationServer = {
    ...issuer,
    jwks_uri: endpoint('jwks'),
  }
  const kp = t.context.rs256

  const id_token = await new jose.SignJWT(payload)
    .setIssuedAt()
    .setExpirationTime('30s')
    .setProtectedHeader({ alg: 'RS256' })
    .sign(kp.privateKey)
  const params = new URLSearchParams({ id_token, code })
  await t.notThrowsAsync(lib.validateCodeIdTokenResponse(tIssuer, client, params, 'nonce-value'))
})

test('validateCodeIdTokenResponse() - alg mismatches', async (t) => {
  const tIssuer: lib.AuthorizationServer = {
    ...issuer,
    jwks_uri: endpoint('jwks'),
  }

  {
    const id_token = await new jose.SignJWT(payload)
      .setIssuedAt()
      .setExpirationTime('30s')
      .setProtectedHeader({ alg: 'ES256' })
      .sign(t.context.es256.privateKey)

    const params = new URLSearchParams({ id_token, code })
    await t.throwsAsync(lib.validateCodeIdTokenResponse(tIssuer, client, params, 'nonce-value'), {
      message: 'unexpected JWT "alg" header parameter',
    })
  }

  {
    const id_token = await new jose.SignJWT(payload)
      .setIssuedAt()
      .setExpirationTime('30s')
      .setProtectedHeader({ alg: 'ES256' })
      .sign(t.context.es256.privateKey)

    const params = new URLSearchParams({ id_token, code })
    await t.throwsAsync(
      lib.validateCodeIdTokenResponse(
        {
          ...tIssuer,
          id_token_signing_alg_values_supported: ['RS256'],
        },
        client,
        params,
        'nonce-value',
      ),
      {
        message: 'unexpected JWT "alg" header parameter',
      },
    )
  }

  {
    const id_token = await new jose.SignJWT(payload)
      .setIssuedAt()
      .setExpirationTime('30s')
      .setProtectedHeader({ alg: 'ES256' })
      .sign(t.context.es256.privateKey)

    const params = new URLSearchParams({ id_token, code })
    await t.throwsAsync(
      lib.validateCodeIdTokenResponse(
        tIssuer,
        { ...client, id_token_signed_response_alg: 'RS256' },
        params,
        'nonce-value',
      ),
      {
        message: 'unexpected JWT "alg" header parameter',
      },
    )
  }
})
