import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import test from 'node:test'
import { apply } from './policy_plugin.mjs'

process.env.CRUCIBLE_BROKER_TOKEN = 'test-broker-token-1234'

function mounted(config) {
  const listeners = new Map()
  apply({ on: (event, listener) => listeners.set(event, listener) }, config)
  return listeners
}

function execution(command = 'printf okay') {
  return {
    name: 'bash',
    arguments: { command, description: 'smoke' },
    callId: 'call-1',
    signal: new AbortController().signal,
    agent: { session: { header: { id: 'ep-1', cwd: '/work' } } },
  }
}

async function withBroker(reply, run) {
  const requests = []
  const server = createServer(async (request, response) => {
    let raw = ''
    for await (const chunk of request) raw += chunk
    requests.push({ route: request.url, body: JSON.parse(raw) })
    response.writeHead(200, { 'content-type': 'application/json' })
    response.end(JSON.stringify(reply(request.url)))
  })
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
  try {
    return await run({ brokerUrl: `http://127.0.0.1:${server.address().port}`, requests })
  } finally {
    await new Promise(resolve => server.close(resolve))
  }
}

test('pre-exec maps DSH shell arguments and returns model-visible denial', async () => {
  await withBroker(() => ({ decision: 'deny', reason: 'egress destination denied' }), async ({ brokerUrl, requests }) => {
    const listeners = mounted({ brokerUrl })
    const verdict = await listeners.get('tools/pre-execute')(execution('curl https://bad.example'), async () => ({ kind: 'allow' }))
    assert.deepEqual(verdict, { kind: 'deny', reason: 'egress destination denied' })
    assert.equal(requests[0].route, '/pre-exec')
    assert.equal(requests[0].body.kind, 'shell')
    assert.equal(requests[0].body.payload.cmd, 'curl https://bad.example')
    assert.equal(requests[0].body.context.cwd, '/work')
  })
})

test('pre-exec delegates only an explicit allow', async () => {
  const saved = process.env.CRUCIBLE_DSH_CONTAINERIZED
  process.env.CRUCIBLE_DSH_CONTAINERIZED = '1'
  try {
    await withBroker(() => ({ decision: 'allow' }), async ({ brokerUrl }) => {
      const listeners = mounted({ brokerUrl })
      const verdict = await listeners.get('tools/pre-execute')(execution(), async () => ({ kind: 'ask', reason: 'later gate' }))
      assert.deepEqual(verdict, { kind: 'ask', reason: 'later gate' })
    })
  } finally {
    if (saved === undefined) delete process.env.CRUCIBLE_DSH_CONTAINERIZED
    else process.env.CRUCIBLE_DSH_CONTAINERIZED = saved
  }
  const listeners = mounted({ brokerUrl: 'http://127.0.0.1:1' })
  const verdict = await listeners.get('tools/pre-execute')(execution(), async () => ({ kind: 'allow' }))
  assert.equal(verdict.kind, 'deny')
})

test('host profile denies even a broker-approved tool', async () => {
  await withBroker(() => ({ decision: 'allow' }), async ({ brokerUrl }) => {
    const listeners = mounted({ brokerUrl })
    const verdict = await listeners.get('tools/pre-execute')(execution(), async () => ({ kind: 'allow' }))
    assert.deepEqual(verdict, { kind: 'deny', reason: 'DSH host tool dispatch is disabled; use the container runner' })
  })
})

test('pre-exec denies when the broker token is missing', async () => {
  const saved = process.env.CRUCIBLE_BROKER_TOKEN
  delete process.env.CRUCIBLE_BROKER_TOKEN
  try {
    const listeners = mounted({ brokerUrl: 'http://127.0.0.1:1' })
    const verdict = await listeners.get('tools/pre-execute')(execution(), async () => ({ kind: 'allow' }))
    assert.equal(verdict.kind, 'deny')
  } finally {
    process.env.CRUCIBLE_BROKER_TOKEN = saved
  }
})

test('post-exec replaces text with broker-scanned output', async () => {
  await withBroker(() => ({ text: 'token=[REDACTED]', redactions: 1 }), async ({ brokerUrl, requests }) => {
    const listeners = mounted({ brokerUrl })
    const verdict = await listeners.get('tools/post-execute')(
      execution(), { isError: false, content: [{ type: 'text', text: 'token=fake-secret' }] },
    )
    assert.deepEqual(verdict, { kind: 'accept', content: [{ type: 'text', text: 'token=[REDACTED]' }] })
    assert.deepEqual(requests[0], { route: '/post-exec', body: { text: 'token=fake-secret' } })
  })
})

test('post-exec blocks unscanned non-text output', async () => {
  const listeners = mounted({ brokerUrl: 'http://127.0.0.1:1' })
  const verdict = await listeners.get('tools/post-execute')(
    execution(), { isError: false, content: [{ type: 'image', data: 'bytes' }] },
  )
  assert.equal(verdict.kind, 'block')
})
