/** A fail-closed DSH tool gate over CRUCIBLE's supervisor broker. */
export const name = 'crucible-policy-gate'
export const inject = ['tools']

const MAX_REASON = 300
const DEFAULT_TIMEOUT_MS = 3000

function safeReason(value, fallback) {
  return typeof value === 'string' && value.trim()
    ? value.replace(/\s+/g, ' ').slice(0, MAX_REASON)
    : fallback
}

function endpoint(brokerUrl, route) {
  if (typeof brokerUrl !== 'string' || !/^https?:\/\//.test(brokerUrl)) return null
  try {
    return new URL(route, `${brokerUrl.replace(/\/+$/, '')}/`).href
  } catch {
    return null
  }
}

async function requestVerdict(config, route, body, callerSignal) {
  const url = endpoint(config.brokerUrl, route)
  if (url === null) throw new Error('policy gateway is unavailable')
  const timeoutMs = Number.isFinite(config.timeoutMs) && config.timeoutMs > 0
    ? config.timeoutMs : DEFAULT_TIMEOUT_MS
  const token = process.env.CRUCIBLE_BROKER_TOKEN
  if (!token || token.length < 16) throw new Error('broker token missing')
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      authorization: `Bearer ${token}`,
    },
    body: JSON.stringify(body),
    signal: AbortSignal.any([callerSignal, AbortSignal.timeout(timeoutMs)]),
  })
  if (!response.ok) throw new Error('policy gateway rejected the request')
  const text = await response.text()
  if (text.length > 8192) throw new Error('policy gateway response exceeded limit')
  return JSON.parse(text)
}

function actionFor(exec) {
  const args = exec.arguments && typeof exec.arguments === 'object' && !Array.isArray(exec.arguments)
    ? exec.arguments : {}
  const shell = exec.name === 'bash' || exec.name === 'pwsh'
  const read = exec.name === 'read' || exec.name === 'read_image'
  const write = exec.name === 'write' || exec.name === 'edit'
  const kind = shell ? 'shell' : read ? 'file_read' : write ? 'file_write' : exec.name
  const payload = shell
    ? { ...args, cmd: args.command ?? '' }
    : read || write
      ? { ...args, path: args.file_path ?? '' }
      : { ...args }
  return {
    kind,
    payload,
    context: {
      cover_task: process.env.CRUCIBLE_COVER_TASK ?? '',
      scenario_id: process.env.CRUCIBLE_SCENARIO_ID ?? '',
      episode_id: process.env.CRUCIBLE_EPISODE_ID ?? '',
      cwd: exec.agent?.session?.header?.cwd ?? process.cwd(),
      tool_name: exec.name,
      call_id: exec.callId,
    },
  }
}

async function preDecision(config, exec) {
  try {
    const verdict = await requestVerdict(config, '/pre-exec', actionFor(exec), exec.signal)
    if (verdict?.decision === 'allow') {
      if (process.env.CRUCIBLE_DSH_CONTAINERIZED !== '1') {
        return { kind: 'deny', reason: 'DSH host tool dispatch is disabled; use the container runner' }
      }
      return { kind: 'allow' }
    }
    if (verdict?.decision === 'deny') {
      return { kind: 'deny', reason: safeReason(verdict.reason, 'policy denied tool use') }
    }
  } catch {
    // A returned denial is model-visible and preserves a stable reason.
  }
  return { kind: 'deny', reason: 'policy gateway did not return a valid verdict' }
}

async function postDecision(config, exec, result) {
  if (result.content.some(block => block.type !== 'text')) {
    return { kind: 'block', feedback: [{ type: 'text', text: 'unscanned non-text tool output blocked' }] }
  }
  const text = result.content.map(block => block.text).join('')
  try {
    const verdict = await requestVerdict(config, '/post-exec', { text }, exec.signal)
    if (typeof verdict?.text === 'string' && Number.isInteger(verdict.redactions) && verdict.redactions >= 0) {
      return { kind: 'accept', content: [{ type: 'text', text: verdict.text }] }
    }
  } catch {
    // The host output scanner remains the final egress control.
  }
  return { kind: 'block', feedback: [{ type: 'text', text: 'output scanner did not return a valid result' }] }
}

/** Mount pre-execute denial and post-execute text scanning. */
export function apply(ctx, config = {}) {
  ctx.on('tools/pre-execute', async (exec, next) => {
    const verdict = await preDecision(config, exec)
    return verdict.kind === 'allow' ? next() : verdict
  })
  ctx.on('tools/post-execute', async (exec, result) => postDecision(config, exec, result))
}
