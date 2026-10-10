import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { defineComponent, h } from 'vue'
import { flushPromises, mount } from '@vue/test-utils'
import { accountVaultAPI } from '@/api/admin/accountVault'
import { useWorkerConnection } from '../useWorkerConnection'
import type { VaultWorkerToken } from '@/types/accountVault'

vi.mock('@/api/admin/accountVault', () => ({ accountVaultAPI: { createWorkerToken: vi.fn(), revokeWorkerTokens: vi.fn() } }))
const authorize = vi.fn(async <T>(action: () => Promise<T>) => action())
const copy = vi.fn(async () => true)
const cancelAuthorization = vi.fn()
let wrapper: ReturnType<typeof mount> | undefined
function setup() {
  let state!: ReturnType<typeof useWorkerConnection>
  wrapper = mount(defineComponent({ setup() {
    state = useWorkerConnection({ authorize, copy, cancelAuthorization, t: key => key })
    return () => h('div')
  } }))
  return state
}
const deferred = <T>() => {
  let resolve!: (value: T) => void
  const promise = new Promise<T>(done => { resolve = done })
  return { promise, resolve }
}
beforeEach(() => {
  vi.clearAllMocks()
  vi.useFakeTimers()
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' })
  vi.mocked(accountVaultAPI.createWorkerToken).mockImplementation(async () => ({ token: 'synthetic-worker-code', token_id: 'synthetic-id', expires_at: new Date(Date.now() + 8 * 60 * 60 * 1000).toISOString() }))
  vi.mocked(accountVaultAPI.revokeWorkerTokens).mockResolvedValue({ revoked: true })
})
afterEach(() => { wrapper?.unmount(); wrapper = undefined; vi.useRealTimers(); vi.restoreAllMocks() })

describe('one-time browser helper connection code', () => {
  it('authorizes generation, permits one copy, and clears the displayed code after 30 seconds', async () => {
    const state = setup()
    await state.generate()
    expect(authorize).toHaveBeenCalledTimes(1)
    expect(state.token.value).toBe('synthetic-worker-code')
    await state.copyToken()
    await state.copyToken()
    expect(copy).toHaveBeenCalledTimes(1)
    await vi.advanceTimersByTimeAsync(30_000)
    expect(state.token.value).toBe('')
    expect(state.issued.value).toBe(true)
  })
  it('clears the secret immediately when backgrounded', async () => {
    const state = setup()
    await state.generate()
    Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'hidden' })
    document.dispatchEvent(new Event('visibilitychange'))
    expect(state.token.value).toBe('')
  })
  it('does not reveal a token response after the dialog is closed', async () => {
    const pending = deferred<VaultWorkerToken>()
    vi.mocked(accountVaultAPI.createWorkerToken).mockReturnValueOnce(pending.promise)
    const state = setup()
    const request = state.generate()
    wrapper?.unmount()
    wrapper = undefined
    const response = { token: 'late-synthetic-code', token_id: 'id', expires_at: new Date(Date.now() + 60_000).toISOString() }
    pending.resolve(response)
    await request
    expect(state.token.value).toBe('')
    expect(response.token).toBe('')
    expect(cancelAuthorization).toHaveBeenCalled()
  })
  it('revokes all actor codes through authorized API and removes the current displayed code', async () => {
    const state = setup()
    await state.generate()
    await state.revoke()
    expect(authorize).toHaveBeenCalledTimes(2)
    expect(accountVaultAPI.revokeWorkerTokens).toHaveBeenCalledTimes(1)
    expect(state.token.value).toBe('')
    expect(state.revoked.value).toBe(true)
    expect(state.issued.value).toBe(false)
  })
  it('ignores delayed generation after switching to the background', async () => {
    const pending = deferred<VaultWorkerToken>()
    vi.mocked(accountVaultAPI.createWorkerToken).mockReturnValueOnce(pending.promise)
    const state = setup()
    const request = state.generate()
    Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'hidden' })
    document.dispatchEvent(new Event('visibilitychange'))
    pending.resolve({ token: 'late-synthetic-code', token_id: 'id', expires_at: new Date(Date.now() + 60_000).toISOString() })
    await request
    await flushPromises()
    expect(state.token.value).toBe('')
    expect(state.busy.value).toBe('')
  })
})
