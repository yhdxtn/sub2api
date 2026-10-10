import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { defineComponent, h, ref } from 'vue'
import { flushPromises, mount } from '@vue/test-utils'
import { accountVaultAPI } from '@/api/admin/accountVault'
import { useVaultRotation } from '../useVaultRotation'
import type { VaultAccount, VaultRotationJob } from '@/types/accountVault'

vi.mock('@/api/admin/accountVault', () => ({ accountVaultAPI: { rotationJobs: vi.fn() } }))
const job = (revision = 1, status = 'queued', phase = 'login'): VaultRotationJob => ({ id: 'synthetic-job', account_id: 1, status, phase, revision, progress: status, message: '', can_cancel: phase === 'login', can_resume: status === 'paused', created_at: '2026-10-09T00:00:00Z', updated_at: '2026-10-09T00:00:00Z', ...(status === 'completed' ? { completed_at: '2026-10-09T01:00:00Z' } : {}) })
const deferred = <T>() => {
  let resolve!: (value: T) => void
  const promise = new Promise<T>(done => { resolve = done })
  return { promise, resolve }
}
let wrapper: ReturnType<typeof mount> | undefined
function setup() {
  const accounts = ref<VaultAccount[]>([{ id: 1, email: 'alice@example.test', issuer: 'OpenAI', has_password: true, has_totp: true, algorithm: 'SHA1', digits: 6, period: 30, created_at: '', updated_at: '', rotation_state: 'queued', rotation_phase: 'login' }])
  let state!: ReturnType<typeof useVaultRotation>
  wrapper = mount(defineComponent({ setup() {
    state = useVaultRotation(accounts, jobs => {
      for (const next of jobs) Object.assign(accounts.value[0], { rotation_state: next.status, rotation_phase: next.phase, rotation_completed_at: next.completed_at })
    })
    return () => h('div')
  } }))
  return state
}
beforeEach(() => {
  vi.clearAllMocks()
  vi.useFakeTimers()
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' })
  vi.mocked(accountVaultAPI.rotationJobs).mockResolvedValue({ jobs: [job()] })
})
afterEach(() => { wrapper?.unmount(); wrapper = undefined; vi.useRealTimers(); vi.restoreAllMocks() })

describe('rotation job polling', () => {
  it('polls active phases then stops once the server reports durable completion', async () => {
    const state = setup()
    await flushPromises()
    expect(state.jobs.value[1].status).toBe('queued')
    vi.mocked(accountVaultAPI.rotationJobs).mockResolvedValueOnce({ jobs: [job(2, 'running', 'enrolled')] })
    await vi.advanceTimersByTimeAsync(2000)
    expect(state.jobs.value[1].phase).toBe('enrolled')
    vi.mocked(accountVaultAPI.rotationJobs).mockResolvedValueOnce({ jobs: [job(3, 'completed', 'completed')] })
    await vi.advanceTimersByTimeAsync(2000)
    const count = vi.mocked(accountVaultAPI.rotationJobs).mock.calls.length
    await vi.advanceTimersByTimeAsync(10_000)
    expect(state.jobs.value[1].status).toBe('completed')
    expect(accountVaultAPI.rotationJobs).toHaveBeenCalledTimes(count)
  })
  it('does not let an old response revive a job that has just been cancelled', async () => {
    const state = setup()
    await flushPromises()
    const pending = deferred<{ jobs: VaultRotationJob[] }>()
    vi.mocked(accountVaultAPI.rotationJobs).mockReturnValueOnce(pending.promise)
    const request = state.query()
    state.acceptJob(job(3, 'cancelled'))
    pending.resolve({ jobs: [job(2, 'running')] })
    await request
    expect(state.jobs.value[1].status).toBe('cancelled')
    const count = vi.mocked(accountVaultAPI.rotationJobs).mock.calls.length
    await vi.advanceTimersByTimeAsync(10_000)
    expect(accountVaultAPI.rotationJobs).toHaveBeenCalledTimes(count)
  })
  it('rejects older job revisions even if they arrive in a newer HTTP request', async () => {
    const state = setup()
    await flushPromises()
    state.acceptJob(job(5, 'running', 'activate_intent'))
    vi.mocked(accountVaultAPI.rotationJobs).mockResolvedValueOnce({ jobs: [job(3, 'running', 'disabled')] })
    await state.query()
    expect(state.jobs.value[1].phase).toBe('activate_intent')
    expect(state.jobs.value[1].revision).toBe(5)
  })
  it('pauses in the background and refreshes on return without accepting an aborted response', async () => {
    const state = setup()
    await flushPromises()
    const pending = deferred<{ jobs: VaultRotationJob[] }>()
    vi.mocked(accountVaultAPI.rotationJobs).mockReturnValueOnce(pending.promise)
    const request = state.query()
    Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'hidden' })
    document.dispatchEvent(new Event('visibilitychange'))
    pending.resolve({ jobs: [job(2, 'completed', 'completed')] })
    await request
    expect(state.jobs.value[1].status).toBe('queued')
    const count = vi.mocked(accountVaultAPI.rotationJobs).mock.calls.length
    await vi.advanceTimersByTimeAsync(10_000)
    expect(accountVaultAPI.rotationJobs).toHaveBeenCalledTimes(count)
    Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' })
    document.dispatchEvent(new Event('visibilitychange'))
    await flushPromises()
    expect(accountVaultAPI.rotationJobs).toHaveBeenCalledTimes(count + 1)
  })
})
