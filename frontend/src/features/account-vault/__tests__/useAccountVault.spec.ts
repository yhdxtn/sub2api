import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { defineComponent, h } from 'vue'
import { flushPromises, mount } from '@vue/test-utils'
import { useAccountVault } from '../useAccountVault'
import { accountVaultAPI } from '@/api/admin/accountVault'
import type { VaultAccount, VaultPage, VaultRotationJob } from '@/types/accountVault'

vi.mock('@/api/admin/accountVault', () => ({ accountVaultAPI: {
  status: vi.fn(), list: vi.fn(), codes: vi.fn()
} }))

const account = (id: number): VaultAccount => ({ id, email: `user${id}@example.test`, issuer: 'Example',
  has_password: true, has_totp: true, algorithm: 'SHA1', digits: 6, period: 30, created_at: '', updated_at: '' })
const pageOf = (ids: number[]): VaultPage => ({ items: ids.map(account), total: ids.length, page: 1, page_size: 50, pages: 1 })
const deferred = <T>() => {
  let resolve!: (value: T) => void
  const promise = new Promise<T>(done => { resolve = done })
  return { promise, resolve }
}
let wrappers: ReturnType<typeof mount>[] = []
let time = 1000
const errors = vi.fn()

function setup() {
  let vault!: ReturnType<typeof useAccountVault>
  const wrapper = mount(defineComponent({ setup() {
    vault = useAccountVault(errors, () => 'request failed')
    return () => h('div')
  } }))
  wrappers.push(wrapper)
  return vault
}

beforeEach(() => {
  vi.clearAllMocks()
  vi.useFakeTimers()
  time = 1000
  vi.spyOn(performance, 'now').mockImplementation(() => time)
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' })
  vi.mocked(accountVaultAPI.status).mockResolvedValue({ configured: true, ready: true, max_import_rows: 500, max_import_bytes: 2097152 })
  vi.mocked(accountVaultAPI.list).mockResolvedValue(pageOf([1, 2]))
  vi.mocked(accountVaultAPI.codes).mockImplementation(async ids => ({ server_time: 1_000_000,
    items: ids.map(id => ({ id, code: '123456', remaining: 30, period: 30, server_time: 1_000_000, expires_at: 1_030_000 })) }))
})

afterEach(() => {
  wrappers.forEach(wrapper => wrapper.unmount())
  wrappers = []
  vi.restoreAllMocks()
  vi.useRealTimers()
})

describe('account vault request lifecycle', () => {
  it('never requests stored accounts before server encryption is ready', async () => {
    vi.mocked(accountVaultAPI.status).mockResolvedValue({ configured: false, ready: false, max_import_rows: 500, max_import_bytes: 2097152 })
    const vault = setup()
    await flushPromises()
    expect(vault.ready.value).toBe(false)
    expect(accountVaultAPI.list).not.toHaveBeenCalled()
    expect(accountVaultAPI.codes).not.toHaveBeenCalled()
  })

  it('does not resurrect a deleted row from an old list response that ignores abort', async () => {
    const vault = setup()
    await flushPromises()
    const stale = deferred<VaultPage>()
    vi.mocked(accountVaultAPI.list).mockReturnValueOnce(stale.promise)
    const oldLoad = vault.load()
    vault.forget(1)
    vi.mocked(accountVaultAPI.list).mockResolvedValueOnce(pageOf([2]))
    await vault.load()
    stale.resolve(pageOf([1, 2]))
    await oldLoad
    expect(vault.accounts.value.map(row => row.id)).toEqual([2])
    expect(vault.total.value).toBe(1)
    expect(vault.code(1)).toBe('')
  })

  it('keeps a new request loading when a superseded request completes', async () => {
    const vault = setup()
    await flushPromises()
    const older = deferred<VaultPage>()
    const newer = deferred<VaultPage>()
    vi.mocked(accountVaultAPI.list).mockReturnValueOnce(older.promise).mockReturnValueOnce(newer.promise)
    const first = vault.load()
    const second = vault.load()
    older.resolve(pageOf([9]))
    await first
    expect(vault.loading.value).toBe(true)
    newer.resolve(pageOf([3]))
    await second
    expect(vault.loading.value).toBe(false)
    expect(vault.accounts.value[0].id).toBe(3)
  })

  it('masks expired codes using monotonic elapsed time and refreshes their matching IDs', async () => {
    const vault = setup()
    await flushPromises()
    expect(vault.code(1)).toBe('123456')
    expect(vault.remaining(1)).toBe(30)
    const pending = deferred<Awaited<ReturnType<typeof accountVaultAPI.codes>>>()
    vi.mocked(accountVaultAPI.codes).mockReturnValueOnce(pending.promise)
    time += 30_000
    await vi.advanceTimersByTimeAsync(250)
    expect(vault.code(1)).toBe('')
    expect(vault.remaining(1)).toBe(0)
    expect(accountVaultAPI.codes).toHaveBeenLastCalledWith([1, 2], expect.any(AbortSignal))
    pending.resolve({ server_time: 1_030_000, items: [{ id: 1, code: '654321', period: 30, expires_at: 1_060_000, server_time: 1_030_000 }] })
    await flushPromises()
    expect(vault.code(1)).toBe('654321')
  })

  it('clears hidden-page codes and ignores the late response until a fresh visible-page request', async () => {
    const vault = setup()
    await flushPromises()
    const pending = deferred<Awaited<ReturnType<typeof accountVaultAPI.codes>>>()
    vi.mocked(accountVaultAPI.codes).mockReturnValueOnce(pending.promise)
    const update = vault.refreshCodes()
    Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'hidden' })
    document.dispatchEvent(new Event('visibilitychange'))
    pending.resolve({ server_time: 1_000_000, items: [{ id: 1, code: '999999', expires_at: 1_030_000 }] })
    await update
    expect(vault.code(1)).toBe('')
    expect(vault.codes.value).toEqual({})
    Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' })
    document.dispatchEvent(new Event('visibilitychange'))
    await flushPromises()
    expect(vault.code(1)).toBe('123456')
  })

  it('does not let a delayed running list undo a completed rotation', async () => {
    const vault = setup()
    await flushPromises()
    const oldList = deferred<VaultPage>()
    vi.mocked(accountVaultAPI.list).mockReturnValueOnce(oldList.promise)
    const load = vault.load()
    const completed: VaultRotationJob = { id: 'finished', account_id: 1, status: 'completed', phase: 'completed', revision: 8, progress: 'completed', message: '', can_cancel: false, can_resume: false, created_at: '', updated_at: '', completed_at: '2026-10-09T01:00:00Z' }
    vault.syncRotation([completed])
    await flushPromises()
    const stale = pageOf([1, 2])
    stale.items[0].rotation_state = 'running'
    stale.items[0].rotation_phase = 'activate_intent'
    oldList.resolve(stale)
    await load
    expect(vault.accounts.value[0].rotation_state).toBe('completed')
    expect(vault.code(1)).toBe('123456')
  })

  it('suppresses old codes when rotation begins and never restores a stale response after completion', async () => {
    const vault = setup()
    await flushPromises()
    const pending = deferred<Awaited<ReturnType<typeof accountVaultAPI.codes>>>()
    vi.mocked(accountVaultAPI.codes).mockReturnValueOnce(pending.promise)
    const oldRequest = vault.refreshCodes([1])
    const base: VaultRotationJob = { id: 'synthetic-job', account_id: 1, status: 'queued', phase: 'login', revision: 1, progress: 'queued', message: '', can_cancel: true, can_resume: false, created_at: '', updated_at: '' }
    vault.syncRotation([base])
    await flushPromises()
    expect(vault.code(1)).toBe('')
    expect(accountVaultAPI.codes).toHaveBeenLastCalledWith([2], expect.any(AbortSignal))
    vi.mocked(accountVaultAPI.codes).mockResolvedValueOnce({ server_time: 1_000_000, items: [{ id: 1, code: '654321', expires_at: 1_030_000 }] })
    vault.syncRotation([{ ...base, status: 'completed', phase: 'completed', revision: 2, completed_at: '2026-10-09T01:00:00Z' }])
    await flushPromises()
    pending.resolve({ server_time: 1_000_000, items: [{ id: 1, code: '111111', expires_at: 1_030_000 }] })
    await oldRequest
    expect(vault.code(1)).toBe('654321')
  })
})
