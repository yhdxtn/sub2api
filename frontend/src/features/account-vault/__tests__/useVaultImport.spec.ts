import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { defineComponent, h } from 'vue'
import { flushPromises, mount } from '@vue/test-utils'
import { useVaultImport } from '../useVaultImport'
import { accountVaultAPI } from '@/api/admin/accountVault'
import { decodeImageLocally } from '../qr/decode-image'
import type { VaultImportResult } from '@/types/accountVault'

vi.mock('@/api/admin/accountVault', () => ({ accountVaultAPI: { import: vi.fn(), parse: vi.fn() } }))
vi.mock('../qr/inspect-image', async original => ({
  ...await original<typeof import('../qr/inspect-image')>(),
  inspectImageFile: vi.fn().mockResolvedValue({ width: 100, height: 100, type: 'image/png' })
}))
vi.mock('../qr/decode-image', () => ({ decodeImageLocally: vi.fn() }))

const record = 'alice@example.test----SyntheticPassword----JBSWY3DPEHPK3PXP'
const preview: VaultImportResult = { total: 1, created: 0, duplicate: 0, failed: 0, ignored: 0,
  rows: [{ line: 1, email: 'alice@example.test', status: 'ready' }] }
const saved: VaultImportResult = { ...preview, created: 1, rows: [{ ...preview.rows[0], id: 9, status: 'created' }] }
const deferred = <T>() => {
  let resolve!: (value: T) => void
  const promise = new Promise<T>(done => { resolve = done })
  return { promise, resolve }
}
const imported = vi.fn()
const authorize = vi.fn(async <T>(action: () => Promise<T>) => action())
let wrappers: ReturnType<typeof mount>[] = []
function setup() {
  let state!: ReturnType<typeof useVaultImport>
  const wrapper = mount(defineComponent({ setup() {
    state = useVaultImport({ maxBytes: 2097152, maxRows: 500, t: key => key, imported, authorize })
    return () => h('div')
  } }))
  wrappers.push(wrapper)
  return state
}
const image = (name = 'synthetic.png') => new File(['synthetic'], name, { type: 'image/png' })

beforeEach(() => {
  vi.clearAllMocks()
  vi.stubGlobal('URL', Object.assign(URL, { createObjectURL: vi.fn(() => 'blob:synthetic'), revokeObjectURL: vi.fn() }))
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' })
  vi.mocked(accountVaultAPI.import).mockResolvedValue(preview)
  vi.mocked(decodeImageLocally).mockResolvedValue('otpauth://totp/Example:alice%40example.test?secret=JBSWY3DPEHPK3PXP')
  vi.mocked(accountVaultAPI.parse).mockResolvedValue({ email: 'alice@example.test', secret: 'JBSWY3DPEHPK3PXP', password: '', issuer: 'Example', algorithm: 'SHA1', digits: 6, period: 30 })
})

afterEach(() => {
  wrappers.forEach(wrapper => wrapper.unmount())
  wrappers = []
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('account vault import review and cleanup', () => {
  it('previews before writing, confirms the reviewed input, then discards credentials', async () => {
    const state = setup()
    // Rendering the footer reads this before the first validation result arrives.
    expect(state.canCommit.value).toBe(false)
    state.setContent(record)
    await state.validate()
    expect(accountVaultAPI.import).toHaveBeenCalledWith({ content: record, dry_run: true, rotate_on_import: false }, expect.any(AbortSignal))
    expect(imported).not.toHaveBeenCalled()
    expect(state.canCommit.value).toBe(true)
    vi.mocked(accountVaultAPI.import).mockResolvedValueOnce(saved)
    await state.commit()
    expect(accountVaultAPI.import).toHaveBeenLastCalledWith({ content: record, dry_run: false, rotate_on_import: true }, expect.any(AbortSignal))
    expect(state.content.value).toBe('')
    expect(state.completed.value).toBe(true)
    expect(state.canCommit.value).toBe(false)
    expect(imported).toHaveBeenCalledWith(saved)
  })

  it('requires another preview after any edit and does not accidentally commit stale input', async () => {
    const state = setup()
    state.setContent(record)
    await state.validate()
    state.setContent(record.replace('alice', 'bob'))
    expect(state.canCommit.value).toBe(false)
    expect(state.result.value).toBeNull()
    await state.commit()
    expect(accountVaultAPI.import).toHaveBeenCalledTimes(1)
  })

  it('ignores a validation response that arrives after editing even when cancellation is ignored', async () => {
    const pending = deferred<VaultImportResult>()
    vi.mocked(accountVaultAPI.import).mockReturnValueOnce(pending.promise)
    const state = setup()
    state.setContent(record)
    const request = state.validate()
    state.setContent('bob@example.test----Changed----GEZDGNBVGY3TQOJQ')
    pending.resolve(preview)
    await request
    expect(state.result.value).toBeNull()
    expect(state.canCommit.value).toBe(false)
  })

  it('previews pasted images until recognize is clicked and releases the original after parsing', async () => {
    const state = setup()
    state.switchTab('images')
    await state.addImages([image()])
    expect(state.images.value[0].preview).toBe('blob:synthetic')
    expect(decodeImageLocally).not.toHaveBeenCalled()
    state.recognizeAll()
    await flushPromises()
    expect(state.images.value[0].state).toBe('ready')
    expect(state.images.value[0].preview).toBe('')
    expect(state.images.value[0].showSecret).toBe(false)
    expect(URL.revokeObjectURL).toHaveBeenCalledWith('blob:synthetic')
    expect(accountVaultAPI.parse).toHaveBeenCalledTimes(1)
  })

  it('requires an email for a QR with no email label, then sends the edited email for server validation', async () => {
    vi.mocked(accountVaultAPI.parse).mockResolvedValueOnce({ email: '', secret: 'JBSWY3DPEHPK3PXP', issuer: 'Example' })
    const state = setup()
    state.switchTab('images')
    await state.addImages([image()], true)
    await flushPromises()
    expect(state.canValidate.value).toBe(false)
    state.images.value[0].item!.email = 'alice@example.test'
    state.changed()
    expect(state.canValidate.value).toBe(true)
    await state.validate()
    expect(accountVaultAPI.import).toHaveBeenCalledWith({ items: [expect.objectContaining({ email: 'alice@example.test', secret: 'JBSWY3DPEHPK3PXP' })], dry_run: true, rotate_on_import: false }, expect.any(AbortSignal))
  })

  it('cancels pending QR responses on reset and cannot repopulate discarded credentials', async () => {
    const pending = deferred<Awaited<ReturnType<typeof accountVaultAPI.parse>>>()
    vi.mocked(accountVaultAPI.parse).mockReturnValueOnce(pending.promise)
    const state = setup()
    state.switchTab('images')
    await state.addImages([image()], true)
    await flushPromises()
    state.reset()
    pending.resolve({ email: 'alice@example.test', secret: 'JBSWY3DPEHPK3PXP' })
    await flushPromises()
    expect(state.images.value).toEqual([])
    expect(state.canValidate.value).toBe(false)
    expect(state.canCommit.value).toBe(false)
    expect(URL.revokeObjectURL).toHaveBeenCalledTimes(1)
  })

  it('recognizes at most two images concurrently and retains individual errors', async () => {
    const one = deferred<string | null>()
    const two = deferred<string | null>()
    vi.mocked(decodeImageLocally).mockReturnValueOnce(one.promise).mockReturnValueOnce(two.promise).mockResolvedValueOnce(null)
    const state = setup()
    await state.addImages([image('1.png'), image('2.png'), image('3.png')], true)
    expect(decodeImageLocally).toHaveBeenCalledTimes(2)
    one.resolve('otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP')
    await flushPromises()
    expect(decodeImageLocally).toHaveBeenCalledTimes(3)
    expect(state.images.value[2].state).toBe('error')
    two.resolve('otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP')
    await flushPromises()
    expect(state.parsedImages.value).toHaveLength(2)
    expect(state.images.value.every(item => !item.preview)).toBe(true)
  })

  it('caps rapid image additions at 20 and hides an explicitly shown Secret on backgrounding', async () => {
    const state = setup()
    await Promise.all([state.addImages(Array.from({ length: 15 }, (_, index) => image(`${index}.png`))), state.addImages(Array.from({ length: 15 }, (_, index) => image(`next-${index}.png`)))])
    expect(state.images.value).toHaveLength(20)
    state.recognizeAll()
    await flushPromises()
    state.toggleSecret(state.images.value[0])
    expect(state.images.value[0].showSecret).toBe(true)
    Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'hidden' })
    document.dispatchEvent(new Event('visibilitychange'))
    expect(state.images.value.every(item => !item.showSecret)).toBe(true)
  })

  it('authorizes automatic rotation only on commit and returns the server queue result without waiting for jobs', async () => {
    const state = setup()
    state.setContent(record)
    expect(state.rotateOnImport.value).toBe(true)
    await state.validate()
    expect(authorize).not.toHaveBeenCalled()
    const result = { ...saved, rotation: { rows: [{ account_id: 9, status: 'queued' as const }] } }
    vi.mocked(accountVaultAPI.import).mockResolvedValueOnce(result)
    await state.commit()
    expect(authorize).toHaveBeenCalledTimes(1)
    expect(state.completed.value).toBe(true)
    expect(imported).toHaveBeenCalledWith(result)
    expect(accountVaultAPI.import).toHaveBeenCalledTimes(2)
  })

  it('retains successful account import when queue submission returns a separate rotation error', async () => {
    const state = setup()
    state.setContent(record)
    await state.validate()
    const result = { ...saved, rotation_error: 'Synthetic queue unavailable' }
    vi.mocked(accountVaultAPI.import).mockResolvedValueOnce(result)
    await state.commit()
    expect(state.completed.value).toBe(true)
    expect(state.result.value?.created).toBe(1)
    expect(state.result.value?.rotation_error).toBe('Synthetic queue unavailable')
    expect(state.content.value).toBe('')
  })

  it('unchecking automatic rotation invalidates the reviewed snapshot and avoids sensitive authorization', async () => {
    const state = setup()
    state.setContent(record)
    await state.validate()
    state.setRotateOnImport(false)
    expect(state.canCommit.value).toBe(false)
    await state.validate()
    vi.mocked(accountVaultAPI.import).mockResolvedValueOnce(saved)
    await state.commit()
    expect(authorize).not.toHaveBeenCalled()
    expect(accountVaultAPI.import).toHaveBeenLastCalledWith({ content: record, dry_run: false, rotate_on_import: false }, expect.any(AbortSignal))
  })

  it('does not automatically mark a Google QR for ChatGPT rotation', async () => {
    vi.mocked(accountVaultAPI.parse).mockResolvedValueOnce({ email: 'alice@example.test', secret: 'JBSWY3DPEHPK3PXP', issuer: 'Google' })
    const state = setup()
    state.switchTab('images')
    await state.addImages([image()], true)
    await flushPromises()
    expect(state.rotateOnImport.value).toBe(false)
    expect(state.rotationHint.value).toBe('admin.accountVault.rotation.otherPlatformDetected')
  })

  it('keeps automatic first rotation enabled for an OpenAI QR', async () => {
    vi.mocked(accountVaultAPI.parse).mockResolvedValueOnce({ email: 'alice@example.test', secret: 'JBSWY3DPEHPK3PXP', issuer: 'OpenAI' })
    const state = setup()
    state.switchTab('images')
    await state.addImages([image()], true)
    await flushPromises()
    expect(state.rotateOnImport.value).toBe(true)
  })

  it('invalidates an already reviewed text batch when a late QR result turns rotation off', async () => {
    const pending = deferred<Awaited<ReturnType<typeof accountVaultAPI.parse>>>()
    vi.mocked(accountVaultAPI.parse).mockReturnValueOnce(pending.promise)
    const state = setup()
    state.switchTab('images')
    await state.addImages([image()], true)
    await flushPromises()
    state.switchTab('text')
    state.setContent(record)
    await state.validate()
    expect(state.canCommit.value).toBe(true)
    pending.resolve({ email: 'alice@example.test', secret: 'JBSWY3DPEHPK3PXP', issuer: 'Google' })
    await flushPromises()
    expect(state.rotateOnImport.value).toBe(false)
    expect(state.canCommit.value).toBe(false)
    await state.commit()
    expect(accountVaultAPI.import).toHaveBeenCalledTimes(1)
  })
})
