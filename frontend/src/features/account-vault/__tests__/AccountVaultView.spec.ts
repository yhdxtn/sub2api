import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { defineComponent, h } from 'vue'
import { flushPromises, mount } from '@vue/test-utils'
import AccountVaultView from '@/views/admin/AccountVaultView.vue'
import { accountVaultAPI } from '@/api/admin/accountVault'

const mocks = vi.hoisted(() => ({ copy: vi.fn().mockResolvedValue(true), success: vi.fn(), error: vi.fn() }))
vi.mock('@/api/admin/accountVault', () => ({ accountVaultAPI: {
  automationSettings: vi.fn(), setAutomation: vi.fn(), automationHealth: vi.fn(), reauthorizeInvalid: vi.fn(),
  status: vi.fn(), list: vi.fn(), codes: vi.fn(), password: vi.fn(), secret: vi.fn(), delete: vi.fn(), rotationJobs: vi.fn(), queueRotation: vi.fn(), sessionJobs: vi.fn(), queueSessions: vi.fn(), exportSessions: vi.fn(), exportText: vi.fn(), groups: vi.fn(), assignGroup: vi.fn()
} }))
vi.mock('@/stores/app', () => ({ useAppStore: () => ({ showSuccess: mocks.success, showError: mocks.error }) }))
vi.mock('@/composables/useClipboard', () => ({ useClipboard: () => ({ copyToClipboard: mocks.copy }) }))
vi.mock('vue-i18n', async original => ({ ...await original<typeof import('vue-i18n')>(), useI18n: () => ({ t: (key: string) => key }) }))
vi.mock('@/components/admin/account-vault/AccountVaultImportDialog.vue', () => ({ default: defineComponent({ setup: () => () => h('div') }) }))

const row = (id: number) => ({ id, email: `user${id}@example.test`, issuer: 'Example', has_password: true,
  has_totp: true, algorithm: 'SHA1', digits: 6, period: 30, rotation_state: 'required', rotation_phase: '', created_at: '', updated_at: '' })
const deferred = <T>() => {
  let resolve!: (value: T) => void
  const promise = new Promise<T>(done => { resolve = done })
  return { promise, resolve }
}
let wrapper: ReturnType<typeof mount> | undefined
const DataTableStub = defineComponent({
  props: ['data', 'selectedKeys'],
  emits: ['update:selectedKeys'],
  setup(props, { slots, emit }) {
    return () => h('section', (props.data ?? []).map((value: ReturnType<typeof row>) => h('article', { 'data-row': value.id },
      [h('input', { type: 'checkbox', 'data-testid': `select-${value.id}`, onChange: (event: Event) => {
        const selected = props.selectedKeys ?? []
        emit('update:selectedKeys', (event.target as HTMLInputElement).checked ? [...selected, value.id] : selected.filter((id: number) => id !== value.id))
      } }), ...['email', 'group', 'id', 'password', 'totp', 'remaining', 'rotation', 'session', 'actions'].flatMap(key => slots[`cell-${key}`]?.({ row: value }) ?? [])]
    )))
  }
})

beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(accountVaultAPI.automationSettings).mockResolvedValue({ enabled: false, query_interval_seconds: 60 })
  vi.mocked(accountVaultAPI.automationHealth).mockResolvedValue({ rows: [] })
  vi.mocked(accountVaultAPI.setAutomation).mockResolvedValue({ enabled: true, query_interval_seconds: 60 })
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' })
  vi.mocked(accountVaultAPI.status).mockResolvedValue({ configured: true, ready: true, max_import_rows: 500, max_import_bytes: 2097152 })
  vi.mocked(accountVaultAPI.list).mockResolvedValue({ items: [row(1), row(2)], page: 1, page_size: 50, total: 2, pages: 1 })
  vi.mocked(accountVaultAPI.rotationJobs).mockResolvedValue({ jobs: [] })
  vi.mocked(accountVaultAPI.sessionJobs).mockResolvedValue({ jobs: [] })
  vi.mocked(accountVaultAPI.groups).mockResolvedValue({ groups: [{ name: '测试组', count: 2 }] })
  vi.mocked(accountVaultAPI.assignGroup).mockResolvedValue({ updated: 2 })
  vi.mocked(accountVaultAPI.codes).mockImplementation(async ids => ({ server_time: 1_000_000,
    items: ids.map(id => ({ id, code: '111111', remaining: 30, period: 30, expires_at: 1_030_000, server_time: 1_000_000 })) }))
})

afterEach(() => { wrapper?.unmount(); wrapper = undefined; vi.restoreAllMocks() })

async function setup() {
  wrapper = mount(AccountVaultView, { global: { stubs: {
    AppLayout: { template: '<main><slot /></main>' },
    TablePageLayout: { template: '<div><slot name="actions" /><slot name="filters" /><slot name="table" /><slot name="pagination" /></div>' },
    DataTable: DataTableStub,
    Pagination: true,
    Icon: true,
    BaseDialog: { props: ['show'], template: '<section v-if="show"><slot /><slot name="footer" /></section>' },
    TotpStepUpDialog: { props: ['controller'], template: '<button v-if="controller.visible.value" data-testid="verify-step-up" @click="controller.onVerified()">Verify</button>' }
  } } })
  await flushPromises()
  return wrapper
}

describe('account vault sensitive interactions', () => {
  it('checks invalid credentials across all pages without depending on selection', async () => {
    vi.mocked(accountVaultAPI.reauthorizeInvalid).mockResolvedValue({ rows: [{ account_id: 99, status: 'queued' }], checked: 2, refreshed: 1, failed: 0, skipped: 1 })
    const page = await setup()
    await page.get('[data-testid="select-1"]').setValue(true)
    await page.get('[data-testid="vault-reauthorize-invalid"]').trigger('click')
    await flushPromises()
    expect(accountVaultAPI.reauthorizeInvalid).toHaveBeenCalledWith(expect.any(AbortSignal))
    expect(accountVaultAPI.queueRotation).not.toHaveBeenCalled()
    expect(mocks.success).toHaveBeenCalledWith('admin.accountVault.automation.reauthorizeResult')
  })
  it('keeps completed authorization details collapsed by default', async () => {
    vi.mocked(accountVaultAPI.sessionJobs).mockResolvedValue({ jobs: [{ id: 'completed', account_id: 1, status: 'completed', phase: 'completed', completed_at: '2026-10-10T00:00:00Z', gateway_account_id: 42, revision: 1, progress: 'completed', message: 'Complete', can_cancel: false, can_resume: false, created_at: '', updated_at: '' }] })
    const page = await setup()
    expect(page.get('[data-testid="vault-session-details-1"]').attributes('open')).toBeUndefined()
    expect(page.get('[data-testid="vault-session-1"]').text()).toContain('readyShort')
    expect(page.get('[data-testid="vault-session-1"]').find('[role="progressbar"]').exists()).toBe(false)
  })
  it('enables automatic recovery and requests live quota for the current rows', async () => {
    const page = await setup()
    await page.get('[data-testid="vault-auto-reauth"]').setValue(true)
    await flushPromises()
    expect(accountVaultAPI.setAutomation).toHaveBeenCalledWith(true)
    await page.get('[data-testid="vault-query-quota"]').trigger('click')
    await flushPromises()
    expect(accountVaultAPI.automationHealth).toHaveBeenCalledWith([1, 2], true, expect.any(AbortSignal))
  })
  it('groups exactly the selected accounts and clears the completed selection', async () => {
    const page = await setup()
    await page.get('[data-testid="select-1"]').setValue(true)
    await page.get('[data-testid="select-2"]').setValue(true)
    await page.get('[data-testid="vault-group-selected"]').trigger('click')
    await page.get('[data-testid="vault-group-name"]').setValue(' 新分组 ')
    await page.get('[data-testid="vault-group-save"]').trigger('click')
    await flushPromises()
    expect(accountVaultAPI.assignGroup).toHaveBeenCalledWith([1, 2], '新分组', expect.any(AbortSignal))
    expect(page.find('[data-testid="vault-group-selected"]').exists()).toBe(false)
    expect(accountVaultAPI.password).not.toHaveBeenCalled()
    expect(accountVaultAPI.queueRotation).not.toHaveBeenCalled()
  })
  it('clears a single account group and forwards an ungrouped filter to server pagination', async () => {
    const page = await setup()
    await page.get('[data-testid="vault-group-2"]').trigger('click')
    await page.get('[data-testid="vault-group-clear"]').trigger('click')
    await page.get('[data-testid="vault-group-save"]').trigger('click')
    await flushPromises()
    expect(accountVaultAPI.assignGroup).toHaveBeenCalledWith([2], '', expect.any(AbortSignal))
    await page.get('[data-testid="select-1"]').setValue(true)
    await page.get('[data-testid="vault-group-filter"]').setValue('测试组')
    await flushPromises()
    expect(accountVaultAPI.list).toHaveBeenLastCalledWith(1, 50, '', expect.any(AbortSignal), '测试组')
    expect(page.find('[data-testid="vault-group-selected"]').exists()).toBe(false)
    await page.get('[data-testid="vault-group-filter"]').setValue('')
    await flushPromises()
    expect(accountVaultAPI.list).toHaveBeenLastCalledWith(1, 50, '', expect.any(AbortSignal), '')
  })
	 it('copies exactly the selected accounts in table order as one multiline text', async () => {
		 const content = 'user1@example.test----synthetic-password----JBSWY3DPEHPK3PXP----备注\nuser2@example.test--------JBSWY3DPEHPK3PXP'
		 vi.mocked(accountVaultAPI.exportText).mockResolvedValueOnce({ content, count: 2 })
		 const page = await setup()
		 await page.get('[data-testid="select-2"]').setValue(true)
		 await page.get('[data-testid="select-1"]').setValue(true)
		 await page.get('[data-testid="vault-copy-selected"]').trigger('click')
		 await flushPromises()
		 expect(accountVaultAPI.exportText).toHaveBeenCalledWith([1, 2], expect.any(AbortSignal))
		 expect(mocks.copy).toHaveBeenCalledWith(content, 'admin.accountVault.accountsCopied')
		 expect(page.text()).not.toContain('synthetic-password')
		 expect(page.text()).not.toContain('JBSWY3DPEHPK3PXP')
	 })
	 it('copies one complete account and discards a late batch after backgrounding', async () => {
		 vi.mocked(accountVaultAPI.exportText).mockResolvedValueOnce({ content: 'user2@example.test----synthetic----JBSWY3DPEHPK3PXP', count: 1 })
		 const page = await setup()
		 await page.get('[data-testid="vault-copy-account-2"]').trigger('click')
		 await flushPromises()
		 expect(accountVaultAPI.exportText).toHaveBeenCalledWith([2], expect.any(AbortSignal))
		 mocks.copy.mockClear()
		 const pending = deferred<{ content: string; count: number }>()
		 vi.mocked(accountVaultAPI.exportText).mockReturnValueOnce(pending.promise)
		 await page.get('[data-testid="select-1"]').setValue(true)
		 await page.get('[data-testid="vault-copy-selected"]').trigger('click')
		 Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'hidden' })
		 document.dispatchEvent(new Event('visibilitychange'))
		 const result = { content: 'delayed-private-content', count: 1 }
		 pending.resolve(result)
		 await flushPromises()
		 expect(mocks.copy).not.toHaveBeenCalled()
		 expect(result.content).toBe('')
		 expect(accountVaultAPI.exportText).toHaveBeenLastCalledWith([1], expect.objectContaining({ aborted: true }))
	 })
  it('copies the account email without requesting credentials', async () => {
    const page = await setup()
    await page.get('[data-testid="vault-copy-email-2"]').trigger('click')
    expect(mocks.copy).toHaveBeenCalledWith('user2@example.test', 'admin.accountVault.emailCopied')
    expect(accountVaultAPI.password).not.toHaveBeenCalled()
  })
  it('queues OAuth authorization directly and keeps rotation requests separate', async () => {
    vi.mocked(accountVaultAPI.queueSessions).mockResolvedValue({ rows: [{ account_id: 1, status: 'queued' }, { account_id: 2, status: 'queued' }] })
    vi.mocked(accountVaultAPI.queueRotation).mockResolvedValue({ rows: [{ account_id: 1, status: 'queued' }, { account_id: 2, status: 'queued' }] })
    const page = await setup()
    await page.get('[data-testid="select-1"]').setValue(true)
    await page.get('[data-testid="vault-session-selected"]').trigger('click')
    await flushPromises()
    expect(accountVaultAPI.queueSessions).toHaveBeenCalledWith([1], 1, expect.any(AbortSignal))
    expect(accountVaultAPI.queueRotation).not.toHaveBeenCalled()
    await page.get('[data-testid="select-2"]').setValue(true)
    await page.get('[data-testid="vault-queue-selected"]').trigger('click')
    await flushPromises()
    expect(accountVaultAPI.queueRotation).toHaveBeenCalledWith([1, 2], expect.any(AbortSignal), 2)
  })
  it('shows actual OAuth expiry and permits reauthorization without a raw Session download', async () => {
    vi.mocked(accountVaultAPI.sessionJobs).mockResolvedValue({ jobs: [{ id: 'synthetic-job', account_id: 1, kind: 'session', gateway_account_id: 42, credential_expires_at: '2030-01-01T00:00:00Z', status: 'completed', phase: 'completed', progress: 'completed', revision: 3, message: 'OAuth authorization complete', can_cancel: false, can_resume: false, created_at: '', updated_at: '', completed_at: '2026-10-10T00:00:00Z' }] })
    vi.mocked(accountVaultAPI.queueSessions).mockResolvedValue({ rows: [{ account_id: 1, status: 'queued' }] })
    const page = await setup()
    expect(page.text()).toContain('admin.accountVault.session.expires')
    expect(page.text()).toContain('admin.accountVault.session.refreshHint')
    expect(page.text()).not.toContain('admin.accountVault.session.raw')
    expect(page.get('[data-testid="vault-session-queue-1"]').text()).toBe('admin.accountVault.session.update')
    await page.get('[data-testid="vault-session-queue-1"]').trigger('click')
    await flushPromises()
    expect(accountVaultAPI.queueSessions).toHaveBeenCalledWith([1], 1, expect.any(AbortSignal))
  })
  it('submits all selected eligible accounts directly without a concurrency dialog', async () => {
    vi.mocked(accountVaultAPI.queueRotation).mockResolvedValue({ rows: [{ account_id: 1, status: 'queued' }, { account_id: 2, status: 'queued' }] })
    const page = await setup()
    await page.get('[data-testid="select-1"]').setValue(true)
    await page.get('[data-testid="select-2"]').setValue(true)
    await page.get('[data-testid="vault-queue-selected"]').trigger('click')
    await flushPromises()
    expect(accountVaultAPI.queueRotation).toHaveBeenCalledWith([1, 2], expect.any(AbortSignal), 2)
    expect(page.find('[data-testid="vault-concurrency"]').exists()).toBe(false)
    expect(page.find('[data-testid="vault-confirm-queue"]').exists()).toBe(false)
  })
  it('serializes password and Secret reads while reusing the existing step-up prompt', async () => {
    vi.mocked(accountVaultAPI.password).mockRejectedValueOnce({ code: 'STEP_UP_REQUIRED' }).mockResolvedValueOnce({ password: 'SyntheticPasswordOnly' })
    const page = await setup()
    await page.get('[data-testid="vault-copy-password-1"]').trigger('click')
    await flushPromises()
    expect(page.find('[data-testid="verify-step-up"]').exists()).toBe(true)
    expect(page.get('[data-testid="vault-show-secret-2"]').attributes('disabled')).toBeDefined()
    expect(mocks.copy).not.toHaveBeenCalled()
    await page.get('[data-testid="verify-step-up"]').trigger('click')
    await flushPromises()
    expect(accountVaultAPI.password).toHaveBeenCalledTimes(2)
    expect(mocks.copy).toHaveBeenCalledWith('SyntheticPasswordOnly', 'admin.accountVault.passwordCopied')
    expect(page.text()).not.toContain('SyntheticPasswordOnly')
    expect(accountVaultAPI.secret).not.toHaveBeenCalled()
  })

  it('ignores a delayed Secret response after the page is backgrounded', async () => {
    const pending = deferred<{ secret: string }>()
    vi.mocked(accountVaultAPI.secret).mockReturnValueOnce(pending.promise)
    const page = await setup()
    await page.get('[data-testid="vault-show-secret-1"]').trigger('click')
    Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'hidden' })
    document.dispatchEvent(new Event('visibilitychange'))
    pending.resolve({ secret: 'JBSWY3DPEHPK3PXP' })
    await flushPromises()
    expect(page.find('[data-testid="vault-revealed-secret"]').exists()).toBe(false)
    expect(page.text()).not.toContain('JBSWY3DPEHPK3PXP')
    expect(accountVaultAPI.secret).toHaveBeenCalledWith(1, expect.objectContaining({ aborted: true }))
  })

  it('fetches the exact row code freshly before copying instead of using the displayed cached code', async () => {
    const page = await setup()
    expect(page.get('[data-testid="vault-code-2"]').text()).toBe('111 111')
    vi.mocked(accountVaultAPI.codes).mockResolvedValueOnce({ server_time: 1_030_000,
      items: [{ id: 2, code: '222222', expires_at: 1_060_000, server_time: 1_030_000 }] })
    await page.get('[data-testid="vault-copy-code-2"]').trigger('click')
    await flushPromises()
    expect(accountVaultAPI.codes).toHaveBeenLastCalledWith([2], expect.any(AbortSignal))
    expect(mocks.copy).toHaveBeenCalledWith('222222', 'admin.accountVault.codeCopied')
  })

  it('refuses to copy a response that is already expired', async () => {
    const page = await setup()
    vi.mocked(accountVaultAPI.codes).mockResolvedValueOnce({ server_time: 1_030_000,
      items: [{ id: 1, code: '000000', expires_at: 1_030_000, server_time: 1_030_000 }] })
    await page.get('[data-testid="vault-copy-code-1"]').trigger('click')
    await flushPromises()
    expect(mocks.copy).not.toHaveBeenCalled()
    expect(mocks.error).toHaveBeenCalledWith('admin.accountVault.codeExpired')
  })
})
