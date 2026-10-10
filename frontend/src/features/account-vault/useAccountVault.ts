import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { accountVaultAPI } from '@/api/admin/accountVault'
import type { VaultAccount, VaultCode, VaultRotationJob, VaultStatus } from '@/types/accountVault'
import { rotationSuppressesCode } from './rotation'

interface TimedCode extends VaultCode {
  /** Monotonic local deadline, with the complete request RTT deducted. */
  deadline: number
}

export function vaultError(error: unknown, fallback: string): string {
  const message = (error as { message?: unknown })?.message
  return typeof message === 'string' && message ? message : fallback
}

export function isVaultCancelled(error: unknown): boolean {
  const value = error as { name?: string; code?: string }
  return value?.name === 'AbortError' || value?.code === 'ERR_CANCELED'
}

/** One timer and one batch request serve all visible rows. Credentials never enter this state. */
export function useAccountVault(reportError: (message: string) => void, fallback: () => string) {
  const status = ref<VaultStatus | null>(null)
  const accounts = ref<VaultAccount[]>([])
  const page = ref(1)
  const pageSize = ref(50)
  const total = ref(0)
  const search = ref('')
  const groupName = ref<string | null>(null)
  const loading = ref(false)
  const statusLoading = ref(true)
  const codesLoading = ref(false)
  const codes = ref<Record<number, TimedCode>>({})
  const now = ref(performance.now())
  const selected = ref<Array<string | number>>([])
  const visible = ref(document.visibilityState !== 'hidden')
  const ready = computed(() => status.value?.ready === true)
  let alive = true
  let listGeneration = 0
  let codeGeneration = 0
  let listController: AbortController | null = null
  let codeController: AbortController | null = null
  const statusController = new AbortController()
  let tick: ReturnType<typeof setInterval> | undefined
  let retryAfter = 0

  function invalidateList() {
    listGeneration += 1
    listController?.abort()
    listController = null
    loading.value = false
    clearCodes()
  }

  function clearCodes() {
    codeGeneration += 1
    codeController?.abort()
    codeController = null
    codesLoading.value = false
    codes.value = {}
    retryAfter = 0
  }

  async function load() {
    if (!alive || !ready.value) return
    invalidateList()
    const generation = listGeneration
    const controller = new AbortController()
    listController = controller
    loading.value = true
    try {
      const result = groupName.value === null
        ? await accountVaultAPI.list(page.value, pageSize.value, search.value.trim(), controller.signal)
        : await accountVaultAPI.list(page.value, pageSize.value, search.value.trim(), controller.signal, groupName.value)
      if (!alive || controller.signal.aborted || generation !== listGeneration) return
      if (result.pages > 0 && page.value > result.pages) {
        page.value = result.pages
        await load()
        return
      }
      accounts.value = result.items
      total.value = result.total
      selected.value = selected.value.filter(id => result.items.some(account => account.id === id))
      void refreshCodes()
    } catch (error) {
      if (alive && generation === listGeneration && !isVaultCancelled(error)) reportError(vaultError(error, fallback()))
    } finally {
      if (generation === listGeneration) {
        loading.value = false
        listController = null
      }
    }
  }

  async function refreshCodes(ids = accounts.value.map(account => account.id)) {
    ids = ids.filter(id => accounts.value.some(account => account.id === id && !rotationSuppressesCode(account)))
    if (!alive || !visible.value || !ids.length || codesLoading.value) return
    const generation = codeGeneration
    const controller = new AbortController()
    codeController = controller
    codesLoading.value = true
    const started = performance.now()
    try {
      // The backend caps each request at 200, even if global table preferences are larger.
      for (let offset = 0; offset < ids.length; offset += 200) {
        const result = await accountVaultAPI.codes(ids.slice(offset, offset + 200), controller.signal)
        if (!alive || controller.signal.aborted || generation !== codeGeneration || !visible.value) return
        const received = performance.now()
        const next = { ...codes.value }
        for (const item of result.items) {
          const account = accounts.value.find(account => account.id === item.id)
          if (!account) continue
          if (item.period && Number.isFinite(item.period) && item.period > 0) account.period = item.period
          if (item.code && /^\d+$/.test(item.code)) account.digits = item.code.length
          const lifetime = (item.expires_at ?? 0) - (item.server_time ?? result.server_time)
          next[item.id] = { ...item, deadline: received + Math.max(0, lifetime - (received - started) - 150) }
        }
        codes.value = next
        now.value = received
      }
      retryAfter = performance.now() + 1000
    } catch (error) {
      if (alive && generation === codeGeneration && !isVaultCancelled(error)) {
        const message = vaultError(error, fallback())
        const next = { ...codes.value }
        for (const id of ids) next[id] = { id, error: message, deadline: 0 }
        codes.value = next
        retryAfter = performance.now() + 5000
      }
    } finally {
      if (generation === codeGeneration) {
        codeController = null
        codesLoading.value = false
      }
    }
  }

  function remaining(id: number) {
    const account = accounts.value.find(value => value.id === id)
    if (!visible.value || !codes.value[id]?.code || (account && rotationSuppressesCode(account))) return 0
    return Math.max(0, Math.ceil((codes.value[id].deadline - now.value) / 1000))
  }

  function code(id: number) {
    return remaining(id) > 0 ? codes.value[id]?.code ?? '' : ''
  }

  function forget(id: number) {
    invalidateList()
    accounts.value = accounts.value.filter(account => account.id !== id)
    selected.value = selected.value.filter(value => value !== id)
    total.value = Math.max(0, total.value - 1)
  }

  function syncRotation(jobs: VaultRotationJob[]) {
    const updates = jobs.filter(job => {
      const account = accounts.value.find(value => value.id === job.account_id)
      return account && (account.rotation_state !== job.status || account.rotation_phase !== job.phase
        || (account.rotation_completed_at ?? null) !== (job.completed_at ?? null))
    })
    if (!updates.length) return
    // Invalidate both list and code responses before applying newer job metadata.
    // A delayed list must not restore running state after a completed job.
    invalidateList()
    for (const job of updates) {
      const account = accounts.value.find(value => value.id === job.account_id)
      if (!account) continue
      account.rotation_state = job.status
      account.rotation_phase = job.phase
      account.rotation_completed_at = job.completed_at ?? null
    }
    void refreshCodes()
  }

  async function initialize() {
    statusLoading.value = true
    try {
      const value = await accountVaultAPI.status(statusController.signal)
      if (!alive) return
      status.value = value
      if (value.ready) await load()
    } catch (error) {
      if (alive && !isVaultCancelled(error)) reportError(vaultError(error, fallback()))
    } finally {
      if (alive) statusLoading.value = false
    }
  }

  function visibilityChanged() {
    visible.value = document.visibilityState !== 'hidden'
    clearCodes()
    now.value = performance.now()
    if (visible.value) void refreshCodes()
  }

  onMounted(() => {
    void initialize()
    document.addEventListener('visibilitychange', visibilityChanged)
    tick = setInterval(() => {
      now.value = performance.now()
      if (!visible.value || codesLoading.value || loading.value || now.value < retryAfter) return
      const expired = accounts.value.filter(account => !rotationSuppressesCode(account) && !code(account.id)).map(account => account.id)
      if (expired.length) void refreshCodes(expired)
    }, 250)
  })

  onBeforeUnmount(() => {
    alive = false
    invalidateList()
    statusController.abort()
    clearInterval(tick)
    document.removeEventListener('visibilitychange', visibilityChanged)
    accounts.value = []
  })

  return { status, statusLoading, ready, accounts, page, pageSize, total, search, groupName, selected,
    loading, codesLoading, codes, remaining, code, load, initialize, refreshCodes, forget, invalidateList, syncRotation }
}
