import { onBeforeUnmount, onMounted, ref, watch, type Ref } from 'vue'
import { accountVaultAPI } from '@/api/admin/accountVault'
import type { VaultAccount, VaultAccountHealth } from '@/types/accountVault'

export function useVaultAutomation(accounts: Ref<VaultAccount[]>, jobsChanged: () => Promise<void>) {
  const enabled = ref(false)
  const error = ref('')
  const health = ref<Record<number, VaultAccountHealth>>({})
  const busy = ref(false)
  let alive = true
  let timer: ReturnType<typeof setTimeout> | undefined
  let controller: AbortController | undefined
  const visible = () => document.visibilityState !== 'hidden'
  async function query(force = false) {
    if (!alive || !visible() || busy.value) return
    clearTimeout(timer)
    controller = new AbortController()
    busy.value = true
    try {
      const settings = await accountVaultAPI.automationSettings(controller.signal)
      if (!alive) return
      enabled.value = settings.enabled
      const ids = accounts.value.map(v => v.id)
      const next: Record<number, VaultAccountHealth> = {}
      for (let offset = 0; offset < ids.length; offset += 200) {
        const result = await accountVaultAPI.automationHealth(ids.slice(offset, offset + 200), force, controller.signal)
        if (!alive) return
        for (const row of result.rows) next[row.account_id] = row
      }
      if (ids.join(',') !== accounts.value.map(v => v.id).join(',')) return
      health.value = next
      error.value = ''
      if (Object.values(next).some(v => v.status === 'reauthorizing' || v.status === 'manual_required')) await jobsChanged()
    } catch (failure) {
      if (alive && !controller.signal.aborted) error.value = 'query_failed'
      if (force) throw failure
    }
    finally { busy.value = false; if (alive && visible()) timer = setTimeout(() => { void query() }, 10000) }
  }
  function visibilityChanged() { clearTimeout(timer); if (document.visibilityState === 'hidden') controller?.abort(); else void query() }
  watch(() => accounts.value.map(v => v.id).join(','), () => { void query() })
  onMounted(() => { document.addEventListener('visibilitychange', visibilityChanged); void query() })
  onBeforeUnmount(() => { alive = false; clearTimeout(timer); controller?.abort(); document.removeEventListener('visibilitychange', visibilityChanged) })
  return { enabled, error, health, busy, query }
}
