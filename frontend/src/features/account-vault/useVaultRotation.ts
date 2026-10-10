import { computed, onBeforeUnmount, onMounted, ref, watch, type Ref } from 'vue'
import { accountVaultAPI } from '@/api/admin/accountVault'
import type { VaultAccount, VaultRotationJob, VaultRotationQueueResult } from '@/types/accountVault'
import { isVaultCancelled, vaultError } from './useAccountVault'
import { rotationNeedsPolling } from './rotation'

/** Poll only public job metadata; lease data and credentials never enter the browser. */
export function useVaultRotation(accounts: Ref<VaultAccount[]>, changed: (jobs: VaultRotationJob[]) => void, kind: 'rotation' | 'session' = 'rotation') {
  const jobs = ref<Record<number, VaultRotationJob>>({})
  const loading = ref(false)
  const queryError = ref('')
  const ownJobs = computed(() => Object.values(jobs.value))
  let alive = true
  let generation = 0
  let controller: AbortController | null = null
  let timer: ReturnType<typeof setTimeout> | undefined
  let queriedIds = ''

  function invalidate() {
    generation += 1
    controller?.abort()
    controller = null
    loading.value = false
    clearTimeout(timer)
  }

  function merge(incoming: VaultRotationJob[]) {
    const next = { ...jobs.value }
    const updates: VaultRotationJob[] = []
    for (const job of incoming) {
      if (!accounts.value.some(account => account.id === job.account_id)) continue
      const current = next[job.account_id]
      if (current?.id === job.id && current.revision > job.revision) continue
      if (current?.id !== job.id && current && Date.parse(current.created_at) > Date.parse(job.created_at)) continue
      if (!current || current.id !== job.id || current.revision !== job.revision || current.status !== job.status || current.phase !== job.phase) updates.push(job)
      next[job.account_id] = job
    }
    jobs.value = next
    if (updates.length) changed(updates)
  }

  function schedule() {
    clearTimeout(timer)
    if (!alive || document.visibilityState === 'hidden') return
    if ((queryError.value && accounts.value.length) || accounts.value.some(account => kind === 'session' ? ['queued', 'running'].includes(jobs.value[account.id]?.status ?? '') : rotationNeedsPolling(account, jobs.value[account.id]))) {
      timer = setTimeout(() => { void query() }, queryError.value ? 5000 : 2000)
    }
  }

  async function query() {
    if (!alive || !accounts.value.length || document.visibilityState === 'hidden') return
    invalidate()
    const current = generation
    const request = new AbortController()
    controller = request
    loading.value = true
    const ids = accounts.value.map(account => account.id)
    try {
      for (let offset = 0; offset < ids.length; offset += 200) {
        const result = await (kind === 'session' ? accountVaultAPI.sessionJobs : accountVaultAPI.rotationJobs)(ids.slice(offset, offset + 200), request.signal)
        if (!alive || request.signal.aborted || current !== generation) return
        merge(result.jobs)
      }
      queryError.value = ''
    } catch (error) {
      if (alive && current === generation && !isVaultCancelled(error)) queryError.value = vaultError(error, 'REQUEST_FAILED')
    } finally {
      if (current === generation) { controller = null; loading.value = false; schedule() }
    }
  }

  function acceptQueue(result: VaultRotationQueueResult) {
    invalidate()
    merge(result.rows.flatMap(row => row.job ? [row.job] : []))
    schedule()
  }

  function acceptJob(job: VaultRotationJob) {
    invalidate()
    merge([job])
    schedule()
  }

  watch(() => accounts.value.map(account => `${account.id}:${account.rotation_state ?? ''}:${account.rotation_phase ?? ''}`).join(','), () => {
    const ids = accounts.value.map(account => account.id).join(',')
    if (ids !== queriedIds) {
      queriedIds = ids
      invalidate()
      jobs.value = Object.fromEntries(Object.entries(jobs.value).filter(([id]) => accounts.value.some(account => account.id === Number(id))))
      void query()
    } else schedule()
  }, { immediate: true })

  function visibilityChanged() {
    invalidate()
    if (document.visibilityState !== 'hidden') void query()
  }

  onMounted(() => document.addEventListener('visibilitychange', visibilityChanged))
  onBeforeUnmount(() => {
    alive = false
    invalidate()
    jobs.value = {}
    document.removeEventListener('visibilitychange', visibilityChanged)
  })

  return { jobs, ownJobs, loading, queryError, query, acceptQueue, acceptJob, invalidate }
}
