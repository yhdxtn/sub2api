import { onBeforeUnmount, onMounted, ref } from 'vue'
import { accountVaultAPI } from '@/api/admin/accountVault'
import { isStepUpBlocked, isStepUpCancelled, stepUpBlockReason } from '@/composables/useStepUp'
import { isVaultCancelled, vaultError } from './useAccountVault'

export function useWorkerConnection(options: {
  authorize: <T>(action: () => Promise<T>) => Promise<T>
  cancelAuthorization: () => void
  copy: (value: string) => Promise<boolean>
  t: (key: string) => string
}) {
  const token = ref('')
  const expiresAt = ref('')
  const copied = ref(false)
  const issued = ref(false)
  const revoked = ref(false)
  const busy = ref('')
  const error = ref('')
  let alive = true
  let sequence = 0
  let controller: AbortController | null = null
  let hideTimer: ReturnType<typeof setTimeout> | undefined

  function clearToken() {
    clearTimeout(hideTimer)
    token.value = ''
    copied.value = false
  }

  function invalidate() {
    sequence += 1
    controller?.abort()
    controller = null
    busy.value = ''
    options.cancelAuthorization()
    clearToken()
  }

  function message(value: unknown) {
    if (isStepUpBlocked(value)) return options.t(stepUpBlockReason(value) === 'STEP_UP_ADMIN_API_KEY_FORBIDDEN' ? 'stepUp.adminApiKeyForbidden' : 'stepUp.notEnabled')
    return vaultError(value, options.t('admin.accountVault.requestFailed'))
  }

  async function generate() {
    const isVisible = () => document.visibilityState !== 'hidden'
    if (busy.value || !isVisible()) return
    invalidate()
    const current = sequence
    const request = new AbortController()
    controller = request
    busy.value = 'generate'
    error.value = ''
    revoked.value = false
    try {
      const result = await options.authorize(() => accountVaultAPI.createWorkerToken(request.signal))
      if (!alive || current !== sequence || request.signal.aborted || !isVisible()) {
        result.token = ''
        return
      }
      token.value = result.token
      result.token = ''
      expiresAt.value = result.expires_at
      issued.value = true
      const remaining = Date.parse(result.expires_at) - Date.now()
      if (!Number.isFinite(remaining) || remaining <= 0) clearToken()
      else hideTimer = setTimeout(clearToken, Math.min(remaining, 8 * 60 * 60 * 1000))
    } catch (value) {
      if (alive && current === sequence && !isVaultCancelled(value) && !isStepUpCancelled(value)) error.value = message(value)
    } finally {
      if (current === sequence) { busy.value = ''; controller = null }
    }
  }

  async function copyToken() {
    if (!token.value || copied.value || busy.value) return
    const current = sequence
    busy.value = 'copy'
    try {
      const success = await options.copy(token.value)
      if (current !== sequence || !alive) return
      copied.value = success
      if (success) {
        clearTimeout(hideTimer)
        hideTimer = setTimeout(clearToken, Math.max(0, Math.min(30_000, Date.parse(expiresAt.value) - Date.now())))
      }
    } finally { if (current === sequence) busy.value = '' }
  }

  async function revoke() {
    if (busy.value) return
    invalidate()
    const current = sequence
    const request = new AbortController()
    controller = request
    busy.value = 'revoke'
    error.value = ''
    try {
      await options.authorize(() => accountVaultAPI.revokeWorkerTokens(request.signal))
      if (!alive || current !== sequence || request.signal.aborted) return
      revoked.value = true
      issued.value = false
      expiresAt.value = ''
    } catch (value) {
      if (alive && current === sequence && !isVaultCancelled(value) && !isStepUpCancelled(value)) error.value = message(value)
    } finally { if (current === sequence) { busy.value = ''; controller = null } }
  }

  function visibilityChanged() { if (document.visibilityState === 'hidden') invalidate() }
  onMounted(() => document.addEventListener('visibilitychange', visibilityChanged))
  onBeforeUnmount(() => {
    alive = false
    invalidate()
    document.removeEventListener('visibilitychange', visibilityChanged)
  })
  return { token, expiresAt, copied, issued, revoked, busy, error, generate, copyToken, revoke, invalidate }
}
