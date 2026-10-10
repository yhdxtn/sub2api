import type { VaultAccount, VaultRotationJob } from '@/types/accountVault'

const phaseOrder = ['login', 'prepared', 'disable_intent', 'disabled', 'enroll_intent', 'enrolled', 'activate_intent', 'verified', 'completed']
const activeStates = new Set(['queued', 'running', 'paused', 'blocked'])
const knownStates = new Set(['required', 'queued', 'running', 'paused', 'completed', 'cancelled', 'blocked'])

export function rotationCompleted(account: VaultAccount, job?: VaultRotationJob): boolean {
  if (job?.status === 'completed' && job.phase === 'completed' && Boolean(job.completed_at)) return true
  return account.rotation_state === 'completed' && Boolean(account.rotation_completed_at)
    && ['completed', 'previously_completed'].includes(account.rotation_phase ?? '')
}

export function rotationState(account: VaultAccount, job?: VaultRotationJob): string {
  if (rotationCompleted(account, job)) return 'completed'
  if (['paused', 'blocked'].includes(job?.status ?? account.rotation_state ?? '') && (job?.phase ?? account.rotation_phase) === 'enroll_intent') return 'maintenance'
  if (job?.progress === 'awaiting_provider' && ['queued', 'running', 'paused'].includes(job.status)) return 'awaiting_provider'
  if (job && ['awaiting_user', 'awaiting_navigation', 'awaiting_cloudflare'].includes(job.progress) && ['queued', 'running', 'paused'].includes(job.status)) return 'awaiting_user'
  const state = job?.status ?? account.rotation_state ?? 'unknown'
  return state !== 'completed' && knownStates.has(state) ? state : 'unknown'
}

export function rotationPhase(account: VaultAccount, job?: VaultRotationJob): string {
  const phase = job?.phase ?? account.rotation_phase ?? ''
  if (phase === 'previously_completed' && rotationCompleted(account, job)) return 'completed'
  return phaseOrder.includes(phase) ? phase : 'unknown'
}

export function rotationProgress(account: VaultAccount, job?: VaultRotationJob): number {
  if (rotationCompleted(account, job)) return 100
  const index = phaseOrder.indexOf(rotationPhase(account, job))
  return index < 0 ? 0 : Math.min(95, Math.round(index / (phaseOrder.length - 1) * 100))
}

/** Broad per-stage ranges; remote login and challenge times are unpredictable. */
export function rotationRemainingRange(job?: VaultRotationJob): [number, number] | null {
  if (!job || job.status !== 'running' || ['awaiting_user', 'awaiting_navigation', 'awaiting_cloudflare', 'awaiting_provider'].includes(job.progress)) return null
  const ranges: Record<string, [number, number]> = {
    login: [2, 6], prepared: [2, 4], disable_intent: [2, 4], disabled: [1, 3],
    enroll_intent: [1, 3], enrolled: [1, 2], activate_intent: [1, 2], verified: [0, 1]
  }
  return ranges[job.phase] ?? null
}

export function rotationSuppressesCode(account: VaultAccount, job?: VaultRotationJob): boolean {
  if (rotationCompleted(account, job)) return false
  return activeStates.has(job?.status ?? '') || activeStates.has(account.rotation_state ?? '')
    || ['disable_intent', 'disabled', 'enroll_intent', 'enrolled', 'activate_intent', 'verified'].includes(job?.phase ?? account.rotation_phase ?? '')
}

export function canQueueRotation(account: VaultAccount, job?: VaultRotationJob): boolean {
  if (rotationCompleted(account, job) || rotationSuppressesCode(account, job)) return false
  return ['required', 'cancelled'].includes(account.rotation_state ?? '')
}

export function canCancelRotation(job?: VaultRotationJob): boolean {
  return Boolean(job?.can_cancel && ['queued', 'running', 'paused'].includes(job.status)
    && ['login', 'prepared'].includes(job.phase))
}

export function canResumeRotation(job?: VaultRotationJob): boolean {
  return Boolean(job?.can_resume && job.status === 'paused' && phaseOrder.includes(job.phase)
    && job.phase !== 'enroll_intent' && job.phase !== 'completed')
}

export function rotationNeedsPolling(account: VaultAccount, job?: VaultRotationJob): boolean {
  if (rotationCompleted(account, job) || job?.status === 'cancelled' || rotationState(account, job) === 'maintenance') return false
  return rotationSuppressesCode(account, job)
}
