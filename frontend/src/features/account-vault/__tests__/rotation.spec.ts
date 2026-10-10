import { describe, expect, it } from 'vitest'
import { canCancelRotation, canQueueRotation, canResumeRotation, rotationCompleted, rotationProgress, rotationNeedsPolling, rotationRemainingRange, rotationState, rotationSuppressesCode } from '../rotation'
import type { VaultAccount, VaultRotationJob } from '@/types/accountVault'

const account: VaultAccount = { id: 1, email: 'alice@example.test', issuer: 'OpenAI', has_password: true, has_totp: true, algorithm: 'SHA1', digits: 6, period: 30, created_at: '', updated_at: '', rotation_state: 'required', rotation_phase: 'login' }
const job: VaultRotationJob = { id: 'synthetic-job-1', account_id: 1, status: 'queued', phase: 'login', revision: 1, progress: 'queued', message: '', can_cancel: true, can_resume: false, created_at: '2026-10-09T00:00:00Z', updated_at: '2026-10-09T00:00:00Z' }

describe('first rotation state interpretation', () => {
  it('never treats unknown or incomplete completion metadata as a successful rotation', () => {
    expect(rotationState({ ...account, rotation_state: 'future-state' })).toBe('unknown')
    expect(rotationCompleted(account, { ...job, status: 'completed', phase: 'completed' })).toBe(false)
    expect(rotationState(account, { ...job, status: 'completed', phase: 'completed' })).toBe('unknown')
    expect(rotationProgress(account, { ...job, status: 'running', phase: 'verified' })).toBeLessThan(100)
  })
  it('requires a completed new-factor transaction and never queues a completed account again', () => {
    const completed = { ...account, rotation_state: 'completed', rotation_phase: 'completed', rotation_completed_at: '2026-10-09T01:00:00Z' }
    expect(rotationCompleted(completed)).toBe(true)
    expect(rotationProgress(completed)).toBe(100)
    expect(canQueueRotation(completed)).toBe(false)
    expect(rotationSuppressesCode(completed)).toBe(false)
  })
  it('applies both the server capability and the remote-mutation boundary to cancel/resume', () => {
    expect(canCancelRotation(job)).toBe(true)
    expect(canCancelRotation({ ...job, can_cancel: false })).toBe(false)
    expect(canCancelRotation({ ...job, phase: 'disable_intent', can_cancel: true })).toBe(false)
    expect(canResumeRotation({ ...job, status: 'paused', phase: 'enrolled', can_resume: true })).toBe(true)
    expect(canResumeRotation({ ...job, status: 'paused', phase: 'enroll_intent', can_resume: true })).toBe(false)
  })
  it('restores old codes only for cancellation before remote changes', () => {
    for (const phase of ['login', 'prepared']) expect(rotationSuppressesCode({ ...account, rotation_state: 'cancelled', rotation_phase: phase }, { ...job, status: 'cancelled', phase })).toBe(false)
    expect(rotationSuppressesCode({ ...account, rotation_state: 'cancelled' }, { ...job, status: 'cancelled', phase: 'disabled' })).toBe(true)
  })
  it('stops automatic retries and requires maintenance for uncertain enrollment', () => {
    const uncertain = { ...job, status: 'paused', phase: 'enroll_intent', can_cancel: true, can_resume: true }
    expect(rotationState(account, uncertain)).toBe('maintenance')
    expect(rotationNeedsPolling(account, uncertain)).toBe(false)
    expect(rotationSuppressesCode(account, uncertain)).toBe(true)
    expect(canCancelRotation(uncertain)).toBe(false)
    expect(canResumeRotation(uncertain)).toBe(false)
  })
  it('keeps awaiting_user distinct from durable phase and hides old codes while remote changes are uncertain', () => {
    const manual = { ...job, status: 'running', phase: 'login', progress: 'awaiting_user' }
    expect(rotationState(account, manual)).toBe('awaiting_user')
    expect(rotationSuppressesCode(account, manual)).toBe(true)
    expect(rotationSuppressesCode(account, { ...job, status: 'future-state', phase: 'disabled' })).toBe(true)
  })
  it('shows an official redirect as loading with no unreliable time estimate', () => {
    const redirecting = { ...job, status: 'running', progress: 'awaiting_provider' }
    expect(rotationState(account, redirecting)).toBe('awaiting_provider')
    expect(rotationRemainingRange(redirecting)).toBeNull()
    expect(rotationSuppressesCode(account, redirecting)).toBe(true)
  })
})
