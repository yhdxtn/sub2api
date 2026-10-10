import { describe, expect, it, vi } from 'vitest'
import { mount } from '@vue/test-utils'
import VaultQuotaCell from '@/components/admin/account-vault/VaultQuotaCell.vue'
import { quotaRemaining, quotaWindowLabel } from '../quota'
vi.mock('vue-i18n', () => ({ useI18n: () => ({ t: (key: string, args?: Record<string, unknown>) => `${key} ${Object.values(args || {}).join(' ')}` }) }))
describe('live quota display', () => {
  const health = { account_id: 1, gateway_account_id: 3, status: 'live', checked_at: '2026-10-10T08:00:00Z', quota: { fetched_at: '2026-10-10T08:00:00Z', primary: { used_percent: 7, limit_window_seconds: 2592000, reset_at: 2000000000, reset_after_seconds: 10 } } }
  it('labels the actual 30 day period and shows remaining percentage', () => {
    const view = mount(VaultQuotaCell, { props: { health } })
    expect(view.text()).toContain('30d'); expect(view.text()).toContain('93'); expect(view.text()).not.toContain('7d')
    expect(quotaWindowLabel(18000)).toBe('5h'); expect(quotaRemaining({ ...health.quota.primary, used_percent: 110 })).toBe(0)
  })
  it('hides stale numbers when the latest query fails', () => {
    const view = mount(VaultQuotaCell, { props: { health, queryError: 'query_failed' } })
    expect(view.text()).toContain('queryFailed'); expect(view.text()).not.toContain('remaining'); expect(view.text()).not.toContain('93')
  })
  it('shows manual verification instead of a historical quota', () => {
    const view = mount(VaultQuotaCell, { props: { health: { ...health, status: 'manual_required', error_code: 'paused_job' } } })
    expect(view.text()).toContain('manualHint'); expect(view.text()).not.toContain('remaining')
  })
})
