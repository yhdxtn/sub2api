import type { VaultQuotaWindow } from '@/types/accountVault'

export function quotaWindowLabel(seconds: number): string {
  if (seconds % 86400 === 0) return `${seconds / 86400}d`
  if (seconds % 3600 === 0) return `${seconds / 3600}h`
  if (seconds % 60 === 0) return `${seconds / 60}m`
  return `${seconds}s`
}

export function quotaRemaining(window: VaultQuotaWindow): number {
  return Math.round(Math.max(0, Math.min(100, 100 - window.used_percent)) * 100) / 100
}
