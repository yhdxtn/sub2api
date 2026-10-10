<template>
  <div class="min-w-32 max-w-40 space-y-1 text-xs" data-testid="vault-quota">
    <template v-if="health?.status === 'live' && health.quota && !queryError">
      <div v-for="(window, i) in windows" :key="i">
        <div class="flex justify-between gap-2"><span>{{ quotaWindowLabel(window.limit_window_seconds) }}</span><span>{{ t('admin.accountVault.automation.remaining', { percent: quotaRemaining(window) }) }}</span></div>
        <div class="mt-1 h-1 rounded bg-gray-100 dark:bg-dark-700"><div class="h-full rounded bg-primary-500" :style="{ width: `${quotaRemaining(window)}%` }"></div></div>
      </div>
      <details class="text-gray-500" data-testid="vault-quota-details">
        <summary class="cursor-pointer" :title="t('admin.accountVault.automation.checked', { time: formatTime(health.quota.fetched_at) })">{{ t('admin.accountVault.automation.checked', { time: formatTime(health.quota.fetched_at) }) }}</summary>
        <p v-for="(window, i) in windows" :key="i">{{ quotaWindowLabel(window.limit_window_seconds) }} · {{ t('admin.accountVault.automation.reset', { time: formatTime(window.reset_at * 1000) }) }}</p>
        <p>{{ t('admin.accountVault.automation.checked', { time: formatTime(health.quota.fetched_at) }) }}</p>
      </details>
    </template>
    <p v-else-if="queryError" class="text-amber-700 dark:text-amber-300">{{ t('admin.accountVault.automation.queryFailed') }}</p>
    <template v-else>
      <p :class="health?.status === 'reauthorizing' ? 'text-primary-700 dark:text-primary-300' : 'text-gray-500'">{{ t(`admin.accountVault.automation.states.${health?.status || 'unknown'}`) }}</p>
      <details v-if="health?.status === 'manual_required' || health?.error_code" class="text-gray-500">
        <summary class="cursor-pointer">{{ t('admin.accountVault.session.details') }}</summary>
        <p v-if="health?.status === 'manual_required'" class="text-amber-700 dark:text-amber-300">{{ t('admin.accountVault.automation.manualHint') }}</p>
        <p v-if="health?.error_code" class="break-all font-mono">{{ health.error_code }}</p>
      </details>
    </template>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import type { VaultAccountHealth, VaultQuotaWindow } from '@/types/accountVault'
import { quotaRemaining, quotaWindowLabel } from '@/features/account-vault/quota'
const props = defineProps<{ health?: VaultAccountHealth; queryError?: string }>()
const { t } = useI18n()
const windows = computed(() => [props.health?.quota?.primary, props.health?.quota?.secondary].filter((v): v is VaultQuotaWindow => !!v))
const formatTime = (time: string | number) => new Date(time).toLocaleString()
</script>
