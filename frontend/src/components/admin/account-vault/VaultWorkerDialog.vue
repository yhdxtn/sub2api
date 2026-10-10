<template>
  <BaseDialog :show="true" :title="t('admin.accountVault.worker.title')" width="wide" @close="close">
    <div class="space-y-5" data-testid="vault-worker-dialog">
      <p class="text-sm leading-6 text-gray-600 dark:text-gray-300">{{ t('admin.accountVault.worker.description') }}</p>
      <ol class="space-y-4">
        <li class="flex gap-3"><span class="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-primary-50 text-sm font-semibold text-primary-700 dark:bg-primary-900/30 dark:text-primary-300">1</span><div class="min-w-0 text-sm leading-6 text-gray-700 dark:text-gray-200"><p>{{ t('admin.accountVault.worker.install') }}</p><code class="mt-1 inline-block break-all rounded bg-gray-100 px-2 py-1 text-xs dark:bg-dark-700">tools/account-vault-worker/start.cmd</code></div></li>
        <li class="flex gap-3"><span class="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-primary-50 text-sm font-semibold text-primary-700 dark:bg-primary-900/30 dark:text-primary-300">2</span><div class="min-w-0 flex-1 text-sm leading-6 text-gray-700 dark:text-gray-200"><p>{{ t('admin.accountVault.worker.origin') }}</p><div class="mt-2 flex items-center gap-2 rounded-lg border border-gray-200 p-3 dark:border-dark-700"><code class="min-w-0 flex-1 break-all" data-testid="vault-worker-origin">{{ backendOrigin }}</code><button type="button" class="btn btn-ghost !p-2" :aria-label="t('admin.accountVault.worker.copyOrigin')" @click="copyToClipboard(backendOrigin)"><Icon name="copy" size="sm" /></button></div></div></li>
        <li class="flex gap-3"><span class="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-primary-50 text-sm font-semibold text-primary-700 dark:bg-primary-900/30 dark:text-primary-300">3</span><div class="min-w-0 flex-1 text-sm leading-6 text-gray-700 dark:text-gray-200"><p>{{ t('admin.accountVault.worker.enterCode') }}</p><p class="mt-1 text-xs text-gray-600 dark:text-gray-300">{{ t('admin.accountVault.worker.scope') }}</p></div></li>
      </ol>
      <div class="rounded-xl border border-primary-200 bg-primary-50/50 p-4 dark:border-primary-800 dark:bg-primary-900/10">
        <div v-if="token" class="space-y-3">
          <p class="text-sm font-medium text-gray-900 dark:text-gray-100">{{ t('admin.accountVault.worker.oneTimeCode') }}</p>
          <code class="block break-all rounded-lg bg-white p-3 font-mono text-sm text-gray-900 dark:bg-dark-900 dark:text-gray-100" data-testid="vault-worker-token">{{ token }}</code>
          <p class="text-xs text-gray-600 dark:text-gray-300">{{ t('admin.accountVault.worker.expires', { time: formattedExpiry }) }}</p>
          <button type="button" class="btn btn-primary" :disabled="copied || Boolean(busy)" data-testid="vault-copy-worker-token" @click="copyToken"><Icon :name="copied ? 'check' : 'copy'" size="sm" />{{ copied ? t('admin.accountVault.worker.copied') : t('admin.accountVault.worker.copyCode') }}</button>
          <p class="text-xs text-gray-600 dark:text-gray-300">{{ t('admin.accountVault.worker.clearHint') }}</p>
        </div>
        <div v-else class="space-y-3">
          <p class="text-sm text-gray-700 dark:text-gray-200">{{ issued ? t('admin.accountVault.worker.codeCleared') : t('admin.accountVault.worker.generateHint') }}</p>
          <button type="button" class="btn btn-primary" :disabled="Boolean(busy)" data-testid="vault-generate-worker-token" @click="generate">{{ busy === 'generate' ? t('common.processing') : t('admin.accountVault.worker.generate') }}</button>
        </div>
      </div>
      <div v-if="error" role="alert" class="rounded-lg bg-red-50 p-3 text-sm text-red-700 dark:bg-red-950/30 dark:text-red-300">{{ error }}</div>
      <p v-if="revoked" role="status" class="text-sm text-green-700 dark:text-green-300" data-testid="vault-worker-revoked">{{ t('admin.accountVault.worker.revoked') }}</p>
      <p class="text-sm leading-6 text-gray-600 dark:text-gray-300">{{ t('admin.accountVault.worker.manualHint') }}</p>
    </div>
    <template #footer><div class="flex flex-wrap justify-between gap-3"><button type="button" class="btn btn-secondary text-red-700 dark:text-red-300" :disabled="Boolean(busy)" data-testid="vault-revoke-worker-token" @click="revoke">{{ t('admin.accountVault.worker.revoke') }}</button><button type="button" class="btn btn-secondary" @click="close">{{ t('common.close') }}</button></div></template>
  </BaseDialog>
  <TotpStepUpDialog :controller="stepUp" />
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import BaseDialog from '@/components/common/BaseDialog.vue'
import Icon from '@/components/icons/Icon.vue'
import TotpStepUpDialog from '@/components/auth/TotpStepUpDialog.vue'
import { useStepUp } from '@/composables/useStepUp'
import { useClipboard } from '@/composables/useClipboard'
import { getAPIBaseURL } from '@/api/url'
import { useWorkerConnection } from '@/features/account-vault/useWorkerConnection'

const emit = defineEmits<{ close: [] }>()
const { t, locale } = useI18n()
const stepUp = useStepUp()
const { copyToClipboard } = useClipboard()
const backendOrigin = new URL(getAPIBaseURL(), window.location.origin).origin
const { token, expiresAt, copied, issued, revoked, busy, error, generate, copyToken, revoke, invalidate } = useWorkerConnection({
  authorize: stepUp.run, cancelAuthorization: stepUp.onCancel,
  copy: value => copyToClipboard(value, t('admin.accountVault.worker.copied')), t
})
const formattedExpiry = computed(() => {
  const date = new Date(expiresAt.value)
  return Number.isNaN(date.getTime()) ? '—' : date.toLocaleString(locale.value === 'zh' ? 'zh-CN' : 'en-US')
})
function close() { invalidate(); emit('close') }
</script>
