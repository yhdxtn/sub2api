<template>
  <BaseDialog :show="show" :title="t('admin.accountVault.import.title')" width="extra-wide"
    :close-on-escape="!committing" :show-close-button="!committing" @close="close">
    <div class="space-y-5" data-testid="vault-import-dialog">
      <div v-if="!completed" class="flex flex-wrap gap-2 border-b border-gray-200 pb-4 dark:border-dark-700" role="tablist" :aria-label="t('admin.accountVault.import.method')">
        <button type="button" role="tab" :aria-selected="tab === 'text'" :disabled="committing"
          :class="['btn', tab === 'text' ? 'btn-primary' : 'btn-secondary']" data-testid="vault-import-text-tab" @click="switchTab('text')">
          <Icon name="document" size="sm" />{{ t('admin.accountVault.import.textTab') }}
        </button>
        <button type="button" role="tab" :aria-selected="tab === 'images'" :disabled="committing"
          :class="['btn', tab === 'images' ? 'btn-primary' : 'btn-secondary']" data-testid="vault-import-qr-tab" @click="switchTab('images')">
          <Icon name="grid" size="sm" />{{ t('admin.accountVault.import.imagesTab') }}
        </button>
        <p class="ml-auto self-center text-xs text-gray-600 dark:text-gray-300">{{ t('admin.accountVault.import.transient') }}</p>
      </div>

      <section v-if="!completed && tab === 'text'" class="space-y-3">
        <div class="flex flex-wrap items-center justify-between gap-3">
          <label for="vault-import-content" class="text-sm font-medium text-gray-800 dark:text-gray-100">{{ t('admin.accountVault.import.contentLabel') }}</label>
          <button type="button" class="btn btn-secondary btn-sm" :disabled="committing" @click="textInput?.click()">
            <Icon name="upload" size="sm" />{{ t('admin.accountVault.import.chooseTextFile') }}
          </button>
          <input ref="textInput" type="file" class="hidden" accept=".txt,.json,.csv,text/plain,application/json,text/csv" data-testid="vault-text-file" @change="onTextFile" />
        </div>
        <textarea id="vault-import-content" :value="content" :disabled="committing" rows="8"
          class="input w-full resize-y font-mono text-sm leading-6" autocomplete="off" autocapitalize="off" spellcheck="false"
          :placeholder="textExample" data-testid="vault-import-content" @input="setContent(($event.target as HTMLTextAreaElement).value)"></textarea>
        <p class="text-sm leading-6 text-gray-600 dark:text-gray-300">{{ t('admin.accountVault.import.textHint', { count: maxRows }) }}</p>
      </section>

      <section v-if="!completed && tab === 'images'" class="space-y-4">
        <div tabindex="0" role="region" :aria-label="t('admin.accountVault.import.dropTitle')"
          :class="['rounded-xl border-2 border-dashed p-5 text-center outline-none transition-colors focus-visible:ring-2 focus-visible:ring-primary-500', dragging ? 'border-primary-500 bg-primary-50 dark:bg-primary-900/20' : 'border-gray-300 bg-gray-50/70 dark:border-dark-600 dark:bg-dark-900/40']"
          data-testid="vault-qr-dropzone" @paste="handlePaste" @dragover.prevent="dragging = true" @dragleave.prevent="dragging = false" @drop.prevent="onDrop">
          <Icon name="clipboard" size="lg" class="mx-auto mb-2 text-primary-600 dark:text-primary-400" />
          <h4 class="text-base font-semibold text-gray-900 dark:text-gray-100">{{ t('admin.accountVault.import.dropTitle') }}</h4>
          <p class="mt-1 text-sm text-gray-600 dark:text-gray-300">{{ t('admin.accountVault.import.dropHint') }}</p>
          <p class="mt-2 text-xs text-gray-600 dark:text-gray-400">{{ t('admin.accountVault.import.imageLimits') }}</p>
          <div class="mt-4 flex flex-wrap justify-center gap-2">
            <button type="button" class="btn btn-secondary" :disabled="committing" @click="imageInput?.click()">
              <Icon name="upload" size="sm" />{{ t('admin.accountVault.import.chooseImages') }}
            </button>
            <button type="button" class="btn btn-secondary" :disabled="readingClipboard || committing" data-testid="vault-read-clipboard" @click="readClipboard">
              <Icon name="clipboard" size="sm" />{{ readingClipboard ? t('common.loading') : t('admin.accountVault.import.readClipboard') }}
            </button>
            <button type="button" class="btn btn-primary" :disabled="!pendingImages || committing" data-testid="vault-recognize-all" @click="recognizeAll">
              {{ t('admin.accountVault.import.recognize', { count: pendingImages }) }}
            </button>
          </div>
          <input ref="imageInput" type="file" class="hidden" accept="image/png,image/jpeg,image/webp,.png,.jpg,.jpeg,.webp" multiple data-testid="vault-qr-files" @change="onImages" />
        </div>

        <div v-if="images.length" class="space-y-3" data-testid="vault-image-list">
          <div class="flex items-center justify-between gap-3 text-sm text-gray-600 dark:text-gray-300">
            <span>{{ t('admin.accountVault.import.imageProgress', { total: images.length, parsed: parsedImages.length }) }}</span>
            <span v-if="busyImages" class="flex items-center gap-2"><Icon name="refresh" size="sm" class="animate-spin" />{{ t('admin.accountVault.import.processingImages') }}</span>
          </div>
          <article v-for="image in images" :key="image.id" class="rounded-xl border border-gray-200 p-4 dark:border-dark-600" :data-image-id="image.id">
            <div class="flex items-start gap-3">
              <img v-if="image.preview" :src="image.preview" :alt="t('admin.accountVault.import.previewAlt')" class="h-20 w-20 flex-none rounded-lg border border-gray-200 bg-white object-contain" />
              <div v-else class="flex h-11 w-11 flex-none items-center justify-center rounded-lg" :class="image.state === 'error' ? 'bg-red-50 text-red-700 dark:bg-red-900/20 dark:text-red-300' : 'bg-primary-50 text-primary-700 dark:bg-primary-900/20 dark:text-primary-300'">
                <Icon :name="image.state === 'error' ? 'exclamationCircle' : image.state === 'ready' ? 'checkCircle' : 'grid'" size="md" />
              </div>
              <div class="min-w-0 flex-1">
                <div class="flex flex-wrap items-center gap-2">
                  <h5 class="break-all text-sm font-medium text-gray-900 dark:text-gray-100">{{ image.name }}</h5>
                  <span class="rounded px-2 py-0.5 text-xs font-medium" :class="image.state === 'error' ? 'bg-red-50 text-red-700 dark:bg-red-900/20 dark:text-red-300' : image.state === 'ready' ? 'bg-green-50 text-green-700 dark:bg-green-900/20 dark:text-green-300' : 'bg-gray-100 text-gray-700 dark:bg-dark-700 dark:text-gray-300'">{{ t(`admin.accountVault.import.imageState.${image.state}`) }}</span>
                </div>
                <p v-if="image.message" class="mt-2 break-words text-sm text-red-700 dark:text-red-300">{{ image.message }}</p>
                <p v-if="image.state === 'ready'" class="mt-1 text-xs text-gray-600 dark:text-gray-300">{{ t('admin.accountVault.import.imageReleased') }}</p>
              </div>
              <button type="button" class="btn btn-ghost !p-2" :disabled="committing" :aria-label="t('admin.accountVault.import.removeImage', { name: image.name })" @click="removeImage(image)"><Icon name="x" size="sm" /></button>
            </div>
            <div v-if="image.item" class="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              <label class="min-w-0 text-xs font-medium text-gray-600 dark:text-gray-300">
                {{ t('admin.accountVault.email') }}
                <input v-model="image.item.email" type="email" :disabled="committing" class="input mt-1 w-full text-sm" autocomplete="off" :placeholder="t('admin.accountVault.import.emailRequired')" :data-testid="`vault-qr-email-${image.id}`" @input="changed" />
              </label>
              <div class="min-w-0 text-xs font-medium text-gray-600 dark:text-gray-300">
                {{ t('admin.accountVault.issuer') }}
                <p class="mt-2 break-words text-sm text-gray-900 dark:text-gray-100">{{ image.item.issuer || t('admin.accountVault.noIssuer') }}</p>
                <p class="mt-1 text-xs">{{ image.item.algorithm }} · {{ image.item.digits }} · {{ image.item.period }} s</p>
              </div>
              <label class="min-w-0 text-xs font-medium text-gray-600 dark:text-gray-300">
                {{ t('admin.accountVault.import.optionalPassword') }}
                <input v-model="image.item.password" type="password" :disabled="committing" class="input mt-1 w-full text-sm" autocomplete="new-password" @input="changed" />
              </label>
              <div class="min-w-0 text-xs font-medium text-gray-600 dark:text-gray-300">
                {{ t('admin.accountVault.secret') }}
                <div class="mt-1 flex min-h-10 items-center gap-2">
                  <span class="min-w-0 break-all font-mono text-sm text-gray-800 dark:text-gray-100">{{ image.showSecret ? image.item.secret : '••••••••••••' }}</span>
                  <button type="button" class="btn btn-ghost shrink-0 !p-2" :aria-label="image.showSecret ? t('admin.accountVault.hideSecret') : t('admin.accountVault.showSecret')" @click="toggleSecret(image)"><Icon :name="image.showSecret ? 'eyeOff' : 'eye'" size="sm" /></button>
                </div>
              </div>
            </div>
          </article>
        </div>
      </section>

      <section v-if="!completed" class="rounded-xl border border-primary-200 bg-primary-50/60 p-4 dark:border-primary-800 dark:bg-primary-900/20">
        <label class="flex items-start gap-3 text-sm font-medium text-gray-900 dark:text-gray-100">
          <input :checked="rotateOnImport" type="checkbox" class="mt-0.5 h-4 w-4 rounded border-gray-300 text-primary-600" :disabled="committing" data-testid="vault-rotate-on-import" @change="setRotateOnImport(($event.target as HTMLInputElement).checked)" />
          <span>{{ t('admin.accountVault.rotation.importOption') }}</span>
        </label>
        <p class="mt-2 text-sm leading-6 text-gray-600 dark:text-gray-300">{{ tab === 'images' ? t('admin.accountVault.rotation.qrImportHint') : t('admin.accountVault.rotation.importHint') }}</p>
        <p v-if="rotationHint" class="mt-2 text-sm font-medium text-amber-800 dark:text-amber-300" role="status">{{ rotationHint }}</p>
      </section>

      <div v-if="error" role="alert" class="break-words rounded-lg border border-red-200 bg-red-50 p-3 text-sm text-red-700 dark:border-red-800 dark:bg-red-950/30 dark:text-red-300" data-testid="vault-import-error">{{ error }}</div>

      <section v-if="result" class="space-y-3" aria-live="polite" data-testid="vault-import-results">
        <h4 class="text-base font-semibold text-gray-900 dark:text-gray-100">{{ completed ? t('admin.accountVault.import.completed') : t('admin.accountVault.import.previewTitle') }}</h4>
        <div class="flex flex-wrap gap-2 text-sm">
          <span class="rounded-lg bg-green-50 px-3 py-2 font-medium text-green-800 dark:bg-green-900/20 dark:text-green-300">{{ completed ? t('admin.accountVault.import.createdCount', { count: result.created }) : t('admin.accountVault.import.readyCount', { count: readyCount }) }}</span>
          <span class="rounded-lg bg-gray-100 px-3 py-2 text-gray-700 dark:bg-dark-700 dark:text-gray-200">{{ t('admin.accountVault.import.duplicateCount', { count: result.duplicate }) }}</span>
          <span class="rounded-lg bg-red-50 px-3 py-2 text-red-700 dark:bg-red-900/20 dark:text-red-300">{{ t('admin.accountVault.import.failedCount', { count: result.failed }) }}</span>
          <span v-if="result.ignored" class="rounded-lg bg-gray-100 px-3 py-2 text-gray-700 dark:bg-dark-700 dark:text-gray-200">{{ t('admin.accountVault.import.ignoredCount', { count: result.ignored }) }}</span>
        </div>
        <p class="text-sm text-gray-600 dark:text-gray-300">{{ completed ? (result.rotation ? t('admin.accountVault.rotation.importQueuedHint') : t('admin.accountVault.import.completedHint')) : t('admin.accountVault.import.previewHint') }}</p>
        <div v-if="completed && result.rotation_error" role="alert" class="rounded-lg bg-amber-50 p-3 text-sm text-amber-900 dark:bg-amber-900/20 dark:text-amber-200" data-testid="vault-import-rotation-error">{{ t('admin.accountVault.rotation.importQueueFailed') }} {{ result.rotation_error }}</div>
        <div v-if="completed && result.rotation" class="rounded-lg border border-primary-200 p-3 dark:border-primary-800" data-testid="vault-import-rotation-results">
          <p class="mb-2 text-sm font-medium text-gray-900 dark:text-gray-100">{{ t('admin.accountVault.rotation.queueResults') }}</p>
          <div v-for="row in result.rotation.rows" :key="row.account_id" class="flex flex-wrap justify-between gap-2 py-1 text-sm text-gray-600 dark:text-gray-300">
            <span>#{{ row.account_id }}</span><span>{{ t(`admin.accountVault.rotation.queueStatus.${row.status}`) }}</span>
          </div>
        </div>
        <div class="max-h-72 overflow-auto rounded-lg border border-gray-200 dark:border-dark-700">
          <table class="w-full text-left text-sm">
            <thead class="sticky top-0 bg-gray-50 text-gray-600 dark:bg-dark-800 dark:text-gray-300"><tr>
              <th class="px-3 py-3">{{ t('admin.accountVault.import.line') }}</th><th class="px-3 py-3">{{ t('admin.accountVault.email') }}</th>
              <th class="px-3 py-3">{{ t('admin.accountVault.import.status') }}</th><th class="px-3 py-3">{{ t('admin.accountVault.import.detail') }}</th>
            </tr></thead>
            <tbody class="divide-y divide-gray-100 dark:divide-dark-700">
              <tr v-for="row in result.rows" :key="`${row.line}-${row.email}`">
                <td class="px-3 py-3 text-gray-600 dark:text-gray-300">{{ row.line }}</td>
                <td class="max-w-64 break-all px-3 py-3 font-medium text-gray-900 dark:text-gray-100">{{ row.email || '—' }}</td>
                <td class="whitespace-nowrap px-3 py-3" :class="row.status === 'error' ? 'text-red-700 dark:text-red-300' : row.status === 'duplicate' ? 'text-gray-600 dark:text-gray-300' : 'text-green-700 dark:text-green-300'">{{ t(`admin.accountVault.import.rowStatus.${row.status}`) }}</td>
                <td class="min-w-36 break-words px-3 py-3 text-gray-600 dark:text-gray-300">{{ row.message || (row.issuer || '—') }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </div>
    <template #footer>
      <div class="flex flex-wrap items-center justify-between gap-3">
        <p class="text-xs text-gray-600 dark:text-gray-300">{{ t('admin.accountVault.import.noOverwrite') }}</p>
        <div class="flex flex-wrap gap-2">
          <button type="button" class="btn btn-secondary" :disabled="committing" @click="close">{{ completed ? t('common.close') : t('common.cancel') }}</button>
          <button v-if="completed" type="button" class="btn btn-primary" @click="reset">{{ t('admin.accountVault.import.anotherBatch') }}</button>
          <button v-else-if="canCommit || committing" type="button" class="btn btn-primary" :disabled="!canCommit || committing" data-testid="vault-confirm-import" @click="commit">{{ committing ? t('common.processing') : rotateOnImport ? t('admin.accountVault.rotation.confirmImport', { count: readyCount }) : t('admin.accountVault.import.confirm', { count: readyCount }) }}</button>
          <button v-else type="button" class="btn btn-primary" :disabled="!canValidate" data-testid="vault-preview-import" @click="validate">{{ validating ? t('common.loading') : t('admin.accountVault.import.validate') }}</button>
        </div>
      </div>
    </template>
  </BaseDialog>
  <TotpStepUpDialog :controller="stepUp" />
</template>

<script setup lang="ts">
import { onBeforeUnmount, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import BaseDialog from '@/components/common/BaseDialog.vue'
import Icon from '@/components/icons/Icon.vue'
import { useVaultImport } from '@/features/account-vault/useVaultImport'
import type { VaultImportResult } from '@/types/accountVault'
import TotpStepUpDialog from '@/components/auth/TotpStepUpDialog.vue'
import { useStepUp } from '@/composables/useStepUp'

const props = defineProps<{ show: boolean; maxRows: number; maxBytes: number }>()
const emit = defineEmits<{ close: []; imported: [result: VaultImportResult] }>()
const { t } = useI18n()
const textInput = ref<HTMLInputElement | null>(null)
const imageInput = ref<HTMLInputElement | null>(null)
const dragging = ref(false)
const stepUp = useStepUp()
const textExample = 'alice@example.test----ExamplePassword----JBSWY3DPEHPK3PXP\nbob@example.test----AnotherPassword----GEZDGNBVGY3TQOJQ'
const { tab, content, images, result, error, validating, committing, completed, readingClipboard,
  busyImages, pendingImages, parsedImages, readyCount, canValidate, canCommit, setContent, switchTab,
  changed, reset, toggleSecret, addImages, removeImage, recognizeAll, handlePaste, readClipboard,
  readTextFile, validate, commit, rotateOnImport, rotationHint, setRotateOnImport } = useVaultImport({ maxBytes: props.maxBytes, maxRows: props.maxRows,
    t, imported: value => emit('imported', value), authorize: stepUp.run })
onBeforeUnmount(stepUp.onCancel)

function onImages(event: Event) {
  const input = event.target as HTMLInputElement
  const files = Array.from(input.files ?? [])
  input.value = ''
  void addImages(files)
}

function onDrop(event: DragEvent) {
  dragging.value = false
  void addImages(Array.from(event.dataTransfer?.files ?? []), true)
}

function onTextFile(event: Event) {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  input.value = ''
  if (file) void readTextFile(file)
}

function close() {
  if (committing.value) return
  reset()
  emit('close')
}
</script>
