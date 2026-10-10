import { computed, onBeforeUnmount, onMounted, ref, shallowRef } from 'vue'
import { accountVaultAPI } from '@/api/admin/accountVault'
import type { VaultImportItem, VaultImportPayload, VaultImportResult } from '@/types/accountVault'
import { isVaultCancelled, vaultError } from './useAccountVault'
import { ImageInputError, inspectImageFile } from './qr/inspect-image'
import { decodeImageLocally } from './qr/decode-image'
import { isStepUpBlocked, isStepUpCancelled, stepUpBlockReason } from '@/composables/useStepUp'

export interface VaultImageEntry {
  id: number
  name: string
  preview: string
  state: 'checking' | 'queued' | 'decoding' | 'ready' | 'error'
  message: string
  item: VaultImportItem | null
  showSecret: boolean
  requested: boolean
}

type Translate = (key: string, values?: Record<string, string | number>) => string

export function useVaultImport(options: {
  maxBytes: number
  maxRows: number
  t: Translate
  imported: (result: VaultImportResult) => void
  authorize?: <T>(action: () => Promise<T>) => Promise<T>
}) {
  const { t } = options
  const tab = ref<'text' | 'images'>('text')
  const content = ref('')
  const images = ref<VaultImageEntry[]>([])
  const result = ref<VaultImportResult | null>(null)
  const error = ref('')
  const validating = ref(false)
  const committing = ref(false)
  const readingClipboard = ref(false)
  const completed = ref(false)
  const rotateOnImport = ref(true)
  const rotationHint = ref('')
  let rotationChoiceExplicit = false
  const files = new Map<number, File>()
  const controllers = new Map<number, AbortController>()
  const hideTimers = new Map<number, ReturnType<typeof setTimeout>>()
  let requestController: AbortController | null = null
  const snapshot = shallowRef<VaultImportPayload | null>(null)
  let snapshotRotate = false
  let epoch = 0
  let revision = 0
  let sequence = 0
  let active = 0
  let alive = true

  const busyImages = computed(() => images.value.some(image => image.state === 'checking' || image.state === 'decoding'))
  const pendingImages = computed(() => images.value.filter(image => image.state === 'queued').length)
  const parsedImages = computed(() => images.value.filter(image => image.state === 'ready' && image.item))
  const readyCount = computed(() => result.value?.rows.filter(row => row.status === 'ready').length ?? 0)
  const canValidate = computed(() => !validating.value && !committing.value && !completed.value && (
    tab.value === 'text' ? Boolean(content.value.trim()) : parsedImages.value.length > 0 && !busyImages.value && !pendingImages.value && parsedImages.value.every(image => image.item?.email.trim())
  ))
  const canCommit = computed(() => Boolean(snapshot.value) && readyCount.value > 0 && !validating.value && !committing.value && !completed.value)

  function changed() {
    if (committing.value) return
    revision += 1
    requestController?.abort()
    requestController = null
    validating.value = false
    snapshot.value = null
    result.value = null
    completed.value = false
    error.value = ''
  }

  function setContent(value: string) {
    content.value = value
    changed()
  }

  function switchTab(value: 'text' | 'images') {
    if (committing.value || tab.value === value) return
    changed()
    hideSecrets()
    tab.value = value
  }

  function setRotateOnImport(value: boolean) {
    if (committing.value) return
    changed()
    rotateOnImport.value = value
    rotationChoiceExplicit = true
    rotationHint.value = ''
  }

  function releaseImage(image: VaultImageEntry) {
    if (image.preview) URL.revokeObjectURL(image.preview)
    image.preview = ''
    files.delete(image.id)
  }

  function hideSecrets() {
    for (const timer of hideTimers.values()) clearTimeout(timer)
    hideTimers.clear()
    for (const image of images.value) image.showSecret = false
  }

  function toggleSecret(image: VaultImageEntry) {
    clearTimeout(hideTimers.get(image.id))
    hideTimers.delete(image.id)
    image.showSecret = !image.showSecret
    if (image.showSecret) hideTimers.set(image.id, setTimeout(() => {
      image.showSecret = false
      hideTimers.delete(image.id)
    }, 30_000))
  }

  function clearImages() {
    hideSecrets()
    for (const controller of controllers.values()) controller.abort()
    controllers.clear()
    for (const image of images.value) { releaseImage(image); image.item = null }
    files.clear()
    images.value = []
  }

  function reset() {
    epoch += 1
    revision += 1
    requestController?.abort()
    requestController = null
    clearImages()
    snapshot.value = null
    content.value = ''
    result.value = null
    error.value = ''
    validating.value = false
    readingClipboard.value = false
    committing.value = false
    completed.value = false
    rotateOnImport.value = true
    rotationHint.value = ''
    rotationChoiceExplicit = false
    snapshotRotate = false
  }

  function imageError(value: unknown): string {
    return value instanceof ImageInputError
      ? t(`admin.accountVault.import.errors.${value.key}`)
      : vaultError(value, t('admin.accountVault.import.errors.decodeFailed'))
  }

  async function addImages(values: File[], autoRecognize = false) {
    if (committing.value || completed.value) return
    changed()
    const currentEpoch = epoch
    const available = Math.max(0, 20 - images.value.length)
    if (values.length > available) error.value = t('admin.accountVault.import.errors.imageCount')
    // Reserve all entries before awaiting headers; rapid pastes cannot exceed the queue cap.
    const entries = values.slice(0, available).map(file => {
      const entry: VaultImageEntry = { id: ++sequence, name: file.name, preview: '', state: 'checking',
        message: '', item: null, showSecret: false, requested: autoRecognize }
      images.value.push(entry)
      files.set(entry.id, file)
      return { file, entry: images.value[images.value.length - 1] }
    })
    for (const { file, entry } of entries) {
      try {
        await inspectImageFile(file)
        if (!alive || currentEpoch !== epoch || !images.value.includes(entry)) continue
        entry.preview = URL.createObjectURL(file)
        entry.state = 'queued'
      } catch (value) {
        if (!alive || currentEpoch !== epoch || !images.value.includes(entry)) continue
        entry.state = 'error'
        entry.message = imageError(value)
        releaseImage(entry)
      }
    }
    pump()
  }

  function removeImage(entry: VaultImageEntry) {
    if (committing.value) return
    changed()
    controllers.get(entry.id)?.abort()
    controllers.delete(entry.id)
    clearTimeout(hideTimers.get(entry.id))
    hideTimers.delete(entry.id)
    releaseImage(entry)
    entry.item = null
    images.value = images.value.filter(image => image.id !== entry.id)
  }

  function recognizeAll() {
    if (committing.value || completed.value) return
    changed()
    for (const entry of images.value) if (entry.state === 'queued') entry.requested = true
    pump()
  }

  function pump() {
    if (!alive) return
    while (active < 2) {
      const entry = images.value.find(image => image.state === 'queued' && image.requested)
      if (!entry) return
      entry.state = 'decoding'
      active += 1
      void decode(entry).finally(() => { active -= 1; pump() })
    }
  }

  async function decode(entry: VaultImageEntry) {
    const currentEpoch = epoch
    const controller = new AbortController()
    controllers.set(entry.id, controller)
    const live = () => alive && currentEpoch === epoch && !controller.signal.aborted && images.value.includes(entry)
    try {
      const file = files.get(entry.id)
      if (!file) throw new ImageInputError('invalidImage')
      const uri = await decodeImageLocally(file, controller.signal)
      if (!live()) return
      if (!uri) throw new ImageInputError('noQRCode')
      if (uri.length > 8192) throw new ImageInputError('notTotp')
      const parsed = await accountVaultAPI.parse(uri, controller.signal)
      if (!live()) return
      entry.item = { email: parsed.email, password: '', secret: parsed.secret, issuer: parsed.issuer,
        algorithm: parsed.algorithm, digits: parsed.digits, period: parsed.period }
      entry.state = 'ready'
      if (parsed.issuer && !/openai|chatgpt/i.test(parsed.issuer) && !rotationChoiceExplicit && rotateOnImport.value) {
        changed()
        rotateOnImport.value = false
        rotationHint.value = t('admin.accountVault.rotation.otherPlatformDetected')
      }
    } catch (value) {
      if (live() && !isVaultCancelled(value)) {
        entry.state = 'error'
        entry.message = imageError(value)
      }
    } finally {
      releaseImage(entry)
      controllers.delete(entry.id)
    }
  }

  function handlePaste(event: ClipboardEvent) {
    if (committing.value || completed.value) return
    // Only the focused drop zone owns this listener; text and account fields keep native paste.
    const values = Array.from(event.clipboardData?.items ?? [])
      .filter(item => item.kind === 'file').map(item => item.getAsFile()).filter((file): file is File => Boolean(file))
    if (!values.length) return
    event.preventDefault()
    void addImages(values)
  }

  async function readClipboard() {
    if (readingClipboard.value || committing.value || completed.value) return
    if (!navigator.clipboard?.read || !window.isSecureContext) {
      error.value = t('admin.accountVault.import.errors.clipboardUnavailable')
      return
    }
    const currentEpoch = epoch
    readingClipboard.value = true
    try {
      const items = await navigator.clipboard.read()
      const values: File[] = []
      for (const item of items) {
        const type = item.types.find(value => ['image/png', 'image/jpeg', 'image/webp'].includes(value))
        if (!type) continue
        const blob = await item.getType(type)
        if (!alive || currentEpoch !== epoch) return
        const extension = type === 'image/jpeg' ? 'jpg' : type.split('/')[1]
        values.push(new File([blob], `clipboard-${sequence + values.length + 1}.${extension}`, { type }))
      }
      if (!alive || currentEpoch !== epoch) return
      if (!values.length) error.value = t('admin.accountVault.import.errors.clipboardEmpty')
      else await addImages(values)
    } catch {
      if (alive && currentEpoch === epoch) error.value = t('admin.accountVault.import.errors.clipboardDenied')
    } finally {
      if (currentEpoch === epoch) readingClipboard.value = false
    }
  }

  async function readTextFile(file: File) {
    if (committing.value || completed.value) return
    const currentEpoch = epoch
    const currentRevision = revision
    if (file.size > options.maxBytes) { error.value = t('admin.accountVault.import.errors.contentSize'); return }
    try {
      const text = await file.text()
      if (!alive || currentEpoch !== epoch || currentRevision !== revision) return
      setContent(text)
    } catch {
      if (alive && currentEpoch === epoch) error.value = t('admin.accountVault.import.errors.readFile')
    }
  }

  async function validate() {
    if (!canValidate.value) return
    error.value = ''
    let payload: VaultImportPayload
    if (tab.value === 'text') payload = { content: content.value, dry_run: true, rotate_on_import: false }
    else payload = { items: parsedImages.value.map(image => ({ ...image.item! })), dry_run: true, rotate_on_import: false }
    if (new TextEncoder().encode(JSON.stringify(payload)).length > options.maxBytes) {
      error.value = t('admin.accountVault.import.errors.contentSize')
      return
    }
    if (payload.items && payload.items.length > options.maxRows) {
      error.value = t('admin.accountVault.import.errors.rowCount', { count: options.maxRows })
      return
    }
    requestController?.abort()
    const controller = new AbortController()
    requestController = controller
    const currentRevision = revision
    const currentEpoch = epoch
    validating.value = true
    result.value = null
    snapshot.value = null
    try {
      const value = await accountVaultAPI.import(payload, controller.signal)
      if (!alive || controller.signal.aborted || currentEpoch !== epoch || currentRevision !== revision) return
      result.value = value
      snapshot.value = payload
      snapshotRotate = rotateOnImport.value
    } catch (value) {
      if (alive && currentEpoch === epoch && currentRevision === revision && !isVaultCancelled(value)) {
        error.value = vaultError(value, t('admin.accountVault.import.errors.validateFailed'))
      }
    } finally {
      if (currentEpoch === epoch && currentRevision === revision) validating.value = false
    }
  }

  async function commit() {
    if (!canCommit.value || !snapshot.value) return
    const payload: VaultImportPayload = snapshot.value.items
      ? { items: snapshot.value.items.map(item => ({ ...item })), dry_run: false, rotate_on_import: snapshotRotate }
      : { content: snapshot.value.content, dry_run: false, rotate_on_import: snapshotRotate }
    const controller = new AbortController()
    requestController = controller
    const currentEpoch = epoch
    committing.value = true
    error.value = ''
    try {
      const perform = () => accountVaultAPI.import(payload, controller.signal)
      const value = payload.rotate_on_import && options.authorize ? await options.authorize(perform) : await perform()
      if (!alive || controller.signal.aborted || currentEpoch !== epoch) return
      result.value = value
      completed.value = true
      snapshot.value = null
      content.value = ''
      clearImages()
      options.imported(value)
    } catch (value) {
      if (alive && currentEpoch === epoch && !isVaultCancelled(value) && !isStepUpCancelled(value)) {
        error.value = isStepUpBlocked(value)
          ? t(stepUpBlockReason(value) === 'STEP_UP_ADMIN_API_KEY_FORBIDDEN' ? 'stepUp.adminApiKeyForbidden' : 'stepUp.notEnabled')
          : vaultError(value, t('admin.accountVault.import.errors.commitFailed'))
      }
    } finally {
      if (currentEpoch === epoch) committing.value = false
    }
  }

  function visibilityChanged() {
    if (document.visibilityState === 'hidden') hideSecrets()
  }

  onMounted(() => document.addEventListener('visibilitychange', visibilityChanged))
  onBeforeUnmount(() => {
    alive = false
    reset()
    document.removeEventListener('visibilitychange', visibilityChanged)
  })

  return { tab, content, images, result, error, validating, committing, completed, readingClipboard, rotateOnImport, rotationHint, setRotateOnImport,
    busyImages, pendingImages, parsedImages, readyCount, canValidate, canCommit,
    setContent, switchTab, changed, reset, toggleSecret, addImages, removeImage, recognizeAll,
    handlePaste, readClipboard, readTextFile, validate, commit }
}
