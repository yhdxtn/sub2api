export interface VaultAccount {
  id: number
  email: string
  issuer: string
  group_name?: string
  has_password: boolean
  has_totp: boolean
  algorithm: string
  digits: number
  period: number
  created_at: string
  updated_at: string
  rotation_state?: string
  rotation_phase?: string
  rotation_completed_at?: string | null
}

export interface VaultGroup {
  name: string
  count: number
}

export interface VaultStatus {
  configured: boolean
  ready: boolean
  max_import_rows: number
  max_import_bytes: number
  message?: string
}

export interface VaultPage {
  items: VaultAccount[]
  total: number
  page: number
  page_size: number
  pages: number
}

/** Used only by the transient import dialog. Never place in a persistent store. */
export interface VaultImportItem {
  email: string
  password?: string
  secret: string
  issuer?: string
  algorithm?: string
  digits?: number
  period?: number
	 note?: string
}

export type VaultImportPayload =
  | { content: string; dry_run: boolean; rotate_on_import?: boolean; items?: never }
  | { items: VaultImportItem[]; dry_run: boolean; rotate_on_import?: boolean; content?: never }

export interface VaultImportRow {
  line: number
  email: string
  status: 'ready' | 'created' | 'duplicate' | 'error'
  id?: number
  message?: string
  issuer?: string
  algorithm?: string
  digits?: number
  period?: number
  has_password?: boolean
}

export interface VaultImportResult {
  total: number
  created: number
  duplicate: number
  failed: number
  ignored: number
  rows: VaultImportRow[]
  rotation?: VaultRotationQueueResult
  rotation_error?: string
}

export interface VaultCode {
  id: number
  code?: string
  remaining?: number
  period?: number
  expires_at?: number
  server_time?: number
  error?: string
}

export interface VaultCodesResult {
  items: VaultCode[]
  server_time: number
}

/** Public job metadata only. Unknown server states must never imply completion. */
export interface VaultRotationJob {
	 kind?: 'rotation' | 'session'
	 gateway_account_id?: number
  credential_expires_at?: string
  id: string
  account_id: number
  status: string
  phase: string
  revision: number
  progress: string
  message: string
  worker_status?: 'manual' | 'ready' | 'starting' | 'running' | 'stopped' | 'error'
  worker_error_code?: string
  error_code?: string
  can_cancel: boolean
  can_resume: boolean
  created_at: string
  updated_at: string
  completed_at?: string
}

export interface VaultRotationQueueResult {
  rows: Array<{
    account_id: number
    status: 'queued' | 'existing' | 'blocked' | 'error'
    job?: VaultRotationJob
    error_code?: string
  }>
}

/** One-time response: never persist or put in shared application stores. */
export interface VaultWorkerToken {
  token: string
  token_id: string
  expires_at: string
}
