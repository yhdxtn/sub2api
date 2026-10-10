import { apiClient } from '../client'
import type {
  VaultCodesResult, VaultImportItem, VaultImportPayload, VaultImportResult, VaultPage, VaultStatus,
  VaultRotationJob, VaultRotationQueueResult, VaultWorkerToken, VaultGroup
} from '@/types/accountVault'

const path = '/admin/account-vault'
const options = (signal?: AbortSignal) => ({ signal, headers: { 'Cache-Control': 'no-store' } })

export const accountVaultAPI = {
  async groups(signal?: AbortSignal): Promise<{ groups: VaultGroup[] }> {
    return (await apiClient.get<{ groups: VaultGroup[] }>(`${path}/groups`, options(signal))).data
  },
  async assignGroup(ids: number[], group_name: string, signal?: AbortSignal): Promise<{ updated: number }> {
    return (await apiClient.post<{ updated: number }>(`${path}/groups/assign`, { ids, group_name }, options(signal))).data
  },
	async exportText(ids: number[], signal?: AbortSignal): Promise<{ content: string; count: number }> {
		return (await apiClient.post<{ content: string; count: number }>(`${path}/export-text`, { ids }, options(signal))).data
	},
  async queueSessions(ids: number[], concurrency: number, signal?: AbortSignal): Promise<VaultRotationQueueResult> {
    return (await apiClient.post<VaultRotationQueueResult>(`${path}/session/queue`, { ids, concurrency }, options(signal))).data
  },
  async sessionJobs(ids: number[], signal?: AbortSignal): Promise<{ jobs: VaultRotationJob[] }> {
    return (await apiClient.post<{ jobs: VaultRotationJob[] }>(`${path}/session/jobs/query`, { ids }, options(signal))).data
  },
  async exportSessions(ids: number[], format: 'session' | 'import', signal?: AbortSignal): Promise<unknown> {
    return (await apiClient.post(`${path}/session/export`, { ids, format }, options(signal))).data
  },
  async status(signal?: AbortSignal): Promise<VaultStatus> {
    return (await apiClient.get<VaultStatus>(`${path}/status`, options(signal))).data
  },
  async list(page: number, pageSize: number, search: string, signal?: AbortSignal, groupName?: string | null): Promise<VaultPage> {
    return (await apiClient.get<VaultPage>(path, {
      ...options(signal), params: { page, page_size: pageSize, search, ...(groupName == null ? {} : { group_name: groupName }) }
    })).data
  },
  async import(payload: VaultImportPayload, signal?: AbortSignal): Promise<VaultImportResult> {
    return (await apiClient.post<VaultImportResult>(`${path}/import`, payload, options(signal))).data
  },
  async parse(uri: string, signal?: AbortSignal): Promise<VaultImportItem> {
    return (await apiClient.post<VaultImportItem>(`${path}/parse`, { uri }, options(signal))).data
  },
  async codes(ids: number[], signal?: AbortSignal): Promise<VaultCodesResult> {
    return (await apiClient.post<VaultCodesResult>(`${path}/codes`, { ids }, options(signal))).data
  },
  async password(id: number, signal?: AbortSignal): Promise<{ password: string }> {
    return (await apiClient.post<{ password: string }>(`${path}/${id}/password`, {}, options(signal))).data
  },
  async secret(id: number, signal?: AbortSignal): Promise<{ secret: string }> {
    return (await apiClient.post<{ secret: string }>(`${path}/${id}/secret`, {}, options(signal))).data
  },
  async delete(id: number, signal?: AbortSignal): Promise<{ deleted: boolean }> {
    return (await apiClient.delete<{ deleted: boolean }>(`${path}/${id}`, options(signal))).data
  },
  async queueRotation(ids: number[], signal?: AbortSignal, concurrency?: number): Promise<VaultRotationQueueResult> {
    return (await apiClient.post<VaultRotationQueueResult>(`${path}/rotation/queue`, { ids, ...(concurrency === undefined ? {} : { concurrency }) }, options(signal))).data
  },
  async rotationJobs(ids: number[], signal?: AbortSignal): Promise<{ jobs: VaultRotationJob[] }> {
    return (await apiClient.post<{ jobs: VaultRotationJob[] }>(`${path}/rotation/jobs/query`, { ids }, options(signal))).data
  },
  async resumeRotation(id: string, signal?: AbortSignal): Promise<VaultRotationJob> {
    return (await apiClient.post<VaultRotationJob>(`${path}/rotation/${encodeURIComponent(id)}/resume`, {}, options(signal))).data
  },
  async cancelRotation(id: string, signal?: AbortSignal): Promise<VaultRotationJob> {
    return (await apiClient.post<VaultRotationJob>(`${path}/rotation/${encodeURIComponent(id)}/cancel`, {}, options(signal))).data
  },
  async createWorkerToken(signal?: AbortSignal): Promise<VaultWorkerToken> {
    return (await apiClient.post<VaultWorkerToken>(`${path}/rotation/worker-token`, {}, options(signal))).data
  },
  async revokeWorkerTokens(signal?: AbortSignal): Promise<{ revoked: boolean }> {
    return (await apiClient.delete<{ revoked: boolean }>(`${path}/rotation/worker-token`, options(signal))).data
  }
}
