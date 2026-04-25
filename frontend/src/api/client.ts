import axios, { AxiosError, type AxiosInstance } from 'axios'
import type { ApiError } from '@/types/api'

export const AUTH_TOKEN_STORAGE_KEY = 'nids_auth_token'
export const API_BASE_URL_STORAGE_KEY = 'nids_api_base_url'
const DEFAULT_API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8000'

export const resolveApiBaseUrl = () =>
  localStorage.getItem(API_BASE_URL_STORAGE_KEY)?.trim() || DEFAULT_API_BASE_URL

export const apiClient: AxiosInstance = axios.create({
  baseURL: resolveApiBaseUrl(),
  timeout: 30_000,
  headers: { 'Content-Type': 'application/json' },
})

apiClient.interceptors.request.use(config => {
  config.baseURL = resolveApiBaseUrl()
  config.headers['X-Request-ID'] = crypto.randomUUID()
  const token = localStorage.getItem(AUTH_TOKEN_STORAGE_KEY)
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

apiClient.interceptors.response.use(
  res => res,
  (err: AxiosError) => {
    const timeoutMessage = err.code === 'ECONNABORTED'
      ? 'Request timed out. Backend may be busy; try again in a few seconds.'
      : undefined
    const apiError: ApiError = {
      message: timeoutMessage ?? (err.response?.data as any)?.detail ?? err.message ?? 'Unknown error',
      status: err.response?.status ?? 0,
      code: (err.response?.data as any)?.code,
      request_id: err.config?.headers?.['X-Request-ID'] as string,
    }
    return Promise.reject(apiError)
  }
)

export default apiClient
