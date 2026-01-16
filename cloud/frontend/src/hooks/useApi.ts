import { useMemo } from 'react'
import { apiClient } from '@/services/api'

export function useApi() {
  return useMemo(() => apiClient, [])
}
