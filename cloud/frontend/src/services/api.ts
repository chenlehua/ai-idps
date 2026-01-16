import axios from 'axios'

const baseUrl = `${import.meta.env.VITE_API_URL ?? ''}/v1`

export const apiClient = axios.create({
  baseURL: baseUrl,
  timeout: 10000
})
