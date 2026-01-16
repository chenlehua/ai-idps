import { useEffect, useRef, useCallback, useState } from 'react'

interface WebSocketOptions {
  url: string
  onMessage?: (data: any) => void
  onConnect?: () => void
  onDisconnect?: () => void
  reconnectInterval?: number
  maxReconnectAttempts?: number
}

export function useWebSocket(options: WebSocketOptions) {
  const {
    url,
    onMessage,
    onConnect,
    onDisconnect,
    reconnectInterval = 1000,
    maxReconnectAttempts = 10
  } = options

  const wsRef = useRef<WebSocket | null>(null)
  const reconnectAttempts = useRef(0)
  const reconnectTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const [isConnected, setIsConnected] = useState(false)

  // 使用 ref 存储回调，避免依赖变化导致重连
  const onMessageRef = useRef(onMessage)
  const onConnectRef = useRef(onConnect)
  const onDisconnectRef = useRef(onDisconnect)

  useEffect(() => {
    onMessageRef.current = onMessage
    onConnectRef.current = onConnect
    onDisconnectRef.current = onDisconnect
  }, [onMessage, onConnect, onDisconnect])

  const connect = useCallback(() => {
    // 清理之前的连接
    if (wsRef.current) {
      wsRef.current.close()
      wsRef.current = null
    }

    try {
      console.log('WebSocket connecting to:', url)
      const ws = new WebSocket(url)

      ws.onopen = () => {
        console.log('WebSocket connected')
        setIsConnected(true)
        reconnectAttempts.current = 0
        onConnectRef.current?.()
      }

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data)
          onMessageRef.current?.(data)
        } catch (error) {
          console.error('Failed to parse WebSocket message:', error)
        }
      }

      ws.onclose = (event) => {
        console.log('WebSocket closed:', event.code, event.reason)
        setIsConnected(false)
        wsRef.current = null
        onDisconnectRef.current?.()

        if (reconnectAttempts.current < maxReconnectAttempts) {
          const delay = Math.min(
            reconnectInterval * Math.pow(2, reconnectAttempts.current),
            30000
          )
          reconnectAttempts.current += 1
          console.log(`WebSocket reconnecting in ${delay}ms (attempt ${reconnectAttempts.current})`)
          reconnectTimeoutRef.current = setTimeout(connect, delay)
        }
      }

      ws.onerror = (error) => {
        console.error('WebSocket error:', error)
      }

      wsRef.current = ws
    } catch (error) {
      console.error('Failed to create WebSocket:', error)
    }
  }, [url, reconnectInterval, maxReconnectAttempts])

  const send = useCallback((data: any) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(data))
    }
  }, [])

  const subscribe = useCallback((filters: any = {}) => {
    send({ action: 'subscribe', filters })
  }, [send])

  const unsubscribe = useCallback(() => {
    send({ action: 'unsubscribe' })
  }, [send])

  useEffect(() => {
    connect()
    return () => {
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current)
      }
      if (wsRef.current) {
        wsRef.current.close()
      }
    }
  }, [connect])

  useEffect(() => {
    const interval = setInterval(() => {
      if (isConnected) {
        send({ action: 'ping' })
      }
    }, 30000)

    return () => clearInterval(interval)
  }, [isConnected, send])

  return {
    isConnected,
    send,
    subscribe,
    unsubscribe
  }
}
