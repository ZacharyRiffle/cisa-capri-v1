"use client"

// React hook for real-time threat intelligence
import { useState, useEffect, useCallback } from "react"
import { io, type Socket } from "socket.io-client"
import type { ThreatIntelRecord, FeedStatus } from "@/lib/database"

interface UseRealTimeThreatsOptions {
  autoConnect?: boolean
  reconnect?: boolean
}

interface RealTimeThreatsState {
  threats: ThreatIntelRecord[]
  feedStatuses: FeedStatus[]
  isConnected: boolean
  isLoading: boolean
  error: string | null
  lastUpdate: Date | null
}

export function useRealTimeThreats(options: UseRealTimeThreatsOptions = {}) {
  const { autoConnect = true, reconnect = true } = options

  const [state, setState] = useState<RealTimeThreatsState>({
    threats: [],
    feedStatuses: [],
    isConnected: false,
    isLoading: true,
    error: null,
    lastUpdate: null,
  })

  const [socket, setSocket] = useState<Socket | null>(null)

  const connect = useCallback(() => {
    if (socket?.connected) return

    const newSocket = io(process.env.NODE_ENV === "production" ? "" : "http://localhost:3000", {
      autoConnect: false,
      reconnection: reconnect,
      reconnectionAttempts: 5,
      reconnectionDelay: 1000,
    })

    newSocket.on("connect", () => {
      console.log("Connected to threat intelligence WebSocket")
      setState((prev) => ({ ...prev, isConnected: true, error: null }))

      // Request initial data
      newSocket.emit("request_recent_threats", { hours: 24 })
      newSocket.emit("request_feed_status")
    })

    newSocket.on("disconnect", () => {
      console.log("Disconnected from threat intelligence WebSocket")
      setState((prev) => ({ ...prev, isConnected: false }))
    })

    newSocket.on("connect_error", (error) => {
      console.error("WebSocket connection error:", error)
      setState((prev) => ({
        ...prev,
        isConnected: false,
        error: "Connection failed",
        isLoading: false,
      }))
    })

    newSocket.on("initial_data", (message) => {
      setState((prev) => ({
        ...prev,
        threats: message.data.recentThreats || [],
        isLoading: false,
        lastUpdate: new Date(),
      }))
    })

    newSocket.on("threat_update", (message) => {
      setState((prev) => ({
        ...prev,
        threats: [...message.data, ...prev.threats].slice(0, 1000), // Keep last 1000
        lastUpdate: new Date(),
      }))
    })

    newSocket.on("feed_status", (message) => {
      setState((prev) => ({
        ...prev,
        feedStatuses: message.data || [],
      }))
    })

    newSocket.on("recent_threats", (message) => {
      setState((prev) => ({
        ...prev,
        threats: message.data || [],
        isLoading: false,
        lastUpdate: new Date(),
      }))
    })

    newSocket.on("search_results", (message) => {
      setState((prev) => ({
        ...prev,
        threats: message.data || [],
        lastUpdate: new Date(),
      }))
    })

    newSocket.on("error", (message) => {
      console.error("WebSocket error:", message.data)
      setState((prev) => ({
        ...prev,
        error: message.data.message || "Unknown error",
        isLoading: false,
      }))
    })

    newSocket.connect()
    setSocket(newSocket)
  }, [socket, reconnect])

  const disconnect = useCallback(() => {
    if (socket) {
      socket.disconnect()
      setSocket(null)
      setState((prev) => ({ ...prev, isConnected: false }))
    }
  }, [socket])

  const searchThreats = useCallback(
    (searchTerm: string) => {
      if (socket?.connected) {
        setState((prev) => ({ ...prev, isLoading: true }))
        socket.emit("search_threats", { searchTerm })
      }
    },
    [socket],
  )

  const requestRecentThreats = useCallback(
    (hours = 24) => {
      if (socket?.connected) {
        setState((prev) => ({ ...prev, isLoading: true }))
        socket.emit("request_recent_threats", { hours })
      }
    },
    [socket],
  )

  const toggleFeed = useCallback(
    (feedId: string, enabled: boolean) => {
      if (socket?.connected) {
        socket.emit("toggle_feed", { feedId, enabled })
      }
    },
    [socket],
  )

  const refreshFeedStatus = useCallback(() => {
    if (socket?.connected) {
      socket.emit("request_feed_status")
    }
  }, [socket])

  // Auto-connect on mount
  useEffect(() => {
    if (autoConnect) {
      connect()
    }

    return () => {
      if (socket) {
        socket.disconnect()
      }
    }
  }, [autoConnect, connect])

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (socket) {
        socket.disconnect()
      }
    }
  }, [socket])

  return {
    ...state,
    connect,
    disconnect,
    searchThreats,
    requestRecentThreats,
    toggleFeed,
    refreshFeedStatus,
  }
}
