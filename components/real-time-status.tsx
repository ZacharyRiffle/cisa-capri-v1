"use client"

import { useState, useEffect, useCallback } from "react"
import { Card, CardContent } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Wifi, WifiOff, Clock, CheckCircle2, RefreshCw, Activity } from "lucide-react"
import type { Alert } from "@/types/alert"

interface RealTimeStatusProps {
  onDataUpdate: (alert: Alert) => void
}

interface FeedStatus {
  name: string
  url: string
  status: "connected" | "error" | "polling"
  lastUpdate: Date | null
  alertCount: number
}

export function RealTimeStatus({ onDataUpdate }: RealTimeStatusProps) {
  const [isPolling, setIsPolling] = useState(false)
  const [lastGlobalUpdate, setLastGlobalUpdate] = useState<Date>(new Date())
  const [feedStatuses, setFeedStatuses] = useState<FeedStatus[]>([
    {
      name: "CISA Alerts",
      url: "https://www.cisa.gov/sites/default/files/feeds/alerts.xml",
      status: "connected",
      lastUpdate: new Date(),
      alertCount: 0,
    },
    {
      name: "KEV Feed",
      url: "https://www.cisa.gov/sites/default/files/feeds/kev.xml",
      status: "connected",
      lastUpdate: new Date(),
      alertCount: 0,
    },
    {
      name: "Advisories",
      url: "https://www.cisa.gov/sites/default/files/feeds/cybersecurity-advisories.xml",
      status: "connected",
      lastUpdate: new Date(),
      alertCount: 0,
    },
    {
      name: "Bulletins",
      url: "https://www.cisa.gov/sites/default/files/feeds/sbd_alerts.xml",
      status: "error",
      lastUpdate: null,
      alertCount: 0,
    },
  ])

  // Simulate real-time polling
  const pollFeeds = useCallback(async () => {
    setIsPolling(true)

    try {
      // Simulate API calls with random delays
      await new Promise((resolve) => setTimeout(resolve, 1000 + Math.random() * 2000))

      // Simulate new alerts occasionally
      if (Math.random() > 0.7) {
        const mockAlert: Alert = {
          id: `rt-${Date.now()}`,
          title: `Real-time Alert: ${["CVE-2024-0001", "APT Activity", "Zero-day Exploit"][Math.floor(Math.random() * 3)]}`,
          date: new Date().toISOString(),
          posture: Math.random() > 0.5 ? "Shields Up" : "Shields Ready",
          sector: ["Energy", "Healthcare", "Finance", "Transportation"][Math.floor(Math.random() * 4)],
          urgency: ["High", "Medium", "Low"][Math.floor(Math.random() * 3)] as any,
          kev: Math.random() > 0.6,
          exploitation: Math.random() > 0.7,
          criticalInfrastructure: Math.random() > 0.4,
          summary: "Real-time threat intelligence indicates active exploitation targeting critical infrastructure.",
        }

        onDataUpdate(mockAlert)
      }

      // Update feed statuses
      setFeedStatuses((prev) =>
        prev.map((feed) => ({
          ...feed,
          status: Math.random() > 0.1 ? "connected" : ("error" as any),
          lastUpdate: Math.random() > 0.1 ? new Date() : feed.lastUpdate,
          alertCount: feed.alertCount + (Math.random() > 0.8 ? 1 : 0),
        })),
      )

      setLastGlobalUpdate(new Date())
    } catch (error) {
      console.error("Polling error:", error)
    } finally {
      setIsPolling(false)
    }
  }, [onDataUpdate])

  // Auto-polling every 30 seconds
  useEffect(() => {
    const interval = setInterval(pollFeeds, 30000)
    return () => clearInterval(interval)
  }, [pollFeeds])

  const connectedFeeds = feedStatuses.filter((f) => f.status === "connected").length
  const totalAlerts = feedStatuses.reduce((sum, feed) => sum + feed.alertCount, 0)

  return (
    <Card className="border-l-4 border-l-green-500">
      <CardContent className="p-4">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
          {/* Status Overview */}
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
              <Activity className={`h-5 w-5 ${isPolling ? "text-blue-500 animate-pulse" : "text-green-500"}`} />
              <span className="font-medium text-[#005288]">Real-Time Monitoring</span>
            </div>

            <div className="flex items-center gap-2">
              <Wifi className="h-4 w-4 text-green-500" />
              <span className="text-sm">
                {connectedFeeds}/{feedStatuses.length} feeds active
              </span>
            </div>

            <div className="flex items-center gap-2">
              <Clock className="h-4 w-4 text-gray-500" />
              <span className="text-sm text-gray-600">Last update: {lastGlobalUpdate.toLocaleTimeString()}</span>
            </div>
          </div>

          {/* Action Buttons */}
          <div className="flex items-center gap-2">
            <Badge variant="outline" className="bg-green-50">
              {totalAlerts} alerts processed
            </Badge>

            <Button
              size="sm"
              variant="outline"
              onClick={pollFeeds}
              disabled={isPolling}
              className="border-[#005288] text-[#005288] hover:bg-[#005288] hover:text-white bg-transparent"
            >
              {isPolling ? (
                <>
                  <RefreshCw className="h-4 w-4 mr-1 animate-spin" />
                  Polling...
                </>
              ) : (
                <>
                  <RefreshCw className="h-4 w-4 mr-1" />
                  Refresh Now
                </>
              )}
            </Button>
          </div>
        </div>

        {/* Feed Status Details */}
        <div className="mt-3 grid grid-cols-2 lg:grid-cols-4 gap-2">
          {feedStatuses.map((feed) => (
            <div key={feed.name} className="flex items-center gap-2 text-sm">
              {feed.status === "connected" ? (
                <CheckCircle2 className="h-3 w-3 text-green-500" />
              ) : feed.status === "polling" ? (
                <RefreshCw className="h-3 w-3 text-blue-500 animate-spin" />
              ) : (
                <WifiOff className="h-3 w-3 text-red-500" />
              )}
              <span className="truncate">{feed.name}</span>
              {feed.alertCount > 0 && (
                <Badge variant="secondary" className="text-xs px-1 py-0">
                  {feed.alertCount}
                </Badge>
              )}
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  )
}
