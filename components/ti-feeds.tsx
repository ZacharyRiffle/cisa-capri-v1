"use client"

import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { AlertCircle, CheckCircle2, RefreshCw } from "lucide-react"
import type { Alert as AlertType } from "@/types/alert"
import { Badge } from "@/components/ui/badge"
import { Skeleton } from "@/components/ui/skeleton"

interface TiFeedsProps {
  onAlertIngested: (alert: AlertType) => void
}

export function TiFeeds({ onAlertIngested }: TiFeedsProps) {
  const [loading, setLoading] = useState(false)
  const [status, setStatus] = useState<{
    type: "success" | "error" | null
    message: string
  }>({ type: null, message: "" })
  const [fetchedAlerts, setFetchedAlerts] = useState<AlertType[]>([])

  const tiSources = [
    {
      name: "CISA Alerts",
      url: "https://www.cisa.gov/sites/default/files/feeds/alerts.xml",
      category: "Government",
    },
    {
      name: "Mandiant Threat Intelligence",
      url: "https://www.mandiant.com/resources/blog/rss.xml",
      category: "Commercial TI",
    },
    {
      name: "Microsoft Security Blog",
      url: "https://www.microsoft.com/en-us/security/blog/feed/",
      category: "Vendor Intelligence",
    },
    {
      name: "Wiz Security Research",
      url: "https://www.wiz.io/blog/feed/",
      category: "Cloud Security",
    },
    {
      name: "CrowdStrike Intelligence",
      url: "https://www.crowdstrike.com/blog/feed/",
      category: "Commercial TI",
    },
    {
      name: "Palo Alto Unit 42",
      url: "https://unit42.paloaltonetworks.com/feed/",
      category: "Threat Research",
    },
    {
      name: "Recorded Future",
      url: "https://www.recordedfuture.com/feed",
      category: "Commercial TI",
    },
    {
      name: "Sentinel One Labs",
      url: "https://www.sentinelone.com/labs/feed/",
      category: "Endpoint Security",
    },
  ]

  const fetchTiFeeds = async () => {
    setLoading(true)
    setStatus({ type: null, message: "" })

    try {
      // In a real application, we would use a server action or API route to fetch the TI feeds
      // For this demo, we'll simulate the fetch with a timeout and mock data
      await new Promise((resolve) => setTimeout(resolve, 2000))

      const mockAlerts: AlertType[] = [
        {
          id: "ti-001",
          title: "APT40 Exploiting CVE-2025-0147 in Energy Sector SCADA Systems",
          date: "2025-01-15T14:30:00Z",
          posture: "Shields Up",
          sector: "Energy",
          urgency: "High",
          kev: true,
          exploitation: true,
          criticalInfrastructure: true,
          summary:
            "Mandiant researchers have identified APT40 (Leviathan) actively exploiting CVE-2025-0147 in Schneider Electric SCADA systems to target power grid infrastructure across North America and Europe.",
          url: "https://www.mandiant.com/resources/blog/apt40-scada-exploit-2025",
          source: "Mandiant Threat Intelligence",
        },
        {
          id: "ti-002",
          title: "Microsoft Defender Detects BlackCat 2.0 Ransomware Campaign",
          date: "2025-01-15T11:45:00Z",
          posture: "Shields Up",
          sector: "Healthcare",
          urgency: "High",
          kev: false,
          exploitation: true,
          criticalInfrastructure: true,
          summary:
            "Microsoft Security Intelligence reports BlackCat 2.0 ransomware campaign targeting healthcare organizations using AI-powered social engineering and zero-day exploits in medical device management systems.",
          url: "https://www.microsoft.com/security/blog/blackcat-2-healthcare-2025",
          source: "Microsoft Security Blog",
        },
        {
          id: "ti-003",
          title: "Wiz Research: Critical Kubernetes Escape in Major Cloud Providers",
          date: "2025-01-15T09:20:00Z",
          posture: "Shields Ready",
          sector: "Information Technology",
          urgency: "High",
          kev: true,
          exploitation: false,
          criticalInfrastructure: true,
          summary:
            "Wiz Research discovered a critical container escape vulnerability (CVE-2025-0089) affecting Kubernetes clusters across AWS, Azure, and GCP, potentially exposing millions of cloud workloads.",
          url: "https://www.wiz.io/blog/kubernetes-escape-2025",
          source: "Wiz Security Research",
        },
        {
          id: "ti-004",
          title: "Unit 42: Volt Typhoon 2.0 Targets US Water Infrastructure",
          date: "2025-01-14T16:15:00Z",
          posture: "Shields Up",
          sector: "Water",
          urgency: "High",
          kev: true,
          exploitation: true,
          criticalInfrastructure: true,
          summary:
            "Palo Alto Networks Unit 42 has identified Volt Typhoon 2.0 campaign specifically targeting water treatment facilities and dam control systems using living-off-the-land techniques and AI-enhanced persistence.",
          url: "https://unit42.paloaltonetworks.com/volt-typhoon-2-water-2025",
          source: "Palo Alto Unit 42",
        },
        {
          id: "ti-005",
          title: "CrowdStrike: Lazarus Group Targets Cryptocurrency Exchanges with AI Deepfakes",
          date: "2025-01-14T13:30:00Z",
          posture: "Shields Up",
          sector: "Finance",
          urgency: "High",
          kev: false,
          exploitation: true,
          criticalInfrastructure: false,
          summary:
            "CrowdStrike Intelligence reports Lazarus Group using AI-generated deepfake videos in sophisticated social engineering attacks targeting cryptocurrency exchange executives and employees.",
          url: "https://www.crowdstrike.com/blog/lazarus-deepfake-crypto-2025",
          source: "CrowdStrike Intelligence",
        },
        {
          id: "ti-006",
          title: "Recorded Future: Quantum-Resistant Encryption Under Attack",
          date: "2025-01-14T10:45:00Z",
          posture: "Shields Ready",
          sector: "Defense",
          urgency: "Medium",
          kev: false,
          exploitation: false,
          criticalInfrastructure: true,
          summary:
            "Recorded Future analysis reveals nation-state actors developing quantum computing capabilities to break early implementations of post-quantum cryptography in defense contractor networks.",
          url: "https://www.recordedfuture.com/quantum-crypto-attacks-2025",
          source: "Recorded Future",
        },
        {
          id: "ti-007",
          title: "SentinelOne: AI-Powered Malware Evades Traditional Detection",
          date: "2025-01-13T15:20:00Z",
          posture: "Shields Ready",
          sector: "Manufacturing",
          urgency: "Medium",
          kev: false,
          exploitation: true,
          criticalInfrastructure: true,
          summary:
            "SentinelOne Labs discovered new AI-powered malware family 'ChameleonAI' that adapts its behavior in real-time to evade detection, primarily targeting industrial control systems in manufacturing.",
          url: "https://www.sentinelone.com/labs/chameleon-ai-malware-2025",
          source: "Sentinel One Labs",
        },
        {
          id: "ti-008",
          title: "CISA Advisory: Critical Vulnerabilities in 5G Network Infrastructure",
          date: "2025-01-13T12:00:00Z",
          posture: "Shields Up",
          sector: "Communications",
          urgency: "High",
          kev: true,
          exploitation: false,
          criticalInfrastructure: true,
          summary:
            "CISA releases emergency advisory on critical vulnerabilities in 5G core network equipment from multiple vendors, potentially allowing remote code execution and network disruption.",
          url: "https://www.cisa.gov/news-events/alerts/2025/01/13/5g-network-vulnerabilities",
          source: "CISA Alerts",
        },
      ]

      setFetchedAlerts(mockAlerts)
      setStatus({
        type: "success",
        message: `Successfully fetched ${mockAlerts.length} threat intelligence reports from ${tiSources.length} sources.`,
      })

      // Add these alerts to the main application state
      mockAlerts.forEach((alert) => onAlertIngested(alert))
    } catch (error) {
      setStatus({
        type: "error",
        message: `Failed to fetch TI feeds: ${(error as Error).message}`,
      })
    } finally {
      setLoading(false)
    }
  }

  const getCategoryColor = (category: string) => {
    switch (category) {
      case "Government":
        return "bg-[#005288] text-white"
      case "Commercial TI":
        return "bg-purple-600 text-white"
      case "Vendor Intelligence":
        return "bg-blue-600 text-white"
      case "Cloud Security":
        return "bg-cyan-600 text-white"
      case "Threat Research":
        return "bg-orange-600 text-white"
      case "Endpoint Security":
        return "bg-green-600 text-white"
      default:
        return "bg-gray-600 text-white"
    }
  }

  return (
    <Card className="border-[#005288] border-t-4">
      <CardHeader>
        <CardTitle className="text-[#005288]">Threat Intelligence Feeds</CardTitle>
        <CardDescription>Aggregate threat intelligence from leading security vendors and researchers</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          <div className="flex flex-wrap gap-2 mb-4">
            {tiSources.map((source) => (
              <Badge key={source.name} className={getCategoryColor(source.category)}>
                {source.name}
              </Badge>
            ))}
          </div>

          <Button onClick={fetchTiFeeds} className="w-full bg-[#005288] hover:bg-[#003e66]" disabled={loading}>
            {loading ? (
              <>
                <RefreshCw className="mr-2 h-4 w-4 animate-spin" />
                Fetching Intelligence...
              </>
            ) : (
              "Fetch Threat Intelligence"
            )}
          </Button>

          {status.type && (
            <Alert variant={status.type === "error" ? "destructive" : "default"}>
              {status.type === "error" ? <AlertCircle className="h-4 w-4" /> : <CheckCircle2 className="h-4 w-4" />}
              <AlertTitle>{status.type === "error" ? "Error" : "Success"}</AlertTitle>
              <AlertDescription>{status.message}</AlertDescription>
            </Alert>
          )}

          <div className="space-y-4 mt-4">
            <h3 className="font-medium text-lg">Recent Threat Intelligence</h3>

            {loading ? (
              <div className="space-y-4">
                {[1, 2, 3, 4].map((i) => (
                  <div key={i} className="border rounded-md p-4">
                    <Skeleton className="h-6 w-3/4 mb-2" />
                    <Skeleton className="h-4 w-1/2 mb-2" />
                    <Skeleton className="h-4 w-full mb-2" />
                    <Skeleton className="h-4 w-2/3" />
                  </div>
                ))}
              </div>
            ) : fetchedAlerts.length > 0 ? (
              <div className="space-y-4">
                {fetchedAlerts.map((alert) => (
                  <div key={alert.id} className="border rounded-md p-4 hover:bg-gray-50 transition-colors">
                    <div className="flex justify-between items-start mb-2">
                      <h4 className="font-medium text-sm">{alert.title}</h4>
                      <Badge
                        className={
                          alert.urgency === "High"
                            ? "bg-[#d92525]"
                            : alert.urgency === "Medium"
                              ? "bg-amber-500"
                              : "bg-green-600"
                        }
                      >
                        {alert.urgency}
                      </Badge>
                    </div>
                    <div className="text-xs text-gray-500 mb-2">
                      {new Date(alert.date).toLocaleDateString()} - {alert.sector} | {alert.source}
                    </div>
                    {alert.summary && <p className="text-sm mt-2 text-gray-700">{alert.summary}</p>}
                    <div className="flex flex-wrap gap-2 mt-3">
                      {alert.posture === "Shields Up" && (
                        <Badge variant="outline" className="bg-[#005288] text-white text-xs">
                          Shields Up
                        </Badge>
                      )}
                      {alert.kev && (
                        <Badge variant="outline" className="bg-[#d92525] text-white text-xs">
                          KEV
                        </Badge>
                      )}
                      {alert.exploitation && (
                        <Badge variant="outline" className="bg-purple-600 text-white text-xs">
                          Active Exploitation
                        </Badge>
                      )}
                      {alert.criticalInfrastructure && (
                        <Badge variant="outline" className="bg-orange-600 text-white text-xs">
                          Critical Infrastructure
                        </Badge>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-8 text-gray-500">
                <div className="text-4xl mb-2">🔍</div>
                <p>No threat intelligence fetched yet.</p>
                <p className="text-sm">Click the button above to fetch the latest reports.</p>
              </div>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  )
}
