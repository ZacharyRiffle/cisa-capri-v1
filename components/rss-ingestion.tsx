"use client"

import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { AlertCircle, CheckCircle2, RefreshCw } from "lucide-react"
import type { Alert as AlertType } from "@/types/alert"
import { Badge } from "@/components/ui/badge"
import { Skeleton } from "@/components/ui/skeleton"

interface RssIngestionProps {
  onAlertIngested: (alert: AlertType) => void
}

export function RssIngestion({ onAlertIngested }: RssIngestionProps) {
  const [loading, setLoading] = useState(false)
  const [status, setStatus] = useState<{
    type: "success" | "error" | null
    message: string
  }>({ type: null, message: "" })
  const [fetchedAlerts, setFetchedAlerts] = useState<AlertType[]>([])

  const rssSources = [
    {
      name: "CISA Alerts",
      url: "https://www.cisa.gov/sites/default/files/feeds/alerts.xml",
    },
    {
      name: "Known Exploited Vulnerabilities",
      url: "https://www.cisa.gov/sites/default/files/feeds/kev.xml",
    },
    {
      name: "Stakeholder Bulletins",
      url: "https://www.cisa.gov/sites/default/files/feeds/sbd_alerts.xml",
    },
    {
      name: "Cybersecurity Advisories",
      url: "https://www.cisa.gov/sites/default/files/feeds/cybersecurity-advisories.xml",
    },
  ]

  const fetchRssFeeds = async () => {
    setLoading(true)
    setStatus({ type: null, message: "" })

    try {
      // In a real application, we would use a server action or API route to fetch the RSS feeds
      // For this demo, we'll simulate the fetch with a timeout and mock data
      await new Promise((resolve) => setTimeout(resolve, 1500))

      const mockAlerts: AlertType[] = [
        {
          id: "aa22-216a",
          title: "Vulnerability Summary for the Week of July 31, 2023",
          date: "2023-08-07T14:00:00Z",
          posture: "Shields Up",
          sector: "Energy",
          urgency: "High",
          kev: true,
          exploitation: true,
          criticalInfrastructure: true,
          summary:
            "CISA has added 9 new vulnerabilities to its Known Exploited Vulnerabilities Catalog, based on evidence of active exploitation.",
          url: "https://www.cisa.gov/news-events/alerts/2023/08/07/vulnerability-summary-week-july-31-2023",
        },
        {
          id: "aa23-158a",
          title: "APT Actors Exploit Barracuda ESG Zero-Day Vulnerability",
          date: "2023-06-15T12:30:00Z",
          posture: "Shields Up",
          sector: "Government",
          urgency: "High",
          kev: true,
          exploitation: true,
          criticalInfrastructure: true,
          summary:
            "CISA and FBI are releasing this joint CSA to disseminate known indicators of compromise (IOCs) and TTPs associated with exploits of a zero-day vulnerability in Barracuda Email Security Gateway (ESG) appliances.",
          url: "https://www.cisa.gov/news-events/alerts/2023/06/15/apt-actors-exploit-barracuda-esg-zero-day-vulnerability",
        },
        {
          id: "aa23-075a",
          title: "Threat Actors Exploit Progress Telerik Vulnerabilities",
          date: "2023-03-17T09:15:00Z",
          posture: "Shields Ready",
          sector: "Healthcare",
          urgency: "Medium",
          kev: true,
          exploitation: false,
          criticalInfrastructure: true,
          summary:
            "CISA, FBI, MS-ISAC, ACSC, CCCS, NCSC-NZ, and NCSC-UK are releasing this joint CSA to disseminate known indicators of compromise (IOCs) and TTPs associated with the exploitation of vulnerabilities in Progress Telerik user interface (UI) for ASP.NET AJAX.",
          url: "https://www.cisa.gov/news-events/alerts/2023/03/17/threat-actors-exploit-progress-telerik-vulnerabilities",
        },
      ]

      setFetchedAlerts(mockAlerts)
      setStatus({
        type: "success",
        message: `Successfully fetched ${mockAlerts.length} alerts from CISA RSS feeds.`,
      })

      // Add these alerts to the main application state
      mockAlerts.forEach((alert) => onAlertIngested(alert))
    } catch (error) {
      setStatus({
        type: "error",
        message: `Failed to fetch RSS feeds: ${(error as Error).message}`,
      })
    } finally {
      setLoading(false)
    }
  }

  return (
    <Card className="border-[#005288] border-t-4">
      <CardHeader>
        <CardTitle className="text-[#005288]">CISA RSS Feed Ingestion</CardTitle>
        <CardDescription>Fetch and process alerts from official CISA RSS feeds</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          <div className="flex flex-wrap gap-2 mb-4">
            {rssSources.map((source) => (
              <Badge key={source.name} variant="outline" className="bg-gray-100">
                {source.name}
              </Badge>
            ))}
          </div>

          <Button onClick={fetchRssFeeds} className="w-full bg-[#005288] hover:bg-[#003e66]" disabled={loading}>
            {loading ? (
              <>
                <RefreshCw className="mr-2 h-4 w-4 animate-spin" />
                Fetching Alerts...
              </>
            ) : (
              "Fetch CISA Alerts"
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
            <h3 className="font-medium text-lg">Recent Alerts</h3>

            {loading ? (
              <div className="space-y-4">
                {[1, 2, 3].map((i) => (
                  <div key={i} className="border rounded-md p-4">
                    <Skeleton className="h-6 w-3/4 mb-2" />
                    <Skeleton className="h-4 w-1/2 mb-2" />
                    <Skeleton className="h-4 w-full" />
                  </div>
                ))}
              </div>
            ) : fetchedAlerts.length > 0 ? (
              <div className="space-y-4">
                {fetchedAlerts.map((alert) => (
                  <div key={alert.id} className="border rounded-md p-4 hover:bg-gray-50 transition-colors">
                    <div className="flex justify-between items-start">
                      <h4 className="font-medium">{alert.title}</h4>
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
                    <div className="text-sm text-gray-500 mt-1">
                      {new Date(alert.date).toLocaleDateString()} - {alert.sector}
                    </div>
                    {alert.summary && <p className="text-sm mt-2">{alert.summary}</p>}
                    <div className="flex flex-wrap gap-2 mt-2">
                      {alert.posture === "Shields Up" && (
                        <Badge variant="outline" className="bg-[#005288] text-white">
                          Shields Up
                        </Badge>
                      )}
                      {alert.kev && (
                        <Badge variant="outline" className="bg-[#d92525] text-white">
                          KEV
                        </Badge>
                      )}
                      {alert.exploitation && (
                        <Badge variant="outline" className="bg-purple-600 text-white">
                          Active Exploitation
                        </Badge>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-8 text-gray-500">
                No alerts fetched yet. Click the button above to fetch alerts.
              </div>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  )
}
