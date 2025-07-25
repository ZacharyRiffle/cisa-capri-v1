"use client"

import { useState } from "react"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { ManualIngestion } from "@/components/manual-ingestion"
import { RssIngestion } from "@/components/rss-ingestion"
import { CapriWidget } from "@/components/capri-widget"
import { SectorMap } from "@/components/sector-map"
import type { Alert } from "@/types/alert"
import { calculateCapriScore } from "@/lib/capri-calculator"
import { Shield } from "lucide-react"

export default function Home() {
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [capriScore, setCapriScore] = useState({
    score: 3.2,
    breakdown: {
      P: 1.0, // National Posture
      X: 1.0, // Exploitation Observed
      S: 1.0, // Sector Match
      U: 1.0, // Urgency
      K: 0.6, // KEV Presence
      C: 1.0, // Critical Infrastructure
      A: 0.9, // Alert Targeting Score
      CSS: 0.95, // Computed Sector Score
    },
    rationale: "Shields Up posture targeting Energy sector with observed exploitation",
  })

  const handleNewAlert = (alert: Alert) => {
    const newAlerts = [alert, ...alerts]
    setAlerts(newAlerts)

    // Calculate new CAPRI score based on all alerts
    const newScore = calculateCapriScore(newAlerts)
    setCapriScore(newScore)

    // Store in localStorage
    localStorage.setItem("cisaCapriAlerts", JSON.stringify(newAlerts))
  }

  return (
    <main className="min-h-screen bg-white">
      {/* Header */}
      <header className="bg-[#005288] text-white p-4 shadow-md">
        <div className="container mx-auto flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Shield className="h-8 w-8" />
            <h1 className="text-2xl font-bold">CISA CAPRI</h1>
          </div>
          <div className="text-sm">
            <p>CISA Alert Prioritization and Readiness Index</p>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <div className="container mx-auto p-4">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* CAPRI Widget - Left Column */}
          <div className="lg:col-span-1">
            <CapriWidget capriScore={capriScore} />
          </div>

          {/* Main Content - Right Column */}
          <div className="lg:col-span-2">
            <Tabs defaultValue="manual" className="w-full">
              <TabsList className="w-full bg-gray-100 p-1">
                <TabsTrigger value="manual" className="flex-1">
                  Manual Alert Ingestion
                </TabsTrigger>
                <TabsTrigger value="rss" className="flex-1">
                  CISA RSS Feeds
                </TabsTrigger>
                <TabsTrigger value="map" className="flex-1">
                  Sector Map
                </TabsTrigger>
              </TabsList>
              <TabsContent value="manual">
                <ManualIngestion onAlertIngested={handleNewAlert} />
              </TabsContent>
              <TabsContent value="rss">
                <RssIngestion onAlertIngested={handleNewAlert} />
              </TabsContent>
              <TabsContent value="map">
                <SectorMap capriScore={capriScore} />
              </TabsContent>
            </Tabs>
          </div>
        </div>
      </div>

      {/* Footer */}
      <footer className="bg-[#005288] text-white p-4 mt-8">
        <div className="container mx-auto text-center text-sm">
          <p>CISA CAPRI - Cybersecurity and Infrastructure Security Agency</p>
          <p className="text-xs mt-1">Alert Prioritization and Readiness Index</p>
        </div>
      </footer>
    </main>
  )
}
