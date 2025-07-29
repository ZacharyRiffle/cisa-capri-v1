"use client"

import { useState, useEffect } from "react"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { ManualIngestion } from "@/components/manual-ingestion"
import { TiFeeds } from "@/components/ti-feeds"
import { CapriWidget } from "@/components/capri-widget"
import { DatabaseView } from "@/components/database-view"
import type { Alert } from "@/types/alert"
import { calculateCapriScoresBySector, calculateCapriScore } from "@/lib/capri-calculator"
import { Shield } from "lucide-react"
import { SecurityControls } from "@/components/security-controls"
import { HistoricalTrends } from "@/components/historical-trends"
import { SiemIntegration } from "@/components/siem-integration"
import { generateSampleAlerts } from "@/lib/sample-data"
import { RealTimeStatus } from "@/components/real-time-status"

export default function Home() {
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [sectorScores, setSectorScores] = useState<any[]>([])
  const [overallCapriScore, setOverallCapriScore] = useState({
    score: 3.2,
    breakdown: {
      P: 1.0,
      X: 1.0,
      S: 1.0,
      U: 1.0,
      K: 0.6,
      C: 1.0,
      A: 0.9,
      R: 0.8,
      T: 0.7,
      CSS: 0.85,
    },
    rationale: "Loading sector-specific intelligence...",
    categories: {
      alerts: 0.8,
      research: 0.7,
      threatIntel: 0.75,
      vulnerability: 0.6,
      geopolitical: 0.8,
    },
  })
  const [isLoading, setIsLoading] = useState(true)

  useEffect(() => {
    const initializeData = async () => {
      try {
        setIsLoading(true)

        // Load sample data
        const sampleAlerts = generateSampleAlerts()
        setAlerts(sampleAlerts)

        // Calculate sector-specific CAPRI scores
        const scores = calculateCapriScoresBySector(sampleAlerts)
        setSectorScores(scores)

        // Calculate overall score for backward compatibility
        const overallScore = calculateCapriScore(sampleAlerts)
        setOverallCapriScore(overallScore)

        setIsLoading(false)
      } catch (error) {
        console.error("Error initializing data:", error)
        setIsLoading(false)
      }
    }

    initializeData()
  }, [])

  const handleNewAlert = (alert: Alert) => {
    try {
      const newAlerts = [alert, ...alerts]
      setAlerts(newAlerts)

      // Calculate new sector-specific CAPRI scores
      const newSectorScores = calculateCapriScoresBySector(newAlerts)
      setSectorScores(newSectorScores)

      // Calculate new overall score
      const newOverallScore = calculateCapriScore(newAlerts)
      setOverallCapriScore(newOverallScore)

      // Store in localStorage
      localStorage.setItem("cisaCapriAlerts", JSON.stringify(newAlerts))
    } catch (error) {
      console.error("Error processing new alert:", error)
    }
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
            <p>Critical Infrastructure Alert Prioritization and Readiness Index</p>
            <p className="text-xs opacity-75">Sector-Specific Multi-Source Intelligence Integration</p>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <div className="container mx-auto p-4">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* CAPRI Widget - Left Column */}
          <div className="lg:col-span-1">
            <CapriWidget sectorScores={sectorScores} />
          </div>

          {/* Main Content - Right Column */}
          <div className="lg:col-span-2">
            {/* Real-Time Status Bar */}
            <div className="mb-4">
              <RealTimeStatus onDataUpdate={handleNewAlert} />
            </div>
            <Tabs defaultValue="manual" className="w-full">
              <TabsList className="w-full bg-gray-100 p-1">
                <TabsTrigger value="manual" className="flex-1">
                  Manual Alert Ingestion
                </TabsTrigger>
                <TabsTrigger value="ti-feeds" className="flex-1">
                  TI Feeds
                </TabsTrigger>
                <TabsTrigger value="database" className="flex-1">
                  Database
                </TabsTrigger>
                <TabsTrigger value="controls" className="flex-1">
                  Controls
                </TabsTrigger>
                <TabsTrigger value="trends" className="flex-1">
                  Trends
                </TabsTrigger>
                <TabsTrigger value="integrations" className="flex-1">
                  SIEM & APIs
                </TabsTrigger>
              </TabsList>
              <TabsContent value="manual">
                <ManualIngestion onAlertIngested={handleNewAlert} />
              </TabsContent>
              <TabsContent value="ti-feeds">
                <TiFeeds onAlertIngested={handleNewAlert} />
              </TabsContent>
              <TabsContent value="database">
                <DatabaseView alerts={alerts} sectorScores={sectorScores} />
              </TabsContent>
              <TabsContent value="controls">
                <SecurityControls alerts={alerts} capriScore={overallCapriScore} />
              </TabsContent>
              <TabsContent value="trends">
                <HistoricalTrends alerts={alerts} sectorScores={sectorScores} />
              </TabsContent>
              <TabsContent value="integrations">
                <SiemIntegration alerts={alerts} />
              </TabsContent>
            </Tabs>
          </div>
        </div>
      </div>

      {/* Footer */}
      <footer className="bg-[#005288] text-white p-4 mt-8">
        <div className="container mx-auto text-center text-sm">
          <p>CISA CAPRI - Cybersecurity and Infrastructure Security Agency</p>
          <p className="text-xs mt-1">Sector-Specific Multi-Source Threat Intelligence Integration Platform</p>
        </div>
      </footer>
    </main>
  )
}
