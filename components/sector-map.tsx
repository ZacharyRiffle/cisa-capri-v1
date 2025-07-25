"use client"

import type React from "react"

import { useState } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { MapPin, Zap, Shield, Building2, Truck, Droplets, Radio } from "lucide-react"

interface SectorMapProps {
  capriScore: {
    score: number
    breakdown: any
    rationale: string
  }
}

interface SectorData {
  name: string
  location: string
  coordinates: { x: number; y: number }
  score: number
  icon: React.ReactNode
  alerts: number
  lastUpdate: string
}

export function SectorMap({ capriScore }: SectorMapProps) {
  const [selectedSector, setSelectedSector] = useState<SectorData | null>(null)

  // Enhanced sector data with icons and additional information
  const [sectors] = useState<SectorData[]>([
    {
      name: "Healthcare",
      location: "Chicago, IL",
      coordinates: { x: 58, y: 40 },
      score: 3.8,
      icon: <Building2 className="h-4 w-4" />,
      alerts: 12,
      lastUpdate: "2 hours ago",
    },
    {
      name: "Energy",
      location: "Washington, DC",
      coordinates: { x: 80, y: 42 },
      score: 4.2,
      icon: <Zap className="h-4 w-4" />,
      alerts: 8,
      lastUpdate: "1 hour ago",
    },
    {
      name: "Finance",
      location: "New York, NY",
      coordinates: { x: 85, y: 38 },
      score: 3.5,
      icon: <Building2 className="h-4 w-4" />,
      alerts: 15,
      lastUpdate: "30 minutes ago",
    },
    {
      name: "Transportation",
      location: "Atlanta, GA",
      coordinates: { x: 70, y: 55 },
      score: 2.7,
      icon: <Truck className="h-4 w-4" />,
      alerts: 6,
      lastUpdate: "4 hours ago",
    },
    {
      name: "Water",
      location: "Denver, CO",
      coordinates: { x: 40, y: 42 },
      score: 3.1,
      icon: <Droplets className="h-4 w-4" />,
      alerts: 4,
      lastUpdate: "3 hours ago",
    },
    {
      name: "Communications",
      location: "San Francisco, CA",
      coordinates: { x: 15, y: 42 },
      score: 2.9,
      icon: <Radio className="h-4 w-4" />,
      alerts: 9,
      lastUpdate: "1 hour ago",
    },
    {
      name: "Defense",
      location: "Norfolk, VA",
      coordinates: { x: 78, y: 48 },
      score: 4.5,
      icon: <Shield className="h-4 w-4" />,
      alerts: 3,
      lastUpdate: "45 minutes ago",
    },
  ])

  // Get color based on score
  const getScoreColor = (score: number) => {
    if (score >= 4) return "bg-[#d92525]" // High - Red
    if (score >= 3) return "bg-amber-500" // Medium - Amber
    return "bg-green-600" // Low - Green
  }

  const getScoreColorText = (score: number) => {
    if (score >= 4) return "text-[#d92525]" // High - Red
    if (score >= 3) return "text-amber-600" // Medium - Amber
    return "text-green-600" // Low - Green
  }

  return (
    <Card className="border-[#005288] border-t-4">
      <CardHeader>
        <CardTitle className="text-[#005288]">Critical Infrastructure CAPRI Map</CardTitle>
        <CardDescription>Real-time geographic distribution of CAPRI scores by sector</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {/* Map Section */}
          <div className="lg:col-span-2">
            <div className="relative w-full aspect-[4/3] bg-gradient-to-b from-blue-50 to-blue-100 rounded-lg border overflow-hidden">
              {/* USA Map Outline */}
              <svg
                viewBox="0 0 800 600"
                className="absolute inset-0 w-full h-full"
                style={{ filter: "drop-shadow(0 2px 4px rgba(0,0,0,0.1))" }}
              >
                {/* Simplified USA outline */}
                <path
                  d="M 100 200 L 700 200 L 700 180 L 720 180 L 720 220 L 750 220 L 750 400 L 700 400 L 700 450 L 650 450 L 600 480 L 500 480 L 450 450 L 400 460 L 350 440 L 300 450 L 250 430 L 200 440 L 150 420 L 100 400 Z"
                  fill="white"
                  stroke="#005288"
                  strokeWidth="2"
                  opacity="0.8"
                />
              </svg>

              {/* Sector Pins */}
              {sectors.map((sector) => (
                <div
                  key={sector.name}
                  className="absolute transform -translate-x-1/2 -translate-y-1/2 cursor-pointer group z-10"
                  style={{
                    left: `${sector.coordinates.x}%`,
                    top: `${sector.coordinates.y}%`,
                  }}
                  onClick={() => setSelectedSector(sector)}
                >
                  {/* Pulsing animation for high scores */}
                  {sector.score >= 4 && (
                    <div className="absolute inset-0 w-8 h-8 bg-[#d92525] rounded-full opacity-30 animate-ping"></div>
                  )}

                  {/* Main pin */}
                  <div
                    className={`flex items-center justify-center w-8 h-8 rounded-full ${getScoreColor(sector.score)} text-white text-sm font-bold shadow-lg border-2 border-white hover:scale-110 transition-transform`}
                  >
                    {Math.round(sector.score)}
                  </div>

                  {/* Enhanced Tooltip */}
                  <div className="absolute bottom-full left-1/2 transform -translate-x-1/2 -translate-y-2 w-56 bg-white p-3 rounded-lg shadow-xl opacity-0 group-hover:opacity-100 transition-opacity z-20 pointer-events-none border">
                    <div className="flex items-center gap-2 mb-2">
                      {sector.icon}
                      <div className="font-medium text-[#005288]">{sector.name}</div>
                    </div>
                    <div className="text-xs text-gray-500 mb-2">{sector.location}</div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm font-medium">CAPRI Score:</span>
                      <Badge className={getScoreColor(sector.score)}>{sector.score.toFixed(1)}</Badge>
                    </div>
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs text-gray-600">Active Alerts:</span>
                      <span className="text-xs font-medium">{sector.alerts}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-xs text-gray-600">Last Update:</span>
                      <span className="text-xs">{sector.lastUpdate}</span>
                    </div>
                  </div>
                </div>
              ))}

              {/* Enhanced Legend */}
              <div className="absolute bottom-4 right-4 bg-white bg-opacity-95 p-3 rounded-lg shadow-lg border">
                <div className="text-sm font-medium mb-2 text-[#005288]">CAPRI Threat Level</div>
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <div className="w-4 h-4 rounded-full bg-[#d92525]"></div>
                    <span className="text-xs">Critical (4.0+)</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="w-4 h-4 rounded-full bg-amber-500"></div>
                    <span className="text-xs">Elevated (3.0-3.9)</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="w-4 h-4 rounded-full bg-green-600"></div>
                    <span className="text-xs">Guarded (&lt;3.0)</span>
                  </div>
                </div>
              </div>

              {/* National Alert Banner */}
              <div className="absolute top-4 left-4 bg-[#005288] text-white px-3 py-1 rounded-md text-sm font-medium">
                🛡️ National Posture: Shields Up
              </div>
            </div>
          </div>

          {/* Sector Details Panel */}
          <div className="lg:col-span-1">
            <div className="bg-gray-50 rounded-lg p-4 h-full">
              <h3 className="font-medium text-[#005288] mb-3">Sector Details</h3>

              {selectedSector ? (
                <div className="space-y-3">
                  <div className="flex items-center gap-2">
                    {selectedSector.icon}
                    <div className="font-medium">{selectedSector.name}</div>
                  </div>

                  <div className="text-sm text-gray-600">{selectedSector.location}</div>

                  <div className="flex items-center justify-between">
                    <span className="text-sm font-medium">CAPRI Score:</span>
                    <Badge className={getScoreColor(selectedSector.score)} variant="default">
                      {selectedSector.score.toFixed(1)}
                    </Badge>
                  </div>

                  <div className="flex items-center justify-between">
                    <span className="text-sm">Active Alerts:</span>
                    <span className={`font-medium ${selectedSector.alerts > 10 ? "text-[#d92525]" : "text-gray-700"}`}>
                      {selectedSector.alerts}
                    </span>
                  </div>

                  <div className="flex items-center justify-between">
                    <span className="text-sm">Last Update:</span>
                    <span className="text-sm text-gray-600">{selectedSector.lastUpdate}</span>
                  </div>

                  <Button
                    size="sm"
                    className="w-full mt-3 bg-[#005288] hover:bg-[#003e66]"
                    onClick={() => setSelectedSector(null)}
                  >
                    View All Sectors
                  </Button>
                </div>
              ) : (
                <div className="text-center text-gray-500 py-8">
                  <MapPin className="h-8 w-8 mx-auto mb-2 opacity-50" />
                  <p className="text-sm">Click on a sector pin to view details</p>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Sector Summary Grid */}
        <div className="mt-6 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
          {sectors
            .sort((a, b) => b.score - a.score)
            .map((sector) => (
              <div
                key={sector.name}
                className={`p-3 border rounded-lg cursor-pointer transition-all hover:shadow-md ${
                  selectedSector?.name === sector.name ? "border-[#005288] bg-blue-50" : "hover:border-gray-300"
                }`}
                onClick={() => setSelectedSector(sector)}
              >
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    {sector.icon}
                    <span className="font-medium text-sm">{sector.name}</span>
                  </div>
                  <Badge className={`${getScoreColor(sector.score)} text-xs`} variant="default">
                    {sector.score.toFixed(1)}
                  </Badge>
                </div>
                <div className="text-xs text-gray-500">{sector.location}</div>
                <div className="flex items-center justify-between mt-1">
                  <span className="text-xs text-gray-600">{sector.alerts} alerts</span>
                  <span className="text-xs text-gray-500">{sector.lastUpdate}</span>
                </div>
              </div>
            ))}
        </div>
      </CardContent>
    </Card>
  )
}
