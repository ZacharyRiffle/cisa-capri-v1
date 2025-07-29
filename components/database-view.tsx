"use client"

import { useState, useMemo } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import {
  Database,
  Search,
  Filter,
  Download,
  Eye,
  AlertTriangle,
  Shield,
  Target,
  Activity,
  FileText,
  Zap,
  Clock,
  ExternalLink,
} from "lucide-react"
import type { Alert } from "@/types/alert"
import { generateSampleAlerts, generateHistoricalData, generateThreatPredictions } from "@/lib/sample-data"

interface DatabaseViewProps {
  alerts: Alert[]
  sectorScores: any[]
}

interface DatabaseRecord {
  id: string
  timestamp: string
  type: "alert" | "threat_intel" | "vulnerability" | "incident" | "ioc" | "capri_score"
  severity: "Low" | "Medium" | "High" | "Critical"
  source: string
  title: string
  sector: string
  status: "Active" | "Resolved" | "Investigating" | "Archived"
  tags: string[]
  data: any
}

export function DatabaseView({ alerts, sectorScores }: DatabaseViewProps) {
  const [searchTerm, setSearchTerm] = useState("")
  const [selectedType, setSelectedType] = useState<string>("all")
  const [selectedSeverity, setSelectedSeverity] = useState<string>("all")
  const [selectedRecord, setSelectedRecord] = useState<DatabaseRecord | null>(null)
  const [currentPage, setCurrentPage] = useState(1)
  const recordsPerPage = 50

  // Generate comprehensive database records
  const databaseRecords = useMemo<DatabaseRecord[]>(() => {
    const records: DatabaseRecord[] = []
    const sampleAlerts = generateSampleAlerts()
    const allAlerts = [...alerts, ...sampleAlerts]
    const threatPredictions = generateThreatPredictions()
    const historicalData = generateHistoricalData(30)

    // Convert alerts to database records
    allAlerts.forEach((alert) => {
      records.push({
        id: alert.id,
        timestamp: alert.date,
        type: "alert",
        severity: alert.urgency,
        source: alert.source || "CISA RSS",
        title: alert.title,
        sector: alert.sector,
        status: "Active",
        tags: [
          alert.posture,
          ...(alert.kev ? ["KEV"] : []),
          ...(alert.exploitation ? ["Active Exploitation"] : []),
          ...(alert.criticalInfrastructure ? ["Critical Infrastructure"] : []),
        ],
        data: alert,
      })
    })

    // Add threat intelligence records
    const threatIntelSources = [
      "Mandiant Threat Intelligence",
      "CrowdStrike Intelligence",
      "Microsoft Security Blog",
      "Palo Alto Unit 42",
      "Recorded Future",
      "Wiz Security Research",
    ]

    for (let i = 0; i < 25; i++) {
      const timestamp = new Date(Date.now() - Math.random() * 7 * 24 * 60 * 60 * 1000).toISOString()
      const source = threatIntelSources[Math.floor(Math.random() * threatIntelSources.length)]
      const sectors = ["Energy", "Healthcare", "Finance", "Transportation", "Defense"]
      const sector = sectors[Math.floor(Math.random() * sectors.length)]

      records.push({
        id: `ti-${i + 1}`,
        timestamp,
        type: "threat_intel",
        severity: ["High", "Medium", "Low"][Math.floor(Math.random() * 3)] as any,
        source,
        title: `Threat Intelligence Report ${i + 1}`,
        sector,
        status: "Active",
        tags: ["APT", "Malware", "IOC", "TTP"],
        data: {
          indicators: Math.floor(Math.random() * 50) + 10,
          confidence: Math.floor(Math.random() * 40) + 60,
          attribution: ["APT29", "Lazarus", "APT40", "FIN7"][Math.floor(Math.random() * 4)],
        },
      })
    }

    // Add vulnerability records
    for (let i = 0; i < 30; i++) {
      const timestamp = new Date(Date.now() - Math.random() * 14 * 24 * 60 * 60 * 1000).toISOString()
      const cveId = `CVE-2024-${String(Math.floor(Math.random() * 9999)).padStart(4, "0")}`

      records.push({
        id: `vuln-${i + 1}`,
        timestamp,
        type: "vulnerability",
        severity: ["Critical", "High", "Medium", "Low"][Math.floor(Math.random() * 4)] as any,
        source: "NVD/MITRE",
        title: `${cveId} - Critical Vulnerability Disclosure`,
        sector: "All Sectors",
        status: Math.random() > 0.3 ? "Active" : "Resolved",
        tags: ["CVE", "Zero-day", "RCE", "Privilege Escalation"],
        data: {
          cvss: (Math.random() * 4 + 6).toFixed(1),
          cwe: `CWE-${Math.floor(Math.random() * 900) + 100}`,
          exploitAvailable: Math.random() > 0.7,
        },
      })
    }

    // Add incident records
    for (let i = 0; i < 15; i++) {
      const timestamp = new Date(Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000).toISOString()
      const sectors = ["Energy", "Healthcare", "Finance", "Transportation", "Defense"]
      const sector = sectors[Math.floor(Math.random() * sectors.length)]

      records.push({
        id: `inc-${i + 1}`,
        timestamp,
        type: "incident",
        severity: ["Critical", "High", "Medium"][Math.floor(Math.random() * 3)] as any,
        source: "SOC Team",
        title: `Security Incident ${i + 1} - ${sector} Sector`,
        sector,
        status: ["Investigating", "Resolved", "Active"][Math.floor(Math.random() * 3)] as any,
        tags: ["Breach", "Malware", "Data Exfiltration", "Ransomware"],
        data: {
          affectedSystems: Math.floor(Math.random() * 100) + 5,
          containmentTime: `${Math.floor(Math.random() * 24) + 1} hours`,
          impactLevel: ["Low", "Medium", "High"][Math.floor(Math.random() * 3)],
        },
      })
    }

    // Add IOC records
    for (let i = 0; i < 40; i++) {
      const timestamp = new Date(Date.now() - Math.random() * 7 * 24 * 60 * 60 * 1000).toISOString()
      const iocTypes = ["IP Address", "Domain", "File Hash", "URL", "Email"]
      const iocType = iocTypes[Math.floor(Math.random() * iocTypes.length)]

      records.push({
        id: `ioc-${i + 1}`,
        timestamp,
        type: "ioc",
        severity: ["High", "Medium", "Low"][Math.floor(Math.random() * 3)] as any,
        source: "Threat Intel Feeds",
        title: `IOC Detection - ${iocType}`,
        sector: "All Sectors",
        status: "Active",
        tags: ["IOC", "Malicious", iocType.replace(" ", "")],
        data: {
          type: iocType,
          confidence: Math.floor(Math.random() * 40) + 60,
          firstSeen: timestamp,
          tlp: ["WHITE", "GREEN", "AMBER"][Math.floor(Math.random() * 3)],
        },
      })
    }

    // Add CAPRI score records
    historicalData.forEach((point, index) => {
      records.push({
        id: `capri-${index}`,
        timestamp: new Date(point.date).toISOString(),
        type: "capri_score",
        severity: point.score >= 4 ? "Critical" : point.score >= 3 ? "High" : "Medium",
        source: "CAPRI Calculator",
        title: `CAPRI Score Update - ${point.score.toFixed(1)}`,
        sector: "All Sectors",
        status: "Active",
        tags: ["CAPRI", "Score", "Analysis"],
        data: {
          score: point.score,
          alerts: point.alerts,
          sectors: point.sectors,
        },
      })
    })

    return records.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
  }, [alerts, sectorScores])

  // Filter records based on search and filters
  const filteredRecords = useMemo(() => {
    return databaseRecords.filter((record) => {
      const matchesSearch =
        searchTerm === "" ||
        record.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
        record.source.toLowerCase().includes(searchTerm.toLowerCase()) ||
        record.sector.toLowerCase().includes(searchTerm.toLowerCase()) ||
        record.tags.some((tag) => tag.toLowerCase().includes(searchTerm.toLowerCase()))

      const matchesType = selectedType === "all" || record.type === selectedType
      const matchesSeverity = selectedSeverity === "all" || record.severity === selectedSeverity

      return matchesSearch && matchesType && matchesSeverity
    })
  }, [databaseRecords, searchTerm, selectedType, selectedSeverity])

  // Pagination
  const totalPages = Math.ceil(filteredRecords.length / recordsPerPage)
  const paginatedRecords = filteredRecords.slice((currentPage - 1) * recordsPerPage, currentPage * recordsPerPage)

  const getTypeIcon = (type: string) => {
    switch (type) {
      case "alert":
        return <AlertTriangle className="h-4 w-4" />
      case "threat_intel":
        return <Shield className="h-4 w-4" />
      case "vulnerability":
        return <Target className="h-4 w-4" />
      case "incident":
        return <Activity className="h-4 w-4" />
      case "ioc":
        return <Zap className="h-4 w-4" />
      case "capri_score":
        return <FileText className="h-4 w-4" />
      default:
        return <Database className="h-4 w-4" />
    }
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "Critical":
        return "bg-red-500 text-white"
      case "High":
        return "bg-orange-500 text-white"
      case "Medium":
        return "bg-yellow-500 text-white"
      case "Low":
        return "bg-green-500 text-white"
      default:
        return "bg-gray-500 text-white"
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case "Active":
        return "bg-red-100 text-red-800"
      case "Investigating":
        return "bg-yellow-100 text-yellow-800"
      case "Resolved":
        return "bg-green-100 text-green-800"
      case "Archived":
        return "bg-gray-100 text-gray-800"
      default:
        return "bg-blue-100 text-blue-800"
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold text-[#005288] flex items-center gap-2">
            <Database className="h-6 w-6" />
            Intelligence Database
          </h2>
          <p className="text-gray-600">Comprehensive view of all threat intelligence, alerts, and security data</p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm">
            <Download className="h-4 w-4 mr-1" />
            Export Data
          </Button>
          <Button variant="outline" size="sm">
            <Filter className="h-4 w-4 mr-1" />
            Advanced Filter
          </Button>
        </div>
      </div>

      {/* Statistics Cards */}
      <div className="grid grid-cols-2 md:grid-cols-6 gap-4">
        {[
          {
            type: "alert",
            label: "Alerts",
            count: databaseRecords.filter((r) => r.type === "alert").length,
            color: "text-red-600",
          },
          {
            type: "threat_intel",
            label: "Threat Intel",
            count: databaseRecords.filter((r) => r.type === "threat_intel").length,
            color: "text-purple-600",
          },
          {
            type: "vulnerability",
            label: "Vulnerabilities",
            count: databaseRecords.filter((r) => r.type === "vulnerability").length,
            color: "text-orange-600",
          },
          {
            type: "incident",
            label: "Incidents",
            count: databaseRecords.filter((r) => r.type === "incident").length,
            color: "text-blue-600",
          },
          {
            type: "ioc",
            label: "IOCs",
            count: databaseRecords.filter((r) => r.type === "ioc").length,
            color: "text-green-600",
          },
          {
            type: "capri_score",
            label: "CAPRI Scores",
            count: databaseRecords.filter((r) => r.type === "capri_score").length,
            color: "text-indigo-600",
          },
        ].map((stat) => (
          <Card
            key={stat.type}
            className="cursor-pointer hover:shadow-md transition-shadow"
            onClick={() => setSelectedType(stat.type)}
          >
            <CardContent className="p-4 text-center">
              <div className={`text-2xl font-bold ${stat.color}`}>{stat.count}</div>
              <div className="text-sm text-gray-600">{stat.label}</div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Search and Filters */}
      <Card>
        <CardContent className="p-4">
          <div className="flex flex-col sm:flex-row gap-4">
            <div className="flex-1">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
                <Input
                  placeholder="Search alerts, sources, sectors, tags..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="pl-10"
                />
              </div>
            </div>
            <div className="flex gap-2">
              <select
                value={selectedType}
                onChange={(e) => setSelectedType(e.target.value)}
                className="px-3 py-2 border rounded-md text-sm"
              >
                <option value="all">All Types</option>
                <option value="alert">Alerts</option>
                <option value="threat_intel">Threat Intel</option>
                <option value="vulnerability">Vulnerabilities</option>
                <option value="incident">Incidents</option>
                <option value="ioc">IOCs</option>
                <option value="capri_score">CAPRI Scores</option>
              </select>
              <select
                value={selectedSeverity}
                onChange={(e) => setSelectedSeverity(e.target.value)}
                className="px-3 py-2 border rounded-md text-sm"
              >
                <option value="all">All Severities</option>
                <option value="Critical">Critical</option>
                <option value="High">High</option>
                <option value="Medium">Medium</option>
                <option value="Low">Low</option>
              </select>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Database Table */}
      <Tabs defaultValue="table" className="w-full">
        <TabsList>
          <TabsTrigger value="table">Table View</TabsTrigger>
          <TabsTrigger value="details">Record Details</TabsTrigger>
        </TabsList>

        <TabsContent value="table">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center justify-between">
                <span>Database Records ({filteredRecords.length.toLocaleString()})</span>
                <div className="text-sm text-gray-600">
                  Page {currentPage} of {totalPages}
                </div>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Type</TableHead>
                      <TableHead>Timestamp</TableHead>
                      <TableHead>Title</TableHead>
                      <TableHead>Source</TableHead>
                      <TableHead>Sector</TableHead>
                      <TableHead>Severity</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Tags</TableHead>
                      <TableHead>Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {paginatedRecords.map((record) => (
                      <TableRow key={record.id} className="hover:bg-gray-50">
                        <TableCell>
                          <div className="flex items-center gap-2">
                            {getTypeIcon(record.type)}
                            <span className="text-sm capitalize">{record.type.replace("_", " ")}</span>
                          </div>
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center gap-1 text-sm">
                            <Clock className="h-3 w-3" />
                            {new Date(record.timestamp).toLocaleString()}
                          </div>
                        </TableCell>
                        <TableCell>
                          <div className="max-w-xs truncate font-medium">{record.title}</div>
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline" className="text-xs">
                            {record.source}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <span className="text-sm">{record.sector}</span>
                        </TableCell>
                        <TableCell>
                          <Badge className={getSeverityColor(record.severity)}>{record.severity}</Badge>
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline" className={getStatusColor(record.status)}>
                            {record.status}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <div className="flex flex-wrap gap-1 max-w-xs">
                            {record.tags.slice(0, 2).map((tag) => (
                              <Badge key={tag} variant="secondary" className="text-xs">
                                {tag}
                              </Badge>
                            ))}
                            {record.tags.length > 2 && (
                              <Badge variant="secondary" className="text-xs">
                                +{record.tags.length - 2}
                              </Badge>
                            )}
                          </div>
                        </TableCell>
                        <TableCell>
                          <Button size="sm" variant="outline" onClick={() => setSelectedRecord(record)}>
                            <Eye className="h-3 w-3" />
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>

              {/* Pagination */}
              <div className="flex items-center justify-between mt-4">
                <div className="text-sm text-gray-600">
                  Showing {(currentPage - 1) * recordsPerPage + 1} to{" "}
                  {Math.min(currentPage * recordsPerPage, filteredRecords.length)} of {filteredRecords.length} records
                </div>
                <div className="flex gap-2">
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => setCurrentPage(Math.max(1, currentPage - 1))}
                    disabled={currentPage === 1}
                  >
                    Previous
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => setCurrentPage(Math.min(totalPages, currentPage + 1))}
                    disabled={currentPage === totalPages}
                  >
                    Next
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="details">
          <Card>
            <CardHeader>
              <CardTitle>Record Details</CardTitle>
              <CardDescription>
                {selectedRecord
                  ? `Viewing details for ${selectedRecord.id}`
                  : "Select a record from the table to view details"}
              </CardDescription>
            </CardHeader>
            <CardContent>
              {selectedRecord ? (
                <div className="space-y-6">
                  {/* Record Header */}
                  <div className="flex items-start justify-between">
                    <div>
                      <h3 className="text-lg font-semibold flex items-center gap-2">
                        {getTypeIcon(selectedRecord.type)}
                        {selectedRecord.title}
                      </h3>
                      <p className="text-sm text-gray-600 mt-1">ID: {selectedRecord.id}</p>
                    </div>
                    <div className="flex gap-2">
                      <Badge className={getSeverityColor(selectedRecord.severity)}>{selectedRecord.severity}</Badge>
                      <Badge variant="outline" className={getStatusColor(selectedRecord.status)}>
                        {selectedRecord.status}
                      </Badge>
                    </div>
                  </div>

                  {/* Record Metadata */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <h4 className="font-medium mb-2">Metadata</h4>
                      <div className="space-y-2 text-sm">
                        <div className="flex justify-between">
                          <span className="text-gray-600">Timestamp:</span>
                          <span>{new Date(selectedRecord.timestamp).toLocaleString()}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-600">Source:</span>
                          <span>{selectedRecord.source}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-600">Sector:</span>
                          <span>{selectedRecord.sector}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-600">Type:</span>
                          <span className="capitalize">{selectedRecord.type.replace("_", " ")}</span>
                        </div>
                      </div>
                    </div>

                    <div>
                      <h4 className="font-medium mb-2">Tags</h4>
                      <div className="flex flex-wrap gap-1">
                        {selectedRecord.tags.map((tag) => (
                          <Badge key={tag} variant="secondary" className="text-xs">
                            {tag}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  </div>

                  {/* Record Data */}
                  <div>
                    <h4 className="font-medium mb-2">Raw Data</h4>
                    <div className="bg-gray-50 p-4 rounded-lg">
                      <pre className="text-xs overflow-x-auto">{JSON.stringify(selectedRecord.data, null, 2)}</pre>
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="flex gap-2">
                    <Button size="sm" variant="outline">
                      <ExternalLink className="h-3 w-3 mr-1" />
                      View Source
                    </Button>
                    <Button size="sm" variant="outline">
                      <Download className="h-3 w-3 mr-1" />
                      Export Record
                    </Button>
                    <Button size="sm" variant="outline">
                      <FileText className="h-3 w-3 mr-1" />
                      Generate Report
                    </Button>
                  </div>
                </div>
              ) : (
                <div className="text-center py-12 text-gray-500">
                  <Database className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>Select a record from the table to view detailed information</p>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}
