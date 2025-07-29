"use client"

import { useState } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Switch } from "@/components/ui/switch"
import { Textarea } from "@/components/ui/textarea"
import { Settings, Zap, CheckCircle2, XCircle, AlertTriangle, Send, Database, Webhook, Key, Globe } from "lucide-react"
import type { Alert } from "@/types/alert"

interface SiemIntegrationProps {
  alerts: Alert[]
  onWebhookSend?: (data: any) => void
}

interface SiemConnection {
  id: string
  name: string
  type: "splunk" | "qradar" | "sentinel" | "elastic" | "chronicle"
  status: "connected" | "disconnected" | "error"
  endpoint: string
  lastSync: string
  alertsSent: number
  enabled: boolean
}

interface WebhookConfig {
  url: string
  method: "POST" | "PUT"
  headers: Record<string, string>
  enabled: boolean
  events: string[]
}

interface ApiEndpoint {
  path: string
  method: "GET" | "POST" | "PUT" | "DELETE"
  description: string
  authenticated: boolean
}

export function SiemIntegration({ alerts, onWebhookSend }: SiemIntegrationProps) {
  const [siemConnections, setSiemConnections] = useState<SiemConnection[]>([
    {
      id: "splunk-prod",
      name: "Splunk Enterprise",
      type: "splunk",
      status: "connected",
      endpoint: "https://splunk.company.com:8089",
      lastSync: "2 minutes ago",
      alertsSent: 1247,
      enabled: true,
    },
    {
      id: "sentinel-main",
      name: "Microsoft Sentinel",
      type: "sentinel",
      status: "connected",
      endpoint: "https://company.sentinel.azure.com",
      lastSync: "5 minutes ago",
      alertsSent: 892,
      enabled: true,
    },
    {
      id: "qradar-soc",
      name: "IBM QRadar",
      type: "qradar",
      status: "error",
      endpoint: "https://qradar.company.com",
      lastSync: "2 hours ago",
      alertsSent: 0,
      enabled: false,
    },
  ])

  const [webhookConfig, setWebhookConfig] = useState<WebhookConfig>({
    url: "https://hooks.slack.com/services/YOUR/WEBHOOK/URL",
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: "Bearer YOUR_TOKEN",
    },
    enabled: true,
    events: ["high_severity_alert", "capri_score_change", "new_threat_detected"],
  })

  const [apiKey, setApiKey] = useState("capri_api_key_" + Math.random().toString(36).substr(2, 9))

  const apiEndpoints: ApiEndpoint[] = [
    {
      path: "/api/v1/alerts",
      method: "GET",
      description: "Retrieve all alerts with optional filtering",
      authenticated: true,
    },
    {
      path: "/api/v1/alerts",
      method: "POST",
      description: "Create a new alert",
      authenticated: true,
    },
    {
      path: "/api/v1/capri/scores",
      method: "GET",
      description: "Get current CAPRI scores by sector",
      authenticated: true,
    },
    {
      path: "/api/v1/threats/indicators",
      method: "GET",
      description: "Retrieve threat indicators and IOCs",
      authenticated: true,
    },
    {
      path: "/api/v1/webhooks/test",
      method: "POST",
      description: "Test webhook configuration",
      authenticated: true,
    },
  ]

  const handleSiemToggle = (connectionId: string, enabled: boolean) => {
    setSiemConnections((prev) => prev.map((conn) => (conn.id === connectionId ? { ...conn, enabled } : conn)))
  }

  const handleTestWebhook = async () => {
    const testPayload = {
      event: "test_webhook",
      timestamp: new Date().toISOString(),
      data: {
        message: "CAPRI webhook test successful",
        capri_score: 3.8,
        alert_count: alerts.length,
        test: true,
      },
    }

    try {
      // Simulate webhook call
      console.log("Sending webhook:", testPayload)
      onWebhookSend?.(testPayload)

      // Show success feedback
      alert("Webhook test sent successfully!")
    } catch (error) {
      console.error("Webhook test failed:", error)
      alert("Webhook test failed. Please check your configuration.")
    }
  }

  const handleSiemSync = (connectionId: string) => {
    setSiemConnections((prev) =>
      prev.map((conn) =>
        conn.id === connectionId
          ? { ...conn, lastSync: "Just now", alertsSent: conn.alertsSent + alerts.length }
          : conn,
      ),
    )
  }

  const getStatusIcon = (status: SiemConnection["status"]) => {
    switch (status) {
      case "connected":
        return <CheckCircle2 className="h-4 w-4 text-green-500" />
      case "error":
        return <XCircle className="h-4 w-4 text-red-500" />
      default:
        return <AlertTriangle className="h-4 w-4 text-yellow-500" />
    }
  }

  const getSiemIcon = (type: SiemConnection["type"]) => {
    switch (type) {
      case "splunk":
        return <Database className="h-5 w-5 text-green-600" />
      case "sentinel":
        return <Database className="h-5 w-5 text-blue-600" />
      case "qradar":
        return <Database className="h-5 w-5 text-purple-600" />
      case "elastic":
        return <Database className="h-5 w-5 text-yellow-600" />
      default:
        return <Database className="h-5 w-5 text-gray-600" />
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-[#005288]">SIEM Integration & APIs</h2>
          <p className="text-gray-600">Connect with external security tools and platforms</p>
        </div>
        <Button className="bg-[#005288] hover:bg-[#003e66]">
          <Settings className="h-4 w-4 mr-2" />
          Configure
        </Button>
      </div>

      <Tabs defaultValue="siem" className="w-full">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="siem">SIEM Connections</TabsTrigger>
          <TabsTrigger value="webhooks">Webhooks</TabsTrigger>
          <TabsTrigger value="api">API Endpoints</TabsTrigger>
          <TabsTrigger value="logs">Integration Logs</TabsTrigger>
        </TabsList>

        <TabsContent value="siem">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* SIEM Connections */}
            <div className="space-y-4">
              {siemConnections.map((connection) => (
                <Card key={connection.id}>
                  <CardHeader className="pb-3">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        {getSiemIcon(connection.type)}
                        <div>
                          <CardTitle className="text-lg">{connection.name}</CardTitle>
                          <CardDescription>{connection.endpoint}</CardDescription>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        {getStatusIcon(connection.status)}
                        <Switch
                          checked={connection.enabled}
                          onCheckedChange={(enabled) => handleSiemToggle(connection.id, enabled)}
                        />
                      </div>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <div className="grid grid-cols-2 gap-4 text-sm">
                      <div>
                        <span className="text-gray-600">Status:</span>
                        <Badge
                          className={`ml-2 ${
                            connection.status === "connected"
                              ? "bg-green-100 text-green-800"
                              : connection.status === "error"
                                ? "bg-red-100 text-red-800"
                                : "bg-yellow-100 text-yellow-800"
                          }`}
                        >
                          {connection.status}
                        </Badge>
                      </div>
                      <div>
                        <span className="text-gray-600">Last Sync:</span>
                        <span className="ml-2">{connection.lastSync}</span>
                      </div>
                      <div>
                        <span className="text-gray-600">Alerts Sent:</span>
                        <span className="ml-2 font-medium">{connection.alertsSent.toLocaleString()}</span>
                      </div>
                      <div>
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => handleSiemSync(connection.id)}
                          disabled={!connection.enabled || connection.status !== "connected"}
                        >
                          <Zap className="h-3 w-3 mr-1" />
                          Sync Now
                        </Button>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>

            {/* Add New SIEM Connection */}
            <Card>
              <CardHeader>
                <CardTitle>Add New SIEM Connection</CardTitle>
                <CardDescription>Connect to additional SIEM platforms</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <Label htmlFor="siem-name">Connection Name</Label>
                  <Input id="siem-name" placeholder="My SIEM Instance" />
                </div>
                <div>
                  <Label htmlFor="siem-type">SIEM Type</Label>
                  <select id="siem-type" className="w-full p-2 border rounded-md">
                    <option value="splunk">Splunk</option>
                    <option value="sentinel">Microsoft Sentinel</option>
                    <option value="qradar">IBM QRadar</option>
                    <option value="elastic">Elastic Security</option>
                    <option value="chronicle">Google Chronicle</option>
                  </select>
                </div>
                <div>
                  <Label htmlFor="siem-endpoint">Endpoint URL</Label>
                  <Input id="siem-endpoint" placeholder="https://your-siem.company.com" />
                </div>
                <div>
                  <Label htmlFor="siem-token">API Token</Label>
                  <Input id="siem-token" type="password" placeholder="Your API token" />
                </div>
                <Button className="w-full bg-[#005288] hover:bg-[#003e66]">
                  <CheckCircle2 className="h-4 w-4 mr-2" />
                  Test & Add Connection
                </Button>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="webhooks">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Webhook Configuration */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Webhook className="h-5 w-5" />
                  Webhook Configuration
                </CardTitle>
                <CardDescription>Configure webhooks for real-time notifications</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex items-center justify-between">
                  <Label htmlFor="webhook-enabled">Enable Webhooks</Label>
                  <Switch
                    id="webhook-enabled"
                    checked={webhookConfig.enabled}
                    onCheckedChange={(enabled) => setWebhookConfig((prev) => ({ ...prev, enabled }))}
                  />
                </div>

                <div>
                  <Label htmlFor="webhook-url">Webhook URL</Label>
                  <Input
                    id="webhook-url"
                    value={webhookConfig.url}
                    onChange={(e) => setWebhookConfig((prev) => ({ ...prev, url: e.target.value }))}
                    placeholder="https://hooks.slack.com/services/..."
                  />
                </div>

                <div>
                  <Label htmlFor="webhook-method">HTTP Method</Label>
                  <select
                    id="webhook-method"
                    value={webhookConfig.method}
                    onChange={(e) =>
                      setWebhookConfig((prev) => ({ ...prev, method: e.target.value as "POST" | "PUT" }))
                    }
                    className="w-full p-2 border rounded-md"
                  >
                    <option value="POST">POST</option>
                    <option value="PUT">PUT</option>
                  </select>
                </div>

                <div>
                  <Label htmlFor="webhook-headers">Custom Headers (JSON)</Label>
                  <Textarea
                    id="webhook-headers"
                    value={JSON.stringify(webhookConfig.headers, null, 2)}
                    onChange={(e) => {
                      try {
                        const headers = JSON.parse(e.target.value)
                        setWebhookConfig((prev) => ({ ...prev, headers }))
                      } catch (error) {
                        // Invalid JSON, ignore
                      }
                    }}
                    rows={4}
                  />
                </div>

                <div className="flex gap-2">
                  <Button onClick={handleTestWebhook} disabled={!webhookConfig.enabled} className="flex-1">
                    <Send className="h-4 w-4 mr-2" />
                    Test Webhook
                  </Button>
                  <Button variant="outline" className="flex-1 bg-transparent">
                    Save Configuration
                  </Button>
                </div>
              </CardContent>
            </Card>

            {/* Webhook Events */}
            <Card>
              <CardHeader>
                <CardTitle>Webhook Events</CardTitle>
                <CardDescription>Select which events trigger webhook notifications</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {[
                    { id: "high_severity_alert", label: "High Severity Alerts", description: "CAPRI score >= 4.0" },
                    {
                      id: "capri_score_change",
                      label: "CAPRI Score Changes",
                      description: "Significant score fluctuations",
                    },
                    { id: "new_threat_detected", label: "New Threats", description: "Novel threat indicators" },
                    {
                      id: "sector_compromise",
                      label: "Sector Compromise",
                      description: "Critical infrastructure targeting",
                    },
                    { id: "kev_alert", label: "KEV Alerts", description: "Known Exploited Vulnerabilities" },
                    { id: "system_status", label: "System Status", description: "Platform health updates" },
                  ].map((event) => (
                    <div key={event.id} className="flex items-start gap-3 p-3 border rounded-lg">
                      <Switch
                        checked={webhookConfig.events.includes(event.id)}
                        onCheckedChange={(checked) => {
                          setWebhookConfig((prev) => ({
                            ...prev,
                            events: checked ? [...prev.events, event.id] : prev.events.filter((e) => e !== event.id),
                          }))
                        }}
                      />
                      <div>
                        <div className="font-medium">{event.label}</div>
                        <div className="text-sm text-gray-600">{event.description}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="api">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* API Key Management */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Key className="h-5 w-5" />
                  API Authentication
                </CardTitle>
                <CardDescription>Manage API keys for external integrations</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <Label htmlFor="api-key">Current API Key</Label>
                  <div className="flex gap-2">
                    <Input id="api-key" value={apiKey} readOnly className="font-mono text-sm" />
                    <Button variant="outline" onClick={() => navigator.clipboard.writeText(apiKey)}>
                      Copy
                    </Button>
                  </div>
                </div>

                <div className="p-3 bg-yellow-50 border border-yellow-200 rounded-lg">
                  <div className="flex items-center gap-2 text-yellow-800">
                    <AlertTriangle className="h-4 w-4" />
                    <span className="font-medium">Security Notice</span>
                  </div>
                  <p className="text-sm text-yellow-700 mt-1">
                    Keep your API key secure. Include it in the Authorization header as "Bearer {apiKey}"
                  </p>
                </div>

                <Button
                  variant="outline"
                  onClick={() => setApiKey("capri_api_key_" + Math.random().toString(36).substr(2, 9))}
                  className="w-full"
                >
                  Generate New API Key
                </Button>
              </CardContent>
            </Card>

            {/* API Endpoints */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Globe className="h-5 w-5" />
                  Available API Endpoints
                </CardTitle>
                <CardDescription>RESTful API endpoints for external tool integration</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {apiEndpoints.map((endpoint, index) => (
                    <div key={index} className="p-3 border rounded-lg">
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center gap-2">
                          <Badge
                            className={`${
                              endpoint.method === "GET"
                                ? "bg-green-100 text-green-800"
                                : endpoint.method === "POST"
                                  ? "bg-blue-100 text-blue-800"
                                  : endpoint.method === "PUT"
                                    ? "bg-yellow-100 text-yellow-800"
                                    : "bg-red-100 text-red-800"
                            }`}
                          >
                            {endpoint.method}
                          </Badge>
                          <code className="text-sm font-mono">{endpoint.path}</code>
                        </div>
                        {endpoint.authenticated && (
                          <Badge variant="outline" className="text-xs">
                            <Key className="h-3 w-3 mr-1" />
                            Auth Required
                          </Badge>
                        )}
                      </div>
                      <p className="text-sm text-gray-600">{endpoint.description}</p>
                    </div>
                  ))}
                </div>

                <div className="mt-4 p-3 bg-blue-50 border border-blue-200 rounded-lg">
                  <div className="text-sm">
                    <strong>Base URL:</strong> <code>https://capri.cisa.gov</code>
                  </div>
                  <div className="text-sm mt-1">
                    <strong>Rate Limit:</strong> 1000 requests per hour
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="logs">
          <Card>
            <CardHeader>
              <CardTitle>Integration Activity Logs</CardTitle>
              <CardDescription>Recent integration events and status updates</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {[
                  {
                    timestamp: "2024-01-15 14:32:15",
                    type: "success",
                    message: "Splunk Enterprise sync completed - 45 alerts sent",
                    details: "Connection: splunk-prod",
                  },
                  {
                    timestamp: "2024-01-15 14:30:22",
                    type: "info",
                    message: "Webhook notification sent to Slack",
                    details: "Event: high_severity_alert",
                  },
                  {
                    timestamp: "2024-01-15 14:28:45",
                    type: "warning",
                    message: "Microsoft Sentinel sync delayed",
                    details: "Retrying in 5 minutes",
                  },
                  {
                    timestamp: "2024-01-15 14:25:10",
                    type: "error",
                    message: "IBM QRadar connection failed",
                    details: "Authentication error - check API token",
                  },
                  {
                    timestamp: "2024-01-15 14:20:33",
                    type: "success",
                    message: "API key regenerated",
                    details: "Previous key revoked",
                  },
                ].map((log, index) => (
                  <div key={index} className="flex items-start gap-3 p-3 border rounded-lg">
                    <div
                      className={`w-2 h-2 rounded-full mt-2 ${
                        log.type === "success"
                          ? "bg-green-500"
                          : log.type === "error"
                            ? "bg-red-500"
                            : log.type === "warning"
                              ? "bg-yellow-500"
                              : "bg-blue-500"
                      }`}
                    />
                    <div className="flex-1">
                      <div className="flex items-center justify-between">
                        <span className="font-medium">{log.message}</span>
                        <span className="text-xs text-gray-500">{log.timestamp}</span>
                      </div>
                      <p className="text-sm text-gray-600 mt-1">{log.details}</p>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}
