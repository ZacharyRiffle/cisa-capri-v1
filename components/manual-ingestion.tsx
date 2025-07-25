"use client"

import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Textarea } from "@/components/ui/textarea"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { AlertCircle, CheckCircle2 } from "lucide-react"
import type { Alert as AlertType } from "@/types/alert"

interface ManualIngestionProps {
  onAlertIngested: (alert: AlertType) => void
}

export function ManualIngestion({ onAlertIngested }: ManualIngestionProps) {
  const [inputValue, setInputValue] = useState("")
  const [status, setStatus] = useState<{
    type: "success" | "error" | null
    message: string
  }>({ type: null, message: "" })
  const [parsedAlert, setParsedAlert] = useState<AlertType | null>(null)

  const handleIngest = () => {
    try {
      // Try to parse as JSON first
      let alertData: AlertType

      try {
        alertData = JSON.parse(inputValue)
      } catch (e) {
        // If not valid JSON, try to parse as simplified format
        const lines = inputValue.split("\n")
        alertData = {
          id: `manual-${Date.now()}`,
          title: "Manual Alert",
          date: new Date().toISOString(),
          posture: "Shields Ready",
          sector: "General",
          urgency: "Medium",
          kev: false,
          exploitation: false,
          criticalInfrastructure: false,
        }

        // Parse each line for key:value pairs
        lines.forEach((line) => {
          const [key, value] = line.split(":")
          if (key && value) {
            const trimmedKey = key.trim().toLowerCase()
            const trimmedValue = value.trim()

            if (trimmedKey === "posture") alertData.posture = trimmedValue
            if (trimmedKey === "sector") alertData.sector = trimmedValue
            if (trimmedKey === "urgency") alertData.urgency = trimmedValue as any
            if (trimmedKey === "kev") alertData.kev = trimmedValue.toLowerCase() === "true"
            if (trimmedKey === "exploitation") alertData.exploitation = trimmedValue.toLowerCase() === "true"
            if (trimmedKey === "critical" || trimmedKey === "criticalinfrastructure")
              alertData.criticalInfrastructure = trimmedValue.toLowerCase() === "true"
          }
        })
      }

      // Validate required fields
      if (!alertData.posture || !alertData.sector || !alertData.urgency) {
        throw new Error("Missing required fields: posture, sector, or urgency")
      }

      setParsedAlert(alertData)
      setStatus({
        type: "success",
        message: "Alert successfully parsed and ingested.",
      })

      // Pass the alert to the parent component
      onAlertIngested(alertData)
    } catch (error) {
      setStatus({
        type: "error",
        message: `Failed to parse alert: ${(error as Error).message}`,
      })
      setParsedAlert(null)
    }
  }

  return (
    <Card className="border-[#005288] border-t-4">
      <CardHeader>
        <CardTitle className="text-[#005288]">Manual Alert Ingestion</CardTitle>
        <CardDescription>
          Paste a JSON-formatted alert or use simplified format (e.g., posture: Shields Up, sector: Energy)
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          <Textarea
            placeholder="Paste alert data here..."
            className="min-h-[200px] font-mono text-sm border-2"
            value={inputValue}
            onChange={(e) => setInputValue(e.target.value)}
          />

          <Button onClick={handleIngest} className="w-full bg-[#005288] hover:bg-[#003e66]">
            Ingest Alert
          </Button>

          {status.type && (
            <Alert variant={status.type === "error" ? "destructive" : "default"}>
              {status.type === "error" ? <AlertCircle className="h-4 w-4" /> : <CheckCircle2 className="h-4 w-4" />}
              <AlertTitle>{status.type === "error" ? "Error" : "Success"}</AlertTitle>
              <AlertDescription>{status.message}</AlertDescription>
            </Alert>
          )}

          {parsedAlert && (
            <div className="mt-4 border rounded-md p-4 bg-gray-50">
              <h3 className="font-medium text-lg mb-2">Alert Breakdown</h3>
              <div className="grid grid-cols-2 gap-2 text-sm">
                <div className="font-medium">Posture:</div>
                <div>{parsedAlert.posture}</div>

                <div className="font-medium">Sector:</div>
                <div>{parsedAlert.sector}</div>

                <div className="font-medium">Urgency:</div>
                <div
                  className={`font-medium ${
                    parsedAlert.urgency === "High"
                      ? "text-[#d92525]"
                      : parsedAlert.urgency === "Medium"
                        ? "text-amber-500"
                        : "text-green-600"
                  }`}
                >
                  {parsedAlert.urgency}
                </div>

                <div className="font-medium">KEV Present:</div>
                <div>{parsedAlert.kev ? "Yes" : "No"}</div>

                <div className="font-medium">Exploitation Observed:</div>
                <div>{parsedAlert.exploitation ? "Yes" : "No"}</div>

                <div className="font-medium">Critical Infrastructure:</div>
                <div>{parsedAlert.criticalInfrastructure ? "Yes" : "No"}</div>
              </div>
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  )
}
