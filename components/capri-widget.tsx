import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { AlertTriangle } from "lucide-react"

interface CapriScoreBreakdown {
  P: number // National Posture
  X: number // Exploitation Observed
  S: number // Sector Match
  U: number // Urgency
  K: number // KEV Presence
  C: number // Critical Infrastructure
  A: number // Alert Targeting Score
  CSS: number // Computed Sector Score
}

interface CapriWidgetProps {
  capriScore: {
    score: number
    breakdown: CapriScoreBreakdown
    rationale: string
  }
}

export function CapriWidget({ capriScore }: CapriWidgetProps) {
  // Round to 1 decimal place for display
  const displayScore = Math.round(capriScore.score * 10) / 10

  // Determine severity level based on score
  const getSeverityColor = (score: number) => {
    if (score >= 4) return "text-[#d92525]" // High - Red
    if (score >= 3) return "text-amber-600" // Medium - Amber
    return "text-green-600" // Low - Green
  }

  const severityColor = getSeverityColor(displayScore)

  return (
    <Card className="border-[#005288] border-t-4">
      <CardHeader className="pb-2">
        <CardTitle className="text-[#005288] flex items-center gap-2">
          <AlertTriangle className="h-5 w-5" />
          CAPRI Level
        </CardTitle>
        <CardDescription>Current Alert Prioritization and Readiness Index</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="flex flex-col items-center justify-center py-4">
          <div className={`text-6xl font-bold ${severityColor}`}>{displayScore}</div>
          <div className="text-sm text-center mt-2 max-w-xs">{capriScore.rationale}</div>
        </div>

        <div className="mt-4">
          <h3 className="text-sm font-medium mb-2">Score Breakdown</h3>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-[100px]">Code</TableHead>
                <TableHead>Meaning</TableHead>
                <TableHead className="text-right">Value</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              <TableRow>
                <TableCell className="font-medium">P</TableCell>
                <TableCell>National Posture</TableCell>
                <TableCell className="text-right">{capriScore.breakdown.P.toFixed(1)}</TableCell>
              </TableRow>
              <TableRow>
                <TableCell className="font-medium">X</TableCell>
                <TableCell>Exploitation Observed</TableCell>
                <TableCell className="text-right">{capriScore.breakdown.X.toFixed(1)}</TableCell>
              </TableRow>
              <TableRow>
                <TableCell className="font-medium">S</TableCell>
                <TableCell>Sector Match</TableCell>
                <TableCell className="text-right">{capriScore.breakdown.S.toFixed(1)}</TableCell>
              </TableRow>
              <TableRow>
                <TableCell className="font-medium">U</TableCell>
                <TableCell>Urgency</TableCell>
                <TableCell className="text-right">{capriScore.breakdown.U.toFixed(1)}</TableCell>
              </TableRow>
              <TableRow>
                <TableCell className="font-medium">K</TableCell>
                <TableCell>KEV Presence</TableCell>
                <TableCell className="text-right">{capriScore.breakdown.K.toFixed(1)}</TableCell>
              </TableRow>
              <TableRow>
                <TableCell className="font-medium">C</TableCell>
                <TableCell>Critical Infrastructure</TableCell>
                <TableCell className="text-right">{capriScore.breakdown.C.toFixed(1)}</TableCell>
              </TableRow>
              <TableRow>
                <TableCell className="font-medium">A</TableCell>
                <TableCell>Alert Targeting Score</TableCell>
                <TableCell className="text-right">{capriScore.breakdown.A.toFixed(1)}</TableCell>
              </TableRow>
              <TableRow>
                <TableCell className="font-medium">CSS</TableCell>
                <TableCell>Computed Sector Score</TableCell>
                <TableCell className="text-right">{capriScore.breakdown.CSS.toFixed(2)}</TableCell>
              </TableRow>
            </TableBody>
          </Table>
        </div>
      </CardContent>
    </Card>
  )
}
