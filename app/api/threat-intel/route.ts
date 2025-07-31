// API routes for threat intelligence data
import { type NextRequest, NextResponse } from "next/server"
import { getThreatIntelService } from "@/lib/real-time-service"

export async function GET(request: NextRequest) {
  const { searchParams } = new URL(request.url)
  const action = searchParams.get("action")
  const threatIntelService = getThreatIntelService()

  try {
    switch (action) {
      case "recent":
        const hours = Number.parseInt(searchParams.get("hours") || "24")
        const recentThreats = await threatIntelService.getRecentThreats(hours)
        return NextResponse.json({ success: true, data: recentThreats })

      case "search":
        const searchTerm = searchParams.get("q")
        if (!searchTerm) {
          return NextResponse.json({ success: false, error: "Search term required" }, { status: 400 })
        }
        const searchResults = await threatIntelService.searchThreats(searchTerm)
        return NextResponse.json({ success: true, data: searchResults })

      case "severity":
        const severity = searchParams.get("severity")
        if (!severity) {
          return NextResponse.json({ success: false, error: "Severity parameter required" }, { status: 400 })
        }
        const severityThreats = await threatIntelService.getThreatsBySeverity(severity)
        return NextResponse.json({ success: true, data: severityThreats })

      case "sector":
        const sector = searchParams.get("sector")
        if (!sector) {
          return NextResponse.json({ success: false, error: "Sector parameter required" }, { status: 400 })
        }
        const sectorThreats = await threatIntelService.getThreatsBySector(sector)
        return NextResponse.json({ success: true, data: sectorThreats })

      case "feeds":
        const feedStatuses = await threatIntelService.getFeedStatuses()
        return NextResponse.json({ success: true, data: feedStatuses })

      default:
        return NextResponse.json({ success: false, error: "Invalid action" }, { status: 400 })
    }
  } catch (error) {
    console.error("API error:", error)
    return NextResponse.json(
      {
        success: false,
        error: "Internal server error",
      },
      { status: 500 },
    )
  }
}

export async function POST(request: NextRequest) {
  const threatIntelService = getThreatIntelService()

  try {
    const body = await request.json()
    const { action, ...data } = body

    switch (action) {
      case "toggle_feed":
        if (data.enabled) {
          await threatIntelService.enableFeed(data.feedId)
        } else {
          await threatIntelService.disableFeed(data.feedId)
        }
        return NextResponse.json({ success: true })

      case "start_service":
        await threatIntelService.start()
        return NextResponse.json({ success: true, message: "Threat intelligence service started" })

      case "stop_service":
        await threatIntelService.stop()
        return NextResponse.json({ success: true, message: "Threat intelligence service stopped" })

      default:
        return NextResponse.json({ success: false, error: "Invalid action" }, { status: 400 })
    }
  } catch (error) {
    console.error("API error:", error)
    return NextResponse.json(
      {
        success: false,
        error: "Internal server error",
      },
      { status: 500 },
    )
  }
}
