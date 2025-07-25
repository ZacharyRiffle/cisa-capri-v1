import type { Alert } from "@/types/alert"

// Calculate CAPRI score based on alerts
export function calculateCapriScore(alerts: Alert[]) {
  // If no alerts, return default score
  if (!alerts || alerts.length === 0) {
    return {
      score: 2.5,
      breakdown: {
        P: 0.5, // National Posture
        X: 0.5, // Exploitation Observed
        S: 0.5, // Sector Match
        U: 0.5, // Urgency
        K: 0.5, // KEV Presence
        C: 0.5, // Critical Infrastructure
        A: 0.5, // Alert Targeting Score
        CSS: 0.5, // Computed Sector Score
      },
      rationale: "Default baseline score with no active alerts",
    }
  }

  // Get the most recent alert for initial calculations
  const mostRecentAlert = alerts[0]

  // Calculate individual components
  const postureScore = mostRecentAlert.posture === "Shields Up" ? 1.0 : 0.5

  const urgencyScore = mostRecentAlert.urgency === "High" ? 1.0 : mostRecentAlert.urgency === "Medium" ? 0.7 : 0.3

  const kevScore = mostRecentAlert.kev ? 1.0 : 0.3
  const exploitationScore = mostRecentAlert.exploitation ? 1.0 : 0.4
  const criticalInfrastructureScore = mostRecentAlert.criticalInfrastructure ? 1.0 : 0.5

  // Calculate alert targeting score (simplified for demo)
  const alertTargetingScore = 0.9

  // Calculate sector score based on all alerts
  const sectorMatchScore = 1.0

  // Calculate computed sector score
  const computedSectorScore = (
    postureScore * 0.2 +
    urgencyScore * 0.2 +
    kevScore * 0.15 +
    exploitationScore * 0.15 +
    criticalInfrastructureScore * 0.1 +
    alertTargetingScore * 0.1 +
    sectorMatchScore * 0.1
  ).toFixed(2)

  // Calculate final CAPRI score (1-5 scale)
  const finalScore = 1 + Number.parseFloat(computedSectorScore) * 4

  // Generate rationale
  let rationale = ""
  if (finalScore >= 4) {
    rationale = `${mostRecentAlert.posture} posture targeting ${mostRecentAlert.sector} sector with ${mostRecentAlert.urgency.toLowerCase()} urgency`
    if (mostRecentAlert.exploitation) {
      rationale += " and observed exploitation"
    }
  } else if (finalScore >= 3) {
    rationale = `Elevated alert level for ${mostRecentAlert.sector} sector`
    if (mostRecentAlert.kev) {
      rationale += " with known exploited vulnerabilities"
    }
  } else {
    rationale = `Standard monitoring for ${mostRecentAlert.sector} sector`
  }

  return {
    score: finalScore,
    breakdown: {
      P: postureScore,
      X: exploitationScore,
      S: sectorMatchScore,
      U: urgencyScore,
      K: kevScore,
      C: criticalInfrastructureScore,
      A: alertTargetingScore,
      CSS: Number.parseFloat(computedSectorScore),
    },
    rationale,
  }
}
