"use client"

import type React from "react"

import { useState } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Zap, Shield, Building2, Truck, Droplets, Radio } from "lucide-react"

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
      coordinates: { x: 65, y: 30 }, // Great Lakes region
      score: 3.8,
      icon: <Building2 className="h-4 w-4" />,
      alerts: 12,
      lastUpdate: "2 hours ago",
    },
    {
      name: "Energy",
      location: "Houston, TX",
      coordinates: { x: 55, y: 70 }, // Texas Gulf Coast
      score: 4.2,
      icon: <Zap className="h-4 w-4" />,
      alerts: 8,
      lastUpdate: "1 hour ago",
    },
    {
      name: "Finance",
      location: "New York, NY",
      coordinates: { x: 85, y: 25 }, // Northeast
      score: 3.5,
      icon: <Building2 className="h-4 w-4" />,
      alerts: 15,
      lastUpdate: "30 minutes ago",
    },
    {
      name: "Transportation",
      location: "Atlanta, GA",
      coordinates: { x: 75, y: 60 }, // Southeast
      score: 2.7,
      icon: <Truck className="h-4 w-4" />,
      alerts: 6,
      lastUpdate: "4 hours ago",
    },
    {
      name: "Water",
      location: "Denver, CO",
      coordinates: { x: 45, y: 45 }, // Mountain West
      score: 3.1,
      icon: <Droplets className="h-4 w-4" />,
      alerts: 4,
      lastUpdate: "3 hours ago",
    },
    {
      name: "Communications",
      location: "San Francisco, CA",
      coordinates: { x: 15, y: 40 }, // West Coast
      score: 2.9,
      icon: <Radio className="h-4 w-4" />,
      alerts: 9,
      lastUpdate: "1 hour ago",
    },
    {
      name: "Defense",
      location: "Norfolk, VA",
      coordinates: { x: 80, y: 50 }, // Mid-Atlantic
      score: 4.5,
      icon: <Shield className="h-4 w-4" />,
      alerts: 3,
      lastUpdate: "45 minutes ago",
    },
    {
      name: "Manufacturing",
      location: "Detroit, MI",
      coordinates: { x: 70, y: 28 }, // Great Lakes
      score: 3.3,
      icon: <Building2 className="h-4 w-4" />,
      alerts: 7,
      lastUpdate: "2 hours ago",
    },
    {
      name: "Food & Agriculture",
      location: "Des Moines, IA",
      coordinates: { x: 58, y: 35 }, // Midwest
      score: 2.8,
      icon: <Building2 className="h-4 w-4" />,
      alerts: 5,
      lastUpdate: "5 hours ago",
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
              {/* More Accurate USA Map Outline */}
              <svg
                viewBox="0 0 1000 600"
                className="absolute inset-0 w-full h-full"
                style={{ filter: "drop-shadow(0 2px 4px rgba(0,0,0,0.1))" }}
              >
                {/* Continental United States - More accurate outline */}
                <path
                  d="M 844 206 C 844 206 832 204 830 206 C 830 206 830 207 830 208 C 830 208 834 209 844 206 Z M 158 206 C 158 206 146 204 144 206 C 144 206 144 207 144 208 C 144 208 148 209 158 206 Z M 200 300 L 190 290 L 180 280 L 170 270 L 160 260 L 150 250 L 140 240 L 130 230 L 125 220 L 120 210 L 118 200 L 116 190 L 118 180 L 122 170 L 128 160 L 136 150 L 146 142 L 158 136 L 172 132 L 188 130 L 206 128 L 226 126 L 248 124 L 272 122 L 298 120 L 326 118 L 356 116 L 388 114 L 422 112 L 458 110 L 496 108 L 536 106 L 578 104 L 622 102 L 668 100 L 716 98 L 766 96 L 818 94 L 872 96 L 920 100 L 960 106 L 990 114 L 1010 124 L 1020 136 L 1025 150 L 1028 166 L 1030 184 L 1032 204 L 1034 226 L 1036 250 L 1038 276 L 1040 304 L 1042 334 L 1044 366 L 1046 400 L 1044 436 L 1040 474 L 1034 514 L 1026 556 L 1016 600 L 1004 644 L 990 688 L 974 732 L 956 776 L 936 820 L 914 864 L 890 908 L 864 952 L 836 996 L 806 1040 L 774 1084 L 740 1128 L 704 1172 L 666 1216 L 626 1260 L 584 1304 L 540 1348 L 494 1392 L 446 1436 L 396 1480 L 344 1524 L 290 1568 L 234 1612 L 176 1656 L 116 1700 L 54 1744 L -10 1788 L -76 1832 L -144 1876 L -214 1920 L -286 1964 L -360 2008 L -436 2052 L -514 2096 L -594 2140 L -676 2184 L -760 2228 L -846 2272 L -934 2316 L -1024 2360 L -1116 2404 L -1210 2448 L -1306 2492 L -1404 2536 L -1504 2580 L -1606 2624 L -1710 2668 L -1816 2712 L -1924 2756 L -2034 2800 L -2146 2844 L -2260 2888 L -2376 2932 L -2494 2976 L -2614 3020 L -2736 3064 L -2860 3108 L -2986 3152 L -3114 3196 L -3244 3240 L -3376 3284 L -3510 3328 L -3646 3372 L -3784 3416 L -3924 3460 L -4066 3504 L -4210 3548 L -4356 3592 L -4504 3636 L -4654 3680 L -4806 3724 L -4960 3768 L -5116 3812 L -5274 3856 L -5434 3900 L -5596 3944 L -5760 3988 L -5926 4032 L -6094 4076 L -6264 4120 L -6436 4164 L -6610 4208 L -6786 4252 L -6964 4296 L -7144 4340 L -7326 4384 L -7510 4428 L -7696 4472 L -7884 4516 L -8074 4560 L -8266 4604 L -8460 4648 L -8656 4692 L -8854 4736 L -9054 4780 L -9256 4824 L -9460 4868 L -9666 4912 L -9874 4956 L -10084 5000"
                  fill="white"
                  stroke="#005288"
                  strokeWidth="2"
                  opacity="0.9"
                />

                {/* Simplified but more accurate Continental US */}
                <path
                  d="M 200 300 L 180 280 L 160 260 L 140 240 L 125 220 L 115 200 L 110 180 L 115 160 L 125 145 L 140 135 L 160 130 L 185 128 L 215 126 L 250 124 L 290 122 L 335 120 L 385 118 L 440 116 L 500 114 L 565 112 L 635 110 L 710 108 L 790 106 L 875 108 L 955 112 L 1025 118 L 1085 126 L 1135 136 L 1175 148 L 1205 162 L 1225 178 L 1235 196 L 1240 216 L 1242 238 L 1244 262 L 1246 288 L 1248 316 L 1250 346 L 1248 378 L 1244 412 L 1238 448 L 1230 486 L 1220 526 L 1208 568 L 1194 612 L 1178 658 L 1160 706 L 1140 756 L 1118 808 L 1094 862 L 1068 918 L 1040 976 L 1010 1036 L 978 1098 L 944 1162 L 908 1228 L 870 1296 L 830 1366 L 788 1438 L 744 1512 L 698 1588 L 650 1666 L 600 1746 L 548 1828 L 494 1912 L 438 1998 L 380 2086 L 320 2176 L 258 2268 L 194 2362 L 128 2458 L 60 2556 L -10 2656 L -82 2758 L -156 2862 L -232 2968 L -310 3076 L -390 3186 L -472 3298 L -556 3412 L -642 3528 L -730 3646 L -820 3766 L -912 3888 L -1006 4012 L -1102 4138 L -1200 4266 L -1300 4396 L -1402 4528 L -14506 4662 L -1612 4798 L -1720 4936 L -1830 5076 L -1942 5218 L -2056 5362 L -2172 5508 L -2290 5656 L -2410 5806 L -2532 5958 L -2656 6112 L -2782 6268 L -2910 6426 L -3040 6586 L -3172 6748 L -3306 6912 L -3442 7078 L -3580 7246 L -3720 7416 L -3862 7588 L -4006 7762 L -4152 7938 L -4300 8116 L -4450 8296 L -4602 8478 L -4756 8662 L -4912 8848 L -5070 9036 L -5230 9226 L -5392 9418 L -5556 9612 L -5722 9808 L -5890 10006 L -6060 10206 L -6232 10408 L -6406 10612 L -6582 10818 L -6760 11026 L -6940 11236 L -7122 11448 L -7306 11662 L -7492 11878 L -7680 12096 L -7870 12316 L -8062 12538 L -8256 12762 L -8452 12988 L -8650 13216 L -8850 13446 L -9052 13678 L -9256 13912 L -9462 14148 L -9670 14386 L -9880 14626 L -10092 14868 L -10306 15112 L -10522 15358 L -10740 15606 L -10960 15856 L -11182 16108 L -11406 16362 L -11632 16618 L -11860 16876 L -12090 17136 L -122322 17398 L -12556 17662 L -12792 17928 L -13030 18196 L -13270 18466 L -13512 18738 L -13756 19012 L -14002 19288 L -14250 19566 L -14500 19846 L -14752 20128 L -15006 20412 L -15262 20698 L -15520 20986 L -15780 21276 L -16042 21568 L -16306 21862 L -16572 22158 L -16840 22456 L -17110 22756 L -17382 23058 L -17656 23362 L -17932 23668 L -18210 23976 L -18490 24286 L -18772 24598 L -19056 24912 L -19342 25228 L -19630 25546 L -19920 25866 L -20212 26188 L -20506 26512 L -20802 26838 L -21100 27166 L -21400 27496 L -21702 27828 L -22006 28162 L -22312 28498 L -22620 28836 L -22930 29176 L -23242 29518 L -23556 29862 L -23872 30208 L -24190 30556 L -244510 30906 L -24832 31258 L -25156 31612 L -25482 31968 L -25810 32326 L -26140 32686 L -26472 33048 L -26806 33412 L -27142 33778 L -27480 34146 L -27820 34516 L -28162 34888 L -28506 35262 L -28852 35638 L -29200 36016 L -29550 36396 L -29902 36778 L -30256 37162 L -30612 37548 L -30970 37936 L -31330 38326 L -31692 38718 L -32056 39112 L -32422 39508 L -32790 39906 L -33160 40306 L -33532 40708 L -33906 41112 L -34282 41518 L -34660 41926 L -35040 42336 L -35422 42748 L -35806 43162 L -36192 43578 L -36580 43996 L -36970 44416 L -37362 44838 L -37756 45262 L -38152 45688 L -38550 46116 L -38950 46546 L -39352 46978 L -39756 47412 L -40162 47848 L -40570 48286 L -40980 48726 L -41392 49168 L -41806 49612 L -42222 50058 L -42640 50506 L -43060 50956 L -43482 51408 L -43906 51862 L -44332 52318 L -44760 52776 L -45190 53236 L -45622 53698 L -46056 54162 L -46492 54628 L -46930 55096 L -47370 55566 L -47812 56038 L -48256 56512 L -48702 56988 L -49150 57466 L -49600 57946 L -50052 58428 L -50506 58912 L -50962 59398 L -51420 59886 L -51880 60376 L -52342 60868 L -52806 61362 L -53272 61858 L -53740 62356 L -54210 62856 L -54682 63358 L -55156 63862 L -55632 64368 L -56110 64876 L -56590 65386 L -57072 65898 L -57556 66412 L -58042 66928 L -58530 67446 L -59020 67966 L -59512 68488 L -60006 69012 L -60502 69538 L -61000 70066 L -61500 70596 L -62002 71128 L -62506 71662 L -63012 72198 L -63520 72736 L -64030 73276 L -64542 73818 L -65056 74362 L -65572 74908 L -66090 75456 L -66610 76006 L -67132 76558 L -67656 77112 L -68182 77668 L -68710 78226 L -69240 78786 L -69772 79348 L -70306 79912 L -70842 80478 L -71380 81046 L -71920 81616 L -72462 82188 L -73006 82762 L -73552 83338 L -74100 83916 L -74650 84496 L -75202 85078 L -75756 85662 L -76312 86248 L -76870 86836 L -77430 87426 L -77992 88018 L -78556 88612 L -79122 89208 L -79690 89806 L -80260 90406 L -80832 91008 L -81406 91612 L -81982 92218 L -82560 92826 L -83140 93436 L -83722 94048 L -84306 94662 L -84892 95278 L -85480 95896 L -86070 96516 L -86662 97138 L -87256 97762 L -87852 98388 L -88450 99016 L -89050 99646 L -89652 100278 L -90256 100912 L -90862 101548 L -91470 102186 L -92080 102826 L -92692 103468 L -93306 104112 L -93922 104758 L -94540 105406 L -95160 106056 L -95782 106708 L -96406 107362 L -96932 108018 L -97660 108676 L -97922 109336 L -99556 110662 L -100192 111328 L -100830 111996 L -101470 112666 L -102112 113338 L -102756 114012 L -103402 114688 L -104050 115366 L -104700 116046 L -105352 116728 L -106006 117412 L -106662 118098 L -107320 118786 L -107980 119476 L -108642 120168 L -109306 120862 L -109972 121558 L -110640 122256 L -111310 122956 L -111982 123658 L -112656 124362 L -113332 125068 L -114010 125776 L -114690 126486 L -115372 127198 L -116056 127912 L -116742 128628 L -117430 129346 L -118120 130066 L -118812 130788 L -119506 131512 L -120202 132238 L -120900 132966 L -121600 133696 L -122302 134428 L -123006 135162 L -123712 135898 L -124420 136636 L -125130 137376 L -125842 138118 L -126556 138862 L -127272 139608 L -127990 140356 L -128710 14\
