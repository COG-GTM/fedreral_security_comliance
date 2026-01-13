# Playbook: Federal Agency Demo WebUI Builder

> Copy this entire file to your Devin Playbooks.

## Overview
Build and deploy a modern, interactive single-page demo website for early-stage meetings with US federal government executives. The site showcases Cognition AI's technical capabilities (Devin and Windsurf) by highlighting what has already been accomplished in the customer's repositories. The design follows the National Design Studio (NDS) aesthetic - dark themes, minimalist typography, and clean layouts that mirror NDStudio.gov and AmericaByDesign.gov.

## What's Needed From User
- **Target agency**: Which federal agency/department is being pitched (e.g., US Army, Navy, DHS, FAA)
- **Customer repos**: GitHub repositories where Devin has done work (PRs to showcase)
- **Jira project** (optional): Jira tickets showing planning work Devin completed
- **Call to action**: Desired next step (pilot program, briefing, demo, etc.)
- **Assets** (optional): Agency-specific logos or imagery

---

## Design System

### Color Palette (Required)
```css
/* Background colors */
--background: #0a0a0f;        /* Primary dark background */
--background-secondary: #111118;  /* Section alternating background */
--card: #18181b;              /* Card backgrounds */

/* Text colors */
--foreground: #fafafa;        /* Primary text */
--muted: #71717a;             /* Secondary/muted text */
--muted-foreground: #a1a1aa;  /* Tertiary text */

/* Border colors */
--border: #27272a;            /* Primary borders */
--border-secondary: #3f3f46;  /* Secondary borders */
--border-tertiary: #52525b;   /* Tertiary borders */

/* Cognition brand colors */
--devin-purple: #3969CA;      /* Primary brand */
--devin-green: #21C19A;       /* Success/accent */
--devin-blue: #0294DE;        /* Info/accent */
--accent: #6366f1;            /* Purple accent */
```

### Cognition Sprocket Monogram Pattern
Add this CSS for the signature Cognition branding on left/right sides:

```css
.monogram-left, .monogram-right {
  position: fixed;
  top: 0;
  bottom: 0;
  width: 280px;
  pointer-events: none;
  z-index: 2;
  overflow: hidden;
}

.monogram-left { left: 0; }
.monogram-right { right: 0; }

.monogram-pattern {
  position: absolute;
  top: -150px;
  left: -150px;
  right: -150px;
  bottom: -150px;
  background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='600' height='800' viewBox='0 0 600 800'%3E%3Cdefs%3E%3Cstyle%3E.hex %7B fill: %233969CA; %7D%3C/style%3E%3C/defs%3E%3Cg class='hex'%3E%3Cg transform='translate(180, 280) scale(4)'%3E%3Cpolygon points='30,0 42,7 42,21 30,28 18,21 18,7'/%3E%3Cpolygon points='12,14 24,21 24,35 12,42 0,35 0,21'/%3E%3Cpolygon points='48,14 60,21 60,35 48,42 36,35 36,21'/%3E%3Cpolygon points='30,28 42,35 42,49 30,56 18,49 18,35'/%3E%3Cpolygon points='12,42 24,49 24,63 12,70 0,63 0,49'/%3E%3Cpolygon points='48,42 60,49 60,63 48,70 36,63 36,49'/%3E%3Cpolygon points='30,56 42,63 42,77 30,84 18,77 18,63'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E");
  background-size: 600px 800px;
  background-repeat: repeat;
  opacity: 0.18;
  animation: fadePattern 12s ease-in-out infinite;
}

.monogram-left .monogram-pattern {
  mask-image: linear-gradient(to right, rgba(0,0,0,0.6) 0%, transparent 100%);
  -webkit-mask-image: linear-gradient(to right, rgba(0,0,0,0.6) 0%, transparent 100%);
}

.monogram-right .monogram-pattern {
  mask-image: linear-gradient(to left, rgba(0,0,0,0.6) 0%, transparent 100%);
  -webkit-mask-image: linear-gradient(to left, rgba(0,0,0,0.6) 0%, transparent 100%);
}

@keyframes fadePattern {
  0%, 100% { opacity: 0.18; }
  50% { opacity: 0.12; }
}
```

### Hero Glow Effect
Add this CSS for the signature glow behind hero content:

```css
.hero-glow-container {
  position: relative;
  padding: 4rem 0;
}

.hero-glow {
  position: absolute;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
  width: 90%;
  height: 140%;
  background: radial-gradient(
    ellipse at center,
    rgba(57, 105, 202, 0.20) 0%,
    rgba(33, 193, 154, 0.12) 25%,
    rgba(2, 148, 222, 0.08) 45%,
    transparent 65%
  );
  filter: blur(50px);
  pointer-events: none;
  z-index: 0;
  animation: pulseGlow 6s ease-in-out infinite;
}

@keyframes pulseGlow {
  0%, 100% { opacity: 1; transform: translate(-50%, -50%) scale(1); }
  50% { opacity: 0.7; transform: translate(-50%, -50%) scale(1.05); }
}
```

### Background Beams
Add animated gradient beams for visual depth:

```css
.beam {
  position: fixed;
  width: 400px;
  height: 400px;
  border-radius: 50%;
  filter: blur(100px);
  pointer-events: none;
  z-index: 1;
}

.beam-1 {
  background: rgba(57, 105, 202, 0.15);
  top: 20%;
  left: -10%;
  animation: floatBeam1 20s ease-in-out infinite;
}

.beam-2 {
  background: rgba(33, 193, 154, 0.12);
  bottom: 10%;
  left: 20%;
  animation: floatBeam2 25s ease-in-out infinite;
}

.beam-3 {
  background: rgba(2, 148, 222, 0.10);
  top: 40%;
  right: -5%;
  animation: floatBeam3 22s ease-in-out infinite;
}
```

### Grid Pattern Overlay
Add subtle grid lines for visual texture:

```css
.grid-pattern {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background-image: 
    linear-gradient(rgba(255,255,255,0.02) 1px, transparent 1px),
    linear-gradient(90deg, rgba(255,255,255,0.02) 1px, transparent 1px);
  background-size: 50px 50px;
  pointer-events: none;
  z-index: 1;
}
```

### US Flag (Black/White Minimalist)
Use this SVG for the government banner - NOT red/white:

```jsx
<svg width="20" height="14" viewBox="0 0 20 14" fill="none" xmlns="http://www.w3.org/2000/svg" className="opacity-60">
  <rect width="20" height="14" fill="#27272a"/>
  <rect width="8" height="7" fill="#3f3f46"/>
  <rect y="2" width="20" height="1" fill="#52525b"/>
  <rect y="4" width="20" height="1" fill="#52525b"/>
  <rect y="6" width="20" height="1" fill="#52525b"/>
  <rect y="8" width="20" height="1" fill="#52525b"/>
  <rect y="10" width="20" height="1" fill="#52525b"/>
  <rect y="12" width="20" height="1" fill="#52525b"/>
</svg>
```

### Accessibility
Always respect reduced motion preferences:

```css
@media (prefers-reduced-motion: reduce) {
  .monogram-pattern, .hero-glow, .beam, .beam-1, .beam-2, .beam-3 {
    animation: none;
  }
}
```

---

## Page Structure

### 1. Government Banner
```jsx
<div className="bg-[#0a0a0f] border-b border-[#27272a] py-2">
  <div className="max-w-7xl mx-auto px-6 flex items-center gap-3">
    {/* Black/white flag SVG */}
    <span className="text-xs text-[#71717a] tracking-widest uppercase">
      An Official Demo for the [AGENCY NAME]
    </span>
  </div>
</div>
```

### 2. Header
```jsx
<header className="border-b border-[#27272a] py-4">
  <div className="max-w-7xl mx-auto px-6 flex items-center justify-between">
    <div className="flex flex-col">
      <span className="text-sm font-medium tracking-wide">[AGENCY] MODERNIZATION INITIATIVE</span>
      <span className="text-xs text-[#71717a]">BY <span className="underline">COGNITION</span></span>
    </div>
    <Button className="rounded-full bg-white text-black hover:bg-gray-200 px-6" asChild>
      <a href="https://cognition.ai" target="_blank">Get Started</a>
    </Button>
  </div>
</header>
```

### 3. Hero Section
- Large headline (text-5xl to text-7xl)
- Underline the agency name
- Info grid with 3 columns: Mission, Built By (Cognition AI), Status
- Wrap in hero-glow-container with hero-glow div

### 4. Executive Summary (3 Cards)
- **What This Is**: AI-powered software engineering description
- **Why Now**: Link to federal AI mandates (AI.gov, America's AI Action Plan, State.gov AI, War Dept AI Strategy)
- **The Why**: Focus on modernizing the warfighter's software development cycle

### 5. Proof Section
- Cards showing actual PRs from customer repos
- Include repo name, PR title, description, capabilities, stats
- Link to actual GitHub PRs

### 6. Technical Capabilities (Radix Tabs)
- Security & Compliance tab
- Development Velocity tab
- Planning & Architecture tab

### 7. STIG & NIST 800-53 Compliance
- Link to federal security compliance repo
- Show STIG control IDs (V-220629, V-220631, V-220633, V-220635)
- Show corresponding NIST controls

### 8. Cognition AI Platform Section
- Title: "Cognition AI Platform"
- Subtitle: "The world's first AI software engineer + agentic IDE"
- Mention FedRAMP compliance, SOC 2 Type II, air-gapped deployment
- Link to windsurf.com/enterprise/government
- Two cards: Devin and Windsurf

### 9. Implementation Roadmap
- 3 phases: Pilot, Rollout, Governance
- NO specific timelines (just Phase 1, Phase 2, Phase 3)
- Bullet points for each phase

### 10. Call to Action
- All buttons must link to actual URLs
- Schedule Briefing -> cognition.ai/contact
- View the Code -> GitHub repo
- Start Pilot -> cognition.ai

### 11. Footer
```jsx
<footer className="border-t border-[#27272a] py-8">
  <div className="max-w-7xl mx-auto px-6">
    <div className="flex flex-col md:flex-row items-center justify-between gap-4">
      <div className="flex items-center gap-3">
        {/* Black/white flag SVG */}
        <span className="text-sm text-[#71717a]">
          An Official Demo for the [AGENCY NAME]
        </span>
      </div>
      <div className="text-sm text-[#71717a]">
        <span className="text-white">Cognition AI Platform</span> - The world's first AI software engineer + agentic IDE
      </div>
    </div>
  </div>
</footer>
```

---

## Project Setup

```bash
npx create-next-app@latest [agency]-demo --typescript --tailwind --app --src-dir
cd [agency]-demo
npm install @radix-ui/react-tabs framer-motion lucide-react
npx shadcn@latest init
npx shadcn@latest add card button badge separator
```

### next.config.ts (for static export)
```typescript
import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: 'export',
  images: {
    unoptimized: true,
  },
};

export default nextConfig;
```

---

## Deployment

1. Build locally: `npm run build`
2. Deploy using: `<deploy_frontend dir="[project]/out" />`
3. Share the live URL with the user

---

## Forbidden Actions

- Do NOT use red/white for the US flag - must be black/white/gray
- Do NOT skip the Cognition sprocket monogram pattern
- Do NOT skip the hero glow effect
- Do NOT skip the background beams and grid pattern
- Do NOT use specific timelines in roadmap phases (no "90-day", "12-18 month")
- Do NOT leave CTA buttons without links
- Do NOT use "Built By: Cognition AI + Devin" - just "Cognition AI"
- Do NOT include "Tech Stack" in the info grid
- Do NOT include "How Devin Works" accordion - keep it simple
- Do NOT deviate from the NDS dark theme aesthetic

---

## Reference Links

- NDStudio.gov: https://ndstudio.gov/posts
- Federal Security Compliance: https://github.com/COG-GTM/fedreral_security_comliance
- Windsurf Government: https://windsurf.com/enterprise/government
- War Dept AI Strategy: https://www.war.gov/News/Releases/Release/Article/4376420/war-department-launches-ai-acceleration-strategy-to-secure-american-military-ai/
- America's AI Action Plan: https://www.whitehouse.gov/wp-content/uploads/2025/07/Americas-AI-Action-Plan.pdf
- AI.gov: https://ai.gov
- State.gov AI: https://www.state.gov/artificial-intelligence/

---

## Example Deployment

US Army Demo: https://army-cognition-demo-8hbvv176.devinapps.com
