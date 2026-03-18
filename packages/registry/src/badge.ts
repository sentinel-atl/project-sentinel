/**
 * Badge SVG generator — produces shields.io-style trust badges.
 *
 * Badge formats:
 *   - Trust grade badge:  "Sentinel | A" (green)
 *   - Trust score badge:  "Trust Score | 87/100" (green)
 *   - Verified badge:     "Sentinel Verified | ✓" (green)
 *   - Not found badge:    "Sentinel | Not Found" (gray)
 */

// ─── Types ───────────────────────────────────────────────────────────

export type BadgeStyle = 'flat' | 'flat-square';

export interface BadgeOptions {
  /** Left label text */
  label?: string;
  /** Right value text */
  value: string;
  /** Color of the right side */
  color: string;
  /** Badge style */
  style?: BadgeStyle;
}

// ─── Color Mapping ───────────────────────────────────────────────────

const GRADE_COLORS: Record<string, string> = {
  A: '#4c1',     // bright green
  B: '#97ca00',  // yellow-green
  C: '#dfb317',  // yellow
  D: '#fe7d37',  // orange
  F: '#e05d44',  // red
};

function scoreColor(score: number): string {
  if (score >= 90) return GRADE_COLORS.A;
  if (score >= 75) return GRADE_COLORS.B;
  if (score >= 60) return GRADE_COLORS.C;
  if (score >= 40) return GRADE_COLORS.D;
  return GRADE_COLORS.F;
}

// ─── SVG Generator ───────────────────────────────────────────────────

function escapeXml(str: string): string {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function textWidth(text: string): number {
  // Approximate character widths for Verdana 11px
  return text.length * 6.5 + 10;
}

function renderBadge(options: BadgeOptions): string {
  const label = options.label ?? 'Sentinel';
  const { value, color } = options;
  const isSquare = options.style === 'flat-square';

  const labelWidth = textWidth(label);
  const valueWidth = textWidth(value);
  const totalWidth = labelWidth + valueWidth;
  const radius = isSquare ? 0 : 3;

  const escapedLabel = escapeXml(label);
  const escapedValue = escapeXml(value);

  return `<svg xmlns="http://www.w3.org/2000/svg" width="${totalWidth}" height="20" role="img" aria-label="${escapedLabel}: ${escapedValue}">
  <title>${escapedLabel}: ${escapedValue}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r">
    <rect width="${totalWidth}" height="20" rx="${radius}" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#r)">
    <rect width="${labelWidth}" height="20" fill="#555"/>
    <rect x="${labelWidth}" width="${valueWidth}" height="20" fill="${color}"/>
    <rect width="${totalWidth}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="11">
    <text aria-hidden="true" x="${labelWidth / 2}" y="15" fill="#010101" fill-opacity=".3">${escapedLabel}</text>
    <text x="${labelWidth / 2}" y="14">${escapedLabel}</text>
    <text aria-hidden="true" x="${labelWidth + valueWidth / 2}" y="15" fill="#010101" fill-opacity=".3">${escapedValue}</text>
    <text x="${labelWidth + valueWidth / 2}" y="14">${escapedValue}</text>
  </g>
</svg>`;
}

// ─── Public API ──────────────────────────────────────────────────────

/**
 * Generate a trust grade badge SVG.
 */
export function gradeBadge(grade: string, style?: BadgeStyle): string {
  return renderBadge({
    label: 'Sentinel',
    value: `Grade ${grade}`,
    color: GRADE_COLORS[grade] ?? '#9f9f9f',
    style,
  });
}

/**
 * Generate a trust score badge SVG.
 */
export function scoreBadge(score: number, style?: BadgeStyle): string {
  return renderBadge({
    label: 'Trust Score',
    value: `${score}/100`,
    color: scoreColor(score),
    style,
  });
}

/**
 * Generate a "Sentinel Verified" badge SVG.
 */
export function verifiedBadge(verified: boolean, style?: BadgeStyle): string {
  return renderBadge({
    label: 'Sentinel',
    value: verified ? 'Verified ✓' : 'Unverified',
    color: verified ? '#4c1' : '#9f9f9f',
    style,
  });
}

/**
 * Generate a "not found" badge SVG.
 */
export function notFoundBadge(style?: BadgeStyle): string {
  return renderBadge({
    label: 'Sentinel',
    value: 'Not Found',
    color: '#9f9f9f',
    style,
  });
}
