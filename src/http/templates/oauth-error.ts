/**
 * OAuth Error Page HTML Template
 *
 * The OAuth authorize endpoint is reached by a browser navigation, not by the
 * MCP client's own fetch — so when it fails, the only party who can see the
 * response is the person staring at the tab. A JSON error body tells them
 * nothing they can act on. This page tells them what to do instead.
 */

export interface OAuthErrorPageOptions {
  heading: string;
  message: string;
  /**
   * Optional literal(s) the user should run or check, rendered as code.
   *
   * A list as well as a string because a repair is sometimes a sequence, and
   * joining commands with a newline inside one inline <code> collapses them
   * into a single unrunnable line.
   */
  action?: string | string[];
}

export function renderOAuthErrorPage(options: OAuthErrorPageOptions): string {
  const { heading, message, action } = options;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <title>${escapeHtml(heading)} - InsForge MCP</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Manrope:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      font-family: 'Manrope', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #0F0F0F;
      color: #e5e5e5;
      min-height: 100vh;
      padding: 60px 20px;
      display: flex;
      align-items: center;
      justify-content: center;
      position: relative;
    }

    body::before {
      content: '';
      position: fixed;
      inset: 0;
      background-image: radial-gradient(circle, rgba(255,255,255,0.08) 1px, transparent 1px);
      background-size: 24px 24px;
      pointer-events: none;
    }

    .card {
      position: relative;
      width: 100%;
      max-width: 560px;
      background: linear-gradient(135deg, #1C1C1C 0%, #171717 100%);
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 16px;
      padding: 40px;
    }

    h1 {
      font-size: 22px;
      font-weight: 700;
      margin-bottom: 14px;
      color: #ffffff;
    }

    p {
      font-size: 15px;
      line-height: 1.6;
      color: rgba(255, 255, 255, 0.66);
    }

    code {
      display: block;
      margin-top: 24px;
      padding: 14px 16px;
      font-family: 'SF Mono', Monaco, 'Cascadia Code', monospace;
      font-size: 13px;
      color: #6EE7B7;
      background: rgba(110, 231, 183, 0.1);
      border: 1px solid rgba(110, 231, 183, 0.2);
      border-radius: 10px;
      word-break: break-all;
    }
  </style>
</head>
<body>
  <div class="card">
    <h1>${escapeHtml(heading)}</h1>
    <p>${escapeHtml(message)}</p>
    ${(action ? (Array.isArray(action) ? action : [action]) : [])
      .map((line) => `<code>${escapeHtml(line)}</code>`)
      .join('\n    ')}
  </div>
</body>
</html>`;
}

/**
 * Escape, and survive a value that is not a string.
 *
 * The type says string and the DEPLOYED build proved that is a claim rather
 * than a fact. `?error=x&error_description=a&error_description=b` gives express
 * an array, the callback forwards it with a cast, and this function's
 * `.replace` threw — so the page rendered express's own error instead: a stack
 * trace with absolute paths and the dependency tree, to anyone who crafts that
 * URL, unauthenticated. Max found it live on the slug.
 *
 * `humanFormOf` now normalises that field, which closes the known route. This
 * coercion is here because this function is the one that OWNS every
 * browser-visible field and it trusted its input — the layer below where anyone
 * was looking. Fixing only the caller I know about is how the same crash
 * survives in the next field someone adds.
 *
 * `String(...)` rather than a throw or an empty string: a page that renders
 * "a,b" is ugly and harmless, and the failure this replaces was neither.
 */
function escapeHtml(text: string): string {
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
