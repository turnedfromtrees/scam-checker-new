# Is This Email a Scam?

A static web tool that analyzes email text for common scam patterns and red flags.

## Features

- **Pattern Detection**: Identifies 50+ scam indicators across 7 categories
- **Risk Assessment**: Provides HIGH/MEDIUM/LOW/UNABLE TO DETERMINE ratings
- **Educational**: Scam library with real-world examples
- **Resources**: Links to reporting agencies and recovery steps
- **Privacy-First**: All analysis happens client-side, no data sent anywhere

## Tech Stack

- Pure HTML, CSS, JavaScript (no frameworks)
- No backend required
- Deployable to any static hosting (Cloudflare Pages, GitHub Pages, Netlify)

## File Structure

```
scam-checker/
├── index.html          # Main checker tool
├── library.html        # Scam examples library
├── resources.html      # Reporting & resources
├── test.html           # Testing interface
├── css/
│   └── styles.css      # All styles
├── js/
│   ├── detector.js     # Core detection logic
│   └── app.js          # UI interactions
└── README.md
```

## Detection Categories

1. **Urgency Language** - "act now", "immediate", "limited time", etc.
2. **Suspicious Links** - IP addresses, URL shorteners, suspicious TLDs
3. **Suspicious Requests** - Gift cards, wire transfers, passwords, remote access
4. **Sender Spoofing** - Misspelled domains, suspicious sender patterns
5. **Threatening Language** - Legal action, arrest, account suspension
6. **Emotional Manipulation** - Lottery wins, romance, inheritance
7. **Grammar Issues** - Common scam phrasing patterns

## Running Locally

```bash
# Option 1: Python
cd scam-checker
python3 -m http.server 8000
# Open http://localhost:8000

# Option 2: Node.js
npx serve .
# Open the URL shown

# Option 3: Open directly
# Just open index.html in a browser (some features may be limited)
```

## Deploying to Cloudflare Pages

1. Push to a Git repository
2. Log into Cloudflare Dashboard
3. Go to Workers & Pages > Create application > Pages
4. Connect your repository
5. Build settings: No build command needed (static site)
6. Output directory: `/` (root)

## Testing

Open `test.html` in a browser to test with pre-loaded scam samples, or run:

```bash
node test-detector.js
```

## Disclaimer

⚠️ This tool provides guidance, not guarantees. Scammers evolve constantly. When in doubt, contact the organization directly using official contact information. This is not financial or legal advice.

## License

MIT License - Free to use, modify, and distribute.