# TraceGate

> 🛡️ Modern, high-performance load balancer built in TypeScript with advanced request tracing, SNI-based TLS, multi-domain routing, and a future-ready admin interface.

## ✨ Features

- 🔒 Automatic TLS via Let's Encrypt (multi-domain via SNI)
- 🌐 Reverse proxy with dynamic routing per hostname
- 📈 Advanced request tracing with unique trace IDs
- 🚦 HTTP → HTTPS redirection
- 📊 Structured logging using Pino
- 🖥️ Admin API and WAF rule engine (in progress)

## 🚀 Getting Started

### Requirements

- Node.js v18+
- Domains pointed to your server (ports 80 & 443 open)
- TLS certificates (Let's Encrypt-style) stored in `certs/{domain}/`

### Installation

```bash
git clone https://github.com/gmprestes/tracegate.git
cd tracegate
npm install
```

### Development

```bash
npm run dev
```

### Build and run in production

```bash
npm run build
npm start
```

## ⚙️ Route Configuration

Edit `src/config/routes.json` to map domains to backend services:

```json
{
  "example.com": { "target": "http://localhost:3001" },
  "api.tracegate.io": { "target": "http://localhost:4000" }
}
```

## 📁 Project Structure

```
src/
├── core/          # Main proxy logic
├── services/      # TLS manager, logger, etc.
├── config/        # Routes and domain mappings
├── api/           # Admin API (coming soon)
└── index.ts       # Cluster entry point
```

## 🧩 Coming Soon

- Admin dashboard (`/admin`) for visual config
- WAF rule engine with IP and UA filtering
- Rate limiting and IP blocking
- Plugin support
- Prometheus metrics integration

## 📜 License

Built with ❤️ by SIGE Cloud
