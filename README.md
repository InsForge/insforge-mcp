<div align="center">
  <a href="https://insforge.dev">
    <img src="banner.png" alt="Insforge Banner">
  </a>
</div>

<div align="center">

[![MCP Badge](https://lobehub.com/badge/mcp/insforge-insforge-mcp)](https://lobehub.com/mcp/insforge-insforge-mcp)

</div>

# Insforge MCP Server

InsForge turns your coding agents into full-stack builders, letting them add backend features like auth, databases, file storage, serverless functions, and LLMs to your apps in seconds.

This repo is Model Context Protocol server for [Insforge](https://github.com/InsForge/insforge).

<a href="https://glama.ai/mcp/servers/@InsForge/insforge-mcp">
  <img width="380" height="200" src="https://glama.ai/mcp/servers/@InsForge/insforge-mcp/badge" alt="Insforge Server MCP server" />
</a>

## 📖 Documentation

Please visit the [main Insforge repository](https://github.com/InsForge/insforge) for:

- Installation and setup instructions
- Configuration guide
- Available tools and usage examples
- API documentation
- Contributing guidelines

## 🚀 Quick Start

### Automated Installation (Recommended)

Use the InsForge installer to automatically configure MCP for your client:

```bash
# Claude Code
npx @insforge/install --client claude-code --env API_KEY=your_api_key --env API_BASE_URL=http://localhost:7130

# Cursor
npx @insforge/install --client cursor --env API_KEY=your_api_key --env API_BASE_URL=http://localhost:7130

# Windsurf
npx @insforge/install --client windsurf --env API_KEY=your_api_key --env API_BASE_URL=http://localhost:7130

# Cline
npx @insforge/install --client cline --env API_KEY=your_api_key --env API_BASE_URL=http://localhost:7130

# Roo Code
npx @insforge/install --client roocode --env API_KEY=your_api_key --env API_BASE_URL=http://localhost:7130
# Trae
npx @insforge/install --client trae --env API_KEY=your_api_key --env API_BASE_URL=http://localhost:7130

# Install dev version for testing
npx @insforge/install --client cursor --env API_KEY=your_api_key --env API_BASE_URL=http://localhost:7130 --dev
```

Replace:
- `your_api_key` with your InsForge API key
- `http://localhost:7130` with your InsForge instance URL (optional, defaults to localhost:7130)

### Manual Installation

If you prefer to manually configure your MCP client, add this to your MCP settings file:

```json
{
  "mcpServers": {
    "insforge": {
      "command": "npx",
      "args": [
        "-y",
        "@insforge/mcp@latest"
      ],
      "env": {
        "API_KEY": "your_api_key",
        "API_BASE_URL": "http://localhost:7130"
      }
    }
  }
}
```

For detailed setup instructions, see the [Insforge Documentation](https://docs.insforge.dev).

## 🛠️ Development

If you are contributing to this project or running it locally:

```bash
# Install dependencies
npm install

# Run unit tests
npm run test

# Run linter (static analysis)
npm run lint

# Auto-format code
npm run format

# Build the package
npm run build
```

## 📄 License

Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

---

Part of the [Insforge](https://github.com/InsForge/insforge) project.
