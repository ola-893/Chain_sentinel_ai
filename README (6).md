# Project Title

## Usage

### 🔗 Local Development with `@sei-protocol/sei-mcp-server`

If you're working with a locally cloned version of [`@sei-protocol/sei-mcp-server`](https://github.com/sei-protocol/sei-mcp-server) and want to link it for development, follow these steps:

1. In the root of the `sei-mcp-server` project:
   ```bash
   npm link
   ```

2. In the root of your project where you want to use the linked package:
   ```bash
   npm link @sei-protocol/sei-mcp-server
   ```

This will symlink your local MCP server package into your project so changes reflect without publishing.