// @mcpjam/inspector ≤1.4.2 漏洞模拟
// 文件：vulnerable_server.js
// 说明：模拟 CVE-2026-23744 的漏洞逻辑 - 无认证+命令注入+公网监听

const http = require('http');
const { exec, execFile, spawn } = require('child_process');

/**
 * 模拟 @mcpjam/inspector 的漏洞服务器
 * 特点：
 * 1. 监听所有接口（0.0.0.0）- 远程可访问
 * 2. /api/mcp/connect 接口无认证
 * 3. 直接执行用户传入的命令
 */

class VulnerableInspectorServer {
  constructor(port = 6274) {
    this.port = port;
    this.server = null;
  }

  /**
   * 处理 /api/mcp/connect 请求 - 存在漏洞
   * @param {http.IncomingMessage} req - 请求对象
   * @param {http.ServerResponse} res - 响应对象
   */
  handleConnectRequest(req, res) {
    let body = '';
    
    req.on('data', chunk => {
      body += chunk.toString();
    });

    req.on('end', () => {
      try {
        console.log(`[Vulnerable] Received request: ${body}`);
        
        // 🔴 漏洞点1：无任何认证，直接解析请求
        const data = JSON.parse(body);
        const { serverConfig, serverId } = data;
        
        // 🔴 漏洞点2：直接从用户输入获取命令和参数
        const { command, args = [], env = {} } = serverConfig || {};
        
        console.log(`[Vulnerable] Executing command: ${command} ${args.join(' ')}`);

        // 🔴 漏洞点3：无命令白名单，直接执行
        // 使用 execFile 执行用户指定的命令
        const child = execFile(command, args, { env }, (error, stdout, stderr) => {
          if (error) {
            console.error(`[Vulnerable] Execution error: ${error.message}`);
          } else {
            console.log(`[Vulnerable] stdout: ${stdout}`);
            console.error(`[Vulnerable] stderr: ${stderr}`);
          }
        });

        // 返回成功响应
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ 
          status: 'connected', 
          serverId: serverId || 'unknown',
          pid: child.pid 
        }));

      } catch (err) {
        console.error(`[Vulnerable] Error: ${err.message}`);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: err.message }));
      }
    });
  }

  /**
   * 启动服务器 - 监听所有接口
   */
  start() {
    this.server = http.createServer((req, res) => {
      console.log(`[Vulnerable] ${req.method} ${req.url}`);
      
      if (req.method === 'POST' && req.url === '/api/mcp/connect') {
        this.handleConnectRequest(req, res);
      } else {
        res.writeHead(404);
        res.end('Not found');
      }
    });

    // 🔴 漏洞点4：监听 0.0.0.0，远程可访问
    this.server.listen(this.port, '0.0.0.0', () => {
      console.log(`🔴 [VULNERABLE] @mcpjam/inspector mock server running on http://0.0.0.0:${this.port}`);
      console.log(`🔴 [VULNERABLE] 漏洞特征：`);
      console.log(`   - 监听 0.0.0.0 (远程可访问)`);
      console.log(`   - /api/mcp/connect 接口无认证`);
      console.log(`   - 命令注入漏洞 (CVE-2026-23744)`);
      console.log(`\n测试命令:`);
      console.log(`curl http://127.0.0.1:${this.port}/api/mcp/connect \\`);
      console.log(`  --header "Content-Type: application/json" \\`);
      console.log(`  --data "{\\"serverConfig\\":{\\"command\\":\\"cmd.exe\\",\\"args\\":[\\"/c\\",\\"calc\\"]},\\"serverId\\":\\"test\\"}"`);
    });
  }

  /**
   * 停止服务器
   */
  stop() {
    if (this.server) {
      this.server.close();
      console.log('[Vulnerable] Server stopped');
    }
  }
}

// 如果直接运行此文件，启动服务器
if (require.main === module) {
  const server = new VulnerableInspectorServer(6274);
  server.start();

  // 优雅关闭
  process.on('SIGINT', () => {
    server.stop();
    process.exit();
  });
}

module.exports = VulnerableInspectorServer;