// main.ts - Deno Deploy Edge Network Proxy with Message Audit and WxPusher

interface ApiSite {
  path: string;
  baseurl: string;
  ratelimit?: number;
  MaxAuditNum?: number;
  BanTimeInterval?: number;
  BanTimeDuration?: number;
  "msg-audit-config"?: {
    AuditPath?: string;
    AuditParameter?: string;
  };
}

interface AuditResponse {
  status: string;
  verdict: string;
  rule_id?: string;
  data?: {
    size?: string;
    today_scan_total?: string;
    match_string?: string;
    descr?: string;
    EngineType?: string;
    "Engine Version"?: string;
  };
}

interface BanRecord {
  count: number;
  firstViolationTime: number;
  bannedUntil?: number;
}

// WxPusher configuration from environment
const WXPUSHER_API_URL = Deno.env.get("WXPUSHER_API_URL") || "https://wxpusher.zjiecode.com/api/send/message";
const WXPUSHER_APP_TOKEN = Deno.env.get("WXPUSHER_APP_TOKEN") || "AT_xxx"; // 需要设置实际的token
const WXPUSHER_UID = Deno.env.get("WXPUSHER_UID") || "UID_xxx"; // 需要设置实际的UID

// Default API sites configuration
const DEFAULT_API_SITES: ApiSite[] = [
  {
    path: "openai",
    baseurl: "https://api.openai.com",
    ratelimit: 0,
    MaxAuditNum: 12,
    BanTimeInterval: 60,
    BanTimeDuration: 60,
    "msg-audit-config": {
      AuditPath: "/v1/chat/completions",
      AuditParameter: "messages"
    }
  }
];

// Constants
const DEFAULT_RATE_LIMIT = 120;
const DEFAULT_AUDIT_PATH = "/v1/chat/completions";
const DEFAULT_AUDIT_PARAMETER = "messages";
const DEFAULT_MAX_AUDIT_NUM = 12;
const DEFAULT_BAN_TIME_INTERVAL = 60; // minutes
const DEFAULT_BAN_TIME_DURATION = 60; // minutes
const RATE_LIMIT_WINDOW = 60000; // 1 minute in milliseconds
const AUDIT_API_BASE = "https://apiv1.iminbk.com";

// Get API sites configuration from environment or use default
function getApiSites(): ApiSite[] {
  const envSites = Deno.env.get("API_SITES");
  if (envSites) {
    try {
      return JSON.parse(envSites);
    } catch (e) {
      console.error("Failed to parse api-sites from environment:", e);
    }
  }
  return DEFAULT_API_SITES;
}

// Check if this is a test request
function isTestRequest(body: any, auditParameter: string): boolean {
  try {
    const messages = body[auditParameter];
    if (!Array.isArray(messages) || messages.length !== 1) return false;
    
    const msg = messages[0];
    return msg.role === "user" && msg.content === "hi";
  } catch {
    return false;
  }
}

// Create a mock response for test requests
function createMockResponse(stream: boolean, model: string): Response {
  const responseContent = "Hello, how can I help you today?";
  
  if (stream) {
    // Create streaming response
    const encoder = new TextEncoder();
    const streamData = [
      `data: {"id":"chatcmpl-test","object":"chat.completion.chunk","created":${Math.floor(Date.now()/1000)},"model":"${model}","choices":[{"index":0,"delta":{"role":"assistant"},"finish_reason":null}]}\n\n`,
      `data: {"id":"chatcmpl-test","object":"chat.completion.chunk","created":${Math.floor(Date.now()/1000)},"model":"${model}","choices":[{"index":0,"delta":{"content":"${responseContent}"},"finish_reason":null}]}\n\n`,
      `data: {"id":"chatcmpl-test","object":"chat.completion.chunk","created":${Math.floor(Date.now()/1000)},"model":"${model}","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}\n\n`,
      `data: [DONE]\n\n`
    ];
    
    const stream = new ReadableStream({
      start(controller) {
        for (const chunk of streamData) {
          controller.enqueue(encoder.encode(chunk));
        }
        controller.close();
      }
    });
    
    return new Response(stream, {
      headers: {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive"
      }
    });
  } else {
    // Non-streaming response
    const response = {
      id: "chatcmpl-test",
      object: "chat.completion",
      created: Math.floor(Date.now() / 1000),
      model: model,
      choices: [{
        index: 0,
        message: {
          role: "assistant",
          content: responseContent
        },
        finish_reason: "stop"
      }],
      usage: {
        prompt_tokens: 10,
        completion_tokens: 20,
        total_tokens: 30
      }
    };
    
    return new Response(JSON.stringify(response), {
      headers: { "Content-Type": "application/json" }
    });
  }
}

// Format messages for HTML display
function formatMessagesForHtml(body: any, auditParameter: string): string {
  try {
    const messages = body[auditParameter];
    if (!Array.isArray(messages)) return "";
    
    return messages
      .map((msg: any) => {
        const role = msg.role || "unknown";
        const content = msg.content || "";
        return `<p><strong>${role}:</strong> ${content.replace(/</g, "&lt;").replace(/>/g, "&gt;")}</p>`;
      })
      .join("<br/>");
  } catch {
    return "";
  }
}

// Send WxPusher notification
async function sendWxPusherNotification(
  apiUrl: string,
  token: string,
  model: string,
  auditResult: AuditResponse,
  formattedMessages: string,
  baseurl: string
): Promise<void> {
  try {
    // Prepare summary (max 20 chars)
    let summary = `站点：${baseurl}触发审核告警`;
    if (summary.length > 20) {
      summary = summary.substring(0, 20);
    }
    
    // Prepare content, if need protect token: ${token ? token.substring(0, 10) + "..." : "无"}
    const content = `
      <h2 style="color:red;">触发道德审查</h2>
      <p><strong>API地址：</strong>${apiUrl}</p>
      <p><strong>令牌：</strong>${token ? token : "无"}</p>
      <p><strong>模型：</strong>${model || "未指定"}</p>
      <p><strong>审核结果：</strong>${auditResult.data?.descr || "违规内容"}</p>
      <h3>违规内容：</h3>
      ${formattedMessages}
    `;
    
    const payload = {
      appToken: WXPUSHER_APP_TOKEN,
      content: content,
      summary: summary,
      contentType: 2,
      uids: [WXPUSHER_UID],
      verifyPayType: 0
    };
    
    const response = await fetch(WXPUSHER_API_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(payload)
    });
    
    if (!response.ok) {
      console.error("WxPusher notification failed:", await response.text());
    }
  } catch (e) {
    console.error("Error sending WxPusher notification:", e);
  }
}

// Extract and format messages for audit
function extractMessagesForAudit(body: any, auditParameter: string): string {
  try {
    const messages = body[auditParameter];
    if (!Array.isArray(messages)) return "";
    
    const formatted = messages
      .map((msg: any) => {
        if (typeof msg.content === "string") {
          const cleaned = msg.content
            .replace(/[\n\r\t]+/g, " ")
            .replace(/\s+/g, " ")
            .trim()
            .slice(0, 500);
          return `${msg.role}:${cleaned}`;
        }
        return "";
      })
      .filter(Boolean)
      .join(",");
    
    return formatted;
  } catch (e) {
    console.error("Error extracting messages:", e);
    return "";
  }
}

// Perform message audit
async function auditMessage(message: string): Promise<AuditResponse | null> {
  try {
    let auditUrl: string;
    
    if (/[^\x00-\x7F]/.test(message) || message.length > 200) {
      const base64Message = btoa(unescape(encodeURIComponent(message)));
      auditUrl = `${AUDIT_API_BASE}/base64?word=${base64Message}`;
    } else {
      auditUrl = `${AUDIT_API_BASE}/?word=${encodeURIComponent(message)}`;
    }
    
    const response = await fetch(auditUrl, {
      method: "GET",
      headers: {
        "Accept": "application/json"
      }
    });
    
    if (!response.ok) {
      console.error(`Audit API returned status ${response.status}`);
      return null;
    }
    
    return await response.json();
  } catch (e) {
    console.error("Audit API error:", e);
    return null;
  }
}

// Check and update ban status
async function checkAndUpdateBanStatus(
  baseurl: string,
  token: string,
  maxAuditNum: number,
  banTimeInterval: number,
  banTimeDuration: number
): Promise<{ isBanned: boolean; violationCount: number }> {
  if (maxAuditNum === 0) {
    return { isBanned: false, violationCount: 0 };
  }
  
  const kv = await Deno.openKv();
  const now = Date.now();
  const banKey = ["ban", baseurl, token];
  
  try {
    // Clean up expired ban records
    const iter = kv.list({ prefix: ["ban"] });
    for await (const entry of iter) {
      const record = entry.value as BanRecord;
      if (record.bannedUntil && record.bannedUntil < now) {
        await kv.delete(entry.key);
      } else if (!record.bannedUntil && 
                 now - record.firstViolationTime > banTimeInterval * 60 * 1000) {
        // Reset count if interval has passed
        await kv.delete(entry.key);
      }
    }
    
    // Get current ban record
    const entry = await kv.get<BanRecord>(banKey);
    let record = entry.value;
    
    if (record) {
      // Check if currently banned
      if (record.bannedUntil && record.bannedUntil > now) {
        return { isBanned: true, violationCount: record.count };
      }
      
      // Check if we need to reset the count (interval passed)
      if (now - record.firstViolationTime > banTimeInterval * 60 * 1000) {
        record = null;
      }
    }
    
    if (!record) {
      // Create new record
      record = {
        count: 1,
        firstViolationTime: now
      };
    } else {
      // Increment count
      record.count++;
    }
    
    // Check if should ban
    if (record.count >= maxAuditNum) {
      record.bannedUntil = now + (banTimeDuration * 60 * 1000);
      await kv.set(banKey, record);
      return { isBanned: true, violationCount: record.count };
    }
    
    // Update record
    await kv.set(banKey, record);
    return { isBanned: false, violationCount: record.count };
    
  } catch (e) {
    console.error("Ban status check error:", e);
    return { isBanned: false, violationCount: 0 };
  }
}

// Check if token is currently banned
async function isTokenBanned(baseurl: string, token: string): Promise<{ banned: boolean; remainingMinutes?: number }> {
  const kv = await Deno.openKv();
  const now = Date.now();
  const banKey = ["ban", baseurl, token];
  
  try {
    const entry = await kv.get<BanRecord>(banKey);
    if (entry.value && entry.value.bannedUntil && entry.value.bannedUntil > now) {
      const remainingMinutes = Math.ceil((entry.value.bannedUntil - now) / 60000);
      return { banned: true, remainingMinutes };
    }
    return { banned: false };
  } catch {
    return { banned: false };
  }
}

// Rate limiting using Deno KV
async function checkRateLimit(baseurl: string, limit: number): Promise<boolean> {
  if (limit === 0) return true;
  
  const kv = await Deno.openKv();
  const now = Date.now();
  const key = ["ratelimit", baseurl];
  
  try {
    const expireKey = ["ratelimit_expire", baseurl];
    const expireEntry = await kv.get<number>(expireKey);
    if (expireEntry.value && expireEntry.value < now) {
      await kv.delete(key);
      await kv.delete(expireKey);
    }
    
    const entry = await kv.get<number>(key);
    const currentCount = entry.value || 0;
    
    if (currentCount >= limit) {
      return false;
    }
    
    await kv.atomic()
      .set(key, currentCount + 1)
      .set(["ratelimit_expire", baseurl], now + RATE_LIMIT_WINDOW)
      .commit();
    
    return true;
  } catch (e) {
    console.error("Rate limit check error:", e);
    return true;
  }
}

// Create error response in OpenAI format
function createErrorResponse(status: number, message: string, type?: string, param?: string, code?: string): Response {
  const error: any = {
    error: {
      message: message || "Request blocked",
      type: type || "invalid_request_error"
    }
  };
  
  if (param) error.error.param = param;
  if (code) error.error.code = code;
  
  return new Response(JSON.stringify(error), {
    status,
    headers: {
      "Content-Type": "application/json"
    }
  });
}

// Forward request to target
async function forwardRequest(request: Request, targetUrl: string): Promise<Response> {
  const headers = new Headers(request.headers);
  headers.delete("host");
  
  const forwardReq = new Request(targetUrl, {
    method: request.method,
    headers: headers,
    body: request.body
  });
  
  return await fetch(forwardReq);
}

// Main request handler
async function handleRequest(request: Request): Promise<Response> {
  const url = new URL(request.url);
  
  if (url.pathname === "/" && request.method === "GET") {
    return new Response(JSON.stringify({
      status: "ok",
      message: "Openai-compatible Message Audit API Running..."
    }), {
      headers: { "Content-Type": "application/json" }
    });
  }
  
  if (!url.pathname.startsWith("/proxy/")) {
    return createErrorResponse(404, "Not found");
  }
  
  const proxyPath = url.pathname.substring(7);
  
  let baseurl: string;
  let targetPath: string;
  let rateLimit: number = DEFAULT_RATE_LIMIT;
  let auditPath: string = DEFAULT_AUDIT_PATH;
  let auditParameter: string = DEFAULT_AUDIT_PARAMETER;
  let maxAuditNum: number = DEFAULT_MAX_AUDIT_NUM;
  let banTimeInterval: number = DEFAULT_BAN_TIME_INTERVAL;
  let banTimeDuration: number = DEFAULT_BAN_TIME_DURATION;
  
  if (proxyPath.startsWith("http://") || proxyPath.startsWith("https://")) {
    const urlMatch = proxyPath.match(/^(https?:\/\/[^\/]+)(\/.*)?$/);
    if (!urlMatch) {
      return createErrorResponse(400, "Invalid proxy URL");
    }
    
    baseurl = urlMatch[1];
    targetPath = urlMatch[2] || "/";
  } else {
    const pathParts = proxyPath.split("/");
    const sitePath = pathParts[0];
    targetPath = "/" + pathParts.slice(1).join("/");
    
    const apiSites = getApiSites();
    const site = apiSites.find(s => s.path === sitePath);
    
    if (!site) {
      return createErrorResponse(404, `API site '${sitePath}' not found`);
    }
    
    baseurl = site.baseurl;
    rateLimit = site.ratelimit ?? DEFAULT_RATE_LIMIT;
    maxAuditNum = site.MaxAuditNum ?? DEFAULT_MAX_AUDIT_NUM;
    banTimeInterval = site.BanTimeInterval ?? DEFAULT_BAN_TIME_INTERVAL;
    banTimeDuration = site.BanTimeDuration ?? DEFAULT_BAN_TIME_DURATION;
    
    if (site["msg-audit-config"]) {
      auditPath = site["msg-audit-config"].AuditPath || DEFAULT_AUDIT_PATH;
      auditParameter = site["msg-audit-config"].AuditParameter || DEFAULT_AUDIT_PARAMETER;
    }
  }
  
  // Extract token from Authorization header
  const authHeader = request.headers.get("Authorization");
  const token = authHeader ? authHeader.replace("Bearer ", "") : "";
  
  // Check if token is banned
  const banStatus = await isTokenBanned(baseurl, token);
  if (banStatus.banned) {
    return createErrorResponse(
      403,
      `因在${banTimeInterval}分钟内触发${maxAuditNum}次违规，已暂时被封禁${banTimeDuration}分钟，请稍后再试。剩余封禁时间：${banStatus.remainingMinutes}分钟`,
      "access_denied"
    );
  }
  
  const rateLimitOk = await checkRateLimit(baseurl, rateLimit);
  if (!rateLimitOk) {
    return createErrorResponse(429, "Rate limit exceeded. Please try again later.", "rate_limit_error");
  }
  
  const targetUrl = baseurl + targetPath;
  
  if (targetPath === auditPath && request.method === "POST") {
    try {
      const bodyText = await request.text();
      const body = JSON.parse(bodyText);
      
      // Check if this is a test request
      if (isTestRequest(body, auditParameter)) {
        return createMockResponse(body.stream === true, body.model ? body.model : "model");
      }
      
      const messagesToAudit = extractMessagesForAudit(body, auditParameter);
      
      if (messagesToAudit) {
        const auditResult = await auditMessage(messagesToAudit);
        
        if (auditResult) {
          if (auditResult.status === "done" && auditResult.verdict === "malicious") {
            // Update ban status
            const { isBanned, violationCount } = await checkAndUpdateBanStatus(
              baseurl,
              token,
              maxAuditNum,
              banTimeInterval,
              banTimeDuration
            );
            
            // Send WxPusher notification
            const formattedMessages = formatMessagesForHtml(body, auditParameter);
            await sendWxPusherNotification(
              targetUrl,
              token,
              body.model,
              auditResult,
              formattedMessages,
              baseurl
            );
            
            if (isBanned) {
              return createErrorResponse(
                403,
                `因在${banTimeInterval}分钟内触发${maxAuditNum}次违规，已暂时被封禁${banTimeDuration}分钟，请稍后再试。`,
                "access_denied"
              );
            } else {
              return createErrorResponse(
                403,
                `${auditResult.data?.descr || "Content blocked by security policy"}。当前违规次数：${violationCount}/${maxAuditNum}`,
                auditResult.verdict,
                auditResult.data?.match_string,
                auditResult.rule_id
              );
            }
          }
        } else {
          console.error("Audit API failed, allowing request");
        }
      }
      
      const forwardReq = new Request(targetUrl, {
        method: request.method,
        headers: request.headers,
        body: bodyText
      });
      
      return await fetch(forwardReq);
    } catch (e) {
      console.error("Error processing chat request:", e);
      return createErrorResponse(500, "Internal server error");
    }
  }
  
  return await forwardRequest(request, targetUrl);
}

// Deno Deploy entry point
Deno.serve(handleRequest);
