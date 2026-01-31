// ===========================================
// AETHER WORKFLOW ENGINE - Main Server
// n8n-like automation backend
// ===========================================

import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import axios from 'axios';
import { config } from './config/env';
import { authenticate, apiLimiter, AuthenticatedRequest } from './middleware/security';
import { logger } from './utils/logger';

// Services
import { workflowService } from './services/workflowService';
import { webhookService } from './services/webhookService';
import { schedulerService } from './services/schedulerService';
import { credentialService } from './services/credentialService';
import { jobQueueService } from './services/jobQueueService';
import { aiService } from './services/aiService';
import { executeWorkflow } from './engine/executionEngine';

// Routes
import authRoutes from './routes/auth';

// Integrations
import { slackService } from './integrations/slack';
import { emailService } from './integrations/email';

const app = express();

// --- Global Middleware ---
app.use(helmet());
app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '10mb' }));
app.use(morgan('dev'));

// --- Auth Routes (OAuth) ---
app.use('/api/auth', authRoutes);

// --- Health Check ---
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'ok',
    version: '2.0.0',
    env: config.NODE_ENV,
    services: {
      scheduler: 'active',
      webhooks: 'active',
      queue: jobQueueService.isAvailable() ? 'active' : 'fallback',
    },
  });
});

// ==========================================
// WORKFLOW ROUTES
// ==========================================

// List all workflows
app.get('/api/v1/workflows', authenticate, async (req: Request, res: Response) => {
  try {
    const authReq = req as AuthenticatedRequest;
    const userId = authReq.user?.id || 'anonymous';
    const workflows = workflowService.list(userId);
    res.json({ success: true, data: workflows });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get single workflow
app.get('/api/v1/workflows/:id', authenticate, async (req: Request, res: Response) => {
  try {
    const authReq = req as AuthenticatedRequest;
    const userId = authReq.user?.id || 'anonymous';
    const workflow = workflowService.get(req.params.id, userId);
    
    if (!workflow) {
      return res.status(404).json({ success: false, error: 'Workflow not found' });
    }
    
    res.json({ success: true, data: workflow });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Create workflow
app.post('/api/v1/workflows', authenticate, async (req: Request, res: Response) => {
  try {
    const authReq = req as AuthenticatedRequest;
    const userId = authReq.user?.id || 'anonymous';
    const { id, name, description, nodes, edges, settings } = req.body;
    
    if (!name) {
      return res.status(400).json({ success: false, error: 'Name is required' });
    }
    
    const workflow = workflowService.create(userId, { id, name, description, nodes, edges, settings });
    res.status(201).json({ success: true, data: workflow });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Update workflow
app.put('/api/v1/workflows/:id', authenticate, async (req: Request, res: Response) => {
  try {
    const authReq = req as AuthenticatedRequest;
    const userId = authReq.user?.id || 'anonymous';
    const workflow = workflowService.update(req.params.id, userId, req.body);
    
    if (!workflow) {
      return res.status(404).json({ success: false, error: 'Workflow not found' });
    }
    
    res.json({ success: true, data: workflow });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Delete workflow
app.delete('/api/v1/workflows/:id', authenticate, async (req: Request, res: Response) => {
  try {
    const authReq = req as AuthenticatedRequest;
    const userId = authReq.user?.id || 'anonymous';
    const success = workflowService.delete(req.params.id, userId);
    
    if (!success) {
      return res.status(404).json({ success: false, error: 'Workflow not found' });
    }
    
    res.json({ success: true });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Execute workflow manually
app.post('/api/v1/workflows/:id/execute', authenticate, apiLimiter, async (req: Request, res: Response) => {
  try {
    const authReq = req as AuthenticatedRequest;
    const userId = authReq.user?.id || 'anonymous';
    const workflow = workflowService.get(req.params.id, userId);
    
    if (!workflow) {
      return res.status(404).json({ success: false, error: 'Workflow not found' });
    }

    // Use job queue if available, otherwise direct execution
    if (jobQueueService.isAvailable()) {
      const executionId = await jobQueueService.enqueue(workflow.id, req.body.input, {
        userId,
        mode: 'manual',
      });
      res.json({ success: true, data: { executionId, queued: true } });
    } else {
      const result = await executeWorkflow(workflow, req.body.input, userId, 'manual');
      res.json({ success: true, data: result });
    }
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get workflow executions
app.get('/api/v1/workflows/:id/executions', authenticate, async (req: Request, res: Response) => {
  try {
    const executions = workflowService.getExecutions(req.params.id, 50);
    res.json({ success: true, data: executions });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Duplicate workflow
app.post('/api/v1/workflows/:id/duplicate', authenticate, async (req: Request, res: Response) => {
  try {
    const authReq = req as AuthenticatedRequest;
    const userId = authReq.user?.id || 'anonymous';
    const workflow = workflowService.duplicate(req.params.id, userId);
    
    if (!workflow) {
      return res.status(404).json({ success: false, error: 'Workflow not found' });
    }
    
    res.status(201).json({ success: true, data: workflow });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Export workflow
app.get('/api/v1/workflows/:id/export', authenticate, async (req: Request, res: Response) => {
  try {
    const authReq = req as AuthenticatedRequest;
    const userId = authReq.user?.id || 'anonymous';
    const data = workflowService.export(req.params.id, userId);
    
    if (!data) {
      return res.status(404).json({ success: false, error: 'Workflow not found' });
    }
    
    res.json(data);
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Import workflow
app.post('/api/v1/workflows/import', authenticate, async (req: Request, res: Response) => {
  try {
    const authReq = req as AuthenticatedRequest;
    const userId = authReq.user?.id || 'anonymous';
    const workflow = workflowService.import(userId, req.body);
    
    if (!workflow) {
      return res.status(400).json({ success: false, error: 'Invalid import data' });
    }
    
    res.status(201).json({ success: true, data: workflow });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ==========================================
// WEBHOOK ROUTES
// ==========================================

// Register webhook
app.post('/api/v1/webhooks', authenticate, async (req: Request, res: Response) => {
  try {
    const { workflowId, path, method, authType, authConfig } = req.body;
    
    if (!workflowId) {
      return res.status(400).json({ success: false, error: 'workflowId is required' });
    }
    
    const webhook = webhookService.register(workflowId, { path, method, authType, authConfig });
    res.status(201).json({ success: true, data: webhook });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Incoming webhook handler (public)
// Supports both async (fire-and-forget) and sync (wait for result) modes
app.all('/webhook/*', async (req: Request, res: Response) => {
  try {
    const path = req.path;
    
    // Get webhook configuration to check response mode
    const webhook = webhookService.getByPath(path);
    if (!webhook) {
      return res.status(404).json({ success: false, error: 'Webhook not found' });
    }
    
    const isSync = webhook.responseMode === 'onCompleted';
    
    // For async mode, respond immediately and process in background
    if (!isSync) {
      // Fire and forget - respond immediately
      res.json({ 
        success: true, 
        message: 'Webhook received, processing in background',
        webhookId: webhook.id
      });
      
      // Process webhook in background (don't await)
      webhookService.handleRequest({
        method: req.method,
        path,
        headers: req.headers as Record<string, string>,
        query: req.query as Record<string, string>,
        body: req.body,
        timestamp: new Date(),
      }).catch(err => {
        console.error('Background webhook execution error:', err);
      });
      
      return;
    }
    
    // Sync mode - wait for workflow execution result
    const result = await webhookService.handleRequest({
      method: req.method,
      path,
      headers: req.headers as Record<string, string>,
      query: req.query as Record<string, string>,
      body: req.body,
      timestamp: new Date(),
    });
    
    if (!result.success) {
      return res.status(400).json(result);
    }
    
    // Handle custom response from ACTION_RESPOND node
    if (result.response && result.response.statusCode) {
      // Apply custom headers if provided
      if (result.response.headers && typeof result.response.headers === 'object') {
        Object.entries(result.response.headers).forEach(([key, value]) => {
          res.setHeader(key, value as string);
        });
      }
      
      // Send with custom status code and body
      const body = result.response.body || result.response.response || result.response;
      return res.status(result.response.statusCode).send(body);
    }
    
    // Default response for sync mode
    res.json(result);
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ==========================================
// SCHEDULER ROUTES
// ==========================================

// Schedule workflow
app.post('/api/v1/schedules', authenticate, async (req: Request, res: Response) => {
  try {
    const { workflowId, cronExpression, timezone } = req.body;
    
    if (!workflowId || !cronExpression) {
      return res.status(400).json({ success: false, error: 'workflowId and cronExpression required' });
    }
    
    const jobId = schedulerService.schedule(workflowId, cronExpression, timezone);
    res.status(201).json({ success: true, data: { jobId } });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// List schedules
app.get('/api/v1/schedules', authenticate, async (req: Request, res: Response) => {
  try {
    const schedules = schedulerService.list();
    res.json({ success: true, data: schedules });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Delete schedule
app.delete('/api/v1/schedules/:id', authenticate, async (req: Request, res: Response) => {
  try {
    const success = schedulerService.remove(req.params.id);
    res.json({ success });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Validate cron expression
app.post('/api/v1/schedules/validate', async (req: Request, res: Response) => {
  try {
    const { expression } = req.body;
    const isValid = schedulerService.validateCron(expression);
    const description = isValid ? schedulerService.describeCron(expression) : null;
    res.json({ success: true, data: { isValid, description } });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ==========================================
// CREDENTIALS ROUTES
// ==========================================

// Store credential
app.post('/api/v1/credentials', authenticate, async (req: Request, res: Response) => {
  try {
    const authReq = req as AuthenticatedRequest;
    const userId = authReq.user?.id || 'anonymous';
    const { name, type, data } = req.body;
    
    if (!name || !type || !data) {
      return res.status(400).json({ success: false, error: 'name, type, and data required' });
    }
    
    const id = await credentialService.store(userId, name, type, data);
    res.status(201).json({ success: true, data: { id } });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// List credentials (no sensitive data)
app.get('/api/v1/credentials', authenticate, async (req: Request, res: Response) => {
  try {
    const authReq = req as AuthenticatedRequest;
    const userId = authReq.user?.id || 'anonymous';
    const credentials = await credentialService.list(userId);
    res.json({ success: true, data: credentials });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Delete credential
app.delete('/api/v1/credentials/:id', authenticate, async (req: Request, res: Response) => {
  try {
    const authReq = req as AuthenticatedRequest;
    const userId = authReq.user?.id || 'anonymous';
    const success = await credentialService.delete(req.params.id, userId);
    res.json({ success });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ==========================================
// AI ROUTES
// ==========================================

// Generate workflow from description
app.post('/api/v1/ai/generate-workflow', authenticate, apiLimiter, async (req: Request, res: Response) => {
  try {
    const { description } = req.body;
    
    if (!description) {
      return res.status(400).json({ success: false, error: 'description is required' });
    }
    
    const workflow = await aiService.generateWorkflow(description);
    res.json({ success: true, data: workflow });
  } catch (error: any) {
    logger.error('AI workflow generation failed', { error: error.message });
    res.status(500).json({ success: false, error: error.message });
  }
});

// AI Chat (for workflow assistance)
app.post('/api/v1/ai/chat', authenticate, apiLimiter, async (req: Request, res: Response) => {
  try {
    const { prompt, systemPrompt, model, temperature } = req.body;
    
    if (!prompt) {
      return res.status(400).json({ success: false, error: 'prompt is required' });
    }
    
    const response = await aiService.chat({ prompt, systemPrompt, model, temperature });
    res.json({ success: true, data: { response } });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Analyze workflow
app.post('/api/v1/ai/analyze-workflow', authenticate, async (req: Request, res: Response) => {
  try {
    const { workflow } = req.body;
    
    if (!workflow) {
      return res.status(400).json({ success: false, error: 'workflow is required' });
    }
    
    const analysis = await aiService.analyzeWorkflow(workflow);
    res.json({ success: true, data: { analysis } });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ==========================================
// EXECUTION ROUTES
// ==========================================

// Get execution details
app.get('/api/v1/executions/:id', authenticate, async (req: Request, res: Response) => {
  try {
    const execution = workflowService.getExecution(req.params.id);
    
    if (!execution) {
      return res.status(404).json({ success: false, error: 'Execution not found' });
    }
    
    res.json({ success: true, data: execution });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get queue stats
app.get('/api/v1/queue/stats', authenticate, async (req: Request, res: Response) => {
  try {
    const stats = await jobQueueService.getStats();
    res.json({ success: true, data: stats || { message: 'Queue not available' } });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ==========================================
// STATS ROUTES
// ==========================================

// Get user stats
app.get('/api/v1/stats', authenticate, async (req: Request, res: Response) => {
  try {
    const authReq = req as AuthenticatedRequest;
    const userId = authReq.user?.id || 'anonymous';
    const stats = workflowService.getStats(userId);
    res.json({ success: true, data: stats });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ==========================================
// NODE TYPES INFO
// ==========================================

// Get available node types
app.get('/api/v1/node-types', async (req: Request, res: Response) => {
  const nodeTypes = {
    triggers: [
      { type: 'TRIGGER_MANUAL', name: 'Manual Trigger', description: 'Start workflow manually', icon: 'Play' },
      { type: 'TRIGGER_WEBHOOK', name: 'Webhook', description: 'Start from HTTP request', icon: 'Webhook' },
      { type: 'TRIGGER_SCHEDULE', name: 'Schedule', description: 'Run on cron schedule', icon: 'Clock' },
    ],
    actions: [
      { type: 'ACTION_HTTP', name: 'HTTP Request', description: 'Make API calls', icon: 'Globe' },
      { type: 'ACTION_CODE', name: 'Code', description: 'Run custom JavaScript', icon: 'Code' },
      { type: 'ACTION_SET', name: 'Set', description: 'Set/transform data', icon: 'Settings' },
      { type: 'ACTION_FILTER', name: 'Filter', description: 'Filter data items', icon: 'Filter' },
      { type: 'ACTION_SWITCH', name: 'Switch', description: 'Conditional routing', icon: 'GitBranch' },
      { type: 'ACTION_LOOP', name: 'Loop', description: 'Iterate over items', icon: 'Repeat' },
      { type: 'ACTION_WAIT', name: 'Wait', description: 'Delay execution', icon: 'Clock' },
      { type: 'ACTION_MERGE', name: 'Merge', description: 'Merge multiple inputs', icon: 'Merge' },
    ],
    integrations: [
      { type: 'ACTION_EMAIL', name: 'Email', description: 'Send emails via SMTP', icon: 'Mail' },
      { type: 'ACTION_SLACK', name: 'Slack', description: 'Post to Slack channels', icon: 'MessageSquare' },
      { type: 'ACTION_DISCORD', name: 'Discord', description: 'Send Discord messages', icon: 'MessageCircle' },
      { type: 'ACTION_DATABASE', name: 'Database', description: 'Query databases', icon: 'Database' },
      { type: 'ACTION_GOOGLE_SHEETS', name: 'Google Sheets', description: 'Read/write spreadsheets', icon: 'Table' },
    ],
    ai: [
      { type: 'ACTION_AI_CHAT', name: 'AI Chat', description: 'Generate AI responses', icon: 'Bot' },
      { type: 'ACTION_AI_SUMMARIZE', name: 'AI Summarize', description: 'Summarize text', icon: 'FileText' },
      { type: 'ACTION_AI_CLASSIFY', name: 'AI Classify', description: 'Classify content', icon: 'Tags' },
      { type: 'ACTION_AI_TRANSFORM', name: 'AI Transform', description: 'Transform data with AI', icon: 'Wand' },
    ],
  };
  
  res.json({ success: true, data: nodeTypes });
});

// --- Integration API Endpoints ---

// Test all integrations
app.get('/api/v1/integrations/status', async (req: Request, res: Response) => {
  const status = {
    slack: { configured: false, connected: false, error: null as string | null },
    email: { configured: false, connected: false, error: null as string | null },
    github: { configured: false },
    google: { configured: false },
  };
  
  // Check Slack
  if (process.env.SLACK_BOT_TOKEN) {
    status.slack.configured = true;
    try {
      const result = await slackService.testConnection();
      status.slack.connected = result.ok;
      if (!result.ok) status.slack.error = result.error || 'Unknown error';
    } catch (e: any) {
      status.slack.error = e.message;
    }
  }
  
  // Check Email
  if (process.env.GMAIL_APP_PASSWORD && process.env.GMAIL_USER) {
    status.email.configured = true;
    try {
      const result = await emailService.testConnection();
      status.email.connected = result.success;
      if (!result.success) status.email.error = result.error || 'Unknown error';
    } catch (e: any) {
      status.email.error = e.message;
    }
  }
  
  // Check OAuth
  status.github.configured = !!(process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET);
  status.google.configured = !!(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET);
  
  res.json({ success: true, data: status });
});

// Send Slack message
app.post('/api/v1/integrations/slack/send', async (req: Request, res: Response) => {
  try {
    const { channel, message, blocks } = req.body;
    
    if (!channel || !message) {
      return res.status(400).json({ success: false, error: 'Channel and message are required' });
    }
    
    let result;
    if (blocks) {
      result = await slackService.sendRichMessage(channel, blocks, message);
    } else {
      result = await slackService.sendMessage({ channel, text: message });
    }
    
    if (result.ok) {
      res.json({ success: true, data: { ts: result.ts, channel: result.channel } });
    } else {
      res.status(400).json({ success: false, error: result.error });
    }
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// List Slack channels
app.get('/api/v1/integrations/slack/channels', async (req: Request, res: Response) => {
  try {
    const channels = await slackService.listChannels();
    res.json({ success: true, data: channels });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Send Email
app.post('/api/v1/integrations/email/send', async (req: Request, res: Response) => {
  try {
    const { to, subject, text, html } = req.body;
    
    if (!to || !subject) {
      return res.status(400).json({ success: false, error: 'To and subject are required' });
    }
    
    if (!text && !html) {
      return res.status(400).json({ success: false, error: 'Either text or html body is required' });
    }
    
    console.log(`[EMAIL] Sending email to: ${to}, subject: ${subject}`);
    const result = await emailService.send({ to, subject, text, html });
    
    if (!result.success) {
      console.error(`[EMAIL] Failed: ${result.error}`);
      return res.status(500).json({ success: false, error: result.error || 'Failed to send email' });
    }
    
    console.log(`[EMAIL] Sent successfully! MessageId: ${result.messageId}`);
    res.json({ success: true, data: { messageId: result.messageId } });
  } catch (error: any) {
    console.error(`[EMAIL] Exception: ${error.message}`);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Test Email connection
app.get('/api/v1/integrations/email/test', async (req: Request, res: Response) => {
  try {
    const connected = await emailService.testConnection();
    res.json({ success: true, data: { connected } });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// --- Global Error Handler ---
app.use((err: any, req: Request, res: Response, next: NextFunction) => {
  logger.error('Server Error', { error: err.message, stack: err.stack });
  res.status(err.status || 500).json({
    success: false,
    error: config.NODE_ENV === 'development' ? err.message : 'Internal server error',
  });
});

// --- Server Start ---
const PORT = config.PORT || 8080;
app.listen(PORT, async () => {
  // Try to initialize job queue (optional - falls back to sync execution)
  try {
    await jobQueueService.initialize();
  } catch (e) {
    logger.warn('Job queue not initialized - using synchronous execution');
  }

  // ===========================================
  // KEEP-ALIVE PING SERVICE (Render Free Tier)
  // Prevents spin-down after 15 minutes of inactivity
  // ===========================================
  const RENDER_URL = process.env.RENDER_EXTERNAL_URL || process.env.BACKEND_URL;
  const PING_INTERVAL = 10 * 60 * 1000; // 10 minutes (under 15 min threshold)

  if (RENDER_URL && config.NODE_ENV === 'production') {
    const keepAlive = () => {
      axios.get(`${RENDER_URL}/health`)
        .then((res) => {
          logger.info(`[Keep-Alive] Ping successful at ${new Date().toISOString()} - Status: ${res.status}`);
        })
        .catch((err) => {
          logger.warn(`[Keep-Alive] Ping failed: ${err.message}`);
        });
    };

    // Initial ping after 1 minute, then every 10 minutes
    setTimeout(keepAlive, 60 * 1000);
    setInterval(keepAlive, PING_INTERVAL);
    
    logger.info(`[Keep-Alive] Service enabled - Pinging ${RENDER_URL}/health every 10 minutes`);
  }

  console.log(`
  ┌──────────────────────────────────────────────────────────┐
  │  🚀 Aether Workflow Engine is running                     │
  │                                                          │
  │  ➜ Local:      http://localhost:${PORT}                      │
  │  ➜ API:        http://localhost:${PORT}/api/v1               │
  │  ➜ Webhooks:   http://localhost:${PORT}/webhook/...          │
  │  ➜ Env:        ${config.NODE_ENV}                               │
  │                                                          │
  │  Available Services:                                     │
  │    ✓ Workflow Execution Engine                           │
  │    ✓ Webhook Trigger Service                             │
  │    ✓ Cron Scheduler Service                              │
  │    ✓ Credential Management                               │
  │    ✓ AI Workflow Generator                               │
  │    ${jobQueueService.isAvailable() ? '✓' : '○'} Job Queue (BullMQ)                              │
  │    ${RENDER_URL ? '✓' : '○'} Keep-Alive Ping Service                          │
  └──────────────────────────────────────────────────────────┘
  `);
});

export default app;
