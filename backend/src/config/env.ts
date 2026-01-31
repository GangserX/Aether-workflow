
import dotenv from 'dotenv';
import { z } from 'zod';

dotenv.config();

const envSchema = z.object({
  PORT: z.string().default('8080'),
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  
  // Security Secrets
  JWT_SECRET: z.string().default('dev-secret-do-not-use-in-prod'),
  INTERNAL_AGENT_SECRET: z.string().default('aether-internal-secret-key'),
  
  // Rate Limiting
  RATE_LIMIT_WINDOW_MS: z.string().transform(Number).default('900000'), // 15 minutes
  RATE_LIMIT_MAX_REQUESTS: z.string().transform(Number).default('100'),

  // Internal Webhook Base URLs (Mocked for this implementation)
  WEBHOOK_BASE_URL: z.string().default('http://internal-agent-cluster.local/v1'),
  
  // Render Keep-Alive (set to your deployed Render URL in production)
  RENDER_EXTERNAL_URL: z.string().optional(),
  BACKEND_URL: z.string().optional(),
});

export const config = envSchema.parse(process.env);
