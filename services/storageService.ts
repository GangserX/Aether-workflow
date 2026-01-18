// Storage Service - Persistent data layer for Aether Orchestrate

import { WorkflowNode, WorkflowEdge, User } from '../types';

const STORAGE_KEYS = {
  DB: 'aether_core_db_v2',
  USER_SESSION: 'aether_user_session',
  SETTINGS: 'aether_settings',
  CREDENTIALS: 'aether_credentials',
};

// === TYPES ===

export interface Workflow {
  id: string;
  name: string;
  description?: string;
  nodes: WorkflowNode[];
  edges: WorkflowEdge[];
  isActive: boolean;
  createdAt: string;
  updatedAt: string;
  webhookPath?: string;
  responseMode?: 'onReceived' | 'onCompleted';
  triggerType?: 'manual' | 'webhook' | 'schedule' | 'api';
  scheduleConfig?: {
    cron: string;
    timezone: string;
  };
}

export interface Execution {
  id: string;
  workflowId: string;
  workflowName: string;
  status: 'PENDING' | 'RUNNING' | 'SUCCESS' | 'FAILED' | 'CANCELLED';
  triggeredBy: 'MANUAL' | 'WEBHOOK' | 'SCHEDULE' | 'API';
  startedAt: string;
  completedAt?: string;
  duration?: number;
  nodeExecutions: NodeExecution[];
  logs: ExecutionLog[];
  input?: any;
  output?: any;
  error?: string;
}

export interface NodeExecution {
  id: string;
  nodeId: string;
  nodeName: string;
  nodeType: string;
  status: 'PENDING' | 'RUNNING' | 'SUCCESS' | 'FAILED' | 'SKIPPED';
  startedAt?: string;
  completedAt?: string;
  input?: any;
  output?: any;
  error?: string;
  duration?: number;
}

export interface ExecutionLog {
  id: string;
  timestamp: string;
  level: 'DEBUG' | 'INFO' | 'WARN' | 'ERROR';
  message: string;
  nodeId?: string;
  metadata?: Record<string, any>;
}

export interface Deployment {
  id: string;
  workflowId: string;
  name: string;
  endpoint: string;
  isActive: boolean;
  createdAt: string;
  updatedAt: string;
  stats: {
    totalRequests: number;
    successCount: number;
    errorCount: number;
    avgLatency: number;
    uptime: number;
  };
}

export interface Credential {
  id: string;
  name: string;
  type: 'gmail' | 'slack' | 'github' | 'openai' | 'custom';
  data: Record<string, any>;
  createdAt: string;
  updatedAt: string;
}

export interface SystemSettings {
  apiGateway: string;
  environment: 'production' | 'staging' | 'development';
  defaultModel: string;
  theme: 'dark' | 'light';
}

export interface UserDatabase {
  user: User;
  workflows: Workflow[];
  executions: Execution[];
  deployments: Deployment[];
  credentials: Credential[];
  settings: SystemSettings;
  lastUpdated: string;
}

// === STORAGE CLASS ===

class StorageService {
  private listeners: Map<string, Set<(data: any) => void>> = new Map();

  // Load entire database
  loadDB(): Record<string, UserDatabase> {
    try {
      const data = localStorage.getItem(STORAGE_KEYS.DB);
      return data ? JSON.parse(data) : {};
    } catch (e) {
      console.error("Database load error:", e);
      return {};
    }
  }

  // Save entire database
  saveDB(data: Record<string, UserDatabase>) {
    localStorage.setItem(STORAGE_KEYS.DB, JSON.stringify(data));
  }

  // Get user data
  getUserData(email: string): UserDatabase | null {
    const db = this.loadDB();
    return db[email] || null;
  }

  // Initialize user data
  initUserData(user: User): UserDatabase {
    const userData: UserDatabase = {
      user,
      workflows: [],
      executions: [],
      deployments: [],
      credentials: [],
      settings: {
        apiGateway: typeof window !== 'undefined' && window.location.hostname !== 'localhost' ? 'https://aether-workflow.onrender.com/api/v1' : 'http://localhost:8080/api/v1',
        environment: 'development',
        defaultModel: 'gemini-2.5-flash',
        theme: 'dark',
      },
      lastUpdated: new Date().toISOString(),
    };
    
    const db = this.loadDB();
    db[user.email] = userData;
    this.saveDB(db);
    
    return userData;
  }

  // Update user data
  updateUserData(email: string, updates: Partial<UserDatabase>) {
    const db = this.loadDB();
    if (db[email]) {
      db[email] = {
        ...db[email],
        ...updates,
        lastUpdated: new Date().toISOString(),
      };
      this.saveDB(db);
      this.notify(email, db[email]);
    }
  }

  // === WORKFLOWS ===

  getWorkflows(email: string): Workflow[] {
    const userData = this.getUserData(email);
    return userData?.workflows || [];
  }

  saveWorkflow(email: string, workflow: Workflow): Workflow {
    const db = this.loadDB();
    if (!db[email]) return workflow;
    
    const existingIndex = db[email].workflows.findIndex(w => w.id === workflow.id);
    if (existingIndex >= 0) {
      db[email].workflows[existingIndex] = { ...workflow, updatedAt: new Date().toISOString() };
    } else {
      db[email].workflows.push({ ...workflow, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() });
    }
    
    this.saveDB(db);
    this.notify(email, db[email]);
    return workflow;
  }

  deleteWorkflow(email: string, workflowId: string) {
    const db = this.loadDB();
    if (!db[email]) return;
    
    db[email].workflows = db[email].workflows.filter(w => w.id !== workflowId);
    db[email].deployments = db[email].deployments.filter(d => d.workflowId !== workflowId);
    
    this.saveDB(db);
    this.notify(email, db[email]);
  }

  toggleWorkflow(email: string, workflowId: string): boolean {
    const db = this.loadDB();
    if (!db[email]) return false;
    
    const workflow = db[email].workflows.find(w => w.id === workflowId);
    if (workflow) {
      workflow.isActive = !workflow.isActive;
      workflow.updatedAt = new Date().toISOString();
      
      // Update corresponding deployment
      const deployment = db[email].deployments.find(d => d.workflowId === workflowId);
      if (deployment) {
        deployment.isActive = workflow.isActive;
        deployment.updatedAt = new Date().toISOString();
      }
      
      this.saveDB(db);
      this.notify(email, db[email]);
      return workflow.isActive;
    }
    return false;
  }

  // === EXECUTIONS ===

  getExecutions(email: string): Execution[] {
    const userData = this.getUserData(email);
    return userData?.executions || [];
  }

  addExecution(email: string, execution: Execution): Execution {
    const db = this.loadDB();
    if (!db[email]) return execution;
    
    db[email].executions.unshift(execution); // Add to beginning
    
    // Keep only last 100 executions
    if (db[email].executions.length > 100) {
      db[email].executions = db[email].executions.slice(0, 100);
    }
    
    this.saveDB(db);
    this.notify(email, db[email]);
    return execution;
  }

  updateExecution(email: string, executionId: string, updates: Partial<Execution>) {
    const db = this.loadDB();
    if (!db[email]) return;
    
    const execution = db[email].executions.find(e => e.id === executionId);
    if (execution) {
      Object.assign(execution, updates);
      this.saveDB(db);
      this.notify(email, db[email]);
    }
  }

  // === DEPLOYMENTS ===

  getDeployments(email: string): Deployment[] {
    const userData = this.getUserData(email);
    return userData?.deployments || [];
  }

  createDeployment(email: string, workflow: Workflow): Deployment {
    const db = this.loadDB();
    if (!db[email]) throw new Error('User not found');
    
    const deployment: Deployment = {
      id: `deploy_${Date.now()}`,
      workflowId: workflow.id,
      name: workflow.name,
      endpoint: `/webhook/${workflow.id}${workflow.webhookPath || '/trigger'}`,
      isActive: true,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      stats: {
        totalRequests: 0,
        successCount: 0,
        errorCount: 0,
        avgLatency: 0,
        uptime: 100,
      },
    };
    
    // Remove existing deployment for this workflow if exists
    db[email].deployments = db[email].deployments.filter(d => d.workflowId !== workflow.id);
    db[email].deployments.push(deployment);
    
    this.saveDB(db);
    this.notify(email, db[email]);
    return deployment;
  }

  toggleDeployment(email: string, deploymentId: string): boolean {
    const db = this.loadDB();
    if (!db[email]) return false;
    
    const deployment = db[email].deployments.find(d => d.id === deploymentId);
    if (deployment) {
      deployment.isActive = !deployment.isActive;
      deployment.updatedAt = new Date().toISOString();
      
      // Update corresponding workflow
      const workflow = db[email].workflows.find(w => w.id === deployment.workflowId);
      if (workflow) {
        workflow.isActive = deployment.isActive;
        workflow.updatedAt = new Date().toISOString();
      }
      
      this.saveDB(db);
      this.notify(email, db[email]);
      return deployment.isActive;
    }
    return false;
  }

  updateDeploymentStats(email: string, deploymentId: string, stats: Partial<Deployment['stats']>) {
    const db = this.loadDB();
    if (!db[email]) return;
    
    const deployment = db[email].deployments.find(d => d.id === deploymentId);
    if (deployment) {
      deployment.stats = { ...deployment.stats, ...stats };
      deployment.updatedAt = new Date().toISOString();
      this.saveDB(db);
      this.notify(email, db[email]);
    }
  }

  // === CREDENTIALS ===

  getCredentials(email: string): Credential[] {
    const userData = this.getUserData(email);
    return userData?.credentials || [];
  }

  saveCredential(email: string, credential: Credential): Credential {
    const db = this.loadDB();
    if (!db[email]) return credential;
    
    const existingIndex = db[email].credentials.findIndex(c => c.id === credential.id);
    if (existingIndex >= 0) {
      db[email].credentials[existingIndex] = { ...credential, updatedAt: new Date().toISOString() };
    } else {
      db[email].credentials.push({ ...credential, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() });
    }
    
    this.saveDB(db);
    this.notify(email, db[email]);
    return credential;
  }

  deleteCredential(email: string, credentialId: string) {
    const db = this.loadDB();
    if (!db[email]) return;
    
    db[email].credentials = db[email].credentials.filter(c => c.id !== credentialId);
    this.saveDB(db);
    this.notify(email, db[email]);
  }

  // === SETTINGS ===

  getSettings(email: string): SystemSettings | null {
    const userData = this.getUserData(email);
    return userData?.settings || null;
  }

  updateSettings(email: string, settings: Partial<SystemSettings>) {
    const db = this.loadDB();
    if (!db[email]) return;
    
    db[email].settings = { ...db[email].settings, ...settings };
    db[email].lastUpdated = new Date().toISOString();
    this.saveDB(db);
    this.notify(email, db[email]);
  }

  // === SUBSCRIPTIONS ===

  subscribe(email: string, callback: (data: UserDatabase) => void): () => void {
    if (!this.listeners.has(email)) {
      this.listeners.set(email, new Set());
    }
    this.listeners.get(email)!.add(callback);
    
    return () => {
      this.listeners.get(email)?.delete(callback);
    };
  }

  private notify(email: string, data: UserDatabase) {
    this.listeners.get(email)?.forEach(callback => callback(data));
  }

  // === UTILITY ===

  generateId(): string {
    return `${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  // Create workflow from nodes/edges
  createWorkflowFromBuilder(
    id: string,
    name: string,
    nodes: WorkflowNode[],
    edges: WorkflowEdge[],
    options?: Partial<Workflow>
  ): Workflow {
    // Find webhook trigger to get config
    const webhookNode = nodes.find(n => n.data.model === 'webhook-trigger');
    
    return {
      id,
      name,
      nodes,
      edges,
      isActive: true,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      webhookPath: webhookNode?.data.webhookPath || '/trigger',
      responseMode: (webhookNode?.data.responseMode as 'onReceived' | 'onCompleted') || 'onReceived',
      triggerType: webhookNode ? 'webhook' : 'manual',
      ...options,
    };
  }
}

export const storageService = new StorageService();
export default storageService;
