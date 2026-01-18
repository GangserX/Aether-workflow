// ===========================================
// AETHER WORKFLOW ENGINE - Frontend API Service
// Communication with backend
// ===========================================

// Detect production vs development
const isProduction = typeof window !== 'undefined' && window.location.hostname !== 'localhost';
const API_BASE_URL = isProduction 
  ? 'https://aether-workflow.onrender.com' 
  : 'http://localhost:8080';

interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: string;
}

class ApiService {
  private token: string = '';

  setToken(token: string) {
    this.token = token;
  }

  private async request<T>(
    method: string,
    endpoint: string,
    body?: any
  ): Promise<ApiResponse<T>> {
    try {
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
      };

      if (this.token) {
        headers['Authorization'] = `Bearer ${this.token}`;
      } else {
        // Use demo token for development
        headers['Authorization'] = 'Bearer demo-token';
      }

      const response = await fetch(`${API_BASE_URL}${endpoint}`, {
        method,
        headers,
        body: body ? JSON.stringify(body) : undefined,
      });

      const data = await response.json();
      return data;
    } catch (error: any) {
      return { success: false, error: error.message };
    }
  }

  // =====================
  // Workflow APIs
  // =====================

  async listWorkflows() {
    return this.request<any[]>('GET', '/api/v1/workflows');
  }

  async getWorkflow(id: string) {
    return this.request<any>('GET', `/api/v1/workflows/${id}`);
  }

  async createWorkflow(data: {
    name: string;
    description?: string;
    nodes?: any[];
    edges?: any[];
  }) {
    return this.request<any>('POST', '/api/v1/workflows', data);
  }

  async updateWorkflow(id: string, data: any) {
    return this.request<any>('PUT', `/api/v1/workflows/${id}`, data);
  }

  async deleteWorkflow(id: string) {
    return this.request<any>('DELETE', `/api/v1/workflows/${id}`);
  }

  async executeWorkflow(id: string, input?: any) {
    return this.request<any>('POST', `/api/v1/workflows/${id}/execute`, { input });
  }

  async getWorkflowExecutions(id: string) {
    return this.request<any[]>('GET', `/api/v1/workflows/${id}/executions`);
  }

  async duplicateWorkflow(id: string) {
    return this.request<any>('POST', `/api/v1/workflows/${id}/duplicate`);
  }

  async exportWorkflow(id: string) {
    return this.request<any>('GET', `/api/v1/workflows/${id}/export`);
  }

  async importWorkflow(data: any) {
    return this.request<any>('POST', '/api/v1/workflows/import', data);
  }

  // =====================
  // Webhook APIs
  // =====================

  async createWebhook(workflowId: string, options?: any) {
    return this.request<any>('POST', '/api/v1/webhooks', { workflowId, ...options });
  }

  // =====================
  // Schedule APIs
  // =====================

  async createSchedule(workflowId: string, cronExpression: string, timezone?: string) {
    return this.request<any>('POST', '/api/v1/schedules', {
      workflowId,
      cronExpression,
      timezone,
    });
  }

  async listSchedules() {
    return this.request<any[]>('GET', '/api/v1/schedules');
  }

  async deleteSchedule(id: string) {
    return this.request<any>('DELETE', `/api/v1/schedules/${id}`);
  }

  async validateCron(expression: string) {
    return this.request<{ isValid: boolean; description: string }>(
      'POST',
      '/api/v1/schedules/validate',
      { expression }
    );
  }

  // =====================
  // Credential APIs
  // =====================

  async createCredential(name: string, type: string, data: any) {
    return this.request<{ id: string }>('POST', '/api/v1/credentials', {
      name,
      type,
      data,
    });
  }

  async listCredentials() {
    return this.request<any[]>('GET', '/api/v1/credentials');
  }

  async deleteCredential(id: string) {
    return this.request<any>('DELETE', `/api/v1/credentials/${id}`);
  }

  // =====================
  // AI APIs
  // =====================

  async generateWorkflow(description: string) {
    return this.request<any>('POST', '/api/v1/ai/generate-workflow', { description });
  }

  async aiChat(prompt: string, systemPrompt?: string) {
    return this.request<{ response: string }>('POST', '/api/v1/ai/chat', {
      prompt,
      systemPrompt,
    });
  }

  async analyzeWorkflow(workflow: any) {
    return this.request<{ analysis: string }>('POST', '/api/v1/ai/analyze-workflow', {
      workflow,
    });
  }

  // =====================
  // Stats APIs
  // =====================

  async getStats() {
    return this.request<any>('GET', '/api/v1/stats');
  }

  async getNodeTypes() {
    return this.request<any>('GET', '/api/v1/node-types');
  }

  async getQueueStats() {
    return this.request<any>('GET', '/api/v1/queue/stats');
  }

  async getExecution(id: string) {
    return this.request<any>('GET', `/api/v1/executions/${id}`);
  }
}

export const apiService = new ApiService();
export default apiService;
