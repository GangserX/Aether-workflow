// ===========================================
// AETHER WORKFLOW ENGINE - AI Workflow Generator
// Left panel component for AI-powered workflow creation
// ===========================================

import React, { useState } from 'react';
import { Sparkles, Send, Loader2, Wand2, Copy, Check, X, ChevronDown, ChevronUp, Zap, Bot, FileText, Clock, Mail, Database, Globe, Code, GitBranch } from 'lucide-react';

// Backend URL - auto-detect production vs development
const BACKEND_URL = typeof window !== 'undefined' && window.location.hostname !== 'localhost' 
  ? 'https://aether-workflow.onrender.com' 
  : 'http://localhost:8080';

interface AIWorkflowGeneratorProps {
  onWorkflowGenerated: (workflow: {
    name: string;
    description: string;
    nodes: any[];
    edges: any[];
  }) => void;
  isOpen: boolean;
  onToggle: () => void;
}

const EXAMPLE_PROMPTS = [
  {
    icon: Mail,
    title: 'Email Automation',
    prompt: 'When a new lead fills out the contact form, send a personalized welcome email and notify the sales team on Slack',
  },
  {
    icon: Clock,
    title: 'Scheduled Report',
    prompt: 'Every day at 9 AM, fetch sales data from the database, generate a summary report using AI, and send it via email',
  },
  {
    icon: Database,
    title: 'Data Sync',
    prompt: 'When a webhook is received from Stripe, update the customer record in the database and send a confirmation email',
  },
  {
    icon: Globe,
    title: 'API Integration',
    prompt: 'Create a workflow that receives order data via webhook, validates it, stores in database, and calls an external shipping API',
  },
  {
    icon: Bot,
    title: 'AI Processing',
    prompt: 'When a support ticket is submitted, use AI to classify its priority and sentiment, then route to the appropriate team',
  },
  {
    icon: GitBranch,
    title: 'Conditional Logic',
    prompt: 'Process incoming data, if value is above threshold send urgent notification, otherwise log for daily digest',
  },
];

export const AIWorkflowGenerator: React.FC<AIWorkflowGeneratorProps> = ({
  onWorkflowGenerated,
  isOpen,
  onToggle,
}) => {
  const [prompt, setPrompt] = useState('');
  const [isGenerating, setIsGenerating] = useState(false);
  const [generatedWorkflow, setGeneratedWorkflow] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [showExamples, setShowExamples] = useState(true);

  const handleGenerate = async () => {
    if (!prompt.trim() || isGenerating) return;
    
    setIsGenerating(true);
    setError(null);
    setGeneratedWorkflow(null);

    try {
      // Call the AI service
      const response = await fetch(`${BACKEND_URL}/api/v1/ai/generate-workflow`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer demo-token',
        },
        body: JSON.stringify({ description: prompt }),
      });

      const result = await response.json();

      if (result.success && result.data) {
        setGeneratedWorkflow(result.data);
        setShowExamples(false);
      } else {
        setError(result.error || 'Failed to generate workflow');
      }
    } catch (err: any) {
      // Fallback to client-side generation using Gemini directly
      try {
        const workflow = await generateWorkflowLocally(prompt);
        setGeneratedWorkflow(workflow);
        setShowExamples(false);
      } catch (localErr: any) {
        setError('Failed to connect to AI service. Please ensure the backend is running.');
      }
    } finally {
      setIsGenerating(false);
    }
  };

  const handleApply = () => {
    if (generatedWorkflow) {
      onWorkflowGenerated(generatedWorkflow);
      setGeneratedWorkflow(null);
      setPrompt('');
    }
  };

  const handleExampleClick = (examplePrompt: string) => {
    setPrompt(examplePrompt);
    setShowExamples(false);
  };

  if (!isOpen) {
    return (
      <button
        onClick={onToggle}
        className="fixed left-4 top-24 z-50 flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-purple-600 to-pink-600 rounded-lg text-white font-medium shadow-lg hover:shadow-purple-500/25 transition-all"
      >
        <Wand2 size={18} />
        AI Builder
      </button>
    );
  }

  return (
    <div className="fixed left-0 top-16 bottom-0 w-96 bg-gray-900/95 backdrop-blur-xl border-r border-gray-700/50 z-40 flex flex-col shadow-2xl">
      {/* Header */}
      <div className="p-4 border-b border-gray-700/50 bg-gradient-to-r from-purple-900/30 to-pink-900/30">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-purple-500 to-pink-500 flex items-center justify-center shadow-lg">
              <Sparkles size={20} className="text-white" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-white">AI Workflow Builder</h2>
              <p className="text-xs text-gray-400">Describe what you want to automate</p>
            </div>
          </div>
          <button
            onClick={onToggle}
            className="p-2 hover:bg-gray-700/50 rounded-lg transition-colors"
          >
            <X size={18} className="text-gray-400" />
          </button>
        </div>
      </div>

      {/* Main Content */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {/* Input Area */}
        <div className="space-y-3">
          <div className="relative">
            <textarea
              value={prompt}
              onChange={(e) => setPrompt(e.target.value)}
              placeholder="Describe your workflow in plain English...&#10;&#10;Example: When someone submits a contact form, send them an email and notify my team on Slack"
              className="w-full h-32 px-4 py-3 bg-gray-800/80 border border-gray-600/50 rounded-xl text-white placeholder-gray-500 resize-none focus:outline-none focus:ring-2 focus:ring-purple-500/50 focus:border-purple-500/50 transition-all"
              disabled={isGenerating}
            />
            <div className="absolute bottom-3 right-3 text-xs text-gray-500">
              {prompt.length}/500
            </div>
          </div>

          <button
            onClick={handleGenerate}
            disabled={!prompt.trim() || isGenerating}
            className="w-full flex items-center justify-center gap-2 px-4 py-3 bg-gradient-to-r from-purple-600 to-pink-600 rounded-xl text-white font-medium disabled:opacity-50 disabled:cursor-not-allowed hover:shadow-lg hover:shadow-purple-500/25 transition-all"
          >
            {isGenerating ? (
              <>
                <Loader2 size={18} className="animate-spin" />
                Generating Workflow...
              </>
            ) : (
              <>
                <Wand2 size={18} />
                Generate Workflow
              </>
            )}
          </button>
        </div>

        {/* Error Display */}
        {error && (
          <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400 text-sm">
            {error}
          </div>
        )}

        {/* Generated Workflow Preview */}
        {generatedWorkflow && (
          <div className="space-y-3">
            <div className="p-4 bg-gray-800/50 border border-green-500/30 rounded-xl">
              <div className="flex items-center gap-2 mb-3">
                <Check size={16} className="text-green-400" />
                <span className="text-green-400 font-medium">Workflow Generated!</span>
              </div>
              
              <h3 className="text-white font-semibold mb-1">{generatedWorkflow.name}</h3>
              <p className="text-gray-400 text-sm mb-3">{generatedWorkflow.description}</p>

              <div className="space-y-2 mb-4">
                <div className="text-xs text-gray-500 uppercase tracking-wide">Nodes</div>
                <div className="flex flex-wrap gap-2">
                  {generatedWorkflow.nodes?.map((node: any, i: number) => (
                    <div
                      key={i}
                      className="px-2 py-1 bg-gray-700/50 rounded text-xs text-gray-300"
                    >
                      {node.name || node.type}
                    </div>
                  ))}
                </div>
              </div>

              <div className="flex gap-2">
                <button
                  onClick={handleApply}
                  className="flex-1 flex items-center justify-center gap-2 px-4 py-2 bg-green-600 hover:bg-green-500 rounded-lg text-white font-medium transition-colors"
                >
                  <Zap size={16} />
                  Apply to Canvas
                </button>
                <button
                  onClick={() => setGeneratedWorkflow(null)}
                  className="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-gray-300 transition-colors"
                >
                  Discard
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Example Prompts */}
        {showExamples && !generatedWorkflow && (
          <div className="space-y-3">
            <button
              onClick={() => setShowExamples(!showExamples)}
              className="flex items-center gap-2 text-sm text-gray-400 hover:text-white transition-colors"
            >
              <span>Example Workflows</span>
              {showExamples ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
            </button>

            <div className="grid gap-2">
              {EXAMPLE_PROMPTS.map((example, i) => (
                <button
                  key={i}
                  onClick={() => handleExampleClick(example.prompt)}
                  className="flex items-start gap-3 p-3 bg-gray-800/50 hover:bg-gray-700/50 border border-gray-700/50 hover:border-purple-500/30 rounded-lg text-left transition-all group"
                >
                  <div className="w-8 h-8 rounded-lg bg-gray-700/50 group-hover:bg-purple-500/20 flex items-center justify-center flex-shrink-0 transition-colors">
                    <example.icon size={16} className="text-gray-400 group-hover:text-purple-400" />
                  </div>
                  <div>
                    <div className="text-sm font-medium text-white">{example.title}</div>
                    <div className="text-xs text-gray-500 line-clamp-2">{example.prompt}</div>
                  </div>
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Tips Section */}
        <div className="p-4 bg-gray-800/30 rounded-xl border border-gray-700/30">
          <h4 className="text-sm font-medium text-gray-300 mb-2">💡 Tips for better results</h4>
          <ul className="text-xs text-gray-500 space-y-1">
            <li>• Be specific about triggers (webhook, schedule, form)</li>
            <li>• Mention the services you want to connect</li>
            <li>• Describe any conditions or branching logic</li>
            <li>• Specify what should happen at each step</li>
          </ul>
        </div>
      </div>
    </div>
  );
};

// Fallback local generation using the Gemini service directly
async function generateWorkflowLocally(prompt: string): Promise<any> {
  // Import the gemini service
  const { generateAgentResponse } = await import('../services/geminiService');
  
  const systemPrompt = `You are a workflow automation expert. Given a description of a workflow, generate a JSON structure representing the workflow.

The workflow JSON should have this structure:
{
  "name": "Workflow Name",
  "description": "What this workflow does",
  "nodes": [
    {
      "id": "unique_id",
      "type": "NODE_TYPE",
      "name": "Display Name",
      "position": { "x": number, "y": number },
      "config": { /* node-specific configuration */ }
    }
  ],
  "edges": [
    {
      "id": "edge_id",
      "source": "source_node_id",
      "target": "target_node_id"
    }
  ]
}

Available node types:
TRIGGERS: TRIGGER_MANUAL, TRIGGER_WEBHOOK, TRIGGER_SCHEDULE
ACTIONS: ACTION_HTTP, ACTION_EMAIL, ACTION_CODE, ACTION_SET, ACTION_FILTER, ACTION_SWITCH, ACTION_LOOP, ACTION_WAIT
AI: ACTION_AI_CHAT, ACTION_AI_SUMMARIZE, ACTION_AI_CLASSIFY, ACTION_AI_TRANSFORM
INTEGRATIONS: ACTION_SLACK, ACTION_DISCORD, ACTION_DATABASE, ACTION_GOOGLE_SHEETS

Position nodes in a logical left-to-right flow, starting triggers at x=100, with subsequent nodes at increments of 300.
Return ONLY valid JSON, no markdown or explanation.`;

  const response = await generateAgentResponse(
    `Create a workflow for: ${prompt}`,
    systemPrompt,
    'gemini-2.5-flash'
  );

  // Try to extract JSON from the response
  let jsonStr = response;
  const jsonMatch = response.match(/```json\s*([\s\S]*?)\s*```/) || response.match(/```\s*([\s\S]*?)\s*```/);
  if (jsonMatch) {
    jsonStr = jsonMatch[1];
  }

  return JSON.parse(jsonStr);
}

export default AIWorkflowGenerator;
