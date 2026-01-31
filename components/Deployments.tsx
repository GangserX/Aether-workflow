import React, { useState, useEffect } from 'react';
import { 
  Globe, Clock, CheckCircle, Activity, MoreHorizontal, ArrowUpRight, 
  Play, Archive, Edit, Zap, Power, PowerOff, Copy, ExternalLink,
  Trash2, Settings, RefreshCw, TrendingUp, AlertCircle, X,
  Webhook, Calendar, MousePointer
} from 'lucide-react';
import { View, WorkflowNode, WorkflowEdge, NodeType, User } from '../types';
import { storageService, Workflow, Deployment } from '../services/storageService';

interface DeploymentsProps {
  onNavigate: (view: View) => void;
  nodes: WorkflowNode[];
  edges: WorkflowEdge[];
  user: User | null;
  onEditWorkflow?: (workflowId: string) => void;
}

export const Deployments: React.FC<DeploymentsProps> = ({ onNavigate, nodes, edges, user, onEditWorkflow }) => {
  const [deployments, setDeployments] = useState<Deployment[]>([]);
  const [workflows, setWorkflows] = useState<Workflow[]>([]);
  const [openMenuId, setOpenMenuId] = useState<string | null>(null);
  const [showSaveModal, setShowSaveModal] = useState(false);
  const [newWorkflowName, setNewWorkflowName] = useState('');
  const [copiedEndpoint, setCopiedEndpoint] = useState<string | null>(null);
  const [showSelectWorkflowModal, setShowSelectWorkflowModal] = useState(false);
  const [selectedWorkflowId, setSelectedWorkflowId] = useState<string | null>(null);

  // Load data from storage
  useEffect(() => {
    if (user?.email) {
      const userData = storageService.getUserData(user.email);
      if (userData) {
        setDeployments(userData.deployments || []);
        setWorkflows(userData.workflows || []);
      }
      
      // Subscribe to updates
      const unsubscribe = storageService.subscribe(user.email, (data) => {
        setDeployments(data.deployments || []);
        setWorkflows(data.workflows || []);
      });
      
      return () => unsubscribe();
    }
  }, [user]);

  const toggleMenu = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setOpenMenuId(openMenuId === id ? null : id);
  };

  const handleClickOutside = () => {
    if (openMenuId) setOpenMenuId(null);
  };

  const handleToggleDeployment = (deploymentId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (user?.email) {
      storageService.toggleDeployment(user.email, deploymentId);
    }
    setOpenMenuId(null);
  };

  const handleDeleteDeployment = (deployment: Deployment, e: React.MouseEvent) => {
    e.stopPropagation();
    if (user?.email && confirm(`Are you sure you want to delete "${deployment.name}"?`)) {
      storageService.deleteWorkflow(user.email, deployment.workflowId);
    }
    setOpenMenuId(null);
  };

  const handleSaveCurrentWorkflow = () => {
    if (!user?.email || !newWorkflowName.trim()) return;
    
    const workflowId = `wf_${Date.now()}`;
    const workflow = storageService.createWorkflowFromBuilder(
      workflowId,
      newWorkflowName.trim(),
      nodes,
      edges
    );
    
    storageService.saveWorkflow(user.email, workflow);
    storageService.createDeployment(user.email, workflow);
    
    setShowSaveModal(false);
    setNewWorkflowName('');
  };

  const handleDeploySelectedWorkflow = () => {
    if (!user?.email || !selectedWorkflowId) return;
    
    const workflow = workflows.find(w => w.id === selectedWorkflowId);
    if (!workflow) return;
    
    // Check if already deployed
    const existingDeployment = deployments.find(d => d.workflowId === workflow.id);
    if (existingDeployment) {
      alert('This workflow is already deployed!');
      return;
    }
    
    storageService.createDeployment(user.email, workflow);
    setShowSelectWorkflowModal(false);
    setSelectedWorkflowId(null);
  };

  const handleClearAllDeployments = () => {
    if (!user?.email) return;
    if (!confirm('Are you sure you want to clear ALL deployments? This cannot be undone.')) return;
    
    deployments.forEach(d => {
      storageService.deleteWorkflow(user.email!, d.workflowId);
    });
  };

  const handleCopyEndpoint = (endpoint: string, deploymentId: string) => {
    const fullUrl = `http://localhost:8080${endpoint}`;
    navigator.clipboard.writeText(fullUrl);
    setCopiedEndpoint(deploymentId);
    setTimeout(() => setCopiedEndpoint(null), 2000);
  };

  const handleTestEndpoint = async (deployment: Deployment) => {
    const fullUrl = `http://localhost:8080${deployment.endpoint}`;
    try {
      const response = await fetch(fullUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ test: true, timestamp: new Date().toISOString() }),
      });
      const data = await response.json();
      alert(`Test successful!\nStatus: ${response.status}\nResponse: ${JSON.stringify(data, null, 2)}`);
    } catch (error) {
      alert(`Test failed: ${error}`);
    }
    setOpenMenuId(null);
  };

  // Calculate stats
  const activeDeployments = deployments.filter(d => d.isActive);
  const totalRequests = deployments.reduce((sum, d) => sum + (d.stats?.totalRequests || 0), 0);
  const avgLatency = deployments.length > 0 
    ? Math.round(deployments.reduce((sum, d) => sum + (d.stats?.avgLatency || 0), 0) / deployments.length)
    : 0;
  const errorRate = totalRequests > 0
    ? ((deployments.reduce((sum, d) => sum + (d.stats?.errorCount || 0), 0) / totalRequests) * 100).toFixed(2)
    : '0.00';

  const getTriggerIcon = (workflow?: Workflow) => {
    if (!workflow) return <Globe className="w-4 h-4 text-blue-400" />;
    switch (workflow.triggerType) {
      case 'webhook': return <Webhook className="w-4 h-4 text-purple-400" />;
      case 'schedule': return <Calendar className="w-4 h-4 text-amber-400" />;
      case 'manual': return <MousePointer className="w-4 h-4 text-green-400" />;
      default: return <Zap className="w-4 h-4 text-blue-400" />;
    }
  };

  return (
    <div className="w-full max-w-screen-xl mx-auto px-6 py-12 pt-28" onClick={handleClickOutside}>
      <div className="flex items-center justify-between mb-12">
        <div>
          <h1 className="font-display text-4xl font-bold text-white mb-2">Deployments</h1>
          <p className="text-gray-400">Manage your active agent endpoints and webhooks.</p>
        </div>
        <div className="flex gap-3">
          {deployments.length > 0 && (
            <button 
              onClick={handleClearAllDeployments}
              className="bg-red-500/10 text-red-400 px-4 py-3 rounded-xl font-bold text-sm uppercase tracking-wide hover:bg-red-500/20 transition-colors border border-red-500/20"
            >
              <Trash2 className="w-4 h-4 inline mr-2" />
              Clear All
            </button>
          )}
          {nodes.length > 0 && (
            <button 
              onClick={() => setShowSaveModal(true)}
              className="bg-white/10 text-white px-6 py-3 rounded-xl font-bold text-sm uppercase tracking-wide hover:bg-white/20 transition-colors border border-white/10"
            >
              Deploy Current Workflow
            </button>
          )}
          {workflows.length > 0 && (
            <button 
              onClick={() => setShowSelectWorkflowModal(true)}
              className="bg-fuchsia-500/20 text-fuchsia-400 px-6 py-3 rounded-xl font-bold text-sm uppercase tracking-wide hover:bg-fuchsia-500/30 transition-colors border border-fuchsia-500/30"
            >
              Deploy Saved Workflow
            </button>
          )}
          <button 
            onClick={() => onNavigate('BUILDER')}
            className="bg-white text-black px-6 py-3 rounded-xl font-bold text-sm uppercase tracking-wide hover:bg-fuchsia-100 transition-colors"
          >
            New Deployment
          </button>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-12">
        <div className="p-6 glass-panel rounded-2xl">
          <div className="text-xs font-bold text-gray-500 uppercase tracking-wider mb-2">Total Requests (24h)</div>
          <div className="text-3xl font-display text-white">{totalRequests.toLocaleString()}</div>
          <div className="mt-2 text-xs text-green-400 flex items-center gap-1">
            <ArrowUpRight className="w-3 h-3" /> +12%
          </div>
        </div>
        <div className="p-6 glass-panel rounded-2xl">
          <div className="text-xs font-bold text-gray-500 uppercase tracking-wider mb-2">Avg Latency</div>
          <div className="text-3xl font-display text-white">{avgLatency > 0 ? `${avgLatency}ms` : '-'}</div>
          <div className="mt-2 text-xs text-gray-500">Global Avg</div>
        </div>
        <div className="p-6 glass-panel rounded-2xl">
          <div className="text-xs font-bold text-gray-500 uppercase tracking-wider mb-2">Error Rate</div>
          <div className="text-3xl font-display text-white">{errorRate}%</div>
          <div className="mt-2 text-xs text-green-400">
            {parseFloat(errorRate) < 1 ? 'Optimal' : 'Needs Attention'}
          </div>
        </div>
        <div className="p-6 glass-panel rounded-2xl">
          <div className="text-xs font-bold text-gray-500 uppercase tracking-wider mb-2">Active Deployments</div>
          <div className="text-3xl font-display text-white">{activeDeployments.length}</div>
          <div className="mt-2 text-xs text-gray-500">{deployments.length} total</div>
        </div>
      </div>

      {/* Deployments Table */}
      <div className="glass-panel rounded-3xl overflow-visible">
        <div className="grid grid-cols-12 gap-4 p-6 border-b border-white/10 text-xs font-bold text-gray-500 uppercase tracking-wider bg-white/[0.02]">
          <div className="col-span-3">Workflow Name</div>
          <div className="col-span-3">Endpoint</div>
          <div className="col-span-2">Status</div>
          <div className="col-span-1">Latency</div>
          <div className="col-span-1">Uptime</div>
          <div className="col-span-1">Toggle</div>
          <div className="col-span-1 text-right">Actions</div>
        </div>

        {deployments.length === 0 ? (
          <div className="p-12 text-center">
            <div className="w-16 h-16 bg-white/5 rounded-full flex items-center justify-center mx-auto mb-4">
              <Globe className="w-8 h-8 text-gray-600" />
            </div>
            <p className="text-gray-500 mb-4">No deployments yet. Create and deploy a workflow to get started.</p>
            <button 
              onClick={() => onNavigate('BUILDER')}
              className="text-sm text-fuchsia-400 hover:text-fuchsia-300 font-medium"
            >
              Go to Builder →
            </button>
          </div>
        ) : (
          deployments.map((deployment) => {
            const workflow = workflows.find(w => w.id === deployment.workflowId);
            const nodeCount = workflow?.nodes.length || 0;
            
            return (
              <div 
                key={deployment.id}
                className="grid grid-cols-12 gap-4 p-6 border-b border-white/5 items-center hover:bg-white/[0.04] transition-colors group relative"
              >
                {/* Workflow Name */}
                <div 
                  className="col-span-3 flex items-center gap-3 cursor-pointer"
                  onClick={() => onEditWorkflow?.(deployment.workflowId)}
                >
                  <div className={`w-8 h-8 rounded-lg flex items-center justify-center border transition-colors ${
                    deployment.isActive 
                      ? 'bg-white/5 border-white/10 group-hover:border-fuchsia-500/50' 
                      : 'bg-gray-900 border-gray-700'
                  }`}>
                    {getTriggerIcon(workflow)}
                  </div>
                  <div>
                    <div className={`text-sm font-bold transition-colors flex items-center gap-2 ${
                      deployment.isActive ? 'text-white group-hover:text-fuchsia-400' : 'text-gray-500'
                    }`}>
                      {deployment.name}
                      {nodeCount > 1 && (
                        <span className="text-[10px] bg-white/10 px-1.5 py-0.5 rounded text-gray-400">
                          Pipeline
                        </span>
                      )}
                    </div>
                    <div className="text-xs text-gray-500 font-mono flex items-center gap-1">
                      {deployment.id.substring(0, 12)}... • {nodeCount} nodes
                    </div>
                  </div>
                </div>

                {/* Endpoint */}
                <div className="col-span-3">
                  <div className="flex items-center gap-2">
                    <div className="text-xs text-gray-400 font-mono truncate max-w-[180px] bg-black/30 px-2 py-1 rounded">
                      {deployment.endpoint}
                    </div>
                    <button
                      onClick={() => handleCopyEndpoint(deployment.endpoint, deployment.id)}
                      className="p-1 hover:bg-white/10 rounded transition-colors"
                      title="Copy endpoint"
                    >
                      {copiedEndpoint === deployment.id ? (
                        <CheckCircle className="w-3 h-3 text-green-400" />
                      ) : (
                        <Copy className="w-3 h-3 text-gray-500 hover:text-white" />
                      )}
                    </button>
                  </div>
                </div>

                {/* Status */}
                <div className="col-span-2">
                  <div className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold border ${
                    deployment.isActive
                      ? 'bg-green-500/10 border-green-500/20 text-green-400'
                      : 'bg-gray-500/10 border-gray-500/20 text-gray-400'
                  }`}>
                    <div className={`w-1.5 h-1.5 rounded-full ${
                      deployment.isActive ? 'bg-green-400' : 'bg-gray-400'
                    }`} />
                    {deployment.isActive ? 'Active' : 'Disabled'}
                  </div>
                </div>

                {/* Latency */}
                <div className="col-span-1 text-sm text-white font-mono">
                  {deployment.stats?.avgLatency || '-'}ms
                </div>

                {/* Uptime */}
                <div className="col-span-1 text-sm text-white font-mono">
                  {deployment.stats?.uptime || 100}%
                </div>

                {/* Toggle */}
                <div className="col-span-1">
                  <button
                    onClick={(e) => handleToggleDeployment(deployment.id, e)}
                    className={`p-2 rounded-lg transition-all ${
                      deployment.isActive
                        ? 'bg-green-500/20 text-green-400 hover:bg-green-500/30'
                        : 'bg-gray-500/20 text-gray-400 hover:bg-gray-500/30'
                    }`}
                    title={deployment.isActive ? 'Disable' : 'Enable'}
                  >
                    {deployment.isActive ? <Power className="w-4 h-4" /> : <PowerOff className="w-4 h-4" />}
                  </button>
                </div>

                {/* Actions */}
                <div className="col-span-1 text-right relative">
                  <button 
                    className={`transition-colors p-2 rounded hover:bg-white/10 ${
                      openMenuId === deployment.id ? 'text-white' : 'text-gray-500'
                    }`}
                    onClick={(e) => toggleMenu(deployment.id, e)}
                  >
                    <MoreHorizontal className="w-5 h-5 ml-auto" />
                  </button>

                  {/* Dropdown Menu */}
                  {openMenuId === deployment.id && (
                    <div className="absolute right-0 top-10 w-48 glass-panel rounded-xl shadow-2xl z-50 border border-white/10 overflow-hidden animate-in fade-in zoom-in-95 duration-200">
                      <div className="flex flex-col py-1">
                        <button 
                          onClick={() => { onEditWorkflow?.(deployment.workflowId); setOpenMenuId(null); }}
                          className="text-left px-4 py-3 text-xs font-bold text-gray-300 hover:text-white hover:bg-white/10 flex items-center gap-2"
                        >
                          <Edit className="w-3 h-3" /> Edit Workflow
                        </button>
                        <button 
                          onClick={() => handleTestEndpoint(deployment)}
                          className="text-left px-4 py-3 text-xs font-bold text-gray-300 hover:text-white hover:bg-white/10 flex items-center gap-2"
                        >
                          <Play className="w-3 h-3 text-green-400" /> Test Endpoint
                        </button>
                        <button 
                          onClick={() => { handleCopyEndpoint(deployment.endpoint, deployment.id); setOpenMenuId(null); }}
                          className="text-left px-4 py-3 text-xs font-bold text-gray-300 hover:text-white hover:bg-white/10 flex items-center gap-2"
                        >
                          <Copy className="w-3 h-3" /> Copy URL
                        </button>
                        <div className="h-px bg-white/5 my-1" />
                        <button 
                          onClick={(e) => handleToggleDeployment(deployment.id, e)}
                          className="text-left px-4 py-3 text-xs font-bold text-gray-300 hover:text-white hover:bg-white/10 flex items-center gap-2"
                        >
                          {deployment.isActive ? (
                            <><PowerOff className="w-3 h-3 text-amber-400" /> Disable</>
                          ) : (
                            <><Power className="w-3 h-3 text-green-400" /> Enable</>
                          )}
                        </button>
                        <div className="h-px bg-white/5 my-1" />
                        <button 
                          onClick={(e) => handleDeleteDeployment(deployment, e)}
                          className="text-left px-4 py-3 text-xs font-bold text-red-400 hover:bg-red-500/10 flex items-center gap-2"
                        >
                          <Trash2 className="w-3 h-3" /> Delete
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* Save Workflow Modal */}
      {showSaveModal && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center z-50 animate-in fade-in duration-200">
          <div className="glass-panel rounded-3xl p-8 w-full max-w-md animate-in zoom-in-95 duration-200">
            <div className="flex items-center justify-between mb-6">
              <h2 className="font-display text-2xl font-bold text-white">Deploy Workflow</h2>
              <button 
                onClick={() => setShowSaveModal(false)}
                className="text-gray-500 hover:text-white transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>
            
            <div className="space-y-4">
              <div>
                <label className="text-xs font-bold text-gray-400 uppercase tracking-wider mb-2 block">
                  Workflow Name
                </label>
                <input
                  type="text"
                  value={newWorkflowName}
                  onChange={(e) => setNewWorkflowName(e.target.value)}
                  placeholder="e.g., Customer Onboarding Pipeline"
                  className="w-full bg-black/50 border border-white/10 p-3 text-sm text-white focus:border-fuchsia-500 focus:outline-none rounded-xl"
                  autoFocus
                />
              </div>
              
              <div className="p-4 bg-white/5 rounded-xl">
                <div className="text-xs text-gray-400 mb-2">This workflow contains:</div>
                <div className="text-sm text-white font-medium">{nodes.length} nodes, {edges.length} connections</div>
              </div>
              
              <div className="flex gap-3 pt-4">
                <button
                  onClick={() => setShowSaveModal(false)}
                  className="flex-1 py-3 bg-white/5 text-gray-400 rounded-xl font-bold text-sm hover:bg-white/10 transition-colors"
                >
                  Cancel
                </button>
                <button
                  onClick={handleSaveCurrentWorkflow}
                  disabled={!newWorkflowName.trim()}
                  className="flex-1 py-3 bg-fuchsia-500 text-white rounded-xl font-bold text-sm hover:bg-fuchsia-400 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  Deploy
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Select Saved Workflow Modal */}
      {showSelectWorkflowModal && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center z-50 animate-in fade-in duration-200">
          <div className="glass-panel rounded-3xl p-8 w-full max-w-lg animate-in zoom-in-95 duration-200">
            <div className="flex items-center justify-between mb-6">
              <h2 className="font-display text-2xl font-bold text-white">Deploy Saved Workflow</h2>
              <button 
                onClick={() => { setShowSelectWorkflowModal(false); setSelectedWorkflowId(null); }}
                className="text-gray-500 hover:text-white transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>
            
            <div className="space-y-4">
              <div>
                <label className="text-xs font-bold text-gray-400 uppercase tracking-wider mb-2 block">
                  Select a Workflow
                </label>
                <div className="max-h-60 overflow-y-auto space-y-2">
                  {workflows.filter(w => !deployments.some(d => d.workflowId === w.id)).map(workflow => (
                    <button
                      key={workflow.id}
                      onClick={() => setSelectedWorkflowId(workflow.id)}
                      className={`w-full text-left p-4 rounded-xl border transition-all ${
                        selectedWorkflowId === workflow.id
                          ? 'bg-fuchsia-500/20 border-fuchsia-500/50 text-white'
                          : 'bg-white/5 border-white/10 text-gray-300 hover:bg-white/10 hover:text-white'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <div>
                          <div className="text-sm font-bold">{workflow.name}</div>
                          <div className="text-xs text-gray-500 mt-1">
                            {workflow.nodes.length} nodes • Created {new Date(workflow.createdAt).toLocaleDateString()}
                          </div>
                        </div>
                        {selectedWorkflowId === workflow.id && (
                          <CheckCircle className="w-5 h-5 text-fuchsia-400" />
                        )}
                      </div>
                    </button>
                  ))}
                  {workflows.filter(w => !deployments.some(d => d.workflowId === w.id)).length === 0 && (
                    <div className="text-center py-8 text-gray-500">
                      <p>No workflows available to deploy.</p>
                      <p className="text-xs mt-2">All workflows are already deployed or you haven't saved any yet.</p>
                    </div>
                  )}
                </div>
              </div>
              
              <div className="flex gap-3 pt-4">
                <button
                  onClick={() => { setShowSelectWorkflowModal(false); setSelectedWorkflowId(null); }}
                  className="flex-1 py-3 bg-white/5 text-gray-400 rounded-xl font-bold text-sm hover:bg-white/10 transition-colors"
                >
                  Cancel
                </button>
                <button
                  onClick={handleDeploySelectedWorkflow}
                  disabled={!selectedWorkflowId}
                  className="flex-1 py-3 bg-fuchsia-500 text-white rounded-xl font-bold text-sm hover:bg-fuchsia-400 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  Deploy Selected
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
