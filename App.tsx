
import React, { useState, useEffect } from 'react';
import { Layout } from './components/Layout';
import { Landing } from './components/Landing';
import { Builder } from './components/Builder';
import { Deployments } from './components/Deployments';
import { Auth } from './components/Auth';
import { InfoPage } from './components/InfoPage';
import { Profile } from './components/Profile';
import { ExecutionDashboard } from './components/ExecutionDashboard';
import { View, User, WorkflowNode, WorkflowEdge, NodeType } from './types';
import { storageService } from './services/storageService';

// --- DATA PERSISTENCE LAYER ---
const DB_KEY = 'aether_core_db_v1';

// Load the entire database from local storage
const loadDB = (): Record<string, any> => {
  try {
    const data = localStorage.getItem(DB_KEY);
    return data ? JSON.parse(data) : {};
  } catch (e) {
    console.error("Database corruption detected", e);
    return {};
  }
};

// Save the entire database
const saveDB = (data: Record<string, any>) => {
  localStorage.setItem(DB_KEY, JSON.stringify(data));
};

const App: React.FC = () => {
  const [currentView, setCurrentView] = useState<View>('LANDING');
  const [user, setUser] = useState<User | null>(null);

  // --- WORKFLOW STATE ---
  // Default state for guest/new workspace
  const [nodes, setNodes] = useState<WorkflowNode[]>([
    { id: '1', type: NodeType.TRIGGER, position: { x: 100, y: 300 }, data: { label: 'Webhook Trigger', output: 'Start workflow' } },
  ]);
  const [edges, setEdges] = useState<WorkflowEdge[]>([]);

  // 1. Session Restoration on Mount & OAuth Callback Handling
  useEffect(() => {
    // Check for OAuth callback token in URL
    const urlParams = new URLSearchParams(window.location.search);
    const token = urlParams.get('token');
    const oauthError = urlParams.get('error');
    const errorMessage = urlParams.get('message');
    
    if (oauthError) {
      console.error('OAuth error:', oauthError, errorMessage);
      // Clean URL
      window.history.replaceState({}, document.title, window.location.pathname);
    }
    
    if (token) {
      // OAuth callback - decode JWT token directly (no backend call needed)
      try {
        // Decode JWT payload (middle part)
        const parts = token.split('.');
        if (parts.length === 3) {
          const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
          console.log('OAuth token payload:', payload);
          
          const oauthUser: User = {
            id: payload.id,
            name: payload.name || payload.email?.split('@')[0] || 'User',
            email: payload.email,
            avatar: payload.avatar || payload.picture || `https://api.dicebear.com/7.x/shapes/svg?seed=${payload.email}`,
            token: token,
            joinedAt: new Date().toLocaleDateString('en-US', { month: 'short', year: '2-digit' })
          };
          console.log('Created OAuth user:', oauthUser);
          handleLogin(oauthUser);
        } else {
          console.error('Invalid token format');
        }
      } catch (err) {
        console.error('Failed to decode OAuth token:', err);
      } finally {
        // Clean URL regardless of result
        window.history.replaceState({}, document.title, window.location.pathname);
      }
      return;
    }
    
    // Normal session restoration
    const storedUserSession = localStorage.getItem('aether_user_session');
    if (storedUserSession) {
      try {
        const parsedUser = JSON.parse(storedUserSession);
        setUser(parsedUser);
        
        // Restore their data from the "Database"
        const db = loadDB();
        const userData = db[parsedUser.email];
        if (userData) {
           if (userData.nodes) setNodes(userData.nodes);
           if (userData.edges) setEdges(userData.edges);
           // Update user profile from DB just in case
           if (userData.user) setUser(userData.user);
        }
      } catch (e) {
        console.error("Failed to parse user session", e);
        localStorage.removeItem('aether_user_session');
      }
    }
  }, []);

  // 2. Data Auto-Save Logic
  useEffect(() => {
    if (user && user.email) {
       const db = loadDB();
       // Update the entry for this user
       db[user.email] = {
          user: user, // Keep profile up to date
          nodes: nodes,
          edges: edges,
          lastUpdated: new Date().toISOString()
       };
       saveDB(db);
    }
  }, [nodes, edges, user]);

  const handleLogin = (incomingUser: User) => {
    const db = loadDB();
    const existingData = db[incomingUser.email];

    // Initialize user data in the new storage service
    if (!storageService.getUserData(incomingUser.email)) {
      storageService.initUserData(incomingUser);
    }

    if (existingData) {
        // --- LOGIN: Restore existing state ---
        console.log("Restoring existing user profile:", incomingUser.email);
        setUser(existingData.user); // Use stored user data to preserve joinedAt etc
        setNodes(existingData.nodes || []);
        setEdges(existingData.edges || []);
        // Update session
        localStorage.setItem('aether_user_session', JSON.stringify(existingData.user));
    } else {
        // --- SIGNUP: Create new state, merging current workspace ---
        console.log("Creating new user profile with current workspace:", incomingUser.email);
        
        // We save the CURRENT nodes/edges to the new user's profile
        // This effectively "claims" the guest work for the new account
        const newData = {
            user: incomingUser,
            nodes: nodes,
            edges: edges,
            created: new Date().toISOString()
        };
        
        db[incomingUser.email] = newData;
        saveDB(db);
        
        setUser(incomingUser);
        localStorage.setItem('aether_user_session', JSON.stringify(incomingUser));
    }
    
    setCurrentView('BUILDER');
  };

  const handleLogout = () => {
    setUser(null);
    localStorage.removeItem('aether_user_session');
    // Reset workspace to default for the next "guest"
    setNodes([{ id: '1', type: NodeType.TRIGGER, position: { x: 100, y: 300 }, data: { label: 'Webhook Trigger', output: 'Start workflow' } }]);
    setEdges([]);
    setCurrentView('LANDING');
  };

  const renderView = () => {
    switch (currentView) {
      case 'LANDING':
        return <Landing onStart={() => setCurrentView(user ? 'BUILDER' : 'AUTH')} onNavigate={setCurrentView} user={user} />;
      case 'AUTH':
        return <Auth onLogin={handleLogin} />;
      case 'BUILDER':
        return (
          <Builder 
            onNavigate={setCurrentView} 
            nodes={nodes}
            setNodes={setNodes}
            edges={edges}
            setEdges={setEdges}
            user={user}
          />
        );
      case 'DEPLOYMENTS':
        return (
          <Deployments 
            onNavigate={setCurrentView} 
            nodes={nodes} 
            edges={edges}
            user={user}
            onEditWorkflow={(workflowId) => {
              // Load workflow from storage and switch to builder
              if (user?.email) {
                const workflows = storageService.getWorkflows(user.email);
                const workflow = workflows.find(w => w.id === workflowId);
                if (workflow) {
                  setNodes(workflow.nodes);
                  setEdges(workflow.edges);
                  setCurrentView('BUILDER');
                }
              }
            }}
          />
        );
      
      case 'EXECUTIONS':
        return <ExecutionDashboard onNavigate={setCurrentView} user={user} />;
      
      case 'PROFILE':
        return user ? <Profile user={user} onNavigate={setCurrentView} nodes={nodes} /> : <Auth onLogin={handleLogin} />;

      // Architecture & Platform Pages
      case 'ARCHITECTURE':
      case 'PLATFORM_OBSERVABILITY':
      case 'PLATFORM_EVALUATIONS':
      case 'PLATFORM_PROMPT_CHAIN':
      case 'PLATFORM_CHANGELOG':
      // Resources Pages
      case 'RESOURCES_DOCS':
      case 'RESOURCES_API':
      case 'RESOURCES_COMMUNITY':
      case 'RESOURCES_HELP':
      // Company Pages
      case 'COMPANY_ABOUT':
      case 'COMPANY_ENTERPRISE':
      case 'COMPANY_CAREERS':
      case 'COMPANY_LEGAL':
        return <InfoPage view={currentView} onNavigate={setCurrentView} />;
        
      default:
        return <Landing onStart={() => setCurrentView(user ? 'BUILDER' : 'AUTH')} onNavigate={setCurrentView} user={user} />;
    }
  };

  return (
    <Layout currentView={currentView} setCurrentView={setCurrentView} user={user} onLogout={handleLogout}>
      {renderView()}
    </Layout>
  );
};

export default App;
