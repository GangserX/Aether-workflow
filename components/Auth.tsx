
import React, { useState } from 'react';
import { Mail, Lock, User, ArrowRight, Github, Chrome, AlertCircle, Eye, EyeOff } from 'lucide-react';
import { User as UserType } from '../types';

interface AuthProps {
  onLogin: (user: UserType) => void;
}

// Local storage keys
const USERS_DB_KEY = 'aether_users_db';

// Simple hash function for password (for demo - in production use bcrypt on backend)
const hashPassword = (password: string): string => {
  let hash = 0;
  for (let i = 0; i < password.length; i++) {
    const char = password.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  return `hash_${Math.abs(hash).toString(36)}_${password.length}`;
};

// Get users database
const getUsersDB = (): Record<string, { name: string; email: string; passwordHash: string; createdAt: string }> => {
  try {
    const data = localStorage.getItem(USERS_DB_KEY);
    return data ? JSON.parse(data) : {};
  } catch {
    return {};
  }
};

// Save user to database
const saveUser = (email: string, name: string, passwordHash: string) => {
  const db = getUsersDB();
  db[email] = {
    name,
    email,
    passwordHash,
    createdAt: new Date().toISOString(),
  };
  localStorage.setItem(USERS_DB_KEY, JSON.stringify(db));
};

export const Auth: React.FC<AuthProps> = ({ onLogin }) => {
  const [isLogin, setIsLogin] = useState(true);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showPassword, setShowPassword] = useState(false);

  // Form State
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    password: ''
  });

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
    if (error) setError(null); // Clear error on typing
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    // Basic Validation
    if (!formData.email || !formData.password) {
      setError("Please provide both email and password.");
      return;
    }

    if (formData.password.length < 6) {
      setError("Password must be at least 6 characters.");
      return;
    }

    if (!isLogin && !formData.name) {
      setError("Full Name is required for account creation.");
      return;
    }

    setIsLoading(true);

    // Simulate network request/authentication delay
    setTimeout(() => {
      setIsLoading(false);
      
      const usersDB = getUsersDB();
      const passwordHash = hashPassword(formData.password);
      
      if (isLogin) {
        // LOGIN - Check if user exists and password matches
        const existingUser = usersDB[formData.email];
        
        if (!existingUser) {
          setError("No account found with this email. Please sign up first.");
          return;
        }
        
        if (existingUser.passwordHash !== passwordHash) {
          setError("Incorrect password. Please try again.");
          return;
        }
        
        // Login successful
        const userProfile: UserType = {
          id: `user_${formData.email.replace(/[^a-zA-Z0-9]/g, '')}`,
          name: existingUser.name,
          email: formData.email,
          avatar: `https://api.dicebear.com/7.x/shapes/svg?seed=${formData.email}`,
          token: `jwt_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
          joinedAt: new Date(existingUser.createdAt).toLocaleDateString('en-US', { month: 'short', year: '2-digit' })
        };
        
        onLogin(userProfile);
        
      } else {
        // SIGNUP - Check if email already exists
        if (usersDB[formData.email]) {
          setError("An account with this email already exists. Please sign in.");
          return;
        }
        
        // Save new user with hashed password
        saveUser(formData.email, formData.name, passwordHash);
        
        const userProfile: UserType = {
          id: `user_${formData.email.replace(/[^a-zA-Z0-9]/g, '')}`,
          name: formData.name,
          email: formData.email,
          avatar: `https://api.dicebear.com/7.x/shapes/svg?seed=${formData.email}`,
          token: `jwt_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
          joinedAt: new Date().toLocaleDateString('en-US', { month: 'short', year: '2-digit' })
        };
        
        onLogin(userProfile);
      }
    }, 1000);
  };

  // OAuth handlers - redirect to Vercel serverless API routes
  const handleGithubAuth = () => {
    // Redirect to GitHub OAuth endpoint (works on both localhost and Vercel)
    window.location.href = '/api/auth/github';
  };

  const handleGoogleAuth = () => {
    // Redirect to Google OAuth endpoint (works on both localhost and Vercel)
    window.location.href = '/api/auth/google';
  };

  return (
    <div className="w-full min-h-[calc(100vh-80px)] flex flex-col items-center justify-center relative overflow-hidden px-6 pt-20">
      {/* Background Decor */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-gradient-to-tr from-cherry/20 to-transparent rounded-full blur-[120px] pointer-events-none" />

      <div className="w-full max-w-md relative z-10 animate-in fade-in zoom-in-95 duration-700">
        
        {/* Rotating Light Border Container */}
        <div className="relative group rounded-3xl">
            {/* The Moving Gradient Layer */}
            <div className="absolute -inset-[1px] rounded-3xl overflow-hidden pointer-events-none">
                <div className="absolute inset-[-50%] bg-[conic-gradient(from_0deg,transparent_0_340deg,#D90429_350deg,#ffffff_360deg)] animate-[spin_3s_linear_infinite] opacity-60"></div>
            </div>
            
            {/* Inner Darkening Layer to ensure text legibility if glass is too transparent */}
            <div className="absolute inset-[1px] bg-black/40 rounded-[22px] pointer-events-none"></div>

            <div className="glass-card p-8 md:p-12 rounded-3xl border-t border-white/10 shadow-2xl relative overflow-hidden backdrop-blur-3xl">
              
              {/* Header */}
              <div className="text-center mb-10">
                <h2 className="font-display text-4xl font-bold text-transparent bg-clip-text bg-gradient-to-br from-white via-cream to-cherry mb-3">
                  {isLogin ? 'Welcome Back' : 'Initialize Identity'}
                </h2>
                <p className="text-gray-400 text-sm font-sans">
                  {isLogin ? 'Authenticate to access the neural mesh.' : 'Join the architects of the new intelligence.'}
                </p>
              </div>

              {/* Social Auth */}
              <div className="grid grid-cols-2 gap-4 mb-8">
                <button type="button" onClick={handleGithubAuth} className="flex items-center justify-center gap-2 py-3 px-4 bg-white/5 hover:bg-white/10 border border-white/10 rounded-xl transition-all group">
                  <Github className="w-4 h-4 text-gray-400 group-hover:text-white" />
                  <span className="text-xs font-bold text-gray-400 group-hover:text-white uppercase tracking-wider">Github</span>
                </button>
                <button type="button" onClick={handleGoogleAuth} className="flex items-center justify-center gap-2 py-3 px-4 bg-white/5 hover:bg-white/10 border border-white/10 rounded-xl transition-all group">
                  <Chrome className="w-4 h-4 text-gray-400 group-hover:text-white" />
                  <span className="text-xs font-bold text-gray-400 group-hover:text-white uppercase tracking-wider">Google</span>
                </button>
              </div>

              <div className="relative mb-8">
                <div className="absolute inset-0 flex items-center">
                  <div className="w-full border-t border-white/10"></div>
                </div>
                <div className="relative flex justify-center text-xs uppercase">
                  <span className="bg-[#0c0c0c] px-2 text-gray-500 font-mono tracking-widest">Or Continue With</span>
                </div>
              </div>

              {/* Error Message */}
              {error && (
                <div className="mb-6 p-3 bg-red-500/10 border border-red-500/20 rounded-lg flex items-center gap-2 text-red-400 text-xs font-bold animate-in fade-in slide-in-from-top-2">
                   <AlertCircle className="w-4 h-4" /> {error}
                </div>
              )}

              {/* Form */}
              <form onSubmit={handleSubmit} className="space-y-5">
                {!isLogin && (
                  <div className="group relative">
                    <User className="absolute left-4 top-3.5 w-4 h-4 text-gray-500 group-focus-within:text-cherry transition-colors" />
                    <input 
                      name="name"
                      type="text" 
                      placeholder="Full Name"
                      value={formData.name}
                      onChange={handleInputChange}
                      className="w-full bg-black/40 border border-white/10 rounded-xl py-3 pl-11 pr-4 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-cherry/50 focus:ring-1 focus:ring-cherry/50 transition-all font-sans"
                    />
                  </div>
                )}

                <div className="group relative">
                  <Mail className="absolute left-4 top-3.5 w-4 h-4 text-gray-500 group-focus-within:text-cherry transition-colors" />
                  <input 
                    name="email"
                    type="email" 
                    placeholder="Work Email"
                    value={formData.email}
                    onChange={handleInputChange}
                    className="w-full bg-black/40 border border-white/10 rounded-xl py-3 pl-11 pr-4 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-cherry/50 focus:ring-1 focus:ring-cherry/50 transition-all font-sans"
                  />
                </div>

                <div className="group relative">
                  <Lock className="absolute left-4 top-3.5 w-4 h-4 text-gray-500 group-focus-within:text-cherry transition-colors" />
                  <input 
                    name="password"
                    type={showPassword ? "text" : "password"}
                    placeholder="Password (min. 6 characters)"
                    value={formData.password}
                    onChange={handleInputChange}
                    className="w-full bg-black/40 border border-white/10 rounded-xl py-3 pl-11 pr-11 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-cherry/50 focus:ring-1 focus:ring-cherry/50 transition-all font-sans"
                  />
                  <button 
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-4 top-3.5 text-gray-500 hover:text-white transition-colors"
                  >
                    {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>

                <button 
                  type="submit"
                  disabled={isLoading}
                  className="w-full py-4 bg-gradient-to-r from-cherry to-red-800 hover:from-red-600 hover:to-red-900 text-white font-bold text-xs uppercase tracking-widest rounded-xl transition-all shadow-[0_0_20px_-5px_rgba(217,4,41,0.4)] hover:shadow-[0_0_30px_-5px_rgba(217,4,41,0.6)] flex items-center justify-center gap-2 disabled:opacity-70 disabled:cursor-not-allowed mt-2 relative overflow-hidden"
                >
                  {/* Subtle shine effect on button */}
                  <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/10 to-transparent translate-x-[-100%] animate-[shimmer_2s_infinite]"></div>
                  
                  {isLoading ? (
                    <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  ) : (
                    <>
                      {isLogin ? 'Access System' : 'Create Account'} <ArrowRight className="w-4 h-4" />
                    </>
                  )}
                </button>
              </form>

              {/* Toggle */}
              <div className="mt-8 text-center">
                <p className="text-gray-500 text-xs font-sans">
                  {isLogin ? "New to Aether?" : "Already possess clearance?"}{' '}
                  <button 
                    type="button"
                    onClick={() => { setIsLogin(!isLogin); setError(null); }}
                    className="text-white font-bold hover:text-cherry transition-colors ml-1 border-b border-transparent hover:border-cherry"
                  >
                    {isLogin ? "Request Access" : "Sign In"}
                  </button>
                </p>
              </div>
            </div>
        </div>
      </div>
    </div>
  );
};
