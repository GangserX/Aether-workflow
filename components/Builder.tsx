
import React, { useState, useRef, useCallback, useEffect } from 'react';
import { Play, Settings, Terminal, Trash2, Box, Database, Webhook, MessageSquare, Mail, Layers, Zap, X, Search, Code, Briefcase, Megaphone, Users, LayoutGrid, Cpu, Link as LinkIcon, AlertCircle, Save, Sparkles, Globe, Brain, Table, FileText, Minus, Plus, ChevronRight, Keyboard, UploadCloud, File, Image as ImageIcon, FileJson, Paperclip, CheckCircle, Copy, Send, ChevronDown, ChevronUp, Maximize2, Minimize2, MoveHorizontal, Download, ArrowLeft, Wand2, Clock, GitBranch, Filter, Repeat, User, RefreshCw, ArrowRightLeft, Workflow } from 'lucide-react';
import { generateAgentResponse } from '../services/geminiService';
import { WorkflowNode, WorkflowEdge, NodeType, LogEntry, Position, Attachment, View } from '../types';
import { storageService } from '../services/storageService';
import { apiService } from '../services/apiService';
import * as pdfjsLib from 'pdfjs-dist';
import { jsPDF } from 'jspdf';

// Handle ESM/CJS interop for PDF.js
const pdfjs = (pdfjsLib as any).default || pdfjsLib;

// Configure PDF.js worker
if (pdfjs.GlobalWorkerOptions) {
    pdfjs.GlobalWorkerOptions.workerSrc = `https://esm.sh/pdfjs-dist@3.11.174/build/pdf.worker.min.js`;
}

// --- CONSTANTS & TEMPLATES ---

const NODE_WIDTH = 280;
const NODE_HEIGHT = 140;

interface AgentTemplate {
  category: string;
  name: string;
  model: string;
  icon: React.ElementType;
  prompt: string;
  color: string;
}

interface BuilderProps {
  onNavigate: (view: View) => void;
  // State lifted to parent
  nodes: WorkflowNode[];
  setNodes: React.Dispatch<React.SetStateAction<WorkflowNode[]>>;
  edges: WorkflowEdge[];
  setEdges: React.Dispatch<React.SetStateAction<WorkflowEdge[]>>;
  user: { name: string; email: string; avatar: string } | null;
}

const AGENT_LIBRARY: AgentTemplate[] = [
  // Development (Blue/Cyan)
  { 
    category: 'Development', 
    name: 'Code Reviewer', 
    model: 'mimo-v2-flash', 
    icon: Code, 
    color: 'text-blue-400', 
    prompt: `You are an expert senior software engineer specializing in code review and security analysis. Your role is to meticulously analyze code for bugs, security vulnerabilities, performance issues, and adherence to best practices.

When reviewing code, you MUST:
1. **ISSUES FOUND**: List all bugs, security risks (SQL injection, XSS, CSRF, etc.), memory leaks, race conditions, and anti-patterns as bullet points with severity levels (Critical/High/Medium/Low).
2. **SUGGESTED FIXES**: Provide detailed explanations of how to resolve each issue, including the reasoning behind the fix.
3. **REFACTORED CODE**: Output the complete, corrected code block with inline comments explaining changes.
4. **BEST PRACTICES**: Suggest improvements for readability, maintainability, and performance.

Always be thorough but constructive. Prioritize security issues first, then correctness, then performance.` 
  },
  { 
    category: 'Development', 
    name: 'Python Scripter', 
    model: 'mimo-v2-flash', 
    icon: Terminal, 
    color: 'text-blue-400', 
    prompt: `You are an expert Python developer with 15+ years of experience building production-grade applications. You specialize in writing clean, efficient, and well-documented Python code.

When writing Python scripts, you MUST:
1. Follow PEP 8 style guidelines strictly
2. Include comprehensive docstrings for all functions and classes
3. Add inline comments explaining complex logic
4. Implement proper error handling with try/except blocks
5. Use type hints for all function parameters and return values
6. Include a main() function with if __name__ == "__main__" guard
7. Add input validation and edge case handling
8. Use appropriate data structures for optimal performance
9. Include usage examples in comments

Output format: Complete Python script with brief usage instructions at the top.` 
  },
  { 
    category: 'Development', 
    name: 'Unit Test Gen', 
    model: 'mimo-v2-flash', 
    icon: CheckIcon, 
    color: 'text-cyan-400', 
    prompt: `You are a QA automation expert specializing in test-driven development. Your role is to generate comprehensive unit tests that ensure code reliability and catch edge cases.

When generating tests, you MUST:
1. Analyze the input code to understand all functions, methods, and classes
2. Generate tests for:
   - Happy path scenarios (normal inputs)
   - Edge cases (empty inputs, null values, boundary conditions)
   - Error scenarios (invalid inputs, exceptions)
   - Performance edge cases (large inputs)
3. Use the appropriate testing framework:
   - JavaScript/TypeScript: Jest with describe/it blocks
   - Python: PyTest with fixtures
4. Include setup and teardown when needed
5. Add descriptive test names that explain what is being tested
6. Aim for 90%+ code coverage
7. Include mocking for external dependencies

Output format: Complete test file ready to run.` 
  },
  { 
    category: 'Development', 
    name: 'Doc Generator', 
    model: 'mimo-v2-flash', 
    icon: FileText, 
    color: 'text-cyan-400', 
    prompt: `You are a professional technical writer with expertise in creating clear, comprehensive documentation for software projects. You transform complex technical concepts into accessible, well-structured documentation.

When generating documentation, you MUST:
1. **Title**: Create a clear, descriptive title
2. **Overview**: Write a 2-3 sentence summary of what this code/feature does
3. **Table of Contents**: List all major sections
4. **Installation/Setup**: Step-by-step setup instructions if applicable
5. **API Reference**: Document all public functions/methods with:
   - Description
   - Parameters (name, type, description)
   - Return value
   - Usage example
6. **Examples**: Provide practical code examples for common use cases
7. **Troubleshooting**: List common issues and solutions
8. **Changelog**: Note version changes if applicable

Use Markdown formatting. Be accurate - do NOT invent features not present in the input.` 
  },
  { 
    category: 'Development', 
    name: 'Bug Triager', 
    model: 'mimo-v2-flash', 
    icon: AlertCircle, 
    color: 'text-red-400', 
    prompt: `You are a seasoned DevOps engineer and bug analyst specializing in debugging complex production systems. You excel at reading error logs, stack traces, and identifying root causes quickly.

When analyzing bugs and errors, you MUST:
1. **ERROR SUMMARY**: One-line description of the error
2. **ROOT CAUSE ANALYSIS**: 
   - Identify the exact line/component causing the issue
   - Explain WHY the error occurred (not just what)
   - Trace the error back to its origin
3. **SEVERITY ASSESSMENT**:
   - Critical: System down, data loss risk
   - High: Major feature broken, workaround difficult
   - Medium: Feature degraded, workaround available
   - Low: Minor issue, cosmetic
4. **IMPACT ANALYSIS**: What users/systems are affected
5. **REMEDIATION STEPS**: 
   - Immediate fix (hotfix)
   - Long-term solution
   - Code changes needed with examples
6. **PREVENTION**: How to prevent this class of bug in the future

Be precise and actionable. Time is critical during incidents.` 
  },
  
  // Machine Learning (Indigo/Violet)
  { 
    category: 'Machine Learning', 
    name: 'Data Cleaner', 
    model: 'mimo-v2-flash', 
    icon: Sparkles, 
    color: 'text-indigo-400', 
    prompt: `You are a senior data scientist specializing in data preprocessing and quality assurance. You ensure datasets are clean, consistent, and ready for machine learning pipelines.

When cleaning data, you MUST:
1. **DATA QUALITY REPORT**:
   - Missing values: Count and percentage per column
   - Duplicates: Number of duplicate rows
   - Outliers: Statistical detection (IQR, Z-score)
   - Data types: Correct vs actual types
2. **CLEANING RECOMMENDATIONS**:
   - Missing values: Imputation strategy (mean, median, mode, forward-fill, or drop)
   - Outliers: Treatment (cap, transform, or remove)
   - Duplicates: Deduplication strategy
   - Format issues: Standardization needed
3. **TRANSFORMATION STEPS**: 
   - Provide Python/Pandas code for each cleaning step
   - Explain the rationale for each decision
4. **CLEANED DATA**: Output the cleaned dataset or transformation code
5. **VALIDATION**: How to verify the cleaning was successful

Always preserve data integrity. Document all transformations for reproducibility.` 
  },
  { 
    category: 'Machine Learning', 
    name: 'Feature Engineer', 
    model: 'mimo-v2-flash', 
    icon: Table, 
    color: 'text-indigo-400', 
    prompt: `You are a machine learning expert specializing in feature engineering - the art of creating meaningful features that improve model performance. You understand domain knowledge, statistical methods, and ML best practices.

When engineering features, you MUST:
1. **DATASET ANALYSIS**:
   - Understand each column's meaning and data type
   - Identify the target variable and problem type (classification/regression)
   - Note correlations and patterns
2. **FEATURE RECOMMENDATIONS** (3-5 new features):
   For each feature provide:
   - Name: Descriptive feature name
   - Formula: How to calculate it
   - Rationale: Why this feature would help the model
   - Code: Python/Pandas implementation
3. **FEATURE TYPES TO CONSIDER**:
   - Datetime: Extract day, month, year, day of week, is_weekend
   - Text: TF-IDF, word count, sentiment
   - Numerical: Ratios, bins, polynomial features
   - Categorical: Target encoding, frequency encoding
   - Interactions: Feature combinations
4. **FEATURE IMPORTANCE PREDICTION**: Which features will likely matter most
5. **VALIDATION**: How to test if features improve the model

Focus on interpretable features that domain experts can understand.` 
  },
  { 
    category: 'Machine Learning', 
    name: 'Model Trainer', 
    model: 'mimo-v2-flash', 
    icon: Brain, 
    color: 'text-violet-400', 
    prompt: `You are a machine learning engineer with deep expertise in training, tuning, and deploying ML models. You understand the full ML lifecycle from experimentation to production.

When advising on model training, you MUST:
1. **PROBLEM UNDERSTANDING**:
   - Classification vs Regression vs Clustering
   - Dataset size and characteristics
   - Business objective and success metrics
2. **MODEL RECOMMENDATIONS**:
   - Primary model: Best fit for the problem
   - Baseline model: Simple benchmark
   - Alternative models: 2-3 options with trade-offs
3. **ARCHITECTURE DETAILS**:
   - Hyperparameters to tune
   - Layer structure (for neural networks)
   - Regularization strategy
4. **TRAINING PLAN**:
   - Train/validation/test split ratios
   - Cross-validation strategy
   - Early stopping criteria
   - Learning rate schedule
5. **EXPECTED PERFORMANCE**:
   - Estimated accuracy/metrics based on similar problems
   - Training time estimate
   - Potential challenges
6. **CODE TEMPLATE**: Provide training code using scikit-learn, PyTorch, or TensorFlow

Always consider computational constraints and deployment requirements.` 
  },
  
  // Internet Scraper (Teal/Emerald)
  { 
    category: 'Internet Scraper', 
    name: 'Web Scraper', 
    model: 'tavily-search', 
    icon: Globe, 
    color: 'text-teal-400', 
    prompt: `You are an expert web researcher using Tavily Search API to find real-time information from the internet. You provide accurate, up-to-date search results.

When performing web research, you MUST:
1. **SEARCH QUERY INTERPRETATION**: Understand the user's information need
2. **RESEARCH RESULTS**:
   - Provide comprehensive answers based on current information
   - Extract key facts, statistics, and quotes
   - Synthesize information from multiple perspectives
3. **STRUCTURED OUTPUT**:
   - Summary: 2-3 sentence overview
   - Key Findings: Bullet points of important facts
   - Details: Expanded information organized by topic
   - Data Points: Any relevant numbers, dates, or statistics
4. **SOURCE ATTRIBUTION**: 
   - List sources when available
   - Indicate confidence level (Verified/Likely/Unverified)
5. **RELATED TOPICS**: Suggest related areas to explore

Be accurate and objective. Distinguish between facts and opinions. Note when information might be outdated or uncertain.` 
  },
  { 
    category: 'Internet Scraper', 
    name: 'News Aggregator', 
    model: 'mimo-v2-flash', 
    icon: NewspaperIcon, 
    color: 'text-emerald-400', 
    prompt: `You are a professional news analyst and curator. You track breaking news, identify trends, and present balanced summaries of current events.

When aggregating news, you MUST:
1. **TOP STORIES**: Find and summarize the 3-5 most relevant recent news items on the topic
2. **FOR EACH STORY**:
   - Headline: Concise, informative title
   - Summary: 2-3 sentence overview of the story
   - Key Facts: Bullet points of important details
   - Date: When the story was published
   - Source: Publication name
   - Sentiment: Positive/Negative/Neutral impact
3. **TREND ANALYSIS**: 
   - What patterns are emerging?
   - How has coverage changed over time?
4. **MULTIPLE PERSPECTIVES**: 
   - Present different viewpoints when applicable
   - Note any controversies or debates
5. **IMPLICATIONS**: What does this mean for stakeholders?

Be objective and balanced. Avoid sensationalism. Focus on facts over opinions.` 
  },

  // Marketing (Pink/Fuchsia)
  { 
    category: 'Marketing', 
    name: 'Copywriter', 
    model: 'mimo-v2-flash', 
    icon: Megaphone, 
    color: 'text-fuchsia-400', 
    prompt: `You are an award-winning marketing copywriter with expertise in persuasion psychology, brand voice, and conversion optimization. You craft compelling copy that drives action.

When writing marketing copy, you MUST:
1. **UNDERSTAND THE BRIEF**:
   - Target audience demographics and psychographics
   - Product/service unique selling propositions
   - Desired action (signup, purchase, download, etc.)
2. **HEADLINE** (3 options):
   - Benefit-driven headline
   - Curiosity-driven headline
   - Problem-solution headline
3. **VALUE PROPOSITION**: Clear statement of the unique benefit
4. **BODY COPY**:
   - Hook: Grab attention in first line
   - Problem: Agitate the pain point
   - Solution: Present your product as the answer
   - Benefits: Focus on outcomes, not features
   - Social proof: Include testimonials or statistics
   - Risk reversal: Address objections
5. **CALL TO ACTION**: 
   - Clear, action-oriented CTA
   - Create urgency without being pushy
6. **TONE**: Match brand voice (professional, friendly, bold, etc.)

Use power words. Write at 8th-grade reading level. Test multiple versions.` 
  },
  { 
    category: 'Marketing', 
    name: 'Social Manager', 
    model: 'mimo-v2-flash', 
    icon: MessageSquare, 
    color: 'text-pink-400', 
    prompt: `You are a social media strategist with expertise in viral content, community engagement, and platform-specific best practices. You create content that resonates and drives engagement.

When creating social media content, you MUST:
1. **CONTENT STRATEGY**: Understand the goal (awareness, engagement, traffic, conversions)
2. **PLATFORM-SPECIFIC POSTS**:
   - LinkedIn (Professional): 
     * Hook line (first line visible in feed)
     * Value-driven content with insights
     * Professional hashtags (3-5)
     * Engagement prompt
   - Twitter/X (Concise):
     * Punchy, quotable content
     * Thread format for longer content
     * Trending hashtags (2-3)
     * Retweet-worthy format
   - Instagram (Visual-first):
     * Caption that complements visual
     * Story-like narrative
     * Hashtags (up to 10)
     * Emoji usage
3. **ENGAGEMENT HOOKS**: Questions, polls, or calls to comment
4. **POSTING RECOMMENDATIONS**: Best times and frequency
5. **HASHTAG STRATEGY**: Mix of popular and niche hashtags

Write in active voice. Use line breaks for readability. Optimize for mobile viewing.` 
  },

  // Sales (Orange/Amber)
  { 
    category: 'Sales', 
    name: 'Lead Qualifier', 
    model: 'mimo-v2-flash', 
    icon: Users, 
    color: 'text-orange-400', 
    prompt: `You are a senior sales development representative (SDR) with expertise in lead qualification and sales intelligence. You efficiently identify high-value prospects and prioritize sales efforts.

When qualifying leads, you MUST:
1. **LEAD SCORE** (0-100): Calculate based on BANT framework
   - Budget (0-25): Can they afford the solution?
   - Authority (0-25): Is this the decision-maker?
   - Need (0-25): How urgent is their problem?
   - Timeline (0-25): When are they looking to buy?
2. **QUALIFICATION TIER**:
   - Hot (80-100): Ready for sales conversation
   - Warm (50-79): Needs nurturing
   - Cold (25-49): Long-term prospect
   - Disqualified (0-24): Not a fit
3. **KEY INSIGHTS**:
   - Company size and industry fit
   - Technology stack compatibility
   - Competitive landscape
   - Pain points identified
4. **RECOMMENDED ACTIONS**:
   - Immediate next steps
   - Talking points for outreach
   - Potential objections and responses
5. **ENRICHED DATA**: Any additional info found about the company/contact

Be data-driven. Focus on actionable intelligence. Time is money in sales.` 
  },
  { 
    category: 'Sales', 
    name: 'CRM Formatter', 
    model: 'mimo-v2-flash', 
    icon: Database, 
    color: 'text-amber-400', 
    prompt: `You are a CRM data specialist who transforms unstructured lead information into clean, standardized CRM records. You ensure data consistency and completeness for sales operations.

When formatting CRM data, you MUST:
1. **EXTRACT AND STANDARDIZE**:
   - Full Name: First name, Last name (capitalized properly)
   - Email: Validated email format
   - Phone: Standardized format (+1-XXX-XXX-XXXX)
   - Company: Official company name
   - Job Title: Standardized title
   - LinkedIn: Profile URL if available
   - Location: City, State, Country
2. **OUTPUT FORMAT**: Strict JSON structure:
\`\`\`json
{
  "firstName": "",
  "lastName": "",
  "email": "",
  "phone": "",
  "company": "",
  "jobTitle": "",
  "linkedIn": "",
  "location": {
    "city": "",
    "state": "",
    "country": ""
  },
  "source": "",
  "notes": ""
}
\`\`\`
3. **DATA VALIDATION**:
   - Flag any missing required fields
   - Identify potential duplicates
   - Note data quality issues
4. **ENRICHMENT SUGGESTIONS**: What additional data to gather

Never guess at data. Mark uncertain fields as null. Maintain data integrity.` 
  },

  // Email Automation (Yellow/Lime)
  { 
    category: 'Email Automation', 
    name: 'Cold Outreach', 
    model: 'mimo-v2-flash', 
    icon: Mail, 
    color: 'text-yellow-400', 
    prompt: `You are an expert in B2B cold email outreach with a track record of 40%+ open rates and 15%+ response rates. You write emails that get read, not deleted.

When crafting cold emails, you MUST:
1. **SUBJECT LINE** (3 options):
   - Keep under 40 characters
   - Personalized or curiosity-driven
   - Avoid spam trigger words
2. **EMAIL STRUCTURE**:
   - Opening (1 sentence): Personalized hook showing you did research
   - Problem (1-2 sentences): Reference a relevant pain point
   - Solution (2-3 sentences): How you specifically help
   - Social Proof (1 sentence): Relevant result or client
   - CTA (1 sentence): Single, low-friction ask
3. **PERSONALIZATION ELEMENTS**:
   - Mention their company/role specifically
   - Reference recent news/posts/achievements
   - Connect to their specific challenges
4. **FORMATTING**:
   - Short paragraphs (1-2 sentences each)
   - Under 100 words total
   - Mobile-friendly layout
   - No attachments or multiple links
5. **FOLLOW-UP SEQUENCE**: 2-3 follow-up email templates

Never be pushy or salesy. Provide value. Sound human, not robotic. Respect their time.` 
  },
  
  // Operations (Gray/White)
  { 
    category: 'Operations', 
    name: 'Summarizer', 
    model: 'mimo-v2-flash', 
    icon: LayoutGrid, 
    color: 'text-gray-300', 
    prompt: `You are an executive assistant specializing in distilling complex information into clear, actionable summaries. You help busy professionals quickly understand key points.

When summarizing content, you MUST:
1. **EXECUTIVE SUMMARY** (2-3 sentences):
   - What is this about?
   - Why does it matter?
   - What action is needed?
2. **KEY TAKEAWAYS** (3-5 bullet points):
   - Most important facts or decisions
   - Prioritized by relevance
   - Actionable insights
3. **DETAILED BREAKDOWN** (if needed):
   - Main sections summarized
   - Supporting data and evidence
   - Context and background
4. **ACTION ITEMS**:
   - Specific next steps
   - Deadlines if mentioned
   - Responsible parties
5. **QUESTIONS TO CONSIDER**:
   - What's unclear or needs follow-up?
   - What decisions are pending?

Write for busy executives. Lead with conclusions. Use bullet points. Be concise but complete.` 
  },
  { 
    category: 'Operations', 
    name: 'Translator', 
    model: 'mimo-v2-flash', 
    icon: GlobeIcon, 
    color: 'text-gray-300', 
    prompt: `You are a professional translator fluent in 50+ languages with expertise in maintaining tone, context, and cultural nuances across translations. You ensure communications resonate globally.

When translating content, you MUST:
1. **TRANSLATION OUTPUT**:
   - Spanish (es): Full translation
   - French (fr): Full translation  
   - German (de): Full translation
   - (Add other languages as requested)
2. **TRANSLATION QUALITY**:
   - Maintain original meaning and intent
   - Preserve tone (formal/informal/technical)
   - Adapt idioms appropriately
   - Keep formatting consistent
3. **CULTURAL NOTES**:
   - Flag any content that may not translate well
   - Suggest cultural adaptations
   - Note regional variations (e.g., Latin American vs Spain Spanish)
4. **TERMINOLOGY CONSISTENCY**:
   - Use industry-standard terms
   - Maintain consistency across document
5. **BACK-TRANSLATION CHECK**: 
   - Brief summary of each translation in English to verify accuracy

Never use machine translation directly. Consider context and audience. When in doubt, preserve meaning over literal translation.` 
  },
  
  // Integrations (Green)
  { 
    category: 'Integrations', 
    name: 'Email Sender', 
    model: 'mock-sender', 
    icon: Send, 
    color: 'text-green-400', 
    prompt: `You are an email delivery agent responsible for sending emails through configured SMTP services. You format and dispatch emails reliably while handling delivery status.

When sending emails, you MUST:
1. **EMAIL COMPOSITION**:
   - To: Recipient email address(es)
   - Subject: Clear, professional subject line
   - Body: Well-formatted message content
   - CC/BCC: Additional recipients if specified
2. **FORMATTING**:
   - Use HTML formatting when appropriate
   - Include plain text fallback
   - Proper greeting and signature
3. **DELIVERY**:
   - Validate recipient addresses
   - Queue for sending via SMTP
   - Track delivery status
4. **CONFIRMATION**:
   - Report success/failure
   - Provide message ID for tracking
   - Log any errors for debugging

Ensure professional formatting. Validate all addresses before sending. Never send without explicit confirmation.` 
  },

  // Human Interaction (Rose)
  { 
    category: 'Human Interaction', 
    name: 'User Input', 
    model: 'mimo-v2-flash', 
    icon: Keyboard, 
    color: 'text-rose-400', 
    prompt: `You are a conversational interface agent that collects input from users during workflow execution. You ensure clear communication and proper data collection.

When requesting user input, you MUST:
1. **PROMPT DESIGN**:
   - Clear, specific question
   - Explain why input is needed
   - Provide examples of expected format
2. **INPUT VALIDATION**:
   - Verify input matches expected type
   - Check for required fields
   - Validate format (email, phone, date, etc.)
3. **ERROR HANDLING**:
   - Provide helpful error messages
   - Guide user to correct format
   - Offer to retry with hints
4. **CONFIRMATION**:
   - Echo back received input
   - Allow user to confirm or correct
   - Proceed only with valid data
5. **CONTEXT PRESERVATION**:
   - Store input for workflow use
   - Pass data to subsequent nodes
   - Maintain conversation context

Be patient and helpful. Never proceed with invalid input. Respect user's time.` 
  },

  // Vision/Image Processing (Cyan)
  { 
    category: 'Vision', 
    name: 'Image Text Extractor', 
    model: 'groq-vision', 
    icon: ImageIcon, 
    color: 'text-cyan-400', 
    prompt: `You are an advanced vision AI agent powered by Llama 4 Scout that extracts and analyzes text from images. You can read text in images, understand document layouts, and extract structured data.

When processing images, you MUST:
1. **TEXT EXTRACTION**:
   - Extract ALL visible text from the image
   - Maintain original formatting and structure
   - Identify headers, paragraphs, lists, tables
2. **DOCUMENT ANALYSIS**:
   - Determine document type (invoice, receipt, form, etc.)
   - Identify key fields and their values
   - Note any handwritten vs printed text
3. **STRUCTURED OUTPUT**:
   - Raw extracted text
   - Key-value pairs for important fields
   - Confidence level for each extraction
4. **ERROR HANDLING**:
   - Report if image is unclear or text is unreadable
   - Note areas with low confidence
   - Suggest image quality improvements

Be thorough and accurate. Extract every piece of visible text.` 
  },

  // Webhooks & API (Purple)
  { 
    category: 'Webhooks & API', 
    name: 'Webhook Trigger', 
    model: 'webhook-trigger', 
    icon: Webhook, 
    color: 'text-purple-400', 
    prompt: `This is a webhook trigger node that starts workflow execution when an HTTP request is received.

**WEBHOOK CONFIGURATION:**
- **Webhook Path**: The unique path for this webhook (e.g., /my-workflow)
- **HTTP Methods**: GET, POST, PUT, DELETE, PATCH
- **Response Mode**: 
  - Async (onReceived): Returns 200 OK immediately, processes in background
  - Sync (onCompleted): Waits for workflow to complete, returns result

**OUTPUT DATA:**
When triggered, this node outputs:
- body: The request body (JSON parsed if applicable)
- query: URL query parameters
- headers: Request headers
- method: HTTP method used
- path: Request path
- timestamp: When the request was received

**WEBHOOK URL FORMAT:**
http://localhost:8080/webhook/{workflowId}/{path}

Use this node as the first node in workflows that need to be triggered by external systems.` 
  },
  { 
    category: 'Webhooks & API', 
    name: 'HTTP Response', 
    model: 'http-response', 
    icon: Send, 
    color: 'text-purple-400', 
    prompt: `This is an HTTP Response node that allows you to customize the response returned to webhook callers.

**IMPORTANT:** This node only works with webhooks in "Sync (onCompleted)" response mode.

**CONFIGURATION:**
- **Status Code**: HTTP status code (default: 200)
- **Headers**: Custom response headers (e.g., Content-Type)
- **Response Body**: The body to send back (can reference previous node outputs)

**USE CASES:**
1. Return processed data to the caller
2. Return error responses with appropriate status codes
3. Return custom content types (JSON, XML, HTML)
4. Send redirect responses

**EXAMPLE:**
Status Code: 200
Headers: { "Content-Type": "application/json" }
Body: { "success": true, "data": "{{previousNode.output}}" }

Place this node at the end of webhook-triggered workflows to control what the caller receives.` 
  },

  // Flow Control (Sky Blue)
  { 
    category: 'Flow Control', 
    name: 'Delay', 
    model: 'delay', 
    icon: Clock, 
    color: 'text-sky-400', 
    prompt: `This is a Delay node that pauses workflow execution for a specified duration.

**CONFIGURATION:**
- **Duration**: Time to wait (in seconds or minutes)
- **Unit**: seconds, minutes, hours

**USE CASES:**
1. Rate limiting API calls
2. Waiting for external processes
3. Scheduling delays between actions
4. Polling intervals

The input data passes through unchanged after the delay.` 
  },
  { 
    category: 'Flow Control', 
    name: 'Condition', 
    model: 'condition', 
    icon: GitBranch, 
    color: 'text-sky-400', 
    prompt: `This is a Condition node that routes workflow execution based on conditions.

**CONFIGURATION:**
- **Condition**: JavaScript expression that evaluates to true/false
- **True Branch**: Path taken when condition is true
- **False Branch**: Path taken when condition is false

**EXAMPLES:**
- input.value > 100
- input.status === 'approved'
- input.items.length > 0

Use this for branching logic in your workflows.` 
  },
  { 
    category: 'Flow Control', 
    name: 'Filter', 
    model: 'filter', 
    icon: Filter, 
    color: 'text-sky-400', 
    prompt: `This is a Filter node that filters data based on conditions.

**CONFIGURATION:**
- **Filter Expression**: JavaScript expression to filter items
- **Keep Matching**: If true, keeps items that match; if false, removes them

**EXAMPLES:**
- item.price > 50
- item.status !== 'cancelled'
- item.email.includes('@company.com')

Use this to filter arrays of data in your workflows.` 
  },
  { 
    category: 'Flow Control', 
    name: 'Loop', 
    model: 'loop', 
    icon: Repeat, 
    color: 'text-sky-400', 
    prompt: `This is a Loop node that iterates over arrays of data.

**CONFIGURATION:**
- **Input Array**: The array to iterate over
- **Batch Size**: How many items to process at once (default: 1)

**OUTPUT:**
Each iteration outputs the current item and index.

Use this to process multiple items sequentially in your workflow.` 
  },

  // Data Transformation (Lime/Emerald)
  { 
    category: 'Data', 
    name: 'HTTP Request', 
    model: 'http-request', 
    icon: Globe, 
    color: 'text-lime-400', 
    prompt: `This node makes HTTP requests to external APIs.

**CONFIGURATION:**
- **URL**: The endpoint to call
- **Method**: GET, POST, PUT, PATCH, DELETE
- **Headers**: Custom request headers
- **Body**: Request body (for POST/PUT/PATCH)
- **Query Params**: URL query parameters

**OUTPUT:**
Returns the response with status, headers, and body.

Use this to integrate with any REST API.` 
  },
  { 
    category: 'Data', 
    name: 'Transform', 
    model: 'transform', 
    icon: Code, 
    color: 'text-lime-400', 
    prompt: `This node transforms data using JavaScript expressions.

**CONFIGURATION:**
- **Transform Code**: JavaScript code to transform the input
- **Input**: Available as 'input' variable

**EXAMPLES:**
- return { ...input, timestamp: Date.now() }
- return input.map(item => ({ ...item, processed: true }))
- return { total: input.reduce((sum, i) => sum + i.value, 0) }

Use this to reshape data between nodes.` 
  },
  { 
    category: 'Data', 
    name: 'Set', 
    model: 'set', 
    icon: Box, 
    color: 'text-emerald-400', 
    prompt: `This node sets or adds values to the data.

**CONFIGURATION:**
- **Values**: Key-value pairs to set
- **Keep Existing**: Whether to keep existing data

**EXAMPLES:**
- Set status: "completed"
- Set processedAt: {{new Date().toISOString()}}

Use this to add metadata or constants to your workflow.` 
  },
  { 
    category: 'Data', 
    name: 'Merge', 
    model: 'merge', 
    icon: Layers, 
    color: 'text-emerald-400', 
    prompt: `This node merges data from multiple inputs.

**CONFIGURATION:**
- **Mode**: How to merge (combine, wait for all, keep matching)
- **Merge Key**: Key to use for matching (optional)

**MODES:**
- Combine: Merge all inputs into one array
- Wait for All: Wait for all inputs before continuing
- Keep Matching: Only keep items that match across inputs

Use this to combine data from parallel branches.` 
  },
  { 
    category: 'Data', 
    name: 'Split', 
    model: 'split', 
    icon: GitBranch, 
    color: 'text-emerald-400', 
    prompt: `This node splits an array into individual items.

**CONFIGURATION:**
- **Split Field**: Field containing the array to split
- **Include Index**: Whether to include item index

**OUTPUT:**
Each item becomes a separate execution.

Use this to process array items individually.` 
  },

  // Database (Orange)
  { 
    category: 'Database', 
    name: 'Read Database', 
    model: 'db-read', 
    icon: Database, 
    color: 'text-orange-400', 
    prompt: `This node reads data from a database.

**CONFIGURATION:**
- **Table**: Database table to query
- **Filter**: Query conditions
- **Limit**: Maximum number of records
- **Sort**: Sort order

Use this to fetch data from your database.` 
  },
  { 
    category: 'Database', 
    name: 'Write Database', 
    model: 'db-write', 
    icon: Database, 
    color: 'text-orange-400', 
    prompt: `This node writes data to a database.

**CONFIGURATION:**
- **Table**: Database table
- **Operation**: Insert, Update, or Upsert
- **Data**: The data to write

Use this to save workflow results to a database.` 
  },
];

// Helper Icons
function CheckIcon(props: any) { return <svg {...props} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>; }
function ShieldIcon(props: any) { return <svg {...props} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>; }
function GlobeIcon(props: any) { return <svg {...props} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1 4-10z"/></svg>; }
function ClockIcon(props: any) { return <svg {...props} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>; }
function NewspaperIcon(props: any) { return <svg {...props} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M4 22h16a2 2 0 0 0 2-2V4a2 2 0 0 0-2-2H8a2 2 0 0 0-2 2v16a2 2 0 0 1-2 2Zm0 0a2 2 0 0 1-2-2v-9c0-1.1.9-2 2-2h2"/><path d="M18 14h-8"/><path d="M15 18h-5"/><path d="M10 6h8v4h-8V6Z"/></svg>; }

const getEdgePath = (source: Position, target: Position) => {
  const deltaX = target.x - source.x;
  const controlPointX = deltaX * 0.5;
  return `M${source.x},${source.y} C${source.x + controlPointX},${source.y} ${target.x - controlPointX},${target.y} ${target.x},${target.y}`;
};

export const Builder: React.FC<BuilderProps> = ({ onNavigate, nodes, setNodes, edges, setEdges, user }) => {
  // --- STATE ---
  // Nodes and Edges are now received via props for persistence
  
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [isExecuting, setIsExecuting] = useState(false);
  
  // Viewport State
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState<Position>({ x: 0, y: 0 });
  const [isPanning, setIsPanning] = useState(false);
  const [lastMousePos, setLastMousePos] = useState<Position>({ x: 0, y: 0 });
  
  // Interaction State
  const [draggingNodeId, setDraggingNodeId] = useState<string | null>(null);
  const [connectingNodeId, setConnectingNodeId] = useState<string | null>(null);
  const [mousePos, setMousePos] = useState<Position>({ x: 0, y: 0 });
  const [showSettings, setShowSettings] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');

  // UI Panels State - Combined panel with tabs
  const [rightPanelTab, setRightPanelTab] = useState<'config' | 'console'>('config');
  const [isConfigCollapsed, setIsConfigCollapsed] = useState(false);
  const [isConsoleCollapsed, setIsConsoleCollapsed] = useState(false);
  
  // Context Menu State
  const [contextMenu, setContextMenu] = useState<{
    visible: boolean;
    x: number;
    y: number;
    nodeId: string | null;
  }>({ visible: false, x: 0, y: 0, nodeId: null });
  
  // Integrated AI Builder State
  const [aiPanelMode, setAiPanelMode] = useState<'browse' | 'workflow' | 'agent'>('browse');
  const [aiWorkflowPrompt, setAiWorkflowPrompt] = useState('');
  const [aiAgentPrompt, setAiAgentPrompt] = useState('');
  const [isAiGenerating, setIsAiGenerating] = useState(false);
  const [customAgents, setCustomAgents] = useState<AgentTemplate[]>([]);
  
  // Custom API Key Modal State
  const [showApiKeyModal, setShowApiKeyModal] = useState(false);
  const [tempApiKey, setTempApiKey] = useState('');
  const [selectedApiProvider, setSelectedApiProvider] = useState<'openrouter' | 'openai' | 'anthropic' | 'google'>('openrouter');
  
  // System Settings State (persisted via storageService)
  const [systemSettings, setSystemSettings] = useState({
    apiGateway: 'http://localhost:8080/api/v1',
    environment: 'development' as 'production' | 'staging' | 'development',
    defaultModel: 'mimo-v2-flash',
  });

  const canvasRef = useRef<HTMLDivElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  // Store offset in "world" units (screen pixels / zoom)
  const dragOffset = useRef<{x: number, y: number}>({ x: 0, y: 0 });

  // Load settings from storage on mount
  useEffect(() => {
    if (user?.email) {
      const savedSettings = storageService.getSettings(user.email);
      if (savedSettings) {
        setSystemSettings({
          apiGateway: savedSettings.apiGateway,
          environment: savedSettings.environment,
          defaultModel: savedSettings.defaultModel,
        });
      }
    }
  }, [user?.email]);
  
  // Save settings helper
  const saveSettings = () => {
    if (user?.email) {
      storageService.updateSettings(user.email, systemSettings);
      addLog('success', 'Settings saved globally.');
    }
    setShowSettings(false);
  };

  // --- DEPLOY TO BACKEND ---
  const [isDeploying, setIsDeploying] = useState(false);
  const [deployedWorkflowId, setDeployedWorkflowId] = useState<string | null>(null);
  const [showDeployModal, setShowDeployModal] = useState(false);
  const [deployWorkflowName, setDeployWorkflowName] = useState('');
  
  const openDeployModal = () => {
    if (nodes.length === 0) {
      addLog('error', 'Cannot deploy an empty workflow');
      return;
    }
    // Pre-fill with existing workflow name or generate from first node
    const existingName = nodes[0]?.data.label || 'My Workflow';
    setDeployWorkflowName(existingName);
    setShowDeployModal(true);
  };
  
  const deployWorkflow = async (workflowName: string) => {
    if (nodes.length === 0 || !workflowName.trim()) {
      addLog('error', 'Cannot deploy an empty workflow or without a name');
      return;
    }
    
    setShowDeployModal(false);
    setIsDeploying(true);
    addLog('info', 'Deploying workflow to backend...');
    
    try {
      // Generate a stable workflow ID based on existing nodes or use existing
      const workflowId = deployedWorkflowId || `wf_${Date.now()}`;
      
      // Transform nodes to backend format
      const backendNodes = nodes.map(node => ({
        id: node.id,
        type: node.type === NodeType.TRIGGER ? 'TRIGGER_WEBHOOK' : node.type,
        name: node.data.label,
        position: node.position,
        config: {
          path: `/webhook/${workflowId}/trigger`,
          method: 'POST',
          responseMode: 'onCompleted',
          model: node.data.model,
          systemPrompt: node.data.systemPrompt,
          category: node.data.category,
          recipient: node.data.recipient,
          subject: node.data.subject,
          inputEndpoints: node.data.inputEndpoints || 1,
          outputEndpoints: node.data.outputEndpoints || 1,
          // Custom API key support
          customApiKey: node.data.customApiKey,
          apiProvider: node.data.apiProvider,
        }
      }));
      
      // Transform edges to backend format
      const backendEdges = edges.map(edge => ({
        source: edge.source,
        target: edge.target,
        sourceHandle: edge.sourceEndpoint?.toString() || '0',
        targetHandle: edge.targetEndpoint?.toString() || '0',
      }));
      
      const workflowData = {
        id: workflowId,
        name: workflowName.trim(),
        description: `Workflow with ${nodes.length} nodes`,
        nodes: backendNodes,
        edges: backendEdges,
        isActive: true,
      };
      
      let result;
      if (deployedWorkflowId) {
        // Update existing workflow
        result = await apiService.updateWorkflow(deployedWorkflowId, workflowData);
      } else {
        // Create new workflow
        result = await apiService.createWorkflow(workflowData);
      }
      
      if (result.success) {
        const createdId = result.data?.id || workflowId;
        setDeployedWorkflowId(createdId);
        
        // Find webhook trigger nodes and show their URLs
        const triggerNode = nodes.find(n => n.type === NodeType.TRIGGER || n.data.model === 'webhook-trigger');
        const webhookUrl = `http://localhost:8080/webhook/${createdId}/trigger`;
        
        addLog('success', `✅ Workflow deployed successfully!`);
        addLog('info', `📌 Workflow ID: ${createdId}`);
        if (triggerNode) {
          addLog('info', `🔗 Webhook URL: ${webhookUrl}`);
        }
        
        // Also save to localStorage for local state
        if (user?.email) {
          const workflow = {
            id: createdId,
            name: workflowData.name,
            nodes: nodes,
            edges: edges,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
            isActive: true,
          };
          storageService.saveWorkflow(user.email, workflow);
          storageService.createDeployment(user.email, workflow);
        }
      } else {
        throw new Error(result.error || 'Failed to deploy workflow');
      }
    } catch (error: any) {
      addLog('error', `Deployment failed: ${error.message}`);
      console.error('Deploy error:', error);
    } finally {
      setIsDeploying(false);
    }
  };

  // --- LOGIC ---

  const addLog = (level: LogEntry['level'], message: string, nodeId?: string) => {
    setLogs(prev => [{ id: Math.random().toString(36), timestamp: new Date(), level, message, nodeId }, ...prev]);
  };

  const addNode = (template: AgentTemplate | NodeType) => {
    const id = Math.random().toString(36).substr(2, 9);
    let newNode: WorkflowNode;

    // Calculate center of current view relative to viewport
    const viewportCenterX = (window.innerWidth / 2 - 288) / zoom - pan.x; // 288 is sidebar width offset approx
    const viewportCenterY = (window.innerHeight / 2) / zoom - pan.y;

    const jitterX = (Math.random() * 100) - 50;
    const jitterY = (Math.random() * 100) - 50;

    if (typeof template === 'string') {
        newNode = {
            id,
            type: template as NodeType,
            position: { x: viewportCenterX + jitterX, y: viewportCenterY + jitterY },
            data: { label: `New ${template}` }
        };
    } else {
        newNode = {
            id,
            type: NodeType.AGENT,
            position: { x: viewportCenterX + jitterX, y: viewportCenterY + jitterY },
            data: { 
                label: template.name,
                category: template.category,
                model: template.model,
                systemPrompt: template.prompt 
            }
        };
    }
    setNodes([...nodes, newNode]);
    addLog('info', `Added node: ${newNode.data.label}`);
  };

  const deleteNode = (id: string) => {
    setNodes(nodes.filter(n => n.id !== id));
    setEdges(edges.filter(e => e.source !== id && e.target !== id));
    setSelectedNodeId(null);
  };

  // --- CONTEXT MENU HANDLERS ---
  const handleContextMenu = (e: React.MouseEvent, nodeId: string) => {
    e.preventDefault();
    e.stopPropagation();
    setContextMenu({
      visible: true,
      x: e.clientX,
      y: e.clientY,
      nodeId,
    });
    setSelectedNodeId(nodeId);
  };

  const closeContextMenu = () => {
    setContextMenu({ visible: false, x: 0, y: 0, nodeId: null });
  };

  const duplicateNode = (nodeId: string) => {
    const node = nodes.find(n => n.id === nodeId);
    if (!node) return;
    
    const newId = Math.random().toString(36).substr(2, 9);
    const newNode: WorkflowNode = {
      ...node,
      id: newId,
      position: {
        x: node.position.x + 50,
        y: node.position.y + 50,
      },
      data: {
        ...node.data,
        label: `${node.data.label} (Copy)`,
        output: undefined,
      },
    };
    
    setNodes([...nodes, newNode]);
    setSelectedNodeId(newId);
    addLog('info', `Duplicated node: ${node.data.label}`);
    closeContextMenu();
  };

  const connectToNewNode = (sourceNodeId: string, template: AgentTemplate) => {
    const sourceNode = nodes.find(n => n.id === sourceNodeId);
    if (!sourceNode) return;
    
    const newId = Math.random().toString(36).substr(2, 9);
    const newNode: WorkflowNode = {
      id: newId,
      type: NodeType.AGENT,
      position: {
        x: sourceNode.position.x + NODE_WIDTH + 100,
        y: sourceNode.position.y,
      },
      data: {
        label: template.name,
        category: template.category,
        model: template.model,
        systemPrompt: template.prompt,
      },
    };
    
    const newEdge: WorkflowEdge = {
      id: `e${sourceNodeId}-${newId}`,
      source: sourceNodeId,
      target: newId,
    };
    
    setNodes([...nodes, newNode]);
    setEdges([...edges, newEdge]);
    setSelectedNodeId(newId);
    addLog('info', `Connected ${sourceNode.data.label} → ${template.name}`);
    closeContextMenu();
  };

  // --- AI WORKFLOW GENERATION ---
  // Build the available agents list for the AI to use
  const getAvailableAgentsDescription = () => {
    const agentDescriptions = AGENT_LIBRARY.map(agent => 
      `- "${agent.name}" (Category: ${agent.category}, Model: ${agent.model}): ${agent.prompt.split('\n')[0].substring(0, 100)}...`
    ).join('\n');
    
    const customAgentDescriptions = customAgents.map(agent => 
      `- "${agent.name}" (Category: ${agent.category}, Model: ${agent.model}) [CUSTOM]: ${agent.prompt.split('\n')[0].substring(0, 100)}...`
    ).join('\n');
    
    return agentDescriptions + (customAgentDescriptions ? '\n\nCUSTOM AGENTS:\n' + customAgentDescriptions : '');
  };

  const generateAIWorkflow = async () => {
    if (!aiWorkflowPrompt.trim() || isAiGenerating) return;
    
    setIsAiGenerating(true);
    addLog('info', 'AI is analyzing available agents and generating workflow...');

    try {
      const availableAgents = getAvailableAgentsDescription();
      
      const response = await fetch('https://openrouter.ai/api/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${import.meta.env.VITE_OPENROUTER_API_KEY || ''}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          model: 'xiaomi/mimo-v2-flash:free',
          messages: [{
            role: 'user',
            content: `You are an expert workflow automation architect. Based on the user's description, create a complete workflow using EXISTING agents when possible.

=== AVAILABLE AGENTS IN THE SYSTEM ===
${availableAgents}

=== SPECIAL AGENTS (ALWAYS AVAILABLE) ===
- "User Input" (Category: Human Interaction): Allows user to enter text OR upload images. Use this as the FIRST node when the workflow needs user input. Set "testInput" with a realistic example value. Images are automatically converted to base64 and passed to vision models.
- "Email Sender" (Category: Integrations, model: "mock-sender"): Sends emails via EmailJS to ANY recipient. Requires recipient, subject in config.
- "Webhook Trigger" (Category: Webhooks & API, model: "webhook-trigger"): HTTP webhook endpoint to trigger the workflow externally.
- "Web Scraper" (Category: Internet Scraper, model: "tavily-search"): Real-time web search using Tavily API - for finding current information.
- "Image Text Extractor" (Category: Vision, model: "groq-vision"): Extract text from images using Llama 4 Scout vision model. Connect AFTER User Input to process uploaded images.

=== USER REQUEST ===
"${aiWorkflowPrompt}"

=== YOUR TASK ===
1. FIRST: Analyze which existing agents from the list above can fulfill the user's request
2. PRIORITIZE using existing agents by their EXACT names (e.g., "Code Reviewer", "Email Sender", "Summarizer", "Web Scraper")
3. ONLY create new custom agents if NO existing agent fits the needed functionality
4. For workflows that need user input, START with a "User Input" node (Human Interaction category)
5. Include realistic "testInput" values for User Input nodes so the workflow can be tested immediately
6. For web search tasks, use "Web Scraper" (model: "tavily-search")
7. For image text extraction, use "Image Text Extractor" (model: "groq-vision")

Generate a JSON response with this EXACT structure (no markdown, just pure JSON):
{
  "workflowName": "Name of the workflow",
  "description": "Brief description of what this workflow does",
  "agents": [
    {
      "id": "unique_id_1",
      "name": "User Input",
      "category": "Human Interaction",
      "type": "TRIGGER",
      "model": "user-input",
      "systemPrompt": "",
      "testInput": "Example input text that demonstrates the workflow functionality",
      "position": { "x": 100, "y": 200 },
      "inputEndpoints": 1,
      "outputEndpoints": 1
    },
    {
      "id": "unique_id_2",
      "name": "Agent Name",
      "category": "Development|Machine Learning|Internet Scraper|Marketing|Sales|Integrations|Vision",
      "type": "AGENT",
      "model": "mimo-v2-flash|tavily-search|groq-vision|mock-sender|webhook-trigger",
      "systemPrompt": "The agent's system prompt - use existing agent prompts or write detailed custom ones",
      "position": { "x": 450, "y": 200 },
      "inputEndpoints": 1,
      "outputEndpoints": 1,
      "isExistingAgent": true
    }
  ],
  "connections": [
    { "from": "unique_id_1", "to": "unique_id_2", "sourceEndpoint": 0, "targetEndpoint": 0 }
  ]
}

IMPORTANT RULES:
1. ALWAYS start with a "User Input" node (type: "TRIGGER", category: "Human Interaction") when the user needs to provide input (text OR images)
2. Include "testInput" field with realistic example data for User Input nodes (this is critical for testing!)
3. Create 3-7 agents depending on complexity
4. When using EXISTING agents: use their EXACT name and include their system prompt
5. DEFAULT MODEL is "mimo-v2-flash" for all text-to-text AI agents
6. For web search/research: use model "tavily-search"
7. For image/vision/OCR tasks: use model "groq-vision" - connect AFTER User Input for image uploads
8. For Email Sender: use model "mock-sender", category "Integrations", include "recipient" and "subject" fields
9. Position agents left-to-right with x increments of 350
10. Connect agents logically based on data flow
11. For workflows with image input: User Input → Image Text Extractor (groq-vision) → other agents
12. Return ONLY valid JSON, no explanations or markdown`
          }]
        })
      });

      const data = await response.json();
      
      // Check for API errors
      if (data.error) {
        throw new Error(data.error.message || 'API request failed');
      }
      
      const text = data.choices?.[0]?.message?.content || '';
      console.log('AI Workflow Response:', text);
      
      if (!text || text.trim().length === 0) {
        throw new Error('Empty response from AI. Please try again.');
      }
      
      // Extract JSON from response
      let jsonStr = text;
      const jsonMatch = text.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        jsonStr = jsonMatch[0];
      } else {
        throw new Error('No valid JSON found in AI response');
      }
      
      let workflow;
      try {
        workflow = JSON.parse(jsonStr);
      } catch (parseError) {
        console.error('JSON Parse Error. Raw text:', jsonStr);
        throw new Error('Failed to parse AI response as JSON');
      }
      
      if (!workflow.agents || !Array.isArray(workflow.agents)) {
        throw new Error('AI response missing agents array');
      }
      
      // Convert to our node format - include testInput for User Input nodes
      const newNodes: WorkflowNode[] = workflow.agents.map((agent: any, index: number) => {
        const isUserInput = agent.category === 'Human Interaction' || agent.name === 'User Input';
        return {
          id: agent.id || `ai_${Math.random().toString(36).substr(2, 9)}`,
          type: agent.type === 'TRIGGER' ? NodeType.TRIGGER : NodeType.AGENT,
          position: agent.position || { x: 100 + index * 350, y: 200 + (index % 2) * 80 },
          data: {
            label: agent.name,
            category: agent.category,
            model: agent.model || 'mimo-v2-flash',
            // For User Input nodes, use testInput as systemPrompt so it's ready to test
            systemPrompt: isUserInput && agent.testInput ? agent.testInput : agent.systemPrompt,
            inputEndpoints: agent.inputEndpoints || 1,
            outputEndpoints: agent.outputEndpoints || 1,
            // Store email-specific fields
            recipient: agent.recipient,
            subject: agent.subject,
          }
        };
      });

      const newEdges: WorkflowEdge[] = workflow.connections.map((conn: any, index: number) => ({
        id: `e_${conn.from}_${conn.sourceEndpoint || 0}_${conn.to}_${conn.targetEndpoint || 0}`,
        source: conn.from,
        target: conn.to,
        sourceEndpoint: conn.sourceEndpoint || 0,
        targetEndpoint: conn.targetEndpoint || 0,
      }));

      setNodes(newNodes);
      setEdges(newEdges);
      setAiWorkflowPrompt('');
      setAiPanelMode('browse');
      addLog('success', `Created workflow "${workflow.workflowName}" with ${newNodes.length} agents`);

    } catch (error: any) {
      console.error('AI Workflow Error:', error);
      addLog('error', `Failed to generate workflow: ${error.message}`);
    } finally {
      setIsAiGenerating(false);
    }
  };

  // --- AI CUSTOM AGENT GENERATION ---
  const generateCustomAgent = async () => {
    if (!aiAgentPrompt.trim() || isAiGenerating) return;
    
    setIsAiGenerating(true);
    addLog('info', 'AI is creating your custom agent...');

    try {
      const response = await fetch('https://openrouter.ai/api/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${import.meta.env.VITE_OPENROUTER_API_KEY || ''}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          model: 'xiaomi/mimo-v2-flash:free',
          messages: [{
            role: 'user',
            content: `You are an expert at creating AI agent configurations. Based on the user's description, create a custom AI agent with a comprehensive system prompt.

USER REQUEST: "${aiAgentPrompt}"

Generate a JSON response with this EXACT structure (no markdown, just pure JSON):
{
  "name": "Agent Name (short, descriptive)",
  "category": "CUSTOM",
  "model": "mimo-v2-flash",
  "description": "One-line description of what this agent does",
  "systemPrompt": "A comprehensive, professional system prompt of 200+ words that explains:
    1. The agent's role and expertise
    2. What tasks it handles
    3. Expected input format
    4. How it should structure its output
    5. Any specific rules or guidelines it must follow
    6. Edge cases it should handle
    7. Quality standards it must maintain"
}

Make the systemPrompt extremely detailed and professional. The agent should be production-ready.
Return ONLY valid JSON, no explanations or markdown.`
          }]
        })
      });

      const data = await response.json();
      
      // Check for API errors
      if (data.error) {
        throw new Error(data.error.message || 'API request failed');
      }
      
      const text = data.choices?.[0]?.message?.content || '';
      console.log('AI Agent Response:', text);
      
      if (!text || text.trim().length === 0) {
        throw new Error('Empty response from AI. Please try again.');
      }
      
      // Extract JSON from response
      let jsonStr = text;
      const jsonMatch = text.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        jsonStr = jsonMatch[0];
      } else {
        throw new Error('No valid JSON found in AI response');
      }
      
      let agent;
      try {
        agent = JSON.parse(jsonStr);
      } catch (parseError) {
        console.error('JSON Parse Error. Raw text:', jsonStr);
        throw new Error('Failed to parse AI response as JSON');
      }
      
      if (!agent.name || !agent.systemPrompt) {
        throw new Error('AI response missing required fields (name or systemPrompt)');
      }
      
      // Create the agent template
      const newAgent: AgentTemplate = {
        category: 'Custom AI Agents',
        name: agent.name,
        model: agent.model || 'mimo-v2-flash',
        icon: Sparkles,
        color: 'text-purple-400',
        prompt: agent.systemPrompt
      };

      // Add to custom agents list
      setCustomAgents(prev => [newAgent, ...prev]);
      
      // Also add directly to canvas
      const id = Math.random().toString(36).substr(2, 9);
      const viewportCenterX = (window.innerWidth / 2 - 288) / zoom - pan.x;
      const viewportCenterY = (window.innerHeight / 2) / zoom - pan.y;
      
      const newNode: WorkflowNode = {
        id,
        type: NodeType.AGENT,
        position: { x: viewportCenterX, y: viewportCenterY },
        data: {
          label: agent.name,
          category: 'Custom AI Agents',
          model: agent.model || 'mimo-v2-flash',
          systemPrompt: agent.systemPrompt
        }
      };
      
      setNodes([...nodes, newNode]);
      setAiAgentPrompt('');
      setAiPanelMode('browse');
      addLog('success', `Created custom agent "${agent.name}" and added to canvas`);

    } catch (error: any) {
      console.error('AI Agent Error:', error);
      addLog('error', `Failed to create agent: ${error.message}`);
    } finally {
      setIsAiGenerating(false);
    }
  };

  // --- FILE UPLOAD LOGIC ---
  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
      if (e.target.files && e.target.files.length > 0 && selectedNodeId) {
          const file = e.target.files[0];
          const fileType = file.type.includes('image') ? 'image' : file.type.includes('json') ? 'json' : file.type === 'application/pdf' ? 'pdf' : 'file';
          
          let content = "";
          
          try {
              if (file.type === 'application/pdf') {
                  addLog('info', 'Parsing PDF...', selectedNodeId);
                  const arrayBuffer = await file.arrayBuffer();
                  const loadingTask = pdfjs.getDocument({ data: arrayBuffer });
                  const pdf = await loadingTask.promise;
                  
                  let extractedText = '';
                  // Limit to first 10 pages for performance in this demo
                  const maxPages = Math.min(pdf.numPages, 10);
                  
                  for (let i = 1; i <= maxPages; i++) {
                      const page = await pdf.getPage(i);
                      const textContent = await page.getTextContent();
                      const pageText = textContent.items.map((item: any) => item.str).join(' ');
                      extractedText += `\n--- Page ${i} ---\n${pageText}`;
                  }
                  content = extractedText;
                  addLog('success', 'PDF Parsed Successfully', selectedNodeId);

              } else if (file.type.startsWith('image/')) {
                  // Handle images - convert to base64 data URL for vision models
                  addLog('info', 'Processing image...', selectedNodeId);
                  const base64 = await new Promise<string>((resolve, reject) => {
                      const reader = new FileReader();
                      reader.onload = () => resolve(reader.result as string);
                      reader.onerror = reject;
                      reader.readAsDataURL(file);
                  });
                  content = base64; // Store as data URL (e.g., "data:image/png;base64,...")
                  addLog('success', 'Image processed for vision AI', selectedNodeId);

              } else if (file.type.match(/text.*/) || file.type.includes('json') || file.name.endsWith('.md') || file.name.endsWith('.txt')) {
                  content = await file.text();
              } else {
                 content = `[Binary content for file '${file.name}' is not supported. Please use images (jpg, png), PDF, or text files.]`;
              }
          } catch (err) {
              console.error("File Read Error", err);
              addLog('error', 'Failed to read file content', selectedNodeId);
              content = "[Error reading file content]";
          }

          const newAttachment: Attachment = {
              name: file.name,
              type: fileType,
              size: (file.size / 1024).toFixed(1) + 'KB',
              content: content
          };

          setNodes(prev => prev.map(n => {
              if (n.id === selectedNodeId) {
                  const currentAttachments = n.data.attachments || [];
                  return {
                      ...n,
                      data: {
                          ...n.data,
                          attachments: [...currentAttachments, newAttachment]
                      }
                  };
              }
              return n;
          }));
          addLog('success', `Uploaded: ${file.name}`);
          
          // Reset input
          if (fileInputRef.current) fileInputRef.current.value = '';
      }
  };

  const removeAttachment = (index: number) => {
      if (!selectedNodeId) return;
      setNodes(prev => prev.map(n => {
          if (n.id === selectedNodeId) {
              const currentAttachments = n.data.attachments || [];
              const removed = currentAttachments[index];
              return {
                  ...n,
                  data: {
                      ...n.data,
                      attachments: currentAttachments.filter((_, i) => i !== index)
                  }
              };
          }
          return n;
      }));
  };

  // --- DRAG & DROP & PANNING LOGIC ---

  const handleMouseDownCanvas = (e: React.MouseEvent) => {
      // Close context menu on left click anywhere on canvas
      if (e.button === 0 && contextMenu.visible) {
        closeContextMenu();
      }
      // Middle click or Space+Click initiates pan
      if (e.button === 1 || (e.button === 0 && e.shiftKey)) {
          e.preventDefault();
          setIsPanning(true);
          setLastMousePos({ x: e.clientX, y: e.clientY });
      }
  };

  const handleMouseDownNode = (e: React.MouseEvent, nodeId: string) => {
    e.stopPropagation();
    const node = nodes.find(n => n.id === nodeId);
    if (!node || !canvasRef.current) return;

    // Coordinate conversion:
    // Screen (clientX) -> Canvas relative -> Divide by Zoom -> Subtract Pan
    const canvasRect = canvasRef.current.getBoundingClientRect();
    const worldMouseX = (e.clientX - canvasRect.left) / zoom - pan.x;
    const worldMouseY = (e.clientY - canvasRect.top) / zoom - pan.y;
    
    dragOffset.current = { 
      x: worldMouseX - node.position.x, 
      y: worldMouseY - node.position.y 
    };

    setDraggingNodeId(nodeId);
    setSelectedNodeId(nodeId);
  };

  // Track which endpoint we're connecting from
  const [connectingEndpoint, setConnectingEndpoint] = useState<number>(0);

  const handleMouseDownHandle = (e: React.MouseEvent, nodeId: string, endpointIdx: number = 0) => {
    e.stopPropagation();
    e.preventDefault();
    if (!canvasRef.current) return;
    const canvasRect = canvasRef.current.getBoundingClientRect();
    setConnectingNodeId(nodeId);
    setConnectingEndpoint(endpointIdx);
    // Initial mouse pos in World Space
    setMousePos({ 
      x: (e.clientX - canvasRect.left) / zoom - pan.x, 
      y: (e.clientY - canvasRect.top) / zoom - pan.y 
    });
  };

  const handleMouseUpHandle = (e: React.MouseEvent, targetNodeId: string, targetEndpointIdx: number = 0) => {
      e.stopPropagation();
      if (connectingNodeId && connectingNodeId !== targetNodeId) {
          const exists = edges.find(e => e.source === connectingNodeId && e.target === targetNodeId && e.sourceEndpoint === connectingEndpoint && e.targetEndpoint === targetEndpointIdx);
          if (!exists) {
            const newEdge: WorkflowEdge = {
                id: `e-${connectingNodeId}-${connectingEndpoint}-${targetNodeId}-${targetEndpointIdx}`,
                source: connectingNodeId,
                target: targetNodeId,
                sourceEndpoint: connectingEndpoint,
                targetEndpoint: targetEndpointIdx,
            };
            setEdges([...edges, newEdge]);
            addLog('success', `Connected nodes`);
          }
      }
      setConnectingNodeId(null);
      setConnectingEndpoint(0);
  };

  const handleMouseMove = useCallback((e: React.MouseEvent) => {
    if (!canvasRef.current) return;
    
    // Handle Canvas Panning
    if (isPanning) {
        const deltaX = (e.clientX - lastMousePos.x) / zoom;
        const deltaY = (e.clientY - lastMousePos.y) / zoom;
        setPan(prev => ({ x: prev.x + deltaX, y: prev.y + deltaY }));
        setLastMousePos({ x: e.clientX, y: e.clientY });
        return;
    }

    const canvasRect = canvasRef.current.getBoundingClientRect();
    
    // Project mouse to world coordinates
    const worldX = (e.clientX - canvasRect.left) / zoom - pan.x;
    const worldY = (e.clientY - canvasRect.top) / zoom - pan.y;

    if (draggingNodeId) {
      setNodes(prev => prev.map(n => n.id === draggingNodeId ? { 
        ...n, 
        position: { 
          x: worldX - dragOffset.current.x, 
          y: worldY - dragOffset.current.y 
        } 
      } : n));
    } else if (connectingNodeId) {
        setMousePos({ x: worldX, y: worldY });
    }
  }, [draggingNodeId, connectingNodeId, zoom, pan, isPanning, lastMousePos]);

  const handleMouseUpCanvas = (e: React.MouseEvent) => {
    setDraggingNodeId(null);
    setConnectingNodeId(null);
    setIsPanning(false);
    // Only close context menu on LEFT click (button 0), not right click
    if (e.button === 0 && !contextMenu.visible) {
      closeContextMenu();
    }
  };

  // --- EXECUTION LOGIC ---
  const executeWorkflow = async () => {
    setIsExecuting(true);
    setLogs([]);
    addLog('info', 'Starting execution sequence...');
    
    // Create a local map to store outputs for this execution run. 
    // This solves the React state closure issue where subsequent nodes couldn't see updates from previous nodes.
    const executionResults = new Map<string, string>();
    // Also track image URLs separately
    const executionImages = new Map<string, string>();

    try {
        // Start with nodes that have NO incoming edges (can start workflow independently)
        // This includes: Triggers, User Input, or ANY node placed first (like Image Text Extractor)
        const startNodes = nodes.filter(n => {
            // Check if node has any incoming edges
            const hasIncoming = edges.some(e => e.target === n.id);
            
            // If no incoming edges, it can be a start node
            if (!hasIncoming) return true;
            
            // Also allow explicit trigger types
            if (n.type === NodeType.TRIGGER || n.type === NodeType.WEBHOOK) return true;
            
            return false;
        });

        if (startNodes.length === 0) throw new Error("No start node found. Add a node to the canvas to run the workflow.");
        
        // Populate existing output state into execution map (for cases where we are resuming or using static triggers)
        nodes.forEach(n => {
             if (n.data.output) executionResults.set(n.id, n.data.output);
             if (n.data.imageUrl) executionImages.set(n.id, n.data.imageUrl);
        });

        const executed = new Set<string>();
        const queue = [...startNodes];

        while (queue.length > 0) {
            const currentNode = queue.shift();
            if (!currentNode) continue;
            if (executed.has(currentNode.id)) continue;

            const incomingEdges = edges.filter(e => e.target === currentNode.id);
            let inputContext = '';
            
            if (incomingEdges.length > 0) {
                 const inputs = incomingEdges.map(e => {
                     // Prioritize the fresh output from this run's execution map, fall back to node state
                     return executionResults.get(e.source) || nodes.find(n => n.id === e.source)?.data.output;
                 }).filter(Boolean).join('\n---\n');
                 if (inputs) inputContext = inputs;
            }

            // Check if this is a Human Interaction (User Input) node - can be AGENT or TRIGGER type
            const isUserInputNode = currentNode.data.category === 'Human Interaction' || 
                                    currentNode.data.label === 'User Input' ||
                                    currentNode.data.model === 'user-input';

            if (isUserInputNode) {
                // --- USER INPUT NODE ---
                addLog('info', `User Input: ${currentNode.data.label}`, currentNode.id);
                setNodes(prev => prev.map(n => n.id === currentNode.id ? { ...n, data: { ...n.data, isExecuting: true } } : n));
                
                await new Promise(resolve => setTimeout(resolve, 300));
                
                // Get the user's message from systemPrompt field
                let userInput = currentNode.data.systemPrompt || "";
                let imageData: string | null = null;
                
                // Handle attachments - separate images from text files
                if (currentNode.data.attachments && currentNode.data.attachments.length > 0) {
                    const textFiles: string[] = [];
                    
                    for (const attachment of currentNode.data.attachments) {
                        if (attachment.type === 'image' && attachment.content?.startsWith('data:image')) {
                            // Store image data URL separately for vision models
                            imageData = attachment.content;
                            addLog('info', `Image attached: ${attachment.name} (will be sent to vision AI)`, currentNode.id);
                        } else {
                            // Text/PDF content
                            textFiles.push(`--- File: ${attachment.name} ---\n${attachment.content}\n--- End File ---`);
                        }
                    }
                    
                    // Append text file contents to user input
                    if (textFiles.length > 0) {
                        const fileList = textFiles.join('\n\n');
                        userInput = userInput ? `${userInput}\n\nAttached Files:\n${fileList}` : `Attached Files:\n${fileList}`;
                    }
                }
                
                if (!userInput && !imageData) {
                    userInput = "No user input provided.";
                    addLog('warning', 'No message entered in User Input node', currentNode.id);
                } else {
                    addLog('info', `Message: "${userInput.substring(0, 50)}..."${imageData ? ' + Image' : ''}`, currentNode.id);
                }
                
                // Store the user input for downstream nodes
                // If there's an image, store it separately in executionImages map
                let outputValue = userInput || (imageData ? 'Image provided for analysis' : '');
                
                executionResults.set(currentNode.id, outputValue);
                if (imageData) {
                    executionImages.set(currentNode.id, imageData);
                    addLog('info', 'Image stored for downstream nodes', currentNode.id);
                }
                
                setNodes(prev => prev.map(n => n.id === currentNode.id ? { ...n, data: { ...n.data, output: userInput || '[Image attached]', imageUrl: imageData, isExecuting: false } } : n));
                addLog('success', 'User input captured', currentNode.id);

            } else if (currentNode.type === NodeType.AGENT) {
                if (currentNode.data.model === 'mock-sender') {
                    // --- EMAIL SENDER ---
                    // Try to extract recipient from input context if not configured
                    let recipient = currentNode.data.recipient || '';
                    if (!recipient && inputContext) {
                        // Try to extract email from input (look for email pattern)
                        const emailMatch = inputContext.match(/[\w.-]+@[\w.-]+\.\w+/);
                        if (emailMatch) {
                            recipient = emailMatch[0];
                            addLog('info', `Extracted recipient from input: ${recipient}`, currentNode.id);
                        }
                    }
                    if (!recipient) recipient = 'unknown@example.com';
                    
                    const senderEmail = user?.email || 'noreply@aether.ai';
                    addLog('info', `Sending email from ${senderEmail} to ${recipient}...`, currentNode.id);
                    setNodes(prev => prev.map(n => n.id === currentNode.id ? { ...n, data: { ...n.data, isExecuting: true } } : n));
                    
                    const bodyContent = inputContext || currentNode.data.systemPrompt || "No content provided.";
                    const subject = currentNode.data.subject || 'Workflow Notification';
                    
                    let emailOutput = '';
                    let emailSent = false;
                    
                    // Send via EmailJS (works to any email!)
                    try {
                        addLog('info', `Sending email via EmailJS to ${recipient}...`, currentNode.id);
                        
                        // @ts-ignore - emailjs is loaded via CDN
                        const result = await window.emailjs.send(
                            'service_s8kc34i',  // Service ID
                            'template_l8347so', // Template ID
                            {
                                to_email: recipient,
                                subject: subject,
                                message: bodyContent,
                                reply_to: senderEmail,
                            }
                        );
                        
                        if (result.status === 200) {
                            emailSent = true;
                            emailOutput = `[EMAIL SENT SUCCESSFULLY]\n\n--------------------------------------\nSTATUS:  Delivered ✓\nFROM:    ${senderEmail}\nTO:      ${recipient}\nSUBJECT: ${subject}\nDATE:    ${new Date().toISOString()}\nSERVICE: EmailJS\n\nBODY:\n${bodyContent.substring(0, 500)}${bodyContent.length > 500 ? '...' : ''}\n--------------------------------------`;
                            addLog('success', `Email sent successfully to ${recipient}`, currentNode.id);
                        } else {
                            throw new Error('EmailJS returned non-200 status');
                        }
                    } catch (emailJsError: any) {
                        console.error('EmailJS failed:', emailJsError);
                        
                        // Fallback: Try backend Resend API (only works for verified emails)
                        try {
                            const response = await fetch('http://localhost:8080/api/v1/integrations/email/send', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({
                                    to: recipient,
                                    subject: subject,
                                    text: bodyContent,
                                })
                            });
                            
                            const result = await response.json();
                            
                            if (result.success) {
                                emailSent = true;
                                emailOutput = `[EMAIL SENT SUCCESSFULLY]\n\n--------------------------------------\nSTATUS:  Delivered (via Resend)\nTO:      ${recipient}\nSUBJECT: ${subject}\nDATE:    ${new Date().toISOString()}\n--------------------------------------`;
                                addLog('success', `Email sent via backup (Resend) to ${recipient}`, currentNode.id);
                            } else {
                                throw new Error(result.error || 'Resend also failed');
                            }
                        } catch (resendError: any) {
                            // Final fallback: mailto link
                            const mailtoLink = `mailto:${recipient}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(bodyContent.substring(0, 1500))}`;
                            window.open(mailtoLink, '_blank');
                            emailOutput = `[EMAIL CLIENT OPENED]\nAutomatic sending failed. Opening your email client.\n\n--------------------------------------\nTO:      ${recipient}\nSUBJECT: ${subject}\nERROR:   ${emailJsError?.text || emailJsError?.message || 'Unknown error'}\n--------------------------------------`;
                            addLog('warning', 'Email client opened as fallback', currentNode.id);
                        }
                    }
                    
                    executionResults.set(currentNode.id, emailOutput);
                    setNodes(prev => prev.map(n => n.id === currentNode.id ? { ...n, data: { ...n.data, output: emailOutput, isExecuting: false } } : n));

                } else {
                    // Standard AI Agent
                    addLog('info', `Agent Thinking: ${currentNode.data.label} (Model: ${currentNode.data.model})`, currentNode.id);
                    console.log(`[WORKFLOW] Executing node: ${currentNode.data.label}, Model: ${currentNode.data.model}, Input: ${inputContext?.substring(0, 100)}`);
                    setNodes(prev => prev.map(n => n.id === currentNode.id ? { ...n, data: { ...n.data, isExecuting: true } } : n));
                    
                    // Check if input contains image data (from User Input node)
                    let textInput = inputContext || "Start";
                    let imageUrl: string | undefined = undefined;
                    
                    // 1. Check if current node has image directly uploaded (groq-vision config)
                    if (currentNode.data.imageUrl) {
                        imageUrl = currentNode.data.imageUrl;
                        addLog('info', `Using image from node config: ${currentNode.data.imageName || 'image'}`, currentNode.id);
                    }
                    
                    // 2. Check executionImages map (set by User Input node during this run)
                    if (!imageUrl) {
                        const upstreamEdge = edges.find(e => e.target === currentNode.id);
                        if (upstreamEdge && executionImages.has(upstreamEdge.source)) {
                            imageUrl = executionImages.get(upstreamEdge.source);
                            addLog('info', 'Image received from User Input execution', currentNode.id);
                        }
                    }
                    
                    // 3. Check if upstream node has imageUrl in its data (from previous run)
                    if (!imageUrl) {
                        const upstreamEdge = edges.find(e => e.target === currentNode.id);
                        if (upstreamEdge) {
                            const upstreamNode = nodes.find(n => n.id === upstreamEdge.source);
                            if (upstreamNode?.data.imageUrl) {
                                imageUrl = upstreamNode.data.imageUrl;
                                addLog('info', 'Image received from upstream node data', currentNode.id);
                            }
                        }
                    }
                    
                    // Stronger context injection for Doc Generator or any node relying heavily on inputs
                    let effectivePrompt = currentNode.data.systemPrompt || '';
                    if (currentNode.data.label.includes('Doc Generator') && textInput) {
                        effectivePrompt = `${effectivePrompt}\n\n[INPUT CONTENT TO DOCUMENT]:\n${textInput}`;
                    }

                    const response = await generateAgentResponse(textInput, effectivePrompt, currentNode.data.model, imageUrl);
                    console.log(`[WORKFLOW] Response received for ${currentNode.data.label}: ${response?.substring(0, 100)}`);
                    
                    let downloadUrl = undefined;

                    // --- DOC GENERATOR PDF LOGIC ---
                    if (currentNode.data.label === 'Doc Generator' || currentNode.data.label.includes('Doc')) {
                         try {
                             addLog('info', 'Converting output to PDF...', currentNode.id);
                             const doc = new jsPDF();
                             
                             // Strip markdown symbols for cleaner PDF text
                             const cleanText = (text: string) => {
                                return text
                                    .replace(/#{1,6}\s?/g, '') // Remove headers
                                    .replace(/\*\*/g, '')      // Remove bold
                                    .replace(/\*/g, '')        // Remove italics
                                    .replace(/`/g, '')         // Remove code ticks
                                    .replace(/\[([^\]]+)\]\([^\)]+\)/g, '$1'); // Remove links, keep text
                             };

                             const processedText = cleanText(response);

                             // Split text to fit page width
                             const splitText = doc.splitTextToSize(processedText, 180); // 180mm width (A4 is 210mm)
                             
                             let y = 20;
                             const pageHeight = 280;
                             
                             doc.setFontSize(16);
                             doc.text("Generated Documentation", 10, y);
                             y += 15;
                             doc.setFontSize(11);
                             
                             // Simple pagination loop
                             for(let i=0; i<splitText.length; i++) {
                                if (y > pageHeight) {
                                   doc.addPage();
                                   y = 20;
                                }
                                doc.text(splitText[i], 10, y);
                                y += 6;
                             }
                             
                             const pdfBlob = doc.output('blob');
                             downloadUrl = URL.createObjectURL(pdfBlob);
                             addLog('success', 'PDF Generated Successfully', currentNode.id);
                         } catch (pdfErr) {
                             console.error("PDF Gen Error", pdfErr);
                             addLog('error', 'Failed to generate PDF', currentNode.id);
                         }
                    }

                    // Update local execution map immediately
                    executionResults.set(currentNode.id, response);

                    setNodes(prev => prev.map(n => n.id === currentNode.id ? { 
                        ...n, 
                        data: { 
                            ...n.data, 
                            output: response, 
                            downloadUrl: downloadUrl,
                            isExecuting: false 
                        } 
                    } : n));
                    addLog('success', 'Step Complete', currentNode.id);
                }

            } else if (currentNode.type === NodeType.TRIGGER) {
                 // For Triggers, we need to make sure they pass along any input context they might have received
                 // If the trigger was triggered by a User Input node upstream (topology-wise), we pass that through.
                 // Otherwise, standard trigger output.
                 let triggerOutput = inputContext || currentNode.data.output || 'Trigger fired';
                 
                 // Update local execution map
                 executionResults.set(currentNode.id, triggerOutput);

                 // Update the node's output so downstream nodes can read it via inputContext logic
                 setNodes(prev => prev.map(n => n.id === currentNode.id ? { ...n, data: { ...n.data, output: triggerOutput } } : n));
                 addLog('success', 'Trigger Activated', currentNode.id);
            }

            executed.add(currentNode.id);
            const outgoingEdges = edges.filter(e => e.source === currentNode.id);
            outgoingEdges.forEach(e => {
                const nextNode = nodes.find(n => n.id === e.target);
                if (nextNode) queue.push(nextNode);
            });
            if (executed.size > 20) break; 
        }
        addLog('success', 'Workflow finished.');
    } catch (err: any) {
      addLog('error', err.message);
    } finally {
      setIsExecuting(false);
    }
  };

  const selectedNode = nodes.find(n => n.id === selectedNodeId);
  const categories = Array.from(new Set(AGENT_LIBRARY.map(a => a.category)));

  return (
    <div className="flex h-[calc(100vh-64px)] overflow-hidden pt-20 bg-black relative">
      
      {/* Hidden File Input */}
      <input 
        type="file" 
        ref={fileInputRef} 
        onChange={handleFileUpload} 
        className="hidden" 
        multiple={false}
      />

      {/* --- SETTINGS MODAL --- */}
      {showSettings && (
          <div className="fixed inset-0 z-[9999] flex items-center justify-center bg-black/80 backdrop-blur-md p-4 animate-in fade-in duration-200">
              <div className="glass-panel w-full max-w-2xl rounded-2xl p-8 shadow-2xl relative">
                  <button onClick={() => setShowSettings(false)} className="absolute top-6 right-6 text-gray-400 hover:text-white"><X /></button>
                  <h2 className="font-display text-3xl font-bold text-white mb-6 flex items-center gap-3">
                      <Settings className="text-cherry" /> System Configuration
                  </h2>
                  <div className="grid grid-cols-2 gap-8">
                      <div className="space-y-4">
                          <label className="block text-xs font-bold uppercase text-gray-500">API Gateway</label>
                          <input 
                            type="text" 
                            value={systemSettings.apiGateway}
                            onChange={(e) => setSystemSettings(s => ({ ...s, apiGateway: e.target.value }))}
                            className="w-full bg-black/50 border border-white/10 rounded-lg p-3 text-sm text-white focus:border-cherry outline-none" 
                          />
                          
                          <label className="block text-xs font-bold uppercase text-gray-500">Default Model</label>
                          <select 
                            value={systemSettings.defaultModel}
                            onChange={(e) => setSystemSettings(s => ({ ...s, defaultModel: e.target.value }))}
                            className="w-full bg-black border border-white/10 rounded-lg p-3 text-sm text-white focus:border-cherry outline-none"
                          >
                              <option value="gemini-2.5-flash">Gemini 2.5 Flash</option>
                              <option value="gemini-3-pro-preview">Gemini 3.0 Pro</option>
                              <option value="openrouter-free">OpenRouter (Free)</option>
                          </select>
                      </div>
                      <div className="space-y-4">
                          <label className="block text-xs font-bold uppercase text-gray-500">Environment</label>
                          <div className="flex gap-2">
                              <button 
                                onClick={() => setSystemSettings(s => ({ ...s, environment: 'production' }))}
                                className={`flex-1 py-2 text-xs font-bold rounded-lg transition-all ${
                                  systemSettings.environment === 'production' 
                                    ? 'bg-cherry/20 border border-cherry text-cherry' 
                                    : 'bg-white/5 border border-white/10 text-gray-400 hover:bg-white/10'
                                }`}
                              >
                                Production
                              </button>
                              <button 
                                onClick={() => setSystemSettings(s => ({ ...s, environment: 'staging' }))}
                                className={`flex-1 py-2 text-xs font-bold rounded-lg transition-all ${
                                  systemSettings.environment === 'staging' 
                                    ? 'bg-amber-500/20 border border-amber-500 text-amber-400' 
                                    : 'bg-white/5 border border-white/10 text-gray-400 hover:bg-white/10'
                                }`}
                              >
                                Staging
                              </button>
                              <button 
                                onClick={() => setSystemSettings(s => ({ ...s, environment: 'development' }))}
                                className={`flex-1 py-2 text-xs font-bold rounded-lg transition-all ${
                                  systemSettings.environment === 'development' 
                                    ? 'bg-blue-500/20 border border-blue-500 text-blue-400' 
                                    : 'bg-white/5 border border-white/10 text-gray-400 hover:bg-white/10'
                                }`}
                              >
                                Dev
                              </button>
                          </div>
                          
                          <label className="block text-xs font-bold uppercase text-gray-500 mt-4">Logged In As</label>
                          <div className="p-3 bg-white/5 rounded-lg border border-white/10">
                            <p className="text-sm text-white font-medium">{user?.name || 'Guest'}</p>
                            <p className="text-xs text-gray-500">{user?.email || 'Not logged in'}</p>
                          </div>
                      </div>
                  </div>
                  <div className="mt-8 pt-6 border-t border-white/10 flex justify-end gap-3">
                      <button onClick={() => setShowSettings(false)} className="px-6 py-2 rounded-lg text-sm font-bold text-gray-400 hover:text-white">Cancel</button>
                      <button onClick={saveSettings} className="px-6 py-2 rounded-lg bg-cream text-black text-sm font-bold hover:bg-white flex items-center gap-2">
                          <Save className="w-4 h-4" /> Save Changes
                      </button>
                  </div>
              </div>
          </div>
      )}

      {/* --- DEPLOY MODAL --- */}
      {showDeployModal && (
        <div className="fixed inset-0 z-[9999] flex items-center justify-center bg-black/80 backdrop-blur-md p-4 animate-in fade-in duration-200">
          <div className="glass-panel w-full max-w-md rounded-2xl p-8 shadow-2xl relative">
            <button onClick={() => setShowDeployModal(false)} className="absolute top-6 right-6 text-gray-400 hover:text-white"><X /></button>
            <h2 className="font-display text-2xl font-bold text-white mb-2 flex items-center gap-3">
              <UploadCloud className="text-emerald-400" /> Deploy Workflow
            </h2>
            <p className="text-sm text-gray-400 mb-6">Enter a name for your workflow deployment.</p>
            
            <div className="space-y-4">
              <div>
                <label className="block text-xs font-bold uppercase text-gray-500 mb-2">Workflow Name</label>
                <input 
                  type="text" 
                  value={deployWorkflowName}
                  onChange={(e) => setDeployWorkflowName(e.target.value)}
                  placeholder="e.g., Customer Onboarding Pipeline"
                  className="w-full bg-black/50 border border-white/10 rounded-lg p-3 text-sm text-white focus:border-emerald-500 outline-none" 
                  autoFocus
                />
              </div>
              
              <div className="p-4 bg-white/5 rounded-xl">
                <div className="text-xs text-gray-400 mb-2">This workflow contains:</div>
                <div className="text-sm text-white font-medium">{nodes.length} nodes, {edges.length} connections</div>
              </div>
              
              <div className="p-4 bg-emerald-500/10 border border-emerald-500/20 rounded-xl">
                <div className="text-xs text-emerald-400 font-bold mb-1">Webhook URL (after deploy)</div>
                <div className="text-xs text-gray-400 font-mono break-all">
                  http://localhost:8080/webhook/{deployedWorkflowId || 'wf_' + Date.now()}/trigger
                </div>
              </div>
            </div>
            
            <div className="mt-6 flex justify-end gap-3">
              <button 
                onClick={() => setShowDeployModal(false)} 
                className="px-6 py-2 rounded-lg text-sm font-bold text-gray-400 hover:text-white"
              >
                Cancel
              </button>
              <button 
                onClick={() => deployWorkflow(deployWorkflowName)}
                disabled={!deployWorkflowName.trim()}
                className="px-6 py-2 rounded-lg bg-emerald-500 text-white text-sm font-bold hover:bg-emerald-600 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
              >
                <UploadCloud className="w-4 h-4" /> {deployedWorkflowId ? 'Update' : 'Deploy'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* --- LEFT SIDEBAR: AGENT LIBRARY --- */}
      <div className="w-72 border-r border-white/5 bg-[#050505] flex flex-col z-20">
         {/* AI Generation Section - Integrated at Top */}
         <div className="p-3 border-b border-white/5">
            <div className="flex gap-2 mb-3">
               <button 
                  onClick={() => onNavigate('LANDING')}
                  className="w-8 h-8 flex-shrink-0 flex items-center justify-center rounded-lg bg-white/5 hover:bg-white/10 text-gray-400 hover:text-white transition-colors"
                  title="Back to Home"
               >
                  <ArrowLeft className="w-4 h-4" />
               </button>
               <div className="flex-1 flex gap-1.5">
                  <button
                     onClick={() => setAiPanelMode(aiPanelMode === 'workflow' ? 'browse' : 'workflow')}
                     className={`flex-1 py-2 px-2 rounded-lg text-[10px] font-bold uppercase tracking-wide flex items-center justify-center gap-1.5 transition-all ${
                        aiPanelMode === 'workflow' 
                           ? 'bg-gradient-to-r from-purple-600 to-cherry text-white shadow-lg shadow-purple-500/20' 
                           : 'bg-white/5 text-gray-400 hover:bg-white/10 hover:text-white'
                     }`}
                  >
                     <Sparkles className="w-3 h-3" />
                     <span>AI Workflow</span>
                  </button>
                  <button
                     onClick={() => setAiPanelMode(aiPanelMode === 'agent' ? 'browse' : 'agent')}
                     className={`flex-1 py-2 px-2 rounded-lg text-[10px] font-bold uppercase tracking-wide flex items-center justify-center gap-1.5 transition-all ${
                        aiPanelMode === 'agent' 
                           ? 'bg-gradient-to-r from-cyan-600 to-blue-500 text-white shadow-lg shadow-cyan-500/20' 
                           : 'bg-white/5 text-gray-400 hover:bg-white/10 hover:text-white'
                     }`}
                  >
                     <User className="w-3 h-3" />
                     <span>AI Agent</span>
                  </button>
               </div>
            </div>

            {/* AI Workflow Generator Panel */}
            {aiPanelMode === 'workflow' && (
               <div className="mb-3 p-3 rounded-xl bg-gradient-to-br from-purple-900/30 to-cherry/10 border border-purple-500/20">
                  <div className="flex items-center gap-2 mb-2">
                     <Sparkles className="w-4 h-4 text-purple-400" />
                     <span className="text-xs font-bold text-purple-300">Create AI Workflow</span>
                  </div>
                  <p className="text-[10px] text-gray-400 mb-2">Describe what you want to automate and AI will generate a complete workflow with multiple agents.</p>
                  <textarea
                     value={aiWorkflowPrompt}
                     onChange={(e) => setAiWorkflowPrompt(e.target.value)}
                     placeholder="Example: Build a content pipeline that scrapes news, summarizes articles, generates social media posts, and schedules them..."
                     className="w-full h-20 bg-black/40 border border-purple-500/30 rounded-lg p-2 text-xs text-white placeholder-gray-600 resize-none focus:outline-none focus:border-purple-400"
                  />
                  <button
                     onClick={generateAIWorkflow}
                     disabled={isAiGenerating || !aiWorkflowPrompt.trim()}
                     className="w-full mt-2 py-2 rounded-lg bg-gradient-to-r from-purple-600 to-cherry text-white text-xs font-bold uppercase tracking-wide flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed hover:opacity-90 transition-opacity"
                  >
                     {isAiGenerating ? (
                        <>
                           <RefreshCw className="w-3 h-3 animate-spin" />
                           Generating...
                        </>
                     ) : (
                        <>
                           <Zap className="w-3 h-3" />
                           Generate Workflow
                        </>
                     )}
                  </button>
               </div>
            )}

            {/* AI Custom Agent Panel */}
            {aiPanelMode === 'agent' && (
               <div className="mb-3 p-3 rounded-xl bg-gradient-to-br from-cyan-900/30 to-blue-600/10 border border-cyan-500/20">
                  <div className="flex items-center gap-2 mb-2">
                     <User className="w-4 h-4 text-cyan-400" />
                     <span className="text-xs font-bold text-cyan-300">Create Custom Agent</span>
                  </div>
                  <p className="text-[10px] text-gray-400 mb-2">Describe what you need and AI will create a specialized agent with a comprehensive system prompt.</p>
                  <textarea
                     value={aiAgentPrompt}
                     onChange={(e) => setAiAgentPrompt(e.target.value)}
                     placeholder="Example: Create an agent that analyzes customer feedback, extracts sentiment, and categorizes issues by priority..."
                     className="w-full h-20 bg-black/40 border border-cyan-500/30 rounded-lg p-2 text-xs text-white placeholder-gray-600 resize-none focus:outline-none focus:border-cyan-400"
                  />
                  <button
                     onClick={generateCustomAgent}
                     disabled={isAiGenerating || !aiAgentPrompt.trim()}
                     className="w-full mt-2 py-2 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-500 text-white text-xs font-bold uppercase tracking-wide flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed hover:opacity-90 transition-opacity"
                  >
                     {isAiGenerating ? (
                        <>
                           <RefreshCw className="w-3 h-3 animate-spin" />
                           Creating...
                        </>
                     ) : (
                        <>
                           <Plus className="w-3 h-3" />
                           Create Agent
                        </>
                     )}
                  </button>
               </div>
            )}

            {/* Search Bar */}
            <div className="relative">
               <Search className="absolute left-3 top-2.5 w-4 h-4 text-gray-500" />
               <input 
                  type="text" 
                  placeholder="Search agents..." 
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-full bg-white/5 border border-white/10 rounded-lg pl-9 pr-3 py-2 text-xs text-white focus:outline-none focus:border-cherry"
               />
            </div>
         </div>

         {/* Agent Library */}
         <div className="flex-1 overflow-y-auto custom-scrollbar">
             {/* Custom AI Agents Section */}
             {customAgents.length > 0 && (
                <div className="mb-2">
                   <div className="px-4 py-2 text-[10px] font-bold uppercase tracking-widest text-purple-400 sticky top-0 bg-[#050505] z-10 flex items-center gap-2">
                      <Sparkles className="w-3 h-3" />
                      Your Custom Agents
                   </div>
                   <div className="px-2 space-y-1">
                      {customAgents.filter(a => a.name.toLowerCase().includes(searchQuery.toLowerCase())).map((agent, idx) => (
                         <button 
                            key={`custom-${idx}`}
                            onClick={() => addNode(agent)}
                            className="w-full text-left px-3 py-2 rounded-lg hover:bg-purple-500/10 border border-transparent hover:border-purple-500/20 flex items-center gap-3 group transition-all"
                         >
                            <div className="w-8 h-8 rounded-md bg-gradient-to-br from-purple-600/20 to-cherry/20 flex items-center justify-center text-purple-400 group-hover:from-purple-600/30 group-hover:to-cherry/30 transition-colors">
                               <Sparkles className="w-4 h-4" />
                            </div>
                            <div>
                               <div className="text-xs font-bold text-purple-300 group-hover:text-purple-200">{agent.name}</div>
                               <div className="text-[10px] text-gray-600 truncate max-w-[140px]">{agent.model}</div>
                            </div>
                         </button>
                      ))}
                   </div>
                </div>
             )}

             {/* Built-in Agent Categories */}
             {categories.map(cat => {
                 const catAgents = AGENT_LIBRARY.filter(a => a.category === cat && a.name.toLowerCase().includes(searchQuery.toLowerCase()));
                 if (catAgents.length === 0) return null;
                 return (
                     <div key={cat} className="mb-2">
                         <div className="px-4 py-2 text-[10px] font-bold uppercase tracking-widest text-gray-500 sticky top-0 bg-[#050505] z-10">{cat}</div>
                         <div className="px-2 space-y-1">
                             {catAgents.map(agent => (
                                 <button 
                                    key={agent.name}
                                    onClick={() => addNode(agent)}
                                    className="w-full text-left px-3 py-2 rounded-lg hover:bg-white/5 flex items-center gap-3 group transition-all"
                                 >
                                    <div className="w-8 h-8 rounded-md bg-white/5 flex items-center justify-center text-gray-400 group-hover:bg-white/10 transition-colors">
                                        <agent.icon className={`w-4 h-4 ${agent.color}`} />
                                    </div>
                                    <div>
                                        <div className="text-xs font-bold text-gray-300 group-hover:text-white">{agent.name}</div>
                                        <div className="text-[10px] text-gray-600 truncate max-w-[140px]">{agent.model}</div>
                                    </div>
                                 </button>
                             ))}
                         </div>
                     </div>
                 );
             })}
         </div>
      </div>

      {/* --- CANVAS --- */}
      <div 
        className={`flex-1 relative bg-black overflow-hidden ${isPanning ? 'cursor-grabbing' : 'cursor-crosshair'}`}
        ref={canvasRef}
        onMouseMove={handleMouseMove}
        onMouseDown={handleMouseDownCanvas}
        onMouseUp={handleMouseUpCanvas}
        onMouseLeave={handleMouseUpCanvas}
      >
        {/* Background Grid - Scaled to create depth */}
        <div className="absolute inset-0 pointer-events-none origin-top-left" style={{ 
            backgroundImage: 'radial-gradient(#222 1px, transparent 1px)', 
            backgroundSize: `${24 * zoom}px ${24 * zoom}px`, 
            backgroundPosition: `${pan.x * zoom}px ${pan.y * zoom}px`, // Pan bg for visual effect
            opacity: 0.5 
        }} />

        {/* Zoom Controls */}
        <div className="absolute bottom-6 left-6 flex items-center gap-2 z-50">
           <button onClick={() => setZoom(z => Math.max(0.5, z - 0.1))} className="w-8 h-8 rounded-full glass-panel flex items-center justify-center text-gray-400 hover:text-white transition-colors">
              <Minus className="w-4 h-4" />
           </button>
           <span className="text-xs font-mono text-gray-500 w-8 text-center">{Math.round(zoom * 100)}%</span>
           <button onClick={() => setZoom(z => Math.min(2, z + 0.1))} className="w-8 h-8 rounded-full glass-panel flex items-center justify-center text-gray-400 hover:text-white transition-colors">
              <Plus className="w-4 h-4" />
           </button>
           <div className="w-px h-6 bg-white/10 mx-2"></div>
           <span className="text-[9px] text-gray-600 uppercase tracking-wider font-bold">Shift+Drag to Pan</span>
        </div>

        {/* Horizontal Pan Slider */}
        <div className="absolute bottom-6 left-1/2 -translate-x-1/2 z-50 w-64 md:w-96 group">
             <div className="glass-panel px-4 py-2 rounded-full flex items-center gap-3 shadow-xl">
                 <MoveHorizontal className="w-3 h-3 text-gray-500" />
                 <input 
                    type="range" 
                    min="-2000" 
                    max="2000" 
                    value={pan.x}
                    onChange={(e) => setPan(prev => ({ ...prev, x: Number(e.target.value) }))}
                    className="w-full h-1 bg-white/10 rounded-lg appearance-none cursor-pointer [&::-webkit-slider-thumb]:appearance-none [&::-webkit-slider-thumb]:w-3 [&::-webkit-slider-thumb]:h-3 [&::-webkit-slider-thumb]:bg-cherry [&::-webkit-slider-thumb]:rounded-full [&::-webkit-slider-thumb]:transition-all [&::-webkit-slider-thumb]:hover:scale-125"
                 />
                 <span className="text-[9px] font-mono text-gray-500 w-8 text-right">{Math.round(pan.x)}</span>
             </div>
        </div>

        {/* World Container - Transforms everything inside */}
        <div style={{ transform: `scale(${zoom}) translate(${pan.x}px, ${pan.y}px)`, transformOrigin: '0 0', width: '100%', height: '100%' }}>
            
            <svg className="absolute inset-0 w-full h-full pointer-events-none z-0 overflow-visible">
              {edges.map(edge => {
                const source = nodes.find(n => n.id === edge.source);
                const target = nodes.find(n => n.id === edge.target);
                if (!source || !target) return null;
                
                // Calculate Y position based on endpoint index
                const sourceOutputCount = source.data.outputEndpoints || 1;
                const targetInputCount = target.data.inputEndpoints || 1;
                const sourceEndpointIdx = edge.sourceEndpoint || 0;
                const targetEndpointIdx = edge.targetEndpoint || 0;
                
                const sourceYOffset = sourceOutputCount === 1 
                  ? NODE_HEIGHT / 2 
                  : NODE_HEIGHT * (0.2 + (0.6 / sourceOutputCount) * (sourceEndpointIdx + 0.5));
                const targetYOffset = targetInputCount === 1 
                  ? NODE_HEIGHT / 2 
                  : NODE_HEIGHT * (0.2 + (0.6 / targetInputCount) * (targetEndpointIdx + 0.5));
                
                const sourcePos = { x: source.position.x + NODE_WIDTH, y: source.position.y + sourceYOffset };
                const targetPos = { x: target.position.x, y: target.position.y + targetYOffset };
                return (
                    <g key={edge.id}>
                        <path d={getEdgePath(sourcePos, targetPos)} stroke="#333" strokeWidth="4" fill="none" />
                        <path d={getEdgePath(sourcePos, targetPos)} stroke={selectedNodeId === edge.source ? "#D90429" : "#666"} strokeWidth="1.5" fill="none" className="transition-colors duration-300" />
                    </g>
                );
              })}
              
              {connectingNodeId && (() => {
                const connectingNode = nodes.find(n => n.id === connectingNodeId);
                if (!connectingNode) return null;
                const outputCount = connectingNode.data.outputEndpoints || 1;
                const yOffset = outputCount === 1 
                  ? NODE_HEIGHT / 2 
                  : NODE_HEIGHT * (0.2 + (0.6 / outputCount) * (connectingEndpoint + 0.5));
                return (
                  <path 
                    d={getEdgePath(
                        { 
                            x: connectingNode.position.x + NODE_WIDTH, 
                            y: connectingNode.position.y + yOffset 
                        }, 
                        mousePos
                    )} 
                    stroke="#D90429" 
                    strokeWidth="2" 
                    strokeDasharray="5,5" 
                    fill="none" 
                  />
                );
              })()}
            </svg>

            {nodes.map(node => {
              const inputCount = node.data.inputEndpoints || 1;
              const outputCount = node.data.outputEndpoints || 1;
              
              return (
              <div
                key={node.id}
                className={`workflow-node absolute w-[280px] glass-panel rounded-2xl shadow-xl transition-all group
                  ${selectedNodeId === node.id ? 'border-cherry ring-1 ring-cherry/50' : 'hover:border-white/30'}
                  ${node.data.isExecuting ? 'ring-2 ring-yellow-500/50' : ''}
                `}
                style={{ left: node.position.x, top: node.position.y, height: NODE_HEIGHT }}
                onMouseDown={(e) => handleMouseDownNode(e, node.id)}
                onContextMenu={(e) => handleContextMenu(e, node.id)}
              >
                {/* Input Handles - Multiple */}
                {Array.from({ length: inputCount }).map((_, idx) => {
                  const yOffset = inputCount === 1 ? '50%' : `${20 + (60 / (inputCount)) * (idx + 0.5)}%`;
                  return (
                    <div 
                      key={`in-${idx}`}
                      className="absolute -left-3 w-6 h-6 flex items-center justify-center cursor-pointer hover:scale-110 transition-transform z-50 group/handle"
                      style={{ top: yOffset, transform: 'translateY(-50%)' }}
                      onMouseUp={(e) => handleMouseUpHandle(e, node.id, idx)}
                      title={`Input ${idx + 1}`}
                    >
                      <div className="w-3 h-3 bg-black border-2 border-gray-500 rounded-full group-hover/handle:border-white group-hover/handle:bg-cherry transition-colors" />
                      {inputCount > 1 && (
                        <span className="absolute -left-3 text-[8px] text-gray-500 font-mono">{idx + 1}</span>
                      )}
                    </div>
                  );
                })}

                {/* Output Handles - Multiple */}
                {Array.from({ length: outputCount }).map((_, idx) => {
                  const yOffset = outputCount === 1 ? '50%' : `${20 + (60 / (outputCount)) * (idx + 0.5)}%`;
                  return (
                    <div 
                      key={`out-${idx}`}
                      className="absolute -right-3 w-6 h-6 flex items-center justify-center cursor-pointer hover:scale-110 transition-transform z-50 group/handle"
                      style={{ top: yOffset, transform: 'translateY(-50%)' }}
                      onMouseDown={(e) => handleMouseDownHandle(e, node.id, idx)}
                      title={`Output ${idx + 1}`}
                    >
                      <div className="w-3 h-3 bg-black border-2 border-gray-500 rounded-full group-hover/handle:border-white group-hover/handle:bg-emerald-400 transition-colors" />
                      {outputCount > 1 && (
                        <span className="absolute -right-3 text-[8px] text-gray-500 font-mono">{idx + 1}</span>
                      )}
                    </div>
                  );
                })}

                {/* Output Ready Badge */}
                {node.data.output && (
                    <div className="absolute -bottom-3 right-4 bg-emerald-900/80 border border-emerald-500/30 text-emerald-400 text-[9px] px-2 py-0.5 rounded-full shadow-lg flex items-center gap-1 backdrop-blur-sm z-10 animate-in fade-in zoom-in duration-300">
                        <CheckCircle className="w-3 h-3" /> Output Ready
                    </div>
                )}
                
                {/* Download PDF Badge */}
                {node.data.downloadUrl && (
                    <div className="absolute -bottom-3 left-4 bg-blue-900/80 border border-blue-500/30 text-blue-200 text-[9px] px-2 py-0.5 rounded-full shadow-lg flex items-center gap-1 backdrop-blur-sm z-10 animate-in fade-in zoom-in duration-300 cursor-pointer hover:bg-blue-800 transition-colors"
                        onClick={(e) => {
                             e.stopPropagation();
                             const link = document.createElement('a');
                             link.href = node.data.downloadUrl!;
                             link.download = `${node.data.label.replace(/\s+/g, '_')}_output.pdf`;
                             link.click();
                        }}
                    >
                        <Download className="w-3 h-3" /> PDF Ready
                    </div>
                )}

                <div className="px-4 py-3 border-b border-white/5 flex items-center justify-between bg-white/5 rounded-t-2xl">
                   <div className="flex items-center gap-2">
                     <Zap className={`w-3 h-3 ${node.type === NodeType.TRIGGER ? 'text-purple-400' : 'text-cherry'}`} />
                     <span className="text-[10px] font-bold uppercase tracking-wider text-cream/60">{node.data.category || node.type}</span>
                   </div>
                   <div className={`w-1.5 h-1.5 rounded-full ${node.data.isExecuting ? 'bg-yellow-500 animate-pulse' : 'bg-green-500/50'}`} />
                </div>
                <div className="p-4">
                  <h3 className="text-cream font-bold text-sm mb-1 truncate">{node.data.label}</h3>
                  <p className="text-cream/40 text-[10px] font-mono truncate">{node.id}</p>
                  {node.data.model && <div className="mt-2 text-[10px] bg-white/5 inline-block px-2 py-0.5 rounded text-gray-400">{node.data.model}</div>}
                </div>
              </div>
            );
            })}

            {/* Context Menu */}
            {contextMenu.visible && contextMenu.nodeId && (
              <div
                className="fixed glass-panel rounded-xl shadow-2xl z-[9999] border border-white/10 overflow-hidden animate-in fade-in zoom-in-95 duration-150 min-w-[240px]"
                style={{ 
                  left: Math.min(contextMenu.x, window.innerWidth - 260), 
                  top: Math.min(contextMenu.y, window.innerHeight - 450)
                }}
                onClick={(e) => e.stopPropagation()}
              >
                <div className="py-2">
                  {/* Endpoint Management */}
                  <div className="px-3 py-1 text-[9px] text-gray-500 uppercase tracking-wider font-bold">Endpoints</div>
                  <div className="px-4 py-2 flex items-center justify-between gap-4">
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] text-gray-400">Inputs:</span>
                      <button 
                        onClick={() => {
                          setNodes(nodes.map(n => n.id === contextMenu.nodeId 
                            ? { ...n, data: { ...n.data, inputEndpoints: Math.max(1, (n.data.inputEndpoints || 1) - 1) } } 
                            : n
                          ));
                        }}
                        className="w-5 h-5 rounded bg-white/10 text-gray-400 hover:bg-white/20 hover:text-white flex items-center justify-center text-xs"
                      >-</button>
                      <span className="text-xs text-white w-4 text-center">{nodes.find(n => n.id === contextMenu.nodeId)?.data.inputEndpoints || 1}</span>
                      <button 
                        onClick={() => {
                          setNodes(nodes.map(n => n.id === contextMenu.nodeId 
                            ? { ...n, data: { ...n.data, inputEndpoints: (n.data.inputEndpoints || 1) + 1 } } 
                            : n
                          ));
                        }}
                        className="w-5 h-5 rounded bg-white/10 text-gray-400 hover:bg-white/20 hover:text-white flex items-center justify-center text-xs"
                      >+</button>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] text-gray-400">Outputs:</span>
                      <button 
                        onClick={() => {
                          setNodes(nodes.map(n => n.id === contextMenu.nodeId 
                            ? { ...n, data: { ...n.data, outputEndpoints: Math.max(1, (n.data.outputEndpoints || 1) - 1) } } 
                            : n
                          ));
                        }}
                        className="w-5 h-5 rounded bg-white/10 text-gray-400 hover:bg-white/20 hover:text-white flex items-center justify-center text-xs"
                      >-</button>
                      <span className="text-xs text-white w-4 text-center">{nodes.find(n => n.id === contextMenu.nodeId)?.data.outputEndpoints || 1}</span>
                      <button 
                        onClick={() => {
                          setNodes(nodes.map(n => n.id === contextMenu.nodeId 
                            ? { ...n, data: { ...n.data, outputEndpoints: (n.data.outputEndpoints || 1) + 1 } } 
                            : n
                          ));
                        }}
                        className="w-5 h-5 rounded bg-white/10 text-gray-400 hover:bg-white/20 hover:text-white flex items-center justify-center text-xs"
                      >+</button>
                    </div>
                  </div>
                  
                  <div className="h-px bg-white/10 my-2" />
                  
                  {/* Quick Actions */}
                  <div className="px-3 py-1 text-[9px] text-gray-500 uppercase tracking-wider font-bold">Quick Actions</div>
                  <button
                    onClick={() => duplicateNode(contextMenu.nodeId!)}
                    className="w-full text-left px-4 py-2.5 text-xs text-gray-300 hover:text-white hover:bg-white/10 flex items-center gap-3 transition-colors"
                  >
                    <Copy className="w-3.5 h-3.5" /> Duplicate Node
                  </button>
                  <button
                    onClick={() => { deleteNode(contextMenu.nodeId!); closeContextMenu(); }}
                    className="w-full text-left px-4 py-2.5 text-xs text-red-400 hover:text-red-300 hover:bg-red-500/10 flex items-center gap-3 transition-colors"
                  >
                    <Trash2 className="w-3.5 h-3.5" /> Delete Node
                  </button>
                  
                  <div className="h-px bg-white/10 my-2" />
                  
                  {/* Connect to New Node */}
                  <div className="px-3 py-1 text-[9px] text-gray-500 uppercase tracking-wider font-bold">Connect to New Node</div>
                  <div className="max-h-[200px] overflow-y-auto">
                    {Object.entries(
                      [...AGENT_LIBRARY, ...customAgents].reduce((acc, agent) => {
                        if (!acc[agent.category]) acc[agent.category] = [];
                        acc[agent.category].push(agent);
                        return acc;
                      }, {} as Record<string, AgentTemplate[]>)
                    ).slice(0, 5).map(([category, agents]: [string, AgentTemplate[]]) => (
                      <div key={category}>
                        <div className="px-4 py-1.5 text-[9px] text-gray-600 font-medium">{category}</div>
                        {agents.slice(0, 3).map(agent => (
                          <button
                            key={agent.name}
                            onClick={() => connectToNewNode(contextMenu.nodeId!, agent)}
                            className="w-full text-left px-4 py-2 text-xs text-gray-300 hover:text-white hover:bg-white/10 flex items-center gap-3 transition-colors"
                          >
                            <agent.icon className={`w-3.5 h-3.5 ${agent.color}`} />
                            <span className="truncate">{agent.name}</span>
                          </button>
                        ))}
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}
        </div>
        
        {/* --- RIGHT SIDE COMBINED PANEL --- */}
        <div className="absolute right-4 top-4 bottom-4 w-96 flex flex-col z-40">
            
            <div className="w-full glass-panel rounded-2xl flex flex-col shadow-2xl overflow-hidden flex-1">
                {/* Header with Tabs and Actions */}
                <div className="p-3 border-b border-white/5 bg-white/5">
                    {/* Tabs Row */}
                    <div className="flex items-center justify-between mb-2">
                        <div className="flex gap-1">
                            <button 
                                onClick={() => setRightPanelTab('config')}
                                className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all flex items-center gap-1.5 ${
                                    rightPanelTab === 'config' 
                                        ? 'bg-cherry/20 text-cherry border border-cherry/30' 
                                        : 'text-gray-400 hover:text-white hover:bg-white/5'
                                }`}
                            >
                                <Settings className="w-3 h-3" /> Configuration
                            </button>
                            <button 
                                onClick={() => setRightPanelTab('console')}
                                className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all flex items-center gap-1.5 ${
                                    rightPanelTab === 'console' 
                                        ? 'bg-blue-500/20 text-blue-400 border border-blue-500/30' 
                                        : 'text-gray-400 hover:text-white hover:bg-white/5'
                                }`}
                            >
                                <Terminal className="w-3 h-3" /> Console
                            </button>
                        </div>
                        <button 
                            onClick={(e) => { e.stopPropagation(); setShowSettings(true); }} 
                            className="text-cream/50 hover:text-white transition-colors p-1.5 hover:bg-white/10 rounded"
                            title="System Settings"
                        >
                            <Settings className="w-4 h-4" />
                        </button>
                    </div>
                    
                    {/* Action Buttons Row */}
                    <div className="flex gap-2">
                        <button 
                            onClick={() => executeWorkflow()}
                            disabled={isExecuting}
                            className={`flex-1 flex items-center justify-center gap-2 px-3 py-2 rounded-lg text-xs font-bold uppercase tracking-wide transition-all ${
                                isExecuting 
                                    ? 'bg-white/5 text-gray-500 cursor-not-allowed' 
                                    : 'bg-cherry text-white hover:bg-cherry/80 shadow-lg shadow-cherry/20'
                            }`}
                        >
                            <Play size={12} fill="currentColor" /> {isExecuting ? 'Running...' : 'Run'}
                        </button>
                        <button 
                            onClick={() => openDeployModal()}
                            disabled={isDeploying || nodes.length === 0}
                            className={`flex-1 flex items-center justify-center gap-2 px-3 py-2 rounded-lg text-xs font-bold uppercase tracking-wide transition-all ${
                                isDeploying || nodes.length === 0
                                    ? 'bg-white/5 text-gray-500 cursor-not-allowed'
                                    : 'bg-emerald-500 text-white hover:bg-emerald-600 shadow-lg shadow-emerald-500/20'
                            }`}
                        >
                            <UploadCloud size={12} /> {isDeploying ? 'Deploying...' : (deployedWorkflowId ? 'Update' : 'Deploy')}
                        </button>
                    </div>
                    
                    {/* Show deployed webhook URL if available */}
                    {deployedWorkflowId && (
                        <div className="mt-2 p-2 bg-emerald-500/10 border border-emerald-500/30 rounded-lg">
                            <div className="flex items-center gap-2 text-[10px] text-emerald-400">
                                <CheckCircle size={12} />
                                <span className="font-bold">DEPLOYED</span>
                            </div>
                            <div className="mt-1 text-[9px] text-cream/60 font-mono break-all">
                                {`http://localhost:8080/webhook/${deployedWorkflowId}/trigger`}
                            </div>
                            <button
                                onClick={() => {
                                    navigator.clipboard.writeText(`http://localhost:8080/webhook/${deployedWorkflowId}/trigger`);
                                    addLog('info', 'Webhook URL copied to clipboard!');
                                }}
                                className="mt-1 text-[9px] text-emerald-400 hover:text-emerald-300 flex items-center gap-1"
                            >
                                <Copy size={10} /> Copy URL
                            </button>
                        </div>
                    )}
                </div>
                
                {/* Content Area */}
                <div className="flex-1 overflow-y-auto custom-scrollbar">
                    {/* Configuration Tab Content */}
                    {rightPanelTab === 'config' && (
                        <div className="p-4">
                            {selectedNode ? (
                                <>
                                    <div className="flex items-center gap-2 mb-4">
                                        <span className="text-[10px] font-bold text-cream/30 uppercase font-mono tracking-widest">ID: {selectedNode.id}</span>
                                    </div>

                                    <div className="space-y-4">
                        <div className="space-y-1">
                            <label className="text-[10px] font-bold text-cream/50 uppercase tracking-wider">Label</label>
                            <input 
                              type="text" 
                              value={selectedNode.data.label}
                              onChange={(e) => {
                                const newLabel = e.target.value;
                                setNodes(prev => prev.map(n => n.id === selectedNode.id ? { ...n, data: { ...n.data, label: newLabel } } : n));
                              }}
                              className="w-full bg-black/50 border border-white/10 p-2 text-xs text-cream focus:border-cherry focus:outline-none rounded-md transition-colors"
                            />
                        </div>

                        {selectedNode.data.category === 'Human Interaction' ? (
                            // --- USER INPUT INTERFACE ---
                            <>
                                <div className="space-y-1">
                                    <label className="text-[10px] font-bold text-cream/50 uppercase tracking-wider">Message to Agent</label>
                                    <textarea 
                                        value={selectedNode.data.systemPrompt}
                                        placeholder="Type your message here..."
                                        onChange={(e) => {
                                          const newPrompt = e.target.value;
                                          setNodes(prev => prev.map(n => n.id === selectedNode.id ? { ...n, data: { ...n.data, systemPrompt: newPrompt } } : n));
                                        }}
                                        rows={4}
                                        className="w-full bg-black/50 border border-white/10 p-3 text-xs text-cream focus:border-rose-400 focus:outline-none resize-none font-sans rounded-md"
                                    />
                                </div>
                                
                                <div className="space-y-1">
                                    <label className="text-[10px] font-bold text-cream/50 uppercase tracking-wider">Upload Context</label>
                                    
                                    <div 
                                        onClick={() => fileInputRef.current?.click()}
                                        className="w-full h-24 border border-dashed border-white/20 rounded-lg flex flex-col items-center justify-center text-center hover:bg-white/5 hover:border-white/40 transition-all cursor-pointer group active:scale-95"
                                    >
                                         <div className="flex gap-2 mb-2 text-gray-500 group-hover:text-rose-400 transition-colors">
                                            <FileText className="w-4 h-4" />
                                            <ImageIcon className="w-4 h-4" />
                                            <FileJson className="w-4 h-4" />
                                         </div>
                                         <span className="text-[10px] text-gray-500 uppercase tracking-widest font-bold group-hover:text-white">Drag or Click to Upload</span>
                                    </div>

                                    {/* Render Uploaded Files */}
                                    <div className="flex flex-col gap-1 mt-2">
                                        {selectedNode.data.attachments?.map((file, index) => (
                                            <div key={index} className="flex items-center justify-between p-2 bg-white/5 rounded border border-white/5 group animate-in slide-in-from-top-1">
                                                <div className="flex items-center gap-2 overflow-hidden">
                                                    {file.type === 'image' ? (
                                                        <ImageIcon className="w-3 h-3 text-blue-400 shrink-0" />
                                                    ) : file.type === 'json' ? (
                                                        <FileJson className="w-3 h-3 text-yellow-400 shrink-0" />
                                                    ) : file.type === 'pdf' ? (
                                                        <FileText className="w-3 h-3 text-red-400 shrink-0" />
                                                    ) : (
                                                        <FileText className="w-3 h-3 text-gray-400 shrink-0" />
                                                    )}
                                                    <span className="text-[10px] text-gray-400 truncate max-w-[120px]" title={file.name}>{file.name}</span>
                                                    {file.size && <span className="text-[9px] text-gray-600">({file.size})</span>}
                                                </div>
                                                <button 
                                                    onClick={() => removeAttachment(index)}
                                                    className="text-gray-600 hover:text-red-500 transition-colors p-1"
                                                >
                                                    <X className="w-3 h-3" />
                                                </button>
                                            </div>
                                        ))}
                                        {(!selectedNode.data.attachments || selectedNode.data.attachments.length === 0) && (
                                            <div className="text-[9px] text-gray-600 text-center italic py-2">No files attached</div>
                                        )}
                                    </div>
                                </div>
                            </>
                        ) : selectedNode.data.model === 'mock-sender' ? (
                          // --- EMAIL SENDER CONFIGURATION ---
                          <>
                             {/* Gmail Account Configuration */}
                             <div className="space-y-1 mb-4">
                                <label className="text-[10px] font-bold text-cream/50 uppercase tracking-wider">📧 Sender Account</label>
                                <div className="p-3 bg-black/40 border border-white/10 rounded-md space-y-3">
                                  {user?.email ? (
                                    <div className="flex items-center gap-2 p-2 bg-green-500/10 border border-green-500/30 rounded">
                                      <CheckCircle className="w-4 h-4 text-green-400" />
                                      <div className="flex-1">
                                        <span className="text-xs text-green-400 font-medium">{user.email}</span>
                                        <p className="text-[9px] text-gray-400">Logged in account - emails will be sent from this address</p>
                                      </div>
                                    </div>
                                  ) : (
                                    <div className="flex items-center gap-2 p-2 bg-yellow-500/10 border border-yellow-500/30 rounded">
                                      <AlertCircle className="w-4 h-4 text-yellow-400" />
                                      <div className="flex-1">
                                        <span className="text-xs text-yellow-400">Not logged in</span>
                                        <p className="text-[9px] text-gray-400">Login to send emails from your account</p>
                                      </div>
                                    </div>
                                  )}
                                  <p className="text-[9px] text-gray-500">
                                    Emails are sent via backend SMTP. If not configured, your mail client will open.
                                  </p>
                                </div>
                             </div>
                             
                             <div className="space-y-1">
                                <label className="text-[10px] font-bold text-cream/50 uppercase tracking-wider">Recipient Email</label>
                                <input 
                                  type="text" 
                                  value={selectedNode.data.recipient || ''}
                                  onChange={(e) => setNodes(nodes.map(n => n.id === selectedNode.id ? { ...n, data: { ...n.data, recipient: e.target.value } } : n))}
                                  placeholder="name@company.com or leave empty for dynamic input"
                                  className="w-full bg-black/50 border border-white/10 p-2 text-xs text-cream focus:border-cherry focus:outline-none rounded-md"
                                />
                                <p className="text-[9px] text-gray-500">
                                  Enter a fixed email or leave empty. When empty, recipient can come from connected input node.
                                </p>
                             </div>
                             <div className="space-y-1">
                                <label className="text-[10px] font-bold text-cream/50 uppercase tracking-wider">Subject</label>
                                <input 
                                  type="text" 
                                  value={selectedNode.data.subject || ''}
                                  onChange={(e) => setNodes(nodes.map(n => n.id === selectedNode.id ? { ...n, data: { ...n.data, subject: e.target.value } } : n))}
                                  placeholder="Enter subject line..."
                                  className="w-full bg-black/50 border border-white/10 p-2 text-xs text-cream focus:border-cherry focus:outline-none rounded-md"
                                />
                             </div>
                             <div className="space-y-1">
                                <label className="text-[10px] font-bold text-cream/50 uppercase tracking-wider">Email Body Template</label>
                                <textarea 
                                  value={selectedNode.data.systemPrompt}
                                  onChange={(e) => setNodes(nodes.map(n => n.id === selectedNode.id ? { ...n, data: { ...n.data, systemPrompt: e.target.value } } : n))}
                                  rows={5}
                                  className="w-full bg-black/50 border border-white/10 p-2 text-xs text-cream/80 focus:border-cherry focus:outline-none resize-none font-mono rounded-md leading-relaxed"
                                  placeholder="Enter default email body. If this node receives input from another node, that input becomes the email content."
                                />
                                <p className="text-[9px] text-gray-500">
                                  Content from connected nodes will override this template.
                                </p>
                             </div>
                          </>
                        ) : selectedNode.data.model === 'webhook-trigger' ? (
                          // --- WEBHOOK TRIGGER CONFIGURATION ---
                          <>
                             <div className="space-y-1">
                                <label className="text-[10px] font-bold text-cream/50 uppercase tracking-wider">Webhook Path</label>
                                <input 
                                  type="text" 
                                  value={selectedNode.data.webhookPath || ''}
                                  onChange={(e) => setNodes(nodes.map(n => n.id === selectedNode.id ? { ...n, data: { ...n.data, webhookPath: e.target.value } } : n))}
                                  placeholder="/my-workflow"
                                  className="w-full bg-black/50 border border-white/10 p-2 text-xs text-cream focus:border-purple-400 focus:outline-none rounded-md font-mono"
                                />
                             </div>
                             <div className="space-y-1">
                                <label className="text-[10px] font-bold text-cream/50 uppercase tracking-wider">HTTP Method</label>
                                <select 
                                  value={selectedNode.data.httpMethod || 'POST'}
                                  onChange={(e) => setNodes(nodes.map(n => n.id === selectedNode.id ? { ...n, data: { ...n.data, httpMethod: e.target.value } } : n))}
                                  className="w-full bg-black/50 border border-white/10 p-2 text-xs text-cream focus:border-purple-400 focus:outline-none rounded-md"
                                >
                                  <option value="GET">GET</option>
                                  <option value="POST">POST</option>
                                  <option value="PUT">PUT</option>
                                  <option value="PATCH">PATCH</option>
                                  <option value="DELETE">DELETE</option>
                                </select>
                             </div>
                             <div className="space-y-1">
                                <label className="text-[10px] font-bold text-cream/50 uppercase tracking-wider">Response Mode</label>
                                <select 
                                  value={selectedNode.data.responseMode || 'onReceived'}
                                  onChange={(e) => setNodes(nodes.map(n => n.id === selectedNode.id ? { ...n, data: { ...n.data, responseMode: e.target.value } } : n))}
                                  className="w-full bg-black/50 border border-white/10 p-2 text-xs text-cream focus:border-purple-400 focus:outline-none rounded-md"
                                >
                                  <option value="onReceived">Async (Return immediately)</option>
                                  <option value="onCompleted">Sync (Wait for result)</option>
                                </select>
                                <p className="text-[9px] text-gray-500 mt-1">
                                  {selectedNode.data.responseMode === 'onCompleted' 
                                    ? '⏱️ The caller will wait until the workflow completes and receive the result.' 
                                    : '⚡ Returns 200 OK immediately, processes in background.'}
                                </p>
                             </div>
                             <div className="space-y-1 mt-3">
                                <label className="text-[10px] font-bold text-cream/50 uppercase tracking-wider">Webhook URL</label>
                                <div className="flex items-center gap-2">
                                   <input 
                                     type="text" 
                                     readOnly
                                     value={`http://localhost:8080/webhook/{workflowId}${selectedNode.data.webhookPath || '/trigger'}`}
                                     className="w-full bg-black/70 border border-white/10 p-2 text-xs text-gray-400 rounded-md font-mono"
                                   />
                                   <button 
                                     onClick={() => {
                                       navigator.clipboard.writeText(`http://localhost:8080/webhook/{workflowId}${selectedNode.data.webhookPath || '/trigger'}`);
                                       addLog('info', 'Webhook URL copied to clipboard');
                                     }}
                                     className="p-2 hover:bg-white/10 rounded transition-colors text-gray-400 hover:text-white"
                                     title="Copy URL"
                                   >
                                     <Copy className="w-3 h-3" />
                                   </button>
                                </div>
                                <p className="text-[9px] text-gray-600 mt-1">Replace {'{workflowId}'} with your actual workflow ID after saving.</p>
                             </div>
                          </>
                        ) : selectedNode.data.model === 'http-response' ? (
                          // --- HTTP RESPONSE CONFIGURATION ---
                          <>
                             <div className="space-y-1">
                                <label className="text-[10px] font-bold text-cream/50 uppercase tracking-wider">Status Code</label>
                                <input 
                                  type="number" 
                                  value={selectedNode.data.statusCode || 200}
                                  onChange={(e) => setNodes(nodes.map(n => n.id === selectedNode.id ? { ...n, data: { ...n.data, statusCode: parseInt(e.target.value) } } : n))}
                                  placeholder="200"
                                  className="w-full bg-black/50 border border-white/10 p-2 text-xs text-cream focus:border-purple-400 focus:outline-none rounded-md font-mono"
                                />
                             </div>
                             <div className="space-y-1">
                                <label className="text-[10px] font-bold text-cream/50 uppercase tracking-wider">Content-Type</label>
                                <select 
                                  value={selectedNode.data.contentType || 'application/json'}
                                  onChange={(e) => setNodes(nodes.map(n => n.id === selectedNode.id ? { ...n, data: { ...n.data, contentType: e.target.value } } : n))}
                                  className="w-full bg-black/50 border border-white/10 p-2 text-xs text-cream focus:border-purple-400 focus:outline-none rounded-md"
                                >
                                  <option value="application/json">application/json</option>
                                  <option value="text/plain">text/plain</option>
                                  <option value="text/html">text/html</option>
                                  <option value="application/xml">application/xml</option>
                                </select>
                             </div>
                             <div className="space-y-1">
                                <label className="text-[10px] font-bold text-cream/50 uppercase tracking-wider">Response Body</label>
                                <textarea 
                                  value={selectedNode.data.responseBody || ''}
                                  onChange={(e) => setNodes(nodes.map(n => n.id === selectedNode.id ? { ...n, data: { ...n.data, responseBody: e.target.value } } : n))}
                                  rows={5}
                                  placeholder='{"success": true, "message": "Processed"}'
                                  className="w-full bg-black/50 border border-white/10 p-2 text-xs text-cream/80 focus:border-purple-400 focus:outline-none resize-none font-mono rounded-md leading-relaxed"
                                />
                                <p className="text-[9px] text-gray-500 mt-1">💡 Leave empty to return the previous node's output.</p>
                             </div>
                             <div className="p-2 bg-amber-500/10 rounded border border-amber-500/20 mt-2">
                                <p className="text-[9px] text-amber-400">⚠️ Only works with webhooks in "Sync" response mode.</p>
                             </div>
                          </>
                        ) : selectedNode.data.category === 'Flow Control' ? (
                          // --- FLOW CONTROL CONFIGURATION ---
                          <>
                             {selectedNode.data.model === 'delay' && (
                               <>
                                 <div className="space-y-1">
                                    <label className="text-[10px] font-bold text-cream/50 uppercase tracking-wider">Duration</label>
                                    <input 
                                      type="number" 
                                      value={selectedNode.data.duration || 5}
                                      onChange={(e) => setNodes(nodes.map(n => n.id === selectedNode.id ? { ...n, data: { ...n.data, duration: parseInt(e.target.value) } } : n))}
                                      className="w-full bg-black/50 border border-white/10 p-2 text-xs text-cream focus:border-sky-400 focus:outline-none rounded-md font-mono"
                                    />
                                 </div>
                                 <div className="space-y-1">
                                    <label className="text-[10px] font-bold text-cream/50 uppercase tracking-wider">Unit</label>
                                    <select 
                                      value={selectedNode.data.durationUnit || 'seconds'}
                                      onChange={(e) => setNodes(nodes.map(n => n.id === selectedNode.id ? { ...n, data: { ...n.data, durationUnit: e.target.value } } : n))}
                                      className="w-full bg-black/50 border border-white/10 p-2 text-xs text-cream focus:border-sky-400 focus:outline-none rounded-md"
                                    >
                                      <option value="seconds">Seconds</option>
                                      <option value="minutes">Minutes</option>
                                      <option value="hours">Hours</option>
                                    </select>
                                 </div>
                               </>
                             )}
                             {selectedNode.data.model === 'condition' && (
                               <div className="space-y-1">
                                  <label className="text-[10px] font-bold text-cream/50 uppercase tracking-wider">Condition Expression</label>
                                  <textarea 
                                    value={selectedNode.data.condition || ''}
                                    onChange={(e) => setNodes(nodes.map(n => n.id === selectedNode.id ? { ...n, data: { ...n.data, condition: e.target.value } } : n))}
                                    rows={3}
                                    placeholder="input.value > 100"
                                    className="w-full bg-black/50 border border-white/10 p-2 text-xs text-cream/80 focus:border-sky-400 focus:outline-none resize-none font-mono rounded-md"
                                  />
                                  <p className="text-[9px] text-gray-500 mt-1">JavaScript expression that evaluates to true/false</p>
                               </div>
                             )}
                             {selectedNode.data.model === 'filter' && (
                               <div className="space-y-1">
                                  <label className="text-[10px] font-bold text-cream/50 uppercase tracking-wider">Filter Expression</label>
                                  <textarea 
                                    value={selectedNode.data.filterExpr || ''}
                                    onChange={(e) => setNodes(nodes.map(n => n.id === selectedNode.id ? { ...n, data: { ...n.data, filterExpr: e.target.value } } : n))}
                                    rows={3}
                                    placeholder="item.status === 'active'"
                                    className="w-full bg-black/50 border border-white/10 p-2 text-xs text-cream/80 focus:border-sky-400 focus:outline-none resize-none font-mono rounded-md"
                                  />
                               </div>
                             )}
                             {selectedNode.data.model === 'loop' && (
                               <div className="space-y-1">
                                  <label className="text-[10px] font-bold text-cream/50 uppercase tracking-wider">Batch Size</label>
                                  <input 
                                    type="number" 
                                    value={selectedNode.data.batchSize || 1}
                                    onChange={(e) => setNodes(nodes.map(n => n.id === selectedNode.id ? { ...n, data: { ...n.data, batchSize: parseInt(e.target.value) } } : n))}
                                    min={1}
                                    className="w-full bg-black/50 border border-white/10 p-2 text-xs text-cream focus:border-sky-400 focus:outline-none rounded-md font-mono"
                                  />
                                  <p className="text-[9px] text-gray-500 mt-1">Number of items to process at once</p>
                               </div>
                             )}
                          </>
                        ) : selectedNode.data.category === 'Data' ? (
                          // --- DATA NODES CONFIGURATION ---
                          <>
                             {selectedNode.data.model === 'http-request' && (
                               <>
                                 <div className="space-y-1">
                                    <label className="text-[10px] font-bold text-cream/50 uppercase tracking-wider">URL</label>
                                    <input 
                                      type="text" 
                                      value={selectedNode.data.url || ''}
                                      onChange={(e) => setNodes(nodes.map(n => n.id === selectedNode.id ? { ...n, data: { ...n.data, url: e.target.value } } : n))}
                                      placeholder="https://api.example.com/endpoint"
                                      className="w-full bg-black/50 border border-white/10 p-2 text-xs text-cream focus:border-lime-400 focus:outline-none rounded-md font-mono"
                                    />
                                 </div>
                                 <div className="space-y-1">
                                    <label className="text-[10px] font-bold text-cream/50 uppercase tracking-wider">Method</label>
                                    <select 
                                      value={selectedNode.data.httpMethod || 'GET'}
                                      onChange={(e) => setNodes(nodes.map(n => n.id === selectedNode.id ? { ...n, data: { ...n.data, httpMethod: e.target.value } } : n))}
                                      className="w-full bg-black/50 border border-white/10 p-2 text-xs text-cream focus:border-lime-400 focus:outline-none rounded-md"
                                    >
                                      <option value="GET">GET</option>
                                      <option value="POST">POST</option>
                                      <option value="PUT">PUT</option>
                                      <option value="PATCH">PATCH</option>
                                      <option value="DELETE">DELETE</option>
                                    </select>
                                 </div>
                                 <div className="space-y-1">
                                    <label className="text-[10px] font-bold text-cream/50 uppercase tracking-wider">Headers (JSON)</label>
                                    <textarea 
                                      value={selectedNode.data.headers || ''}
                                      onChange={(e) => setNodes(nodes.map(n => n.id === selectedNode.id ? { ...n, data: { ...n.data, headers: e.target.value } } : n))}
                                      rows={2}
                                      placeholder='{"Authorization": "Bearer xxx"}'
                                      className="w-full bg-black/50 border border-white/10 p-2 text-xs text-cream/80 focus:border-lime-400 focus:outline-none resize-none font-mono rounded-md"
                                    />
                                 </div>
                                 {['POST', 'PUT', 'PATCH'].includes(selectedNode.data.httpMethod || '') && (
                                   <div className="space-y-1">
                                      <label className="text-[10px] font-bold text-cream/50 uppercase tracking-wider">Request Body</label>
                                      <textarea 
                                        value={selectedNode.data.body || ''}
                                        onChange={(e) => setNodes(nodes.map(n => n.id === selectedNode.id ? { ...n, data: { ...n.data, body: e.target.value } } : n))}
                                        rows={4}
                                        placeholder='{"key": "value"}'
                                        className="w-full bg-black/50 border border-white/10 p-2 text-xs text-cream/80 focus:border-lime-400 focus:outline-none resize-none font-mono rounded-md"
                                      />
                                   </div>
                                 )}
                               </>
                             )}
                             {selectedNode.data.model === 'transform' && (
                               <div className="space-y-1">
                                  <label className="text-[10px] font-bold text-cream/50 uppercase tracking-wider">Transform Code</label>
                                  <textarea 
                                    value={selectedNode.data.transformCode || ''}
                                    onChange={(e) => setNodes(nodes.map(n => n.id === selectedNode.id ? { ...n, data: { ...n.data, transformCode: e.target.value } } : n))}
                                    rows={6}
                                    placeholder={'// Input is available as `input`\nreturn {\n  ...input,\n  processed: true,\n  timestamp: Date.now()\n}'}
                                    className="w-full bg-black/50 border border-white/10 p-2 text-xs text-cream/80 focus:border-lime-400 focus:outline-none resize-none font-mono rounded-md"
                                  />
                                  <p className="text-[9px] text-gray-500 mt-1">JavaScript code to transform input data</p>
                               </div>
                             )}
                             {selectedNode.data.model === 'set' && (
                               <div className="space-y-1">
                                  <label className="text-[10px] font-bold text-cream/50 uppercase tracking-wider">Values (JSON)</label>
                                  <textarea 
                                    value={selectedNode.data.setValues || ''}
                                    onChange={(e) => setNodes(nodes.map(n => n.id === selectedNode.id ? { ...n, data: { ...n.data, setValues: e.target.value } } : n))}
                                    rows={4}
                                    placeholder='{"status": "processed", "version": 1}'
                                    className="w-full bg-black/50 border border-white/10 p-2 text-xs text-cream/80 focus:border-emerald-400 focus:outline-none resize-none font-mono rounded-md"
                                  />
                                  <p className="text-[9px] text-gray-500 mt-1">Key-value pairs to add/set in the data</p>
                               </div>
                             )}
                             {selectedNode.data.model === 'split' && (
                               <div className="space-y-1">
                                  <label className="text-[10px] font-bold text-cream/50 uppercase tracking-wider">Array Field to Split</label>
                                  <input 
                                    type="text" 
                                    value={selectedNode.data.splitField || ''}
                                    onChange={(e) => setNodes(nodes.map(n => n.id === selectedNode.id ? { ...n, data: { ...n.data, splitField: e.target.value } } : n))}
                                    placeholder="items"
                                    className="w-full bg-black/50 border border-white/10 p-2 text-xs text-cream focus:border-emerald-400 focus:outline-none rounded-md font-mono"
                                  />
                                  <p className="text-[9px] text-gray-500 mt-1">Path to the array field (e.g., "data.items")</p>
                               </div>
                             )}
                             {selectedNode.data.model === 'merge' && (
                               <div className="space-y-1">
                                  <label className="text-[10px] font-bold text-cream/50 uppercase tracking-wider">Merge Mode</label>
                                  <select 
                                    value={selectedNode.data.mergeMode || 'combine'}
                                    onChange={(e) => setNodes(nodes.map(n => n.id === selectedNode.id ? { ...n, data: { ...n.data, mergeMode: e.target.value } } : n))}
                                    className="w-full bg-black/50 border border-white/10 p-2 text-xs text-cream focus:border-emerald-400 focus:outline-none rounded-md"
                                  >
                                    <option value="combine">Combine All</option>
                                    <option value="waitAll">Wait for All</option>
                                    <option value="keepMatching">Keep Matching</option>
                                  </select>
                               </div>
                             )}
                          </>
                        ) : selectedNode.data.category === 'Database' ? (
                          // --- DATABASE NODES CONFIGURATION ---
                          <>
                             <div className="space-y-1">
                                <label className="text-[10px] font-bold text-cream/50 uppercase tracking-wider">Table Name</label>
                                <input 
                                  type="text" 
                                  value={selectedNode.data.tableName || ''}
                                  onChange={(e) => setNodes(nodes.map(n => n.id === selectedNode.id ? { ...n, data: { ...n.data, tableName: e.target.value } } : n))}
                                  placeholder="users"
                                  className="w-full bg-black/50 border border-white/10 p-2 text-xs text-cream focus:border-orange-400 focus:outline-none rounded-md font-mono"
                                />
                             </div>
                             {selectedNode.data.model === 'db-read' && (
                               <>
                                 <div className="space-y-1">
                                    <label className="text-[10px] font-bold text-cream/50 uppercase tracking-wider">Filter (JSON)</label>
                                    <textarea 
                                      value={selectedNode.data.dbFilter || ''}
                                      onChange={(e) => setNodes(nodes.map(n => n.id === selectedNode.id ? { ...n, data: { ...n.data, dbFilter: e.target.value } } : n))}
                                      rows={2}
                                      placeholder='{"status": "active"}'
                                      className="w-full bg-black/50 border border-white/10 p-2 text-xs text-cream/80 focus:border-orange-400 focus:outline-none resize-none font-mono rounded-md"
                                    />
                                 </div>
                                 <div className="space-y-1">
                                    <label className="text-[10px] font-bold text-cream/50 uppercase tracking-wider">Limit</label>
                                    <input 
                                      type="number" 
                                      value={selectedNode.data.dbLimit || 100}
                                      onChange={(e) => setNodes(nodes.map(n => n.id === selectedNode.id ? { ...n, data: { ...n.data, dbLimit: parseInt(e.target.value) } } : n))}
                                      className="w-full bg-black/50 border border-white/10 p-2 text-xs text-cream focus:border-orange-400 focus:outline-none rounded-md font-mono"
                                    />
                                 </div>
                               </>
                             )}
                             {selectedNode.data.model === 'db-write' && (
                               <div className="space-y-1">
                                  <label className="text-[10px] font-bold text-cream/50 uppercase tracking-wider">Operation</label>
                                  <select 
                                    value={selectedNode.data.dbOperation || 'insert'}
                                    onChange={(e) => setNodes(nodes.map(n => n.id === selectedNode.id ? { ...n, data: { ...n.data, dbOperation: e.target.value } } : n))}
                                    className="w-full bg-black/50 border border-white/10 p-2 text-xs text-cream focus:border-orange-400 focus:outline-none rounded-md"
                                  >
                                    <option value="insert">Insert</option>
                                    <option value="update">Update</option>
                                    <option value="upsert">Upsert</option>
                                  </select>
                               </div>
                             )}
                          </>
                        ) : selectedNode.type === NodeType.AGENT ? (
                          // --- AGENT CONFIGURATION ---
                          <>
                            <div className="space-y-1">
                              <label className="text-[10px] font-bold text-cream/50 uppercase tracking-wider">Model</label>
                              <select 
                                value={selectedNode.data.model}
                                onChange={(e) => {
                                  const newModel = e.target.value;
                                  setNodes(prev => prev.map(n => n.id === selectedNode.id ? { 
                                    ...n, 
                                    data: { ...n.data, model: newModel } 
                                  } : n));
                                }}
                                className="w-full bg-black/50 border border-white/10 p-2 text-xs text-cream focus:border-cherry focus:outline-none rounded-md"
                              >
                                <option value="mimo-v2-flash">📱 Xiaomi Mimo V2 Flash (Text AI)</option>
                                <option value="tavily-search">🔍 Tavily (Web Search)</option>
                                <option value="groq-vision">👁️ Groq Llama 4 Scout (Vision/OCR)</option>
                              </select>
                              <p className="text-[9px] text-gray-500 mt-1">
                                {selectedNode.data.model === 'mimo-v2-flash' && '💬 Best for text generation, summaries, code, etc.'}
                                {selectedNode.data.model === 'tavily-search' && '🌐 Real-time web search with sources'}
                                {selectedNode.data.model === 'groq-vision' && '🖼️ Extract text from images (OCR)'}
                              </p>
                            </div>
                            
                            {/* Image Upload for Vision Model */}
                            {selectedNode.data.model === 'groq-vision' && (
                              <div className="space-y-2 p-3 bg-purple-500/10 border border-purple-500/30 rounded-lg">
                                <label className="text-[10px] font-bold text-purple-300 uppercase tracking-wider flex items-center gap-2">
                                  <span>📷</span> Upload Image for OCR
                                </label>
                                <input
                                  type="file"
                                  accept="image/*"
                                  onChange={async (e) => {
                                    if (e.target.files && e.target.files[0]) {
                                      const file = e.target.files[0];
                                      addLog('info', `Processing image: ${file.name}`, selectedNode.id);
                                      
                                      try {
                                        const base64 = await new Promise<string>((resolve, reject) => {
                                          const reader = new FileReader();
                                          reader.onload = () => resolve(reader.result as string);
                                          reader.onerror = reject;
                                          reader.readAsDataURL(file);
                                        });
                                        
                                        setNodes(prev => prev.map(n => n.id === selectedNode.id ? {
                                          ...n,
                                          data: { ...n.data, imageUrl: base64, imageName: file.name }
                                        } : n));
                                        
                                        addLog('success', `Image loaded: ${file.name}`, selectedNode.id);
                                      } catch (err) {
                                        addLog('error', 'Failed to process image', selectedNode.id);
                                      }
                                    }
                                  }}
                                  className="w-full text-xs text-cream file:mr-3 file:py-1 file:px-3 file:rounded file:border-0 file:text-xs file:bg-purple-600 file:text-white hover:file:bg-purple-500 cursor-pointer"
                                />
                                {selectedNode.data.imageUrl && (
                                  <div className="mt-2 space-y-2">
                                    <div className="flex items-center justify-between">
                                      <span className="text-[10px] text-green-400">✓ {selectedNode.data.imageName || 'Image loaded'}</span>
                                      <button
                                        onClick={() => setNodes(prev => prev.map(n => n.id === selectedNode.id ? {
                                          ...n,
                                          data: { ...n.data, imageUrl: undefined, imageName: undefined }
                                        } : n))}
                                        className="text-[10px] text-red-400 hover:text-red-300"
                                      >
                                        Remove
                                      </button>
                                    </div>
                                    <img 
                                      src={selectedNode.data.imageUrl} 
                                      alt="Preview" 
                                      className="max-h-32 rounded border border-white/20 object-contain"
                                    />
                                  </div>
                                )}
                                <p className="text-[9px] text-gray-500">
                                  Upload an image directly, or connect from a User Input node
                                </p>
                              </div>
                            )}
                            
                            <div className="space-y-1">
                              <label className="text-[10px] font-bold text-cream/50 uppercase tracking-wider">System Prompt</label>
                              <textarea 
                                value={selectedNode.data.systemPrompt}
                                onChange={(e) => {
                                  const newPrompt = e.target.value;
                                  setNodes(prev => prev.map(n => n.id === selectedNode.id ? { ...n, data: { ...n.data, systemPrompt: newPrompt } } : n));
                                }}
                                rows={8}
                                className="w-full bg-black/50 border border-white/10 p-2 text-xs text-cream/80 focus:border-cherry focus:outline-none resize-none font-mono rounded-md leading-relaxed"
                              />
                            </div>
                          </>
                        ) : null}
                        
                         {/* --- OUTPUT SECTION --- */}
                         {selectedNode.data.output && (
                            <div className="mt-4 pt-4 border-t border-white/10 animate-in fade-in slide-in-from-bottom-2">
                                <div className="flex items-center justify-between mb-2">
                                   <div className="flex items-center gap-2">
                                       <Sparkles className="w-3 h-3 text-emerald-400" />
                                       <span className="text-[10px] font-bold text-emerald-400 uppercase tracking-wider">Execution Result</span>
                                   </div>
                                   <div className="flex items-center gap-2">
                                       <span className="text-[9px] text-gray-600 font-mono">{selectedNode.data.output.length} chars</span>
                                       
                                       {selectedNode.data.downloadUrl && (
                                          <button 
                                            onClick={() => {
                                                const link = document.createElement('a');
                                                link.href = selectedNode.data.downloadUrl!;
                                                link.download = `${selectedNode.data.label.replace(/\s+/g, '_')}_output.pdf`;
                                                link.click();
                                            }}
                                            className="p-1 hover:bg-white/10 rounded transition-colors text-blue-400"
                                            title="Download PDF"
                                          >
                                            <Download className="w-3 h-3" />
                                          </button>
                                       )}

                                       <button 
                                         onClick={() => {
                                            navigator.clipboard.writeText(selectedNode.data.output || '');
                                            addLog('info', 'Output copied to clipboard');
                                         }}
                                         className="p-1 hover:bg-white/10 rounded transition-colors"
                                         title="Copy output"
                                       >
                                         <Copy className="w-3 h-3 text-gray-500 hover:text-white" />
                                       </button>
                                   </div>
                                </div>
                                <div className="p-3 bg-black/40 rounded border border-emerald-500/20 text-xs text-emerald-100 font-mono whitespace-pre-wrap max-h-48 overflow-y-auto custom-scrollbar shadow-inner">
                                  {selectedNode.data.output}
                                </div>
                            </div>
                         )}

                         <div className="pt-2 mt-auto">
                           <button 
                            onClick={() => deleteNode(selectedNode.id)}
                            className="w-full py-2 flex items-center justify-center gap-2 bg-red-500/10 text-red-500 hover:bg-red-500 hover:text-white rounded-md text-[10px] font-bold uppercase transition-all"
                           >
                              <Trash2 className="w-3 h-3" /> Delete Node
                           </button>
                        </div>
                                    </div>
                                </>
                            ) : (
                                <div className="flex flex-col items-center justify-center h-64 text-cream/30">
                                    <Box className="w-10 h-10 mb-3 opacity-20" />
                                    <p className="text-[10px] font-mono uppercase tracking-widest">Select a node to configure</p>
                                </div>
                            )}
                        </div>
                    )}
                    
                    {/* Console Tab Content */}
                    {rightPanelTab === 'console' && (
                        <div className="p-3 space-y-2 font-mono text-[10px]">
                            {logs.length === 0 ? (
                                <div className="text-gray-600 italic text-center py-16">System Idle. Ready to capture events.</div>
                            ) : (
                                logs.map(log => (
                                    <div key={log.id} className="flex gap-2 animate-in fade-in slide-in-from-left-2 duration-300">
                                        <span className="text-gray-600 shrink-0">{log.timestamp.toLocaleTimeString([], { hour12: false, hour: '2-digit', minute:'2-digit', second:'2-digit' })}</span>
                                        <div className="flex-1 break-words">
                                            <span className={`font-bold mr-1 ${log.level === 'success' ? 'text-emerald-400' : log.level === 'error' ? 'text-red-400' : 'text-blue-400'}`}>
                                                {log.level === 'info' ? 'ℹ' : log.level === 'success' ? '✓' : '!'}
                                            </span>
                                            <span className="text-gray-300">{log.message}</span>
                                        </div>
                                    </div>
                                ))
                            )}
                        </div>
                    )}
                </div>
            </div>
        </div>

      </div>

      {/* Custom API Key Modal */}
      {showApiKeyModal && selectedNode && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-[100] animate-in fade-in duration-200">
          <div className="bg-[#0a0a0a] border border-white/10 rounded-xl w-[450px] shadow-2xl animate-in zoom-in-95 duration-200">
            {/* Modal Header */}
            <div className="flex items-center justify-between p-4 border-b border-white/10">
              <div className="flex items-center gap-2">
                <div className="w-8 h-8 bg-gradient-to-br from-amber-500 to-orange-600 rounded-lg flex items-center justify-center">
                  <Zap className="w-4 h-4 text-white" />
                </div>
                <div>
                  <h3 className="text-sm font-bold text-cream">Configure Custom API Key</h3>
                  <p className="text-[10px] text-gray-500">Use your own API key for this agent</p>
                </div>
              </div>
              <button 
                onClick={() => {
                  setShowApiKeyModal(false);
                  setTempApiKey('');
                }}
                className="p-1.5 hover:bg-white/10 rounded-lg transition-colors"
              >
                <X className="w-4 h-4 text-gray-400" />
              </button>
            </div>
            
            {/* Modal Body */}
            <div className="p-4 space-y-4">
              {/* Provider Selection */}
              <div className="space-y-2">
                <label className="text-[10px] font-bold text-cream/50 uppercase tracking-wider">API Provider</label>
                <div className="grid grid-cols-4 gap-2">
                  {[
                    { id: 'openrouter', name: 'OpenRouter', icon: '🌐' },
                    { id: 'openai', name: 'OpenAI', icon: '🟢' },
                    { id: 'anthropic', name: 'Anthropic', icon: '🟣' },
                    { id: 'google', name: 'Google', icon: '🔵' },
                  ].map((provider) => (
                    <button
                      key={provider.id}
                      onClick={() => setSelectedApiProvider(provider.id as any)}
                      className={`p-2 rounded-lg border text-center transition-all ${
                        selectedApiProvider === provider.id 
                          ? 'border-cherry bg-cherry/20 text-cream' 
                          : 'border-white/10 hover:border-white/30 text-gray-400'
                      }`}
                    >
                      <span className="text-lg">{provider.icon}</span>
                      <span className="block text-[9px] mt-1">{provider.name}</span>
                    </button>
                  ))}
                </div>
              </div>
              
              {/* API Key Input */}
              <div className="space-y-2">
                <label className="text-[10px] font-bold text-cream/50 uppercase tracking-wider">API Key</label>
                <input
                  type="password"
                  value={tempApiKey}
                  onChange={(e) => setTempApiKey(e.target.value)}
                  placeholder={
                    selectedApiProvider === 'openrouter' ? 'sk-or-v1-...' :
                    selectedApiProvider === 'openai' ? 'sk-...' :
                    selectedApiProvider === 'anthropic' ? 'sk-ant-...' :
                    'AI...'
                  }
                  className="w-full bg-black/50 border border-white/10 p-3 text-sm text-cream font-mono focus:border-cherry focus:outline-none rounded-lg"
                />
                <p className="text-[9px] text-gray-500">
                  {selectedApiProvider === 'openrouter' && '🌐 Get your key at openrouter.ai/keys'}
                  {selectedApiProvider === 'openai' && '🟢 Get your key at platform.openai.com/api-keys'}
                  {selectedApiProvider === 'anthropic' && '🟣 Get your key at console.anthropic.com'}
                  {selectedApiProvider === 'google' && '🔵 Get your key at aistudio.google.com/apikey'}
                </p>
              </div>
              
              {/* Model Selection based on provider */}
              <div className="space-y-2">
                <label className="text-[10px] font-bold text-cream/50 uppercase tracking-wider">Model</label>
                <select
                  value={selectedNode.data.model || 'gpt-4o'}
                  onChange={(e) => {
                    setNodes(prev => prev.map(n => n.id === selectedNode.id ? { 
                      ...n, 
                      data: { ...n.data, model: e.target.value } 
                    } : n));
                  }}
                  className="w-full bg-black/50 border border-white/10 p-2 text-xs text-cream focus:border-cherry focus:outline-none rounded-md"
                >
                  {selectedApiProvider === 'openrouter' && (
                    <>
                      <option value="gpt-4o">GPT-4o</option>
                      <option value="gpt-4o-mini">GPT-4o Mini</option>
                      <option value="claude-3.5-sonnet">Claude 3.5 Sonnet</option>
                      <option value="claude-3-opus">Claude 3 Opus</option>
                      <option value="gemini-2.5-flash">Gemini 2.5 Flash</option>
                    </>
                  )}
                  {selectedApiProvider === 'openai' && (
                    <>
                      <option value="custom-openai">GPT-4o</option>
                      <option value="gpt-4o-mini">GPT-4o Mini</option>
                      <option value="gpt-4-turbo">GPT-4 Turbo</option>
                      <option value="gpt-3.5-turbo">GPT-3.5 Turbo</option>
                    </>
                  )}
                  {selectedApiProvider === 'anthropic' && (
                    <>
                      <option value="custom-anthropic">Claude 3.5 Sonnet</option>
                      <option value="claude-3-opus">Claude 3 Opus</option>
                      <option value="claude-3-haiku">Claude 3 Haiku</option>
                    </>
                  )}
                  {selectedApiProvider === 'google' && (
                    <>
                      <option value="custom-google">Gemini 2.0 Flash</option>
                      <option value="gemini-1.5-pro">Gemini 1.5 Pro</option>
                      <option value="gemini-1.5-flash">Gemini 1.5 Flash</option>
                    </>
                  )}
                </select>
              </div>
              
              {/* Warning */}
              <div className="p-3 bg-amber-500/10 border border-amber-500/30 rounded-lg">
                <div className="flex items-start gap-2">
                  <AlertCircle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                  <div>
                    <p className="text-[10px] text-amber-400 font-bold">Security Notice</p>
                    <p className="text-[9px] text-amber-400/70 mt-1">
                      Your API key is stored with the workflow and sent to the backend for execution. 
                      Never share workflows containing API keys publicly.
                    </p>
                  </div>
                </div>
              </div>
            </div>
            
            {/* Modal Footer */}
            <div className="flex items-center justify-end gap-2 p-4 border-t border-white/10">
              <button
                onClick={() => {
                  // Clear custom API key
                  setNodes(prev => prev.map(n => n.id === selectedNode.id ? { 
                    ...n, 
                    data: { ...n.data, customApiKey: undefined, apiProvider: undefined } 
                  } : n));
                  setShowApiKeyModal(false);
                  setTempApiKey('');
                }}
                className="px-4 py-2 text-[10px] font-bold text-gray-400 hover:text-white transition-colors"
              >
                Clear & Use Free Models
              </button>
              <button
                onClick={() => {
                  if (tempApiKey.length > 10) {
                    setNodes(prev => prev.map(n => n.id === selectedNode.id ? { 
                      ...n, 
                      data: { 
                        ...n.data, 
                        customApiKey: tempApiKey,
                        apiProvider: selectedApiProvider
                      } 
                    } : n));
                    setShowApiKeyModal(false);
                    setTempApiKey('');
                    addLog('success', `Custom API key configured for ${selectedApiProvider}`);
                  }
                }}
                disabled={tempApiKey.length < 10}
                className={`px-4 py-2 text-[10px] font-bold uppercase rounded-lg transition-all ${
                  tempApiKey.length >= 10
                    ? 'bg-cherry text-white hover:bg-cherry/80'
                    : 'bg-gray-800 text-gray-500 cursor-not-allowed'
                }`}
              >
                Save API Key
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
};
