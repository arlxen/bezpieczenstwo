// pkce config
const CLIENT_ID = 'web-client';
const REDIRECT_URI = window.location.origin + '/';

// state vars
let accessToken = sessionStorage.getItem('access_token') || null;

// dom elements
const connectionStatus = document.getElementById('connectionStatus');
const connectionText = document.getElementById('connectionText');
const unauthPanel = document.getElementById('unauthPanel');
const authPanel = document.getElementById('authPanel');
const loginBtn = document.getElementById('loginBtn');
const logoutBtn = document.getElementById('logoutBtn');
const profileName = document.getElementById('profileName');
const profileRole = document.getElementById('profileRole');

const step1 = document.getElementById('step1');
const step2 = document.getElementById('step2');
const step3 = document.getElementById('step3');
const step4 = document.getElementById('step4');
const step5 = document.getElementById('step5');

const debugVerifier = document.getElementById('debugVerifier');
const debugChallenge = document.getElementById('debugChallenge');
const debugJwt = document.getElementById('debugJwt');

const resStatus = document.getElementById('resStatus');
const statusCode = document.getElementById('statusCode');
const apiResponse = document.getElementById('apiResponse');

// crypto functions for pkce
function generateRandomString(length) {
  const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
  let result = '';
  const randomValues = new Uint32Array(length);
  crypto.getRandomValues(randomValues);
  for (let i = 0; i < length; i++) {
    result += charset[randomValues[i] % charset.length];
  }
  return result;
}

function base64UrlEncode(arrayBuffer) {
  const bytes = new Uint8Array(arrayBuffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

async function generateChallenge(verifier) {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return base64UrlEncode(hash);
}

// initiate oauth2 redirect
async function login() {
  // generate and store verifier
  const verifier = generateRandomString(64);
  sessionStorage.setItem('code_verifier', verifier);
  
  const challenge = await generateChallenge(verifier);
  const state = generateRandomString(16);
  sessionStorage.setItem('oauth_state', state);
  
  // build redirect url
  const authUrl = new URL(window.location.origin + '/oauth/authorize');
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('client_id', CLIENT_ID);
  authUrl.searchParams.set('redirect_uri', REDIRECT_URI);
  authUrl.searchParams.set('code_challenge', challenge);
  authUrl.searchParams.set('code_challenge_method', 'S256');
  authUrl.searchParams.set('state', state);
  
  window.location.href = authUrl.toString();
}

// exchange code for token
async function handleRedirect() {
  const params = new URLSearchParams(window.location.search);
  const code = params.get('code');
  const state = params.get('state');
  
  if (!code) return;
  
  // clear parameters from url
  window.history.replaceState({}, document.title, window.location.pathname);
  
  // verify state to prevent csrf
  const storedState = sessionStorage.getItem('oauth_state');
  if (state !== storedState) {
    showErrorResponse('CSRF state mismatch. Access denied.');
    return;
  }
  
  // retrieve verifier
  const verifier = sessionStorage.getItem('code_verifier');
  if (!verifier) {
    showErrorResponse('No code verifier found in session storage.');
    return;
  }
  
  // highlight ui flow steps
  step1.classList.add('completed');
  step2.classList.add('completed');
  step3.classList.add('completed');
  step4.classList.add('active');
  
  try {
    const response = await fetch('/oauth/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: code,
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        code_verifier: verifier
      })
    });
    
    const data = await response.json();
    
    if (response.ok) {
      accessToken = data.access_token;
      sessionStorage.setItem('access_token', accessToken);
      
      step4.classList.remove('active');
      step4.classList.add('completed');
      
      updateSessionUI();
      showSuccessResponse(200, data);
    } else {
      showErrorResponse(data.error_description || data.error);
    }
  } catch (err) {
    showErrorResponse(err.message);
  }
}

// decode jwt payload
function decodeJwt(token) {
  try {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(atob(base64).split('').map(function(c) {
      return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
    }).join(''));
    return JSON.parse(jsonPayload);
  } catch (e) {
    return null;
  }
}

// update UI states
function updateSessionUI() {
  if (accessToken) {
    const claims = decodeJwt(accessToken);
    if (!claims) {
      logout();
      return;
    }
    
    connectionStatus.className = 'status-badge status-auth';
    connectionText.textContent = 'Authenticated';
    
    unauthPanel.style.display = 'none';
    authPanel.style.display = 'block';
    
    profileName.textContent = claims.name;
    profileRole.textContent = claims.role;
    if (claims.role === 'admin') {
      profileRole.className = 'user-role-badge admin';
    } else {
      profileRole.className = 'user-role-badge';
    }
    
    // show key details in debug panels
    debugVerifier.textContent = sessionStorage.getItem('code_verifier') || 'N/A';
    generateChallenge(sessionStorage.getItem('code_verifier') || '').then(ch => {
      debugChallenge.textContent = ch || 'N/A';
    });
    
    debugJwt.innerHTML = `<span class="highlight-key">Header:</span> {"alg": "HS256", "typ": "JWT"}\n` +
                         `<span class="highlight-key">Payload:</span> ` + 
                         JSON.stringify(claims, null, 2)
                           .replace(/"role": "(\w+)"/g, '"role": "<span class="highlight-string">$1</span>"')
                           .replace(/"name": "([^"]+)"/g, '"name": "<span class="highlight-string">$1</span>"');
                           
    // update flow step icons
    step1.className = 'flow-step completed';
    step2.className = 'flow-step completed';
    step3.className = 'flow-step completed';
    step4.className = 'flow-step completed';
    step5.className = 'flow-step active';
  } else {
    connectionStatus.className = 'status-badge status-unauth';
    connectionText.textContent = 'Not Authenticated';
    
    unauthPanel.style.display = 'block';
    authPanel.style.display = 'none';
    
    debugVerifier.textContent = 'None generated';
    debugChallenge.textContent = 'None computed';
    debugJwt.textContent = 'No token loaded';
    
    // reset steps
    step1.className = 'flow-step';
    step2.className = 'flow-step';
    step3.className = 'flow-step';
    step4.className = 'flow-step';
    step5.className = 'flow-step';
  }
}

// call backend endpoints
async function callApi(endpoint) {
  resStatus.style.display = 'none';
  apiResponse.textContent = 'Sending request...';
  
  const headers = {};
  if (accessToken) {
    headers['Authorization'] = `Bearer ${accessToken}`;
  }
  
  try {
    const response = await fetch(endpoint, { headers });
    const data = await response.json();
    
    resStatus.style.display = 'inline-flex';
    if (response.ok) {
      resStatus.className = 'response-status status-ok';
      statusCode.textContent = `${response.status} ${response.statusText}`;
    } else {
      resStatus.className = 'response-status status-err';
      statusCode.textContent = `${response.status} ${response.statusText}`;
    }
    
    apiResponse.innerHTML = JSON.stringify(data, null, 2)
      .replace(/"error": "([^"]+)"/g, '"error": "<span class="highlight-key">$1</span>"');
      
  } catch (err) {
    resStatus.style.display = 'inline-flex';
    resStatus.className = 'response-status status-err';
    statusCode.textContent = 'Connection Error';
    apiResponse.textContent = err.message;
  }
}

function showSuccessResponse(code, obj) {
  resStatus.style.display = 'inline-flex';
  resStatus.className = 'response-status status-ok';
  statusCode.textContent = `${code} OK`;
  apiResponse.textContent = JSON.stringify(obj, null, 2);
}

function showErrorResponse(message) {
  resStatus.style.display = 'inline-flex';
  resStatus.className = 'response-status status-err';
  statusCode.textContent = 'Error';
  apiResponse.textContent = message;
}

function logout() {
  sessionStorage.clear();
  accessToken = null;
  updateSessionUI();
}

// tab switching
const tabSession = document.getElementById('tabSession');
const tabEducation = document.getElementById('tabEducation');
const viewSession = document.getElementById('viewSession');
const viewEducation = document.getElementById('viewEducation');

tabSession.addEventListener('click', () => {
  tabSession.classList.add('active');
  tabEducation.classList.remove('active');
  viewSession.style.display = 'block';
  viewEducation.style.display = 'none';
});

tabEducation.addEventListener('click', () => {
  tabEducation.classList.add('active');
  tabSession.classList.remove('active');
  viewSession.style.display = 'none';
  viewEducation.style.display = 'block';
});

// event listeners
loginBtn.addEventListener('click', login);
logoutBtn.addEventListener('click', logout);

document.getElementById('btnHealth').addEventListener('click', () => callApi('/api/health'));
document.getElementById('btnProfile').addEventListener('click', () => callApi('/api/user/profile'));
document.getElementById('btnSettings').addEventListener('click', () => callApi('/api/user/settings'));
document.getElementById('btnData').addEventListener('click', () => callApi('/api/data'));
document.getElementById('btnAdmin').addEventListener('click', () => callApi('/api/admin/dashboard'));

// init
handleRedirect().then(() => {
  updateSessionUI();
});
