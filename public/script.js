const createBtn = document.getElementById('createBtn');
const contentInput = document.getElementById('content');
const passwordInput = document.getElementById('password');
const customUrlInput = document.getElementById('customUrl');
const resultDiv = document.getElementById('result');
const memoLinkInput = document.getElementById('memoLink');
const copyBtn = document.getElementById('copyBtn');

let securityToken = null;
let securityFingerprint = null;

async function getSecurityToken() {
  try {
    const response = await fetch('/api/token');
    const data = await response.json();
    securityToken = data.token;
    securityFingerprint = data.fingerprint;
  } catch (error) {
    console.error('Security initialization failed');
  }
}

getSecurityToken();

createBtn.addEventListener('click', async () => {
  const content = contentInput.value.trim();
  
  if (!content) {
    alert('Please enter your memo');
    return;
  }

  if (!securityToken) {
    await getSecurityToken();
    if (!securityToken) {
      alert('Security error. Please refresh the page.');
      return;
    }
  }
  
  createBtn.disabled = true;
  createBtn.textContent = 'Creating...';
  
  try {
    const response = await fetch('/api/create', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        content,
        password: passwordInput.value || undefined,
        customUrl: customUrlInput.value || undefined,
        token: securityToken,
        fingerprint: securityFingerprint,
        timestamp: Date.now()
      })
    });
    
    const data = await response.json();
    
    if (!response.ok) {
      throw new Error(data.error || 'An error occurred');
    }
    
    const url = `${window.location.origin}/view.html#${data.id}:${data.key}`;
    memoLinkInput.value = url;
    resultDiv.classList.remove('hidden');
    
    contentInput.value = '';
    passwordInput.value = '';
    customUrlInput.value = '';
    
    await getSecurityToken();
    
  } catch (error) {
    alert(error.message);
    await getSecurityToken();
  } finally {
    createBtn.disabled = false;
    createBtn.textContent = 'Create Memo';
  }
});

copyBtn.addEventListener('click', () => {
  memoLinkInput.select();
  document.execCommand('copy');
  
  const originalText = copyBtn.textContent;
  copyBtn.textContent = 'Copied!';
  setTimeout(() => {
    copyBtn.textContent = originalText;
  }, 2000);
});

contentInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) {
    createBtn.click();
  }
});
