const passwordForm = document.getElementById('passwordForm');
const passwordInput = document.getElementById('password');
const unlockBtn = document.getElementById('unlockBtn');
const memoContent = document.getElementById('memoContent');
const contentDiv = document.getElementById('content');
const errorDiv = document.getElementById('error');

let memoId = null;
let encryptionKey = null;
let requiresPassword = false;

function parseHash() {
  const hash = window.location.hash.substring(1);
  if (!hash) {
    showError('Invalid link');
    return;
  }
  
  const parts = hash.split(':');
  if (parts.length !== 2) {
    showError('Invalid link');
    return;
  }
  
  memoId = parts[0];
  encryptionKey = parts[1];
  
  loadMemo();
}

async function loadMemo(password = null) {
  try {
    const response = await fetch('/api/get', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        id: memoId,
        key: encryptionKey,
        password,
        timestamp: Date.now()
      })
    });
    
    const data = await response.json();
    
    if (response.status === 401) {
      requiresPassword = true;
      passwordForm.classList.remove('hidden');
      return;
    }
    
    if (!response.ok) {
      throw new Error(data.error || 'Memo not found');
    }
    
    contentDiv.textContent = data.content;
    memoContent.classList.remove('hidden');
    passwordForm.classList.add('hidden');
    
  } catch (error) {
    showError(error.message);
  }
}

function showError(message) {
  errorDiv.textContent = message;
  errorDiv.classList.remove('hidden');
}

unlockBtn.addEventListener('click', () => {
  const password = passwordInput.value;
  if (!password) {
    alert('Please enter password');
    return;
  }
  loadMemo(password);
});

passwordInput.addEventListener('keypress', (e) => {
  if (e.key === 'Enter') {
    unlockBtn.click();
  }
});

parseHash();
