const fs = require('fs');
const path = require('path');

const dbPath = path.join(__dirname, 'db.json');

// helper for read
function readDb() {
  const data = fs.readFileSync(dbPath, 'utf8');
  return JSON.parse(data);
}

// helper for write
function writeDb(data) {
  fs.writeFileSync(dbPath, JSON.stringify(data, null, 2), 'utf8');
}

const db = {
  getUser: (username) => {
    const data = readDb();
    return data.users.find(u => u.username === username);
  },
  
  getClient: (clientId) => {
    const data = readDb();
    return data.clients.find(c => c.id === clientId);
  },
  
  saveAuthCode: (code, challenge, method, userId, clientId) => {
    const data = readDb();
    const expires = Date.now() + 5 * 60 * 1000; // 5 min
    data.authCodes.push({
      code,
      challenge,
      method,
      userId,
      clientId,
      expires
    });
    writeDb(data);
  },
  
  getAndRemoveAuthCode: (code) => {
    const data = readDb();
    const idx = data.authCodes.findIndex(c => c.code === code);
    if (idx === -1) return null;
    
    const authCode = data.authCodes[idx];
    data.authCodes.splice(idx, 1);
    writeDb(data);
    
    if (Date.now() > authCode.expires) return null; // expired
    return authCode;
  }
};

module.exports = db;
