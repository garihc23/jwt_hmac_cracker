# JWT HMAC Key Cracker (Web Version)

A browser-based tool for testing the security of JWT tokens that use HMAC-based signing algorithms. This web application performs dictionary attacks against weak HMAC keys to demonstrate security vulnerabilities in JWT implementations.

![JWT Security Testing](https://img.shields.io/badge/Security-Testing-red)
![License](https://img.shields.io/badge/License-MIT-blue)
![Platform](https://img.shields.io/badge/Platform-Web%20Browser-green)
![JavaScript](https://img.shields.io/badge/JavaScript-ES6+-yellow)

## ⚠️ Legal Disclaimer

**FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY**

This tool is designed for:
- Security researchers and penetration testers
- Educational purposes and learning about JWT vulnerabilities
- Testing your own applications with proper authorization
- Bug bounty hunting on authorized targets

**Do NOT use this tool on systems you don't own or lack explicit permission to test.**

## 🎯 Features

- **Zero Installation**: Runs entirely in your web browser
- **Dictionary Attack**: Tests 150+ common weak keys automatically
- **Custom Key Testing**: Verify specific keys manually
- **Real-time Progress**: Live feedback with progress bars
- **Multiple Token Support**: Analyze multiple JWT tokens simultaneously
- **Vulnerability Assessment**: Detailed security impact analysis
- **Remediation Guidance**: Step-by-step security recommendations
- **Dark Theme Interface**: Easy on the eyes for long testing sessions

## 🔍 Supported Algorithms

- **HS256** (HMAC with SHA-256)
- **HS384** (HMAC with SHA-384)
- **HS512** (HMAC with SHA-512)

*Note: This tool only works with HMAC-based JWT tokens, not RSA or ECDSA signatures.*

## 🚀 Quick Start

### Simple Setup
```bash
# Clone the repository
git clone https://github.com/your-username/jwt-hmac-cracker.git
cd jwt-hmac-cracker

# Open in browser
open jwt-cracker.html
# or
python3 -m http.server 8000  # Then visit http://localhost:8000
```

### Instant Usage
1. Open `jwt-cracker.html` in any modern web browser
2. Paste your JWT tokens in the input fields
3. Click **"Start Key Cracking"** to begin the attack
4. Monitor progress and results in real-time

## 📋 Usage Examples

### Example JWT Tokens
```
Token 1: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJqb2huZG9lIiwicm9sZSI6InVzZXIiLCJleHAiOjE3MzAwMDAwMDB9.signature1

Token 2: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImV4cCI6MTczMDAwMDAwMH0.signature2
```

**Decoded Example:**
```json
// Token 1 Header: {"alg":"HS256"}
// Token 1 Payload: {"sub":"johndoe","role":"user","exp":1730000000}

// Token 2 Header: {"alg":"HS256"}  
// Token 2 Payload: {"sub":"admin","role":"admin","exp":1730000000}
```

### Test Workflow
1. **Load tokens** into the input fields
2. **Start attack** and watch real-time progress
3. **Analyze results** if key is found
4. **Test custom keys** using the manual test feature

## 🔧 Browser Requirements

### Supported Browsers
- ✅ **Chrome 60+**
- ✅ **Firefox 55+**
- ✅ **Safari 11+**
- ✅ **Edge 79+**

### Required Browser APIs
- **Web Crypto API** (for HMAC-SHA512 calculations)
- **ES6+ JavaScript** (async/await, arrow functions)
- **Modern DOM APIs** (querySelector, addEventListener)

## 📊 How It Works

### 1. JWT Structure Analysis
```
JWT Token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.signature
           ↑ header            ↑ payload     ↑ signature
```

The web tool:
1. **Parses JWT structure** by splitting on dots (`.`)
2. **Decodes header** to verify HMAC algorithm
3. **Extracts signing material** (header.payload)
4. **Tests keys** against the signature using Web Crypto API

### 2. Web Crypto HMAC Implementation
```javascript
async function hmacSHA512(key, message) {
    const encoder = new TextEncoder();
    const keyBuffer = encoder.encode(key);
    const messageBuffer = encoder.encode(message);
    
    const cryptoKey = await crypto.subtle.importKey(
        'raw', keyBuffer, 
        { name: 'HMAC', hash: 'SHA-512' }, 
        false, ['sign']
    );
    
    const signature = await crypto.subtle.sign(
        'HMAC', cryptoKey, messageBuffer
    );
    
    return btoa(String.fromCharCode(...new Uint8Array(signature)))
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
```

### 3. Dictionary Attack Process
```javascript
for (const key of wordlist) {
    const sig1 = await hmacSHA512(key, jwt1.headerPayload);
    const sig2 = await hmacSHA512(key, jwt2.headerPayload);
    
    if (sig1 === jwt1.signature && sig2 === jwt2.signature) {
        // KEY FOUND! 🎉
        return key;
    }
}
```

## 🎯 Built-in Wordlist

The tool includes **150+ carefully curated keys** across multiple categories:

### Basic Patterns
```
'', 'secret', 'key', 'admin', 'password'
'123456', '1234567890', 'qwerty'
```

### JWT-Specific Keys
```
'jwt', 'jwt-secret', 'JWT_SECRET', 'jwtsecret'
'hmac', 'hmackey', 'hs512', 'hs512-key'
'token', 'auth', 'bearer', 'secretkey'
```

### Application Patterns
```
'api-secret', 'app-secret', 'server-secret'
'dev-secret', 'prod-secret', 'staging-secret'
'myapp', 'webapp', 'microservice'
```

### Framework-Specific
```
'spring', 'express', 'laravel', 'django'
'rails', 'symfony', 'node', 'react'
```

### Base64 Encoded Strings
```
'c2VjcmV0' (base64 for 'secret')
'YWRtaW4=' (base64 for 'admin')
'cGFzc3dvcmQ=' (base64 for 'password')
```

## 🔍 Interface Features

### Main Controls
- **Token Input Fields**: Paste your JWT tokens here
- **Start Key Cracking**: Launch the dictionary attack
- **Test Custom Key**: Manually test a specific key
- **Progress Bar**: Real-time attack progress

### Real-time Feedback
```
[14:23:15] 🔍 Starting JWT key cracking attack...
[14:23:15] Token 1 signature: YWJjZGVmZ2hpamsxMjM0...
[14:23:15] Token 2 signature: cXdlcnR5dWlvcDU2Nzg5...
[14:23:16] Progress: 25/150 keys tested
[14:23:17] Progress: 50/150 keys tested
[14:23:18] 🎉 SIGNING KEY FOUND: "secret123"
```

### Security Analysis Output
When a key is found, the tool provides:
- ✅ **Key verification** against both tokens
- ⚠️ **Security implications** analysis
- 🔧 **Remediation steps** and best practices
- 💡 **Impact assessment** details

## 🛡️ Security Implications

### If a weak key is discovered:

#### **Critical Impact**
- 🚨 **Complete authentication bypass**
- 🚨 **Ability to forge any JWT token**
- 🚨 **Modify user IDs, roles, permissions**
- 🚨 **Impersonate any user in the system**

#### **Attack Scenarios**
```javascript
// With the discovered key, an attacker can:
const maliciousPayload = {
    "sub": "admin",
    "role": "SuperAdmin", 
    "exp": 9999999999
};

const forgedToken = createJWT(maliciousPayload, discoveredKey);
// This token will be accepted by the vulnerable application!
```

## 🔧 Remediation Guide

### Immediate Actions
1. **🚨 Rotate JWT signing key immediately**
2. **🚨 Invalidate all existing tokens**
3. **🚨 Force re-authentication for all users**
4. **🚨 Audit access logs for potential abuse**

### Generate Secure Keys
```bash
# Generate cryptographically secure key (512 bits for HS512)
openssl rand -base64 64

# Example output:
# kH8pLm9qR3vN2sT7wX1yE4uI8oP5aS9dF6gH3jK7lM2nB5vC8xZ1qW4eR6tY9uI2oP3aS5dF7gH9jK1lN4mQ6wE8r
```

### Secure Implementation Example
```javascript
// Environment variable (recommended)
const JWT_SECRET = process.env.JWT_SECRET;

// Secure verification with constant-time comparison
const crypto = require('crypto');

function verifyJWT(token, secret) {
    const [header, payload, signature] = token.split('.');
    const expectedSignature = crypto
        .createHmac('sha512', secret)
        .update(`${header}.${payload}`)
        .digest('base64url');
    
    // Use constant-time comparison to prevent timing attacks
    return crypto.timingSafeEqual(
        Buffer.from(signature), 
        Buffer.from(expectedSignature)
    );
}
```

### Security Checklist
- ✅ Use cryptographically secure random keys (256+ bits)
- ✅ Store keys in environment variables, not code
- ✅ Implement proper key rotation policies
- ✅ Use constant-time comparison functions
- ✅ Add proper token expiration (short-lived)
- ✅ Implement token refresh mechanisms
- ✅ Monitor for suspicious authentication patterns

## 📈 Performance Notes

### Browser Optimization
- **Asynchronous processing**: Prevents UI freezing during attacks
- **Batch processing**: Tests keys in chunks for better responsiveness
- **Memory efficient**: Doesn't store unnecessary data
- **Progress tracking**: Real-time feedback without performance impact

### Typical Performance
- **~150 keys in 2-5 seconds** (modern browser)
- **Web Crypto API**: Hardware-accelerated HMAC calculations
- **Non-blocking**: UI remains responsive during testing

## 🤝 Contributing

### File Structure
```
jwt-hmac-cracker/
├── jwt-cracker.html          # Main web application
├── README.md                 # This documentation
├── LICENSE                   # MIT license
└── examples/
    ├── vulnerable-tokens.txt # Example JWT tokens for testing
    └── secure-examples.js    # Secure implementation examples
```

### Adding New Wordlist Entries
Edit the `wordlist` array in `jwt-cracker.html`:
```javascript
const wordlist = [
    // ... existing entries
    'your-new-pattern',
    'another-common-key'
];
```

## 📄 License

This project is licensed under the MIT License:

```
MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software.
```

## 🔗 Related Resources

### Educational Materials
- [OWASP JWT Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [JWT.io Debugger](https://jwt.io/) - Decode and verify JWT tokens
- [RFC 7519 - JSON Web Token](https://tools.ietf.org/html/rfc7519)

### Other Security Tools
- [jwt_tool](https://github.com/ticarpi/jwt_tool) - Comprehensive JWT testing toolkit
- [JWT Inspector](https://www.jwtinspector.io/) - Browser extension for JWT analysis
- [Burp Suite JWT Editor](https://portswigger.net/bappstore/26aaa5ded2f74beea19e2ed8345a93dd)

## 📞 Support & Issues

- **🐛 Bug Reports**: [GitHub Issues](https://github.com/your-username/jwt-hmac-cracker/issues)
- **💡 Feature Requests**: [GitHub Discussions](https://github.com/your-username/jwt-hmac-cracker/discussions)
- **🔒 Security Issues**: security@yourdomain.com

---

**⚡ Ready to test your JWT security?** Just open the HTML file and start cracking! 

**🛡️ Remember**: Use this tool responsibly and only on systems you own or have explicit permission to test.
