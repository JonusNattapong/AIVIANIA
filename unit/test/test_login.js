#!/usr/bin/env node

// Simple test script to verify login functionality
const http = require('http');

const postData = JSON.stringify({
    username: 'admin',
    password: 'password123'
});

const options = {
    hostname: '127.0.0.1',
    port: 3000,
    path: '/login',
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(postData)
    }
};

const req = http.request(options, (res) => {
    console.log(`Status: ${res.statusCode}`);
    console.log(`Headers:`, res.headers);

    res.setEncoding('utf8');
    res.on('data', (chunk) => {
        console.log(`Body: ${chunk}`);
    });
    res.on('end', () => {
        console.log('Test completed');
        process.exit(0);
    });
});

req.on('error', (e) => {
    console.error(`Problem with request: ${e.message}`);
    process.exit(1);
});

req.write(postData);
req.end();