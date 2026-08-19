#!/usr/bin/env node
'use strict';
/* Gjeneron çelësat VAPID për njoftimet push. */
try {
  const webpush = require('web-push');
  const keys = webpush.generateVAPIDKeys();
  console.log('Çelësat VAPID u gjeneruan:\n');
  console.log('VAPID_PUBLIC_KEY=' + keys.publicKey);
  console.log('VAPID_PRIVATE_KEY=' + keys.privateKey + '\n');
  console.log('Vendosi këto si variabla mjedisi (Environment) te Render/Railway,');
  console.log('pastaj rifillo shërbimin dhe hap aplikacionin → Cilësime → Aktivizo njoftimet.');
} catch (e) {
  console.error('Instalo modulin fillimisht:  npm install web-push');
  console.error('Ose përdor direkt:  npx web-push generate-vapid-keys');
  process.exit(1);
}
