const QRCode = require('qrcode');
const fs = require('fs');
const path = require('path');

const outputDir = path.join(__dirname, '..', 'public', 'assets', 'qr-samples');

if (!fs.existsSync(outputDir)) {
  fs.mkdirSync(outputDir, { recursive: true });
}

// Copy vendor jsQR to public/js/vendor
const vendorDir = path.join(__dirname, '..', 'public', 'js', 'vendor');
if (!fs.existsSync(vendorDir)) {
  fs.mkdirSync(vendorDir, { recursive: true });
}

const jsQrSource = path.join(__dirname, '..', 'node_modules', 'jsqr', 'dist', 'jsQR.js');
if (fs.existsSync(jsQrSource)) {
  fs.copyFileSync(jsQrSource, path.join(vendorDir, 'jsQR.js'));
  console.log('Copied jsQR.js to public/js/vendor/jsQR.js');
}

const samples = [
  {
    name: 'safe-google.png',
    data: 'https://www.google.com',
    label: 'Safe URL (Google)'
  },
  {
    name: 'suspicious-portal.png',
    data: 'https://secure-login.example.com',
    label: 'Suspicious Portal'
  },
  {
    name: 'phishing-paypal.png',
    data: 'https://paypal-login-security.verify-account.example',
    label: 'Phishing PayPal Clone'
  },
  {
    name: 'scam-lottery.png',
    data: 'Congratulations! You have won ₹50,000. Click immediately to claim your reward.',
    label: 'Scam Prize Message'
  }
];

async function generateQRs() {
  for (const sample of samples) {
    const filePath = path.join(outputDir, sample.name);
    await QRCode.toFile(filePath, sample.data, {
      width: 400,
      margin: 2,
      color: {
        dark: '#0f172a',
        light: '#ffffff'
      }
    });
    console.log(`Generated: ${sample.name} -> ${sample.data}`);
  }
}

generateQRs().then(() => {
  console.log('All demo QR codes generated successfully!');
}).catch(err => {
  console.error('Error generating QR codes:', err);
});
