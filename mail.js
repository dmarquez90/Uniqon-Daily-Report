// Outgoing email through Gmail SMTP (GMAIL_USER + GMAIL_APP_PASSWORD)
const nodemailer = require('nodemailer');

const enabled = () => !!(process.env.GMAIL_USER && process.env.GMAIL_APP_PASSWORD);
let transport;
function tx() {
  transport ||= nodemailer.createTransport({ service: 'gmail', auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_APP_PASSWORD } });
  return transport;
}

const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
function layout(title, inner, appUrl) {
  return `<div style="font-family:Arial,sans-serif;background:#F2F1EC;padding:24px">
  <div style="max-width:520px;margin:0 auto;background:#fff;border-radius:10px;overflow:hidden;border:1px solid #D8DBDF">
    <div style="padding:18px 24px;border-bottom:4px solid #B3A46A"><img src="${appUrl}/logo.png" alt="Uniqon Home Center" height="48"></div>
    <div style="padding:24px;color:#4A4A4C;font-size:15px;line-height:1.5">
      <h2 style="margin:0 0 14px;color:#1F4B48;font-size:20px">${title}</h2>${inner}
    </div>
    <div style="padding:14px 24px;background:#F7F6F1;color:#6B6F76;font-size:12px">Uniqon Home Center · 40673 Fremont Blvd, Fremont, CA 94538 · +1 (510) 938-4049</div>
  </div></div>`;
}
const button = (href, text) => `<p style="margin:22px 0"><a href="${href}" style="background:#1F4B48;color:#fff;text-decoration:none;padding:12px 22px;border-radius:6px;font-weight:bold;display:inline-block">${text}</a></p>`;

async function send(to, subject, html, text) {
  if (!enabled()) throw new Error('Email is not configured');
  await tx().sendMail({ from: `"Uniqon Home Center" <${process.env.GMAIL_USER}>`, to, subject, html, text });
}

function sendWelcome({ to, name, empNumber, tempPassword, appUrl }) {
  const html = layout('Welcome to Uniqon Daily Reports', `
    <p>Hi ${esc(name)},</p>
    <p>An account was created for you to submit your daily reports.</p>
    <table style="border-collapse:collapse;margin:10px 0">
      <tr><td style="padding:4px 12px 4px 0;color:#6B6F76">User (email)</td><td><b>${esc(to)}</b></td></tr>
      <tr><td style="padding:4px 12px 4px 0;color:#6B6F76">Employee ID</td><td><b>${esc(empNumber)}</b></td></tr>
      <tr><td style="padding:4px 12px 4px 0;color:#6B6F76">Temporary password</td><td><b>${esc(tempPassword)}</b></td></tr>
    </table>
    <p>You will be asked to create your own password the first time you sign in. Please do it as soon as possible.</p>
    ${button(appUrl, 'Sign in')}`, appUrl);
  const text = `Hi ${name},\n\nAn account was created for you.\nUser: ${to}\nEmployee ID: ${empNumber}\nTemporary password: ${tempPassword}\n\nSign in at ${appUrl} and create your own password.`;
  return send(to, 'Your Uniqon Daily Reports account', html, text);
}

function sendReset({ to, name, link, appUrl }) {
  const html = layout('Reset your password', `
    <p>Hi ${esc(name)},</p>
    <p>We received a request to reset your password. Click the button below to choose a new one. The link is valid for 1 hour.</p>
    ${button(link, 'Reset password')}
    <p style="color:#6B6F76;font-size:13px">If you did not request this, you can ignore this email — your password will not change.</p>`, appUrl);
  const text = `Hi ${name},\n\nReset your password here (valid for 1 hour):\n${link}\n\nIf you did not request this, ignore this email.`;
  return send(to, 'Reset your Uniqon password', html, text);
}

module.exports = { enabled, sendWelcome, sendReset };
