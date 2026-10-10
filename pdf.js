// Daily report PDF, laid out like the paper form (one page per report, summary page when there are several)
const PDFDocument = require('pdfkit');
const path = require('path');

const LOGO = path.join(__dirname, 'public', 'logo.png');
const BLACK = '#222222', GRAY = '#8A8D92', TEAL = '#1F4B48';
const L = 50, R = 562, W = R - L, MID = L + W / 2;
const CONTACT = ['+1 (510) 938-4049', 'www.uniqonhomecenter.com', 'info@uniqonhomecenter.com', '40673 Fremont Blvd, Fremont', 'CA 94538'];

const shortDate = d => new Date(d + 'T12:00:00').toLocaleDateString('en-US', { month: '2-digit', day: '2-digit', year: 'numeric' });
const time12 = t => t ? new Date('2000-01-01T' + t).toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit' }) : '';
const stamp = ts => new Date(ts).toLocaleString('en-US', { timeZone: 'America/Los_Angeles', month: 'short', day: 'numeric', year: 'numeric', hour: 'numeric', minute: '2-digit' });
const money = v => v == null || v === '' ? '' : '$' + Number(v).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
const show = v => v == null ? '' : String(v);
const isProject = x => x.location_type === 'Project';

function header(doc) {
  doc.image(LOGO, L, 36, { width: 215 });
  doc.moveTo(L, 112).lineTo(R, 112).lineWidth(0.7).strokeColor(GRAY).stroke();
  return 128;
}

// "Label: ____value____"
function field(doc, x, y, w, label, value, opts = {}) {
  doc.font('Helvetica').fontSize(10.5).fillColor(BLACK).text(label, x, y, { lineBreak: false });
  const lx = x + (opts.labelW || doc.widthOfString(label) + 8);
  doc.font(opts.italic ? 'Helvetica-Oblique' : 'Helvetica').fontSize(11.5)
    .text(show(value), lx + 4, y - 1.5, { width: x + w - lx - 8, lineBreak: false, ellipsis: true });
  doc.moveTo(lx, y + 12).lineTo(x + w - 6, y + 12).lineWidth(0.6).strokeColor(BLACK).stroke();
}

function section(doc, y, title) {
  doc.font('Helvetica-Bold').fontSize(11).fillColor(BLACK).text(title, L, y);
  return y + 16;
}

// Boxed 2x2 table like the form: "Label:  _value_"
function boxes(doc, y, rows) {
  const h = 26;
  rows.forEach((pair, i) => {
    pair.forEach(([label, value], j) => {
      const x = j ? MID : L, top = y + i * h;
      doc.rect(x, top, W / 2, h).lineWidth(0.8).strokeColor(BLACK).stroke();
      doc.font('Helvetica').fontSize(10).fillColor(BLACK).text(label, x + 8, top + 8, { lineBreak: false });
      const vx = x + 8 + doc.widthOfString(label) + 6;
      const v = show(value);
      doc.font('Helvetica').fontSize(11).text(v, vx + 3, top + 7, { lineBreak: false });
      const vw = Math.max(36, doc.widthOfString(v) + 6);
      doc.moveTo(vx, top + 19).lineTo(Math.min(vx + vw, x + W / 2 - 6), top + 19).lineWidth(0.6).stroke();
    });
  });
  return y + rows.length * h + 14;
}

// Text written on ruled lines
function ruled(doc, y, label, text, minLines = 2) {
  doc.font('Helvetica-Bold').fontSize(9.5).fillColor(BLACK).text(label, L, y);
  y += 14;
  doc.font('Helvetica').fontSize(11);
  const lines = [];
  String(text || '').split('\n').forEach(p => {
    const words = p.trim().split(/\s+/).filter(Boolean);
    let cur = '';
    words.forEach(w => {
      const next = cur ? cur + ' ' + w : w;
      if (doc.widthOfString(next) > W - 16 && cur) { lines.push(cur); cur = w; } else cur = next;
    });
    if (cur) lines.push(cur);
  });
  while (lines.length < minLines) lines.push('');
  lines.forEach(t => {
    if (y > 700) { doc.addPage(); y = header(doc); }
    doc.font('Helvetica').fontSize(11).fillColor(BLACK).text(t, L + 8, y + 4, { lineBreak: false });
    doc.moveTo(L, y + 18).lineTo(R, y + 18).lineWidth(0.5).strokeColor(GRAY).stroke();
    y += 21;
  });
  return y + 10;
}

function reportPage(doc, x) {
  let y = header(doc);
  field(doc, L, y, W / 2, 'Date:', shortDate(x.date), { labelW: 62 }); field(doc, MID, y, W / 2, 'Employee:', x.name, { labelW: 78 }); y += 22;
  field(doc, L, y, W / 2, 'Opening:', time12(x.opening), { labelW: 62 }); field(doc, MID, y, W / 2, 'Closing:', time12(x.closing), { labelW: 78 }); y += 22;
  field(doc, L, y, W / 2, 'Job Title:', x.title, { labelW: 62 }); field(doc, MID, y, W / 2, 'Location Type:', x.location_type, { labelW: 78 }); y += 22;
  field(doc, L, y, W, 'Location:', x.location, { labelW: 62 }); y += 32;

  let n = 1;
  if (!isProject(x)) {
    y = section(doc, y, `${n++}. CUSTOMER & SALES ACTIVITY`);
    y = boxes(doc, y, [[['Walk-in Customers:', x.walk_ins], ['Phone Calls / Inquiries:', x.calls]],
                       [['Quotations Issued:', x.quotations], ['Orders Confirmed:', x.orders]]]);
    y = section(doc, y, `${n++}. FINANCIAL SUMMARY`);
    y = boxes(doc, y, [[['Total Sales ($):', money(x.total_sales)], ['Payments Received ($):', money(x.payments_received)]],
                       [['Daily Expenses ($):', money(x.daily_expenses)], ['Payment Methods (Cash / Card / Other):', x.payment_methods]]]);
  }
  y = section(doc, y, `${n++}. DAILY WORK & OPERATIONS`);
  y = ruled(doc, y, 'Completed Work / Deliveries / Customer Meetings', x.completed_work, isProject(x) ? 4 : 2);
  y = ruled(doc, y, 'Pending Orders & Customer Follow-ups', x.pending_followups, isProject(x) ? 3 : 2);
  y = ruled(doc, y, 'Issues / Shortages / Management Attention', x.issues, isProject(x) ? 3 : 2);

  if (y > 640) { doc.addPage(); y = header(doc); }
  y = section(doc, y, `${n++}. REPORT APPROVAL`) + 4;
  field(doc, L, y, W / 2, 'Prepared by:', x.prepared_by, { labelW: 72 }); field(doc, MID, y, W / 2, 'Signature:', x.signature, { labelW: 62, italic: true }); y += 22;
  field(doc, L, y, W / 2, 'Date:', shortDate(x.date), { labelW: 72 });
  doc.font('Helvetica').fontSize(8).fillColor(GRAY).text('Submitted ' + stamp(x.updated_at), MID, y + 3, { width: W / 2, align: 'right' });
  y += 20;
  doc.font('Helvetica-Oblique').fontSize(9).fillColor(BLACK).text('Submit to store management at the end of each business day.', L, y);

  // Contact block bottom-right with a vertical rule
  const cy = 672;
  doc.moveTo(392, cy - 2).lineTo(392, cy + 62).lineWidth(0.8).strokeColor(BLACK).stroke();
  CONTACT.forEach((t, i) => doc.font('Helvetica').fontSize(8.5).fillColor(BLACK).text(t, 400, cy + i * 12.5, { lineBreak: false }));
}

// Photos attached to the report: 2 x 2 per page, each fitted inside its cell
function photoPages(doc, x) {
  const photos = x.photos || [];
  const cellW = (W - 16) / 2, cellH = 270;
  for (let i = 0; i < photos.length; i++) {
    if (i % 4 === 0) {
      doc.addPage();
      let y = header(doc);
      doc.font('Helvetica-Bold').fontSize(11).fillColor(BLACK).text(`PHOTOS — ${shortDate(x.date)} — ${x.name}`, L, y);
      doc.font('Helvetica').fontSize(9).fillColor(GRAY).text(show(x.location), L, y + 15, { width: W, lineBreak: false, ellipsis: true });
    }
    const col = i % 2, row = Math.floor((i % 4) / 2);
    const cx = L + col * (cellW + 16), cy = 168 + row * (cellH + 20);
    doc.rect(cx, cy, cellW, cellH).lineWidth(0.5).strokeColor('#D8DBDF').stroke();
    try { doc.image(photos[i], cx + 6, cy + 6, { fit: [cellW - 12, cellH - 12], align: 'center', valign: 'center' }); }
    catch { doc.font('Helvetica').fontSize(9).fillColor(GRAY).text('Image could not be displayed', cx + 10, cy + cellH / 2); }
    doc.font('Helvetica').fontSize(8).fillColor(GRAY).text(`Photo ${i + 1} of ${photos.length}`, cx, cy + cellH + 4, { width: cellW, align: 'center' });
  }
}

function summaryPage(doc, reports, from, to) {
  let y = header(doc);
  doc.font('Helvetica-Bold').fontSize(14).fillColor(TEAL).text('DAILY REPORTS SUMMARY', L, y);
  doc.font('Helvetica').fontSize(9.5).fillColor(BLACK).text(`Period: ${shortDate(from)} – ${shortDate(to)}  ·  ${reports.length} report(s)`, L, y + 18);
  y += 42;
  const cols = [['Date', 58], ['Employee', 92], ['Location', 132], ['Type', 54], ['Sales', 60], ['Payments', 60], ['Expenses', 56]];
  const row = (vals, bold, fill) => {
    if (y > 720) { doc.addPage(); y = header(doc); }
    if (fill) doc.rect(L, y - 3, W, 17).fill(fill);
    let x = L;
    vals.forEach((v, i) => {
      doc.font(bold ? 'Helvetica-Bold' : 'Helvetica').fontSize(8.5).fillColor(fill === TEAL ? '#FFFFFF' : BLACK)
        .text(show(v), x + 3, y, { width: cols[i][1] - 6, height: 11, lineBreak: false, ellipsis: true, align: i >= 4 ? 'right' : 'left' });
      x += cols[i][1];
    });
    y += 17;
    doc.moveTo(L, y - 3).lineTo(R, y - 3).lineWidth(0.4).strokeColor('#D8DBDF').stroke();
  };
  row(cols.map(c => c[0]), true, TEAL);
  const sum = k => reports.reduce((a, r) => a + (Number(r[k]) || 0), 0);
  reports.forEach(r => row([shortDate(r.date), r.name, r.location_name || r.location, r.location_type,
    isProject(r) ? '' : money(r.total_sales), isProject(r) ? '' : money(r.payments_received), isProject(r) ? '' : money(r.daily_expenses)]));
  row(['TOTALS', '', '', '', money(sum('total_sales')), money(sum('payments_received')), money(sum('daily_expenses'))], true, '#EDE8D6');
}

// Returns a Buffer with the PDF
function buildReportsPdf(reports, from, to) {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ size: 'LETTER', margin: 0, bufferPages: true,
      info: { Title: 'Uniqon Home Center — Daily Report', Author: 'Uniqon Home Center' } });
    const chunks = [];
    doc.on('data', c => chunks.push(c));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);
    const sorted = [...reports].sort((a, b) => a.date < b.date ? -1 : a.date > b.date ? 1 : a.name.localeCompare(b.name));
    sorted.forEach((x, i) => { if (i) doc.addPage(); reportPage(doc, x); photoPages(doc, x); });
    if (sorted.length > 1) { doc.addPage(); summaryPage(doc, sorted, from || sorted[0].date, to || sorted.at(-1).date); }
    if (!sorted.length) { header(doc); doc.font('Helvetica').fontSize(12).text('No reports in this date range.', L, 140); }
    const range = doc.bufferedPageRange();
    for (let i = 0; i < range.count; i++) {
      doc.switchToPage(i);
      doc.font('Helvetica').fontSize(8.5).fillColor(BLACK).text(`Page ${i + 1} of ${range.count}`, L, 752, { width: W, align: 'center', lineBreak: false });
    }
    doc.end();
  });
}

module.exports = { buildReportsPdf };
