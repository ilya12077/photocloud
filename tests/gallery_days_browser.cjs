const { chromium } = require('playwright');
const assert=require('node:assert/strict');
(async()=>{
 const base=process.env.GALLERY_TEST_URL || 'http://127.0.0.1:19872';
 const output=process.env.GALLERY_SCREENSHOTS || '/tmp/photo-days-fixture';
 require('node:fs').mkdirSync(output,{recursive:true});
 const browser=await chromium.launch({headless:true,args:['--no-sandbox']});
 const page=await browser.newPage({viewport:{width:1100,height:850},colorScheme:'dark'});
 const errors=[];page.on('pageerror',e=>errors.push(String(e)));
 await page.goto(base);
 const login=await page.request.post(base+'/api/login',{headers:{'x-requested-with':'photocloud'},data:{u:'tester',p:'Local-gallery-123456'}});
 assert.equal(login.status(),200,await login.text());
 await page.reload();
 await page.waitForFunction(()=>st.list.length===78,null,{timeout:20000});
 const results=[];
 for(const width of [390,768,1100]){
  await page.setViewportSize({width,height:850});
  for(const cols of [2,3,5,8]){
   await page.evaluate(cols=>{Z.cols=cols;relayout(false)},cols);
   const data=await page.evaluate(()=>{
    const rows=L.rows.filter(r=>!r.h);
    const idx=rows.flatMap(r=>r.slots||Array.from({length:r.end-r.start},(_,i)=>r.start+i)).filter(i=>typeof i==='number');
    const dates=rows.flatMap(r=>r.slots||[]).filter(i=>typeof i==='object');
    return {idx, dates:dates.map(d=>[d.start,d.n]), count:st.list.length,
     rows:rows.map(r=>({n:r.end-r.start,used:r.slots?.length??r.end-r.start,band:r.band||0})),
     wrongTiles:[...document.querySelectorAll('.tile')].map(t=>({i:t.dataset.i,
       w:t.getBoundingClientRect().width,h:t.getBoundingClientRect().height,
       expected:L.tileH})).filter(t=>Math.abs(t.w-t.expected)>.5||Math.abs(t.h-t.expected)>.5).slice(0,5),
     narrowDates:[...document.querySelectorAll('.day-spacer')].some(g=>Math.abs(g.getBoundingClientRect().width-L.tileH)>.5),
     datesWithLabels:[...document.querySelectorAll('.day-spacer')].every(g=>{
       const label=g.querySelector('.day-spacer-text'), lines=[...g.querySelectorAll('.day-spacer-line')];
       const style=getComputedStyle(label);
       const first=lines[0],second=lines[1];
       return lines.length===2 && /^\\d{1,2} [А-Яа-яЁё]+$/.test(first.textContent) &&
         /^[А-ЯЁ][а-яё]+$/.test(second.textContent) &&
         style.textAlign==='right' && style.justifyContent==='center' &&
         lines.every(s=>s.scrollWidth<=s.clientWidth+1) &&
         (second.getBoundingClientRect().top-first.getBoundingClientRect().bottom)<Math.max(4,parseFloat(style.fontSize)*.2);
     }),
     lingeringBands:document.querySelectorAll('.dhead').length,
     mappings:idx.every(i=>{const r=L.rows[rowOfIndex(i)];return !r.h&&r.start<=i&&i<r.end})};
   });
   assert.deepEqual(data.idx,Array.from({length:78},(_,i)=>i));
   assert.equal(data.dates.length,7,'every day has a label, including the first');
   assert(!data.lingeringBands,'no extra date rows');
   assert(data.rows.every(r=>!r.band),'no date-band height');
   assert.equal(data.wrongTiles.length,0,`photos must stay square at ${width}px/${cols} cols: ${JSON.stringify(data.wrongTiles)}`);assert(!data.narrowDates);
   assert(data.datesWithLabels,`two aligned, unclipped date lines at ${width}px/${cols} columns`);assert(data.mappings);
   assert(data.rows.slice(0,-1).every(r=>r.used===cols));
   results.push({width,cols,rows:data.rows.length});
  }
 }
 await page.setViewportSize({width:1100,height:850});await page.evaluate(()=>{Z.cols=5;relayout(false)});
 await page.waitForTimeout(1000);await page.screenshot({path:output+'/desktop.png'});
 await page.evaluate(()=>{selStart()});
 await page.locator('.day-spacer .mcheck').first().click();
 assert(await page.evaluate(()=>SEL.set.size>0));
 await page.setViewportSize({width:390,height:850});await page.evaluate(()=>{selEnd();Z.cols=3;relayout(false)});
 await page.waitForTimeout(500);await page.screenshot({path:output+'/mobile.png'});
 await page.evaluate(()=>{st.sort='name';relayout(false)});assert.equal(await page.locator('.day-spacer').count(),0);
 assert.equal(errors.length,0,errors.join('\n'));console.log(JSON.stringify(results));await browser.close();
})().catch(e=>{console.error(e);process.exit(1)});
