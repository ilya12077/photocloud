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
    const rows=L.rows.filter(r=>!r.h),idx=rows.flatMap(r=>Array.from({length:r.end-r.start},(_,i)=>r.start+i));
    return {idx, count:st.list.length, labels:rows.flatMap(r=>r.labels||[]).map(x=>[x.start,x.n]),
     rows:rows.map(r=>({n:r.end-r.start,labels:(r.labels||[]).length,band:r.band})),
     overlaps:[...document.querySelectorAll('.dhead')].some(h=>{
      const tile=h.parentElement.querySelector('.tile'),a=h.getBoundingClientRect(),b=tile.getBoundingClientRect();return a.bottom>b.top+.5;
     }), wrong:[...document.querySelectorAll('.tile')].some(t=>Math.abs(t.getBoundingClientRect().height-L.tileH)>.5),
     mappings:idx.every(i=>{const r=L.rows[rowOfIndex(i)];return !r.h&&r.start<=i&&i<r.end})};
   });
   assert.deepEqual(data.idx,Array.from({length:78},(_,i)=>i));assert.equal(data.labels.length,7);
   assert(!data.overlaps);assert(!data.wrong);assert(data.mappings);
   assert(data.rows.slice(0,-1).every(r=>r.n===cols));
   results.push({width,cols,rows:data.rows.length});
  }
 }
 await page.setViewportSize({width:1100,height:850});await page.evaluate(()=>{Z.cols=5;relayout(false)});
 await page.waitForTimeout(1000);await page.screenshot({path:output+'/desktop.png'});
 await page.evaluate(()=>{selStart()});
 await page.locator('.dhead .mcheck').first().click();
 assert(await page.evaluate(()=>SEL.set.size>0));
 await page.setViewportSize({width:390,height:850});await page.evaluate(()=>{selEnd();Z.cols=3;relayout(false)});
 await page.waitForTimeout(500);await page.screenshot({path:output+'/mobile.png'});
 await page.evaluate(()=>{st.sort='name';relayout(false)});assert.equal(await page.locator('.dhead').count(),0);
 assert.equal(errors.length,0,errors.join('\n'));console.log(JSON.stringify(results));await browser.close();
})().catch(e=>{console.error(e);process.exit(1)});
