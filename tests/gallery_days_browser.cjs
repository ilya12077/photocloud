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
  // Приложение реагирует на смену ширины с debounce 150 мс.
  // Сначала дожидаемся его relayout, затем устанавливаем тестовые столбцы.
  await page.waitForFunction(()=>lastW===window.innerWidth,null,{timeout:5000});
  for(const cols of [2,3,5,8]){
   await page.evaluate(cols=>{Z.cols=cols;relayout(false)},cols);
   const data=await page.evaluate(()=>{
    const rows=L.rows.filter(r=>!r.h);
    const idx=rows.flatMap(r=>r.slots||Array.from({length:r.end-r.start},(_,i)=>r.start+i)).filter(i=>i!==null);
    const gaps=rows.flatMap(r=>r.slots||[]).filter(i=>i===null).length;
    return {idx, gaps, cols:Z.cols, count:st.list.length, labels:rows.flatMap(r=>r.labels||[]).map(x=>[x.start,x.n]),
     rows:rows.map(r=>({n:r.end-r.start,used:r.slots?.length??r.end-r.start,labels:(r.labels||[]).length,band:r.band})),
     overlaps:[...document.querySelectorAll('.dhead')].some(h=>{
      const tile=h.parentElement.querySelector('.tile'),a=h.getBoundingClientRect(),b=tile.getBoundingClientRect();return a.bottom>b.top+.5;
     }), wrong:[...document.querySelectorAll('.tile')].some(t=>
      Math.abs(t.getBoundingClientRect().height-L.tileH)>.5 ||
      Math.abs(t.getBoundingClientRect().width-L.tileH)>.5),
     narrowGaps:[...document.querySelectorAll('.day-spacer')].some(g=>Math.abs(g.getBoundingClientRect().width-L.tileH)>.5),
     mappings:idx.every(i=>{const r=L.rows[rowOfIndex(i)];return !r.h&&r.start<=i&&i<r.end})};
   });
   assert.deepEqual(data.idx,Array.from({length:78},(_,i)=>i));assert.equal(data.labels.length,7);
   assert.equal(data.gaps,0,'no empty tiles between days');
   assert(!data.overlaps);assert(!data.wrong,'photos must stay square');assert(!data.narrowGaps);
   assert.equal(await page.locator('.day-spacer').count(),0,'no blank spacer nodes');
   assert(data.mappings);
   assert.equal(data.cols,cols,`unexpected zoom after viewport resize: ${width}px`);
   assert(data.rows.slice(0,-1).every(r=>r.used===cols),
     `incomplete row at ${width}px/${cols} cols: ${JSON.stringify(data.rows.filter((r,i)=>i<data.rows.length-1&&r.used!==cols))}`);
   // Проверяем реальные стили папки с длинным названием на этом экране.
   const folder=await page.evaluate(()=>{
     const root=document.querySelector('#folders');
     const card=document.createElement('a');card.className='folder';
     const cover=document.createElement('div');cover.className='cover';
     const name=document.createElement('div');name.className='fname';
     name.append(document.createTextNode('Очень длинное название фотоархива за ноябрь 2026 года'));
     const total=document.createElement('small');total.textContent='2 419 файлов';
     name.append(total);card.append(cover,name);root.append(card);
     const rect=name.getBoundingClientRect(),countRect=total.getBoundingClientRect(),style=getComputedStyle(name);
     const ok=style.whiteSpace==='normal'&&style.overflowWrap==='anywhere' &&
       rect.height>parseFloat(style.lineHeight)*2 && countRect.bottom<=rect.bottom+1 &&
       name.scrollWidth<=name.clientWidth+1;
     card.remove();
     return {ok,whiteSpace:style.whiteSpace,wrap:style.overflowWrap,height:rect.height};
   });
   assert(folder.ok,`folder title is clipped at ${width}px: ${JSON.stringify(folder)}`);
   results.push({width,cols,rows:data.rows.length});
  }
 }
 await page.setViewportSize({width:1100,height:850});
 await page.waitForFunction(()=>lastW===window.innerWidth,null,{timeout:5000});await page.evaluate(()=>{Z.cols=5;relayout(false)});
 await page.waitForTimeout(1000);await page.screenshot({path:output+'/desktop.png'});
 await page.evaluate(()=>{selStart()});
 await page.locator('.dhead .mcheck').first().click();
 assert(await page.evaluate(()=>SEL.set.size>0));
 await page.setViewportSize({width:390,height:850});await page.evaluate(()=>{selEnd();Z.cols=3;relayout(false)});
 await page.waitForTimeout(500);await page.screenshot({path:output+'/mobile.png'});
 await page.evaluate(()=>{st.sort='name';relayout(false)});assert.equal(await page.locator('.dhead').count(),0);
 await page.locator('#up-button').click();
 await page.waitForFunction(()=>UP.available);
 assert.equal(await page.locator('#up-folder').evaluate(e=>e.tagName),'SELECT');
 await page.selectOption('#up-folder','');
 page.once('dialog',d=>d.accept('Phone uploads'));
 await page.locator('#up-new-folder').click();
 assert.equal(await page.locator('#up-folder').inputValue(),'Phone uploads');
 await page.locator('#up-refresh').click();
 await page.waitForFunction(()=>UP.available);
 assert.equal(await page.locator('#up-folder').inputValue(),'Phone uploads');
 await page.selectOption('#up-folder','');
 assert.equal(await page.locator('#up-folder').inputValue(),'');
 const batch = Array.from({length:16},(_,i)=>({name:'queue-'+i+'.jpg',mimeType:'image/jpeg',buffer:Buffer.from('photo '+i)}));
 await page.locator('#up-files').setInputFiles(batch);
 assert.equal(await page.evaluate(()=>UP.files.length),16);
 await page.locator('#up-files').setInputFiles({name:'extra.jpg',mimeType:'image/jpeg',buffer:Buffer.from('extra')});
 assert.equal(await page.evaluate(()=>UP.files.length),17);
 await page.evaluate(()=>upPrepare([UP.files[0]]));
 assert.equal(await page.evaluate(()=>UP.files.length),17);
 await page.locator('#up-files').setInputFiles([]);
 assert.equal(await page.evaluate(()=>UP.files.length),17);
 assert.equal(await page.locator('#up-submit').textContent(),'Загрузить 17');
 await page.screenshot({path:output+'/mobile-upload.png'});
 assert.equal(errors.length,0,errors.join('\n'));console.log(JSON.stringify(results));await browser.close();
})().catch(e=>{console.error(e);process.exit(1)});
