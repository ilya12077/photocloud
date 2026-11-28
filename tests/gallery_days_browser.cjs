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
 // Network failure before duplicate checking must preserve the entire selection.
 await page.route('**/api/upload/check', route=>route.abort('failed'));
 await page.locator('#up-submit').click();
 await page.waitForFunction(()=>!UP.busy && !$('up-result').hidden);
 assert.equal(await page.evaluate(()=>UP.files.length),17);
 assert(await page.locator('#up-submit').isDisabled());
 assert(await page.locator('#up-result-retry').isEnabled());
 await page.evaluate(()=>upLoadFolders());
 assert(await page.locator('#up-submit').isDisabled());
 await page.unroute('**/api/upload/check');
 // One failed file, sixteen successful real HTTP uploads.
 const starts=[];
 await page.route('**/api/upload/start', route=>{
   const name=route.request().postDataJSON().name; starts.push(name);
   return name==='queue-0.jpg' ? route.abort('failed') : route.continue();
 });
 await page.locator('#up-result-retry').click();
 await page.waitForFunction(()=>!UP.busy && UP.done===16 && !$('up-result').hidden,null,{timeout:60000});
 assert.equal(await page.evaluate(()=>UP.done),16);
 assert.deepEqual(await page.evaluate(()=>UP.files.map(f=>f.name)),['queue-0.jpg']);
 assert.equal(await page.locator('#up-submit').textContent(),'Загрузить 1');
 assert(await page.locator('#up-submit').isDisabled());
 assert.equal(starts.length,17);
 await page.unroute('**/api/upload/start');
 const retried=[];
 await page.route('**/api/upload/start', route=>{
   retried.push(route.request().postDataJSON().name); return route.continue();
 });
 await page.locator('#up-result-retry').click();
 await page.waitForFunction(()=>!UP.busy && UP.files.length===0 && !$('up-result').hidden,null,{timeout:30000});
 assert.deepEqual(retried,['queue-0.jpg']);
 assert.equal(await page.evaluate(()=>UP.files.length),0);
 assert(await page.locator('#up-result-retry').isHidden());
 await page.unroute('**/api/upload/start');
 const pending=await (await page.request.get(base+'/api/upload/list')).json();
 assert.equal(pending.items.filter(x=>x.name.startsWith('queue-')||x.name==='extra.jpg').length,17);
 await page.waitForFunction(()=>st.list.filter(p=>isPendingId(p[0])).length===17,null,{timeout:20000});
 assert.equal(await page.locator('#up-feed').count(),0);
 assert.equal(await page.evaluate(()=>st.list.length),95);
 assert(await page.evaluate(()=>st.list.filter(p=>isPendingId(p[0])).every(p=>imgUrl('s',p).includes('/api/upload/') && origUrl(p,true).endsWith('/media'))));
 // Тот же файл после индексации не дублируется; целевая вложенная папка создаётся в общей ленте.
 assert(await page.evaluate(()=>{
   const row = ['abcdefgh',0,'IMG_20261121_123456.jpg',1,1,1,0];
   const base = {folders:[''],photos:[row]};
   const duplicate = {id:'duplicate',name:row[2],folder:'',mtime:1,size:1024};
   const nested = {id:'nested',name:'IMG_20261122_123456.jpg',folder:'Новая/Подпапка',mtime:2,size:1024};
   const merged=mergePending(base,[duplicate,nested]);
   return merged.photos.length===2 && merged.photos[0][0]==='upload:nested' &&
      merged.folders[merged.photos[0][1]]==='Новая/Подпапка' && merged.folders.includes('Новая') &&
      (merged.photos[0][6]&F_NAME)!==0 && base.folders.length===1;
 }));
 // The same file can be selected again after completion; duplicate checking stays active.
 await page.locator('#up-files').setInputFiles(batch[0]);
 assert.equal(await page.evaluate(()=>UP.files.length),1);
 await page.locator('#up-submit').click();
 await page.waitForFunction(()=>!UP.busy && !$('up-result').hidden);
 assert.equal(await page.evaluate(()=>UP.files.length),0);
 assert.match(await page.locator('#up-result-summary').textContent(),/Пропущено: 1/);
 // Cancellation while checking must keep the files for another attempt.
 await page.locator('#up-files').setInputFiles({name:'cancel-retry.jpg',mimeType:'image/jpeg',buffer:Buffer.from('cancel')});
 let releaseCheck;
 const checkReached=new Promise(resolve=>{releaseCheck=resolve});
 let heldRoute;
 await page.route('**/api/upload/check',route=>{heldRoute=route;releaseCheck()});
 await page.locator('#up-submit').click();
 await checkReached;
 await page.locator('#up-cancel').click();
 await heldRoute.abort('aborted');
 await page.waitForFunction(()=>!UP.busy && !$('up-result').hidden);
 assert.deepEqual(await page.evaluate(()=>UP.files.map(f=>f.name)),['cancel-retry.jpg']);
 assert(await page.locator('#up-submit').isDisabled());
 assert(await page.locator('#up-result-retry').isEnabled());
 await page.unroute('**/api/upload/check');
 await page.locator('#up-result-retry').click();
 await page.waitForFunction(()=>!UP.busy && UP.files.length===0 && !$('up-result').hidden);
 assert.equal(await page.evaluate(()=>UP.done),1);
 assert.equal(await page.evaluate(()=>UP.files.length),0);
 // A real MP4 with its moov atom beyond the old 4 MiB limit.
 const fs=require('node:fs'), cp=require('node:child_process'), path=require('node:path');
 const ffmpeg=cp.execFileSync('python',['-c','from app.video import find_ffmpeg; print(find_ffmpeg(""))'],{encoding:'utf8'}).trim();
 const videoPath=path.join(output,'pending-fixture.mp4');
 cp.execFileSync(ffmpeg,['-hide_banner','-loglevel','error','-y','-f','lavfi','-i','color=c=red:s=160x120:r=10:d=2','-c:v','mpeg4',videoPath]);
 const raw=fs.readFileSync(videoPath);
 let moov=-1;
 for(let pos=0;pos+8<=raw.length;){
   const size=raw.readUInt32BE(pos);
   if(raw.toString('ascii',pos+4,pos+8)==='moov'){moov=pos;break}
   assert(size>=8);pos+=size;
 }
 assert(moov>0);
 const free=Buffer.alloc(5*1024*1024);free.writeUInt32BE(free.length,0);free.write('free',4);
 const clip=Buffer.concat([raw.subarray(0,moov),free,raw.subarray(moov)]);
 const csrf={'x-requested-with':'photocloud'};
 const started=await page.request.post(base+'/api/upload/start',{headers:csrf,data:{name:'pending-fixture.mp4',folder:'',size:clip.length,mtime:1700000000}});
 assert.equal(started.status(),200,await started.text());
 const uploadId=(await started.json()).id;
 for(let off=0;off<clip.length;off+=2*1024*1024){
   const chunk=await page.request.post(base+'/api/upload/'+uploadId+'/chunk',{headers:{...csrf,'x-upload-offset':String(off),'content-type':'application/octet-stream'},data:clip.subarray(off,off+2*1024*1024)});
   assert.equal(chunk.status(),200,await chunk.text());
 }
 const finished=await page.request.post(base+'/api/upload/'+uploadId+'/finish',{headers:csrf,data:{}});
 assert.equal(finished.status(),200,await finished.text());
 const media=await page.request.get(base+'/api/upload/'+uploadId+'/media',{headers:{range:'bytes='+ (clip.length-16) +'-'}});
 assert.equal(media.status(),206);
 assert.deepEqual(await media.body(),clip.subarray(-16));
 const thumbUrl=base+'/api/upload/'+uploadId+'/thumb';
 const thumb=await page.request.get(thumbUrl,{timeout:120000});
 assert.equal(thumb.status(),200);
 const image=await thumb.body();
 assert.equal(image.toString('ascii',8,12),'WEBP');
 const again=await page.request.get(thumbUrl);
 assert.deepEqual(await again.body(),image);
 fs.unlinkSync(videoPath);
 await page.screenshot({path:output+'/mobile-upload.png'});
 assert.equal(errors.length,0,errors.join('\n'));console.log(JSON.stringify(results));await browser.close();
})().catch(e=>{console.error(e);process.exit(1)});
