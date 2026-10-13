const {test}=require('node:test')
const assert=require('node:assert/strict')
const fs=require('node:fs')
const path=require('node:path')
const crypto=require('node:crypto')
const {execFileSync}=require('node:child_process')
const root=path.resolve(__dirname,'../../..')
test('profile manifest hashes exact candidate Git blobs, not CRLF checkout bytes',()=>{
  const manifest=JSON.parse(fs.readFileSync(path.join(root,'src/STATIC_proxy/profiles/manifest.json')))
  for(const entry of manifest.profiles){
    const bytes=fs.readFileSync(path.join(root,entry.path))
    assert.ok(!bytes.includes(13),`${entry.path}: LF required`)
    assert.equal(crypto.createHash('sha256').update(bytes).digest('hex'),entry.sha256,entry.path)
    const gitId=execFileSync('git',['hash-object','--path',entry.path,'--stdin'],{cwd:root,input:bytes}).toString().trim()
    const rawId=crypto.createHash('sha1').update(Buffer.from(`blob ${bytes.length}\0`)).update(bytes).digest('hex')
    assert.equal(gitId,rawId,`${entry.path}: Git clean filters change published bytes`)
  }
})
