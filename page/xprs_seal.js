// Sealed bodies for the web chat (XPRS.md 6.2): AES-256-CBC with PKCS#7
// padding under the X coordinate of (our scalar x their public point), the
// vector first, base64url without padding. Pure JS because a page served over
// plain HTTP has no WebCrypto.subtle. Uses the curve helpers of xprs_crypto.js
// (P, powmod, jmul, jaff, b2n, n2b, cat), which come before it in the build.

// ---- AES-256 (FIPS 197), one block at a time ----
var AES_SBOX=null,AES_INV=null,AES_RCON=[1,2,4,8,16,32,64,128,27,54];
function aesTables(){
  if(AES_SBOX)return;
  AES_SBOX=new Uint8Array(256);AES_INV=new Uint8Array(256);
  var p=1,q=1,x;
  do{
    p=p^((p<<1)&255)^(p&128?27:0);               /* p *= 3 */
    q^=q<<1;q^=q<<2;q^=q<<4;q&=255;if(q&128)q^=9; /* q /= 3 */
    x=q^((q<<1|q>>7)&255)^((q<<2|q>>6)&255)^((q<<3|q>>5)&255)^((q<<4|q>>4)&255);
    AES_SBOX[p]=(x^99)&255;AES_INV[(x^99)&255]=p;
  }while(p!==1);
  AES_SBOX[0]=99;AES_INV[99]=0;
}
function xt(a){return((a<<1)^(a&128?27:0))&255;}
function gmul(a,b){var r=0;while(b){if(b&1)r^=a;a=xt(a);b>>=1;}return r;}
function aesExpand(key){
  aesTables();
  var w=new Uint8Array(240),i,t0,t1,t2,t3,k;
  w.set(key);
  for(i=8;i<60;i++){
    t0=w[4*i-4];t1=w[4*i-3];t2=w[4*i-2];t3=w[4*i-1];
    if(i%8===0){k=t0;t0=AES_SBOX[t1]^AES_RCON[i/8-1];t1=AES_SBOX[t2];t2=AES_SBOX[t3];t3=AES_SBOX[k];}
    else if(i%8===4){t0=AES_SBOX[t0];t1=AES_SBOX[t1];t2=AES_SBOX[t2];t3=AES_SBOX[t3];}
    w[4*i]=w[4*i-32]^t0;w[4*i+1]=w[4*i-31]^t1;w[4*i+2]=w[4*i-30]^t2;w[4*i+3]=w[4*i-29]^t3;
  }
  return w;
}
function aesBlock(w,s,enc){
  var r,i,a,b,c,d,t=new Uint8Array(16);
  function addKey(round){for(var j=0;j<16;j++)s[j]^=w[round*16+j];}
  if(enc){
    addKey(0);
    for(r=1;r<=14;r++){
      for(i=0;i<16;i++)s[i]=AES_SBOX[s[i]];
      /* ShiftRows */
      t.set(s);
      s[1]=t[5];s[5]=t[9];s[9]=t[13];s[13]=t[1];
      s[2]=t[10];s[6]=t[14];s[10]=t[2];s[14]=t[6];
      s[3]=t[15];s[7]=t[3];s[11]=t[7];s[15]=t[11];
      if(r<14)for(i=0;i<16;i+=4){
        a=s[i];b=s[i+1];c=s[i+2];d=s[i+3];
        s[i]=xt(a)^xt(b)^b^c^d;s[i+1]=a^xt(b)^xt(c)^c^d;
        s[i+2]=a^b^xt(c)^xt(d)^d;s[i+3]=xt(a)^a^b^c^xt(d);
      }
      addKey(r);
    }
  }else{
    addKey(14);
    for(r=13;r>=0;r--){
      /* InvShiftRows */
      t.set(s);
      s[1]=t[13];s[5]=t[1];s[9]=t[5];s[13]=t[9];
      s[2]=t[10];s[6]=t[14];s[10]=t[2];s[14]=t[6];
      s[3]=t[7];s[7]=t[11];s[11]=t[15];s[15]=t[3];
      for(i=0;i<16;i++)s[i]=AES_INV[s[i]];
      addKey(r);
      if(r>0)for(i=0;i<16;i+=4){
        a=s[i];b=s[i+1];c=s[i+2];d=s[i+3];
        s[i]=gmul(a,14)^gmul(b,11)^gmul(c,13)^gmul(d,9);
        s[i+1]=gmul(a,9)^gmul(b,14)^gmul(c,11)^gmul(d,13);
        s[i+2]=gmul(a,13)^gmul(b,9)^gmul(c,14)^gmul(d,11);
        s[i+3]=gmul(a,11)^gmul(b,13)^gmul(c,9)^gmul(d,14);
      }
    }
  }
  return s;
}
function cbcEncrypt(key,iv,data){
  var w=aesExpand(key),pad=16-data.length%16,n=data.length+pad,out=new Uint8Array(n),
      prev=iv,blk,i,j;
  for(i=0;i<n;i+=16){
    blk=new Uint8Array(16);
    for(j=0;j<16;j++)blk[j]=(i+j<data.length?data[i+j]:pad)^prev[j];
    aesBlock(w,blk,true);out.set(blk,i);prev=blk;
  }
  return out;
}
function cbcDecrypt(key,iv,data){
  if(data.length===0||data.length%16!==0)return null;
  var w=aesExpand(key),out=new Uint8Array(data.length),prev=iv,blk,i,j;
  for(i=0;i<data.length;i+=16){
    blk=data.slice(i,i+16);
    aesBlock(w,blk,false);
    for(j=0;j<16;j++)out[i+j]=blk[j]^prev[j];
    prev=data.slice(i,i+16);
  }
  var pad=out[out.length-1];
  if(pad<1||pad>16||pad>out.length)return null;
  for(i=out.length-pad;i<out.length;i++)if(out[i]!==pad)return null;
  return out.slice(0,out.length-pad);
}

// ---- ECDH: the X coordinate of d x P, where P is the x-only public key lifted
// to the point with an even y (the parity does not change the X of the product).
function ecdhX(privBytes,pubX){
  var x=b2n(pubX);
  if(x<=0n||x>=P)return null;
  var y2=(powmod(x,3n,P)+7n)%P,y=powmod(y2,(P+1n)/4n,P);
  if(y*y%P!==y2)return null;
  var r=jaff(jmul(b2n(privBytes),x,y));
  return r?n2b(r[0],32):null;
}

// ---- base64url without padding, and UTF-8 ----
var B64U='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
function b64uEnc(b){var s='',i,n;
  for(i=0;i<b.length;i+=3){
    n=(b[i]<<16)|((i+1<b.length?b[i+1]:0)<<8)|(i+2<b.length?b[i+2]:0);
    s+=B64U[n>>18&63]+B64U[n>>12&63];
    if(i+1<b.length)s+=B64U[n>>6&63];
    if(i+2<b.length)s+=B64U[n&63];
  }
  return s;}
function b64uDec(s){
  var out=[],acc=0,bits=0,i,v;
  for(i=0;i<s.length;i++){
    v=B64U.indexOf(s[i]);if(v<0)return null;
    acc=(acc<<6)|v;bits+=6;
    if(bits>=8){bits-=8;out.push((acc>>bits)&255);}
  }
  return new Uint8Array(out);}
function utf8Enc(s){
  if(typeof TextEncoder!=='undefined')return new TextEncoder().encode(s);
  var u=unescape(encodeURIComponent(s)),b=new Uint8Array(u.length);
  for(var i=0;i<u.length;i++)b[i]=u.charCodeAt(i);return b;}
function utf8Dec(b){
  if(typeof TextDecoder!=='undefined')return new TextDecoder('utf-8').decode(b);
  var s='';for(var i=0;i<b.length;i++)s+=String.fromCharCode(b[i]);
  try{return decodeURIComponent(escape(s));}catch(e){return s;}}

// ---- the seal itself ----
/* `x:` value for [text], from our private key to the peer's x-only public key.
 * [iv] is for the tests; the page lets it be random. */
function sealBody(privBytes,peerX,text,iv){
  var key=ecdhX(privBytes,peerX);
  if(!key)return null;
  if(!iv){iv=new Uint8Array(16);
    if(window.crypto&&crypto.getRandomValues)crypto.getRandomValues(iv);
    else for(var i=0;i<16;i++)iv[i]=Math.floor(Math.random()*256);}
  return b64uEnc(cat(iv,cbcEncrypt(key,iv,utf8Enc(text))));
}
/* The text of an `x:` value from the peer, or null when it does not open. */
function openBody(privBytes,peerX,x){
  var key=ecdhX(privBytes,peerX),blob=b64uDec(x);
  if(!key||!blob||blob.length<32)return null;
  var pt=cbcDecrypt(key,blob.slice(0,16),blob.slice(16));
  return pt?utf8Dec(pt):null;
}
