"""A small pure-Python BIP-340 and base85, written to check the page against an
implementation that shares no code with it (and with BIP-340's own test vector).
Not for production: not constant time."""
import hashlib, json, calendar, time, sys
P=2**256-2**32-977; N=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G=(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
def add(a,b):
    if a is None: return b
    if b is None: return a
    if a[0]==b[0] and (a[1]+b[1])%P==0: return None
    l=(3*a[0]*a[0]*pow(2*a[1],-1,P) if a==b else (b[1]-a[1])*pow(b[0]-a[0],-1,P))%P
    x=(l*l-a[0]-b[0])%P; return (x,(l*(a[0]-x)-a[1])%P)
def mul(k,p=G):
    r=None
    while k:
        if k&1: r=add(r,p)
        p=add(p,p); k>>=1
    return r
def th(tag,m):
    t=hashlib.sha256(tag.encode()).digest(); return hashlib.sha256(t+t+m).digest()
def sign(msg32,d,aux=b'\0'*32):
    Pt=mul(d)
    if Pt[1]%2: d=N-d
    px=Pt[0].to_bytes(32,'big')
    t=(d^int.from_bytes(th('BIP0340/aux',aux),'big')).to_bytes(32,'big')
    k=int.from_bytes(th('BIP0340/nonce',t+px+msg32),'big')%N
    R=mul(k)
    if R[1]%2: k=N-k
    rx=R[0].to_bytes(32,'big')
    e=int.from_bytes(th('BIP0340/challenge',rx+px+msg32),'big')%N
    return rx+((k+e*d)%N).to_bytes(32,'big'), px
def lift(x):
    y2=(pow(x,3,P)+7)%P; y=pow(y2,(P+1)//4,P)
    return (x,y if y%2==0 else P-y)
def verify(msg32,sig,px):
    r=int.from_bytes(sig[:32],'big'); s=int.from_bytes(sig[32:],'big')
    if r>=P or s>=N: return False
    Pt=lift(int.from_bytes(px,'big'))
    e=int.from_bytes(th('BIP0340/challenge',sig[:32]+px+msg32),'big')%N
    R=add(mul(s),mul((N-e)%N,Pt))
    return R is not None and R[1]%2==0 and R[0]==r
B85='0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-+=^!/*?&<>()[]%$#@,;_'
def b85(b):
    o=''
    for i in range(0,len(b),4):
        v=int.from_bytes(b[i:i+4],'big'); s=''
        for _ in range(5): s=B85[v%85]+s; v//=85
        o+=s
    return o
KIND=24767
def example():
    canon='t:message f:X1QZ3N d:LISBOA ts:2026-08-08_14:26:40 m:net starts in ten minutes'
    m=hashlib.sha256(canon.encode()).digest()
    created=calendar.timegm(time.strptime('2026-08-08_14:26:40','%Y-%m-%d_%H:%M:%S'))
    px=mul(7)[0].to_bytes(32,'big')
    ev=json.dumps([0,px.hex(),created,KIND,[],m.hex()],separators=(',',':'))
    eid=hashlib.sha256(ev.encode()).digest()
    sig,_=sign(eid,7)
    assert verify(eid,sig,px)
    return canon,m,px,ev,eid,sig
if __name__=='__main__':
    canon,m,px,ev,eid,sig=example()
    print('event',ev); print('id',eid.hex()); print('sig',sig.hex()); s=b85(sig); print(len(s),s)
    w='t:message f:X1QZ3N d:LISBOA ts:2026-08-08_14:26:40 sig:%s m:net starts in ten minutes'%s
    print(len(w)); print(w)
