from __future__ import print_function
import collections
import random

def mulInv(n, q):  
    return extEuclid(n, q)[0] % q

def extEuclid(a, b):
    s0, s1, t0, t1 = 1, 0, 0, 1
    while b > 0:
        q, r = divmod(a, b)
        a, b = b, r
        s0, s1, t0, t1 = s1, s0 - q * s1, t1, t0 - q * t1
        pass
    return s0, t0, a

def sqrRoot(n, q):
    r = pow(n,(q+1)/4,q)
    return r, q - r

Point = collections.namedtuple("Point", ["x", "y"])

class EC(object):
    def __init__(self, a, b, q):
        assert 0 < a and a < q and 0 < b and b < q and q > 2
        assert (4 * (a ** 3) + 27 * (b ** 2))  % q != 0
        self.a = a
        self.b = b
        self.q = q
        self.zero = Point(0, 0)
        pass

    def isOn(self, p):
        if p == self.zero: return True
        l = (p.y ** 2) % self.q
        r = ((p.x ** 3) + self.a * p.x + self.b) % self.q
        return l == r

    def findY(self, x):
        y2 = (x ** 3 + self.a * x + self.b) % self.q
        y, my = sqrRoot(y2, self.q)
        return y2 == y*y%self.q, y

    def negation(self, p):
        return Point(p.x, -p.y % self.q)

    def addition(self, p1, p2):
        if p1 == self.zero: return p2
        if p2 == self.zero: return p1
        if p1.x == p2.x and (p1.y != p2.y or p1.y == 0):
            return self.zero
        if p1.x == p2.x:
            l = (3 * p1.x * p1.x + self.a) * mulInv(2 * p1.y, self.q) % self.q
            pass
        else:
            l = (p2.y - p1.y) * mulInv(p2.x - p1.x, self.q) % self.q
            pass
        x = (l * l - p1.x - p2.x) % self.q
        y = (l * (p1.x - x) - p1.y) % self.q
        return Point(x, y)

    def smul(self, p, n):
        r = self.zero
        m2 = p
        while 0 < n:
            if n & 1 == 1:
                r = self.addition(r, m2)
                pass
            n, m2 = n >> 1, self.addition(m2, m2)
            pass
        return r

    def random(self, xin):
        while True:
            if xin == 0 :
                x = random.randint(1,self.q)
            else :
                x = xin
            y2 = (x ** 3 + self.a * x + self.b) % self.q
            if pow(y2,(self.q-1)/2,self.q) != 1 :
                continue
            y, my = sqrRoot(y2, self.q)
            return Point(x, y)


class STREAM():
    def __init__(self, ec, seed, P, Q):
        self.ec = ec
        self.seed = seed
        self.P = P
        self.Q = Q

    def genStream(self):
        t = self.seed
        s = (self.ec.smul(self.P,t)).x
        self.seed = s
        #print("s*Q.x",hex(self.ec.smul(self.Q,s).x))
        r = (self.ec.smul(self.Q,s)).x
        return r & (2**(8 * 30) - 1)  # return 30 bytes

    def encryption(self, pt):
        loop = (len(pt)+29)/30
        ct = bytearray('')
        for i in range(0,loop):
            r = self.genStream()
            #print("r=",hex(r))
            blkLen = len(pt[30*i:30*(i+1)])
            for j in range(1,blkLen+1):
                ct += chr(((r>>((30-j)*8))&0xff)^pt[30*i+j-1])
        return ct

    def decryption(self, pt):
        return self.encryption(pt)

class KeyPair():
    def __init__(self, ec, G, n) -> None:
        self.prk = random.randint(1, n-1)  
        self.puk = ec.smul(G, self.prk)

if __name__ == "__main__":
    # Create Domain Parameter
    prime = 112817876910624391112586233842848268584935393852332056135638763933471640076719  # 256 bit
    A = 49606376303929463253586154769489869489108883753251757521607397128446713725753
    B = 79746959374671415610195463996521688925529471350164217787900499181173830926217
    ec = EC(A, B, prime)
    P = Point(103039657693294116462834651854367833897272806854412839639851017006923575559024,
              77619251402197618012332577948300478225863306465872072566919796455982120391100)
    n = prime   # order of P(??)
    # inf = ec.addition(P, ec.negation(P))
    # n = 1 
    # while(True):
    #     tmp = ec.smul(P, n)
    #     if tmp == inf:
    #         break
    #     n += 1

    print("prime = ", prime)
    print("A = ", A)
    print("B = ", B)
    print("G = ", P)     # generator 
    # print("n = ", n)

    # Generate key
    alice = KeyPair(ec, P, n)
    print("alicePuk = ", alice.puk)
    print("alicePrk = ", alice.prk)
    bob = KeyPair(ec, P, n)
    print("bobPuk = ", bob.puk)
    print("bobPrk = ", bob.prk)

    # Derive key
    print("SS1 = ", ec.smul(bob.puk, alice.prk))    # calculated by alice
    print("SS2 = ", ec.smul(alice.puk, bob.prk))    # calculated by bob 
    
    