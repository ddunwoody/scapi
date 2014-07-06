rm *.exe
rm miracl.a
cp mirdef.h64 mirdef.h222
gcc -c -m64 -O2 mrcore.c
gcc -c -m64 -O2 mrarth0.c
gcc -c -m64 -O2 mrarth1.c
gcc -c -m64 -O2 mrarth2.c
gcc -c -m64 -O2 mralloc.c
gcc -c -m64 -O2 mrsmall.c
gcc -c -m64 -O2 mrio1.c
gcc -c -m64 -O2 mrio2.c
gcc -c -m64 -O2 mrgcd.c
gcc -c -m64 -O2 mrjack.c
gcc -c -m64 -O2 mrxgcd.c
gcc -c -m64 -O2 mrarth3.c
gcc -c -m64 -O2 mrbits.c
gcc -c -m64 -O2 mrrand.c
gcc -c -m64 -O2 mrprime.c
gcc -c -m64 -O2 mrcrt.c
gcc -c -m64 -O2 mrscrt.c
gcc -c -m64 -O2 mrmonty.c
gcc -c -m64 -O2 mrpower.c
gcc -c -m64 -O2 mrsroot.c
gcc -c -m64 -O2 mrcurve.c
gcc -c -m64 -O2 mrfast.c
gcc -c -m64 -O2 mrshs.c
gcc -c -m64 -O2 mrshs256.c
gcc -c -m64 -O2 mrshs512.c
gcc -c -m64 -O2 mrsha3.c
gcc -c -m64 -O2 mrfpe.c
gcc -c -m64 -O2 mraes.c
gcc -c -m64 -O2 mrgcm.c
gcc -c -m64 -O2 mrlucas.c
gcc -c -m64 -O2 mrzzn2.c
gcc -c -m64 -O2 mrzzn2b.c
gcc -c -m64 -O2 mrzzn3.c
gcc -c -m64 -O2 mrzzn4.c
gcc -c -m64 -O2 mrecn2.c
gcc -c -m64 -O2 mrstrong.c
gcc -c -m64 -O2 mrbrick.c
gcc -c -m64 -O2 mrebrick.c
gcc -c -m64 -O2 mrec2m.c
gcc -c -m64 -O2 mrgf2m.c
gcc -c -m64 -O2 mrflash.c
gcc -c -m64 -O2 mrfrnd.c
gcc -c -m64 -O2 mrdouble.c
gcc -c -m64 -O2 mrround.c
gcc -c -m64 -O2 mrbuild.c
gcc -c -m64 -O2 mrflsh1.c
gcc -c -m64 -O2 mrpi.c
gcc -c -m64 -O2 mrflsh2.c
gcc -c -m64 -O2 mrflsh3.c
gcc -c -m64 -O2 mrflsh4.c
cp mrmuldv.g64 mrmuldv.c
gcc -c -m64 -O2 mrmuldv.c
ar rc miracl.a mrcore.o mrarth0.o mrarth1.o mrarth2.o mralloc.o mrsmall.o mrzzn2.o mrzzn3.o
ar r miracl.a mrio1.o mrio2.o mrjack.o mrgcd.o mrxgcd.o mrarth3.o mrbits.o mrecn2.o mrzzn4.o
ar r miracl.a mrrand.o mrprime.o mrcrt.o mrscrt.o mrmonty.o mrcurve.o mrsroot.o mrzzn2b.o
ar r miracl.a mrpower.o mrfast.o mrshs.o mrshs256.o mraes.o mrlucas.o mrstrong.o mrgcm.o    
ar r miracl.a mrflash.o mrfrnd.o mrdouble.o mrround.o mrbuild.o
ar r miracl.a mrflsh1.o mrpi.o mrflsh2.o mrflsh3.o mrflsh4.o 
ar r miracl.a mrbrick.o mrebrick.o mrec2m.o mrgf2m.o mrmuldv.o mrshs512.o mrsha3.o mrfpe.o
rm mr*.o
#gcc -m64 -O2 bmark.c miracl.a -o bmark
#gcc -m64 -O2 fact.c miracl.a -o fact
#g++ -c -m64 -O2 big.cpp
#g++ -c -m64 -O2 zzn.cpp
#g++ -c -m64 -O2 ecn.cpp
#g++ -c -m64 -O2 ec2.cpp
#g++ -c -m64 -O2 crt.cpp
#g++ -m64 -O2 mersenne.cpp big.o miracl.a -o mersenne
#g++ -m64 -O2 brent.cpp big.o zzn.o miracl.a -o brent
#g++ -c -m64 -O2 flash.cpp
#g++ -m64 -O2 sample.cpp flash.o miracl.a -o sample
#g++ -m64 -O2 ecsgen.cpp ecn.o big.o miracl.a -o ecsgen
#g++ -m64 -O2 ecsign.cpp ecn.o big.o miracl.a -o ecsign
#g++ -m64 -O2 ecsver.cpp ecn.o big.o miracl.a -o ecsver
#g++ -m64 -O2 pk-demo.cpp ecn.o big.o miracl.a -o pk-demo
#g++ -c -m64 -O2 polymod.cpp
#g++ -c -m64 -O2 poly.cpp
#g++ -m64 -O2 schoof.cpp polymod.o poly.o ecn.o crt.o zzn.o big.o miracl.a -o schoof
