/*
* Copyright (c) by CryptoLab inc.
* This program is licensed under a
* Creative Commons Attribution-NonCommercial 3.0 Unported License.
* You should have received a copy of the license along with this
* work.  If not, see <http://creativecommons.org/licenses/by-nc/3.0/>.
*/
#include "TestScheme.h"

#include <NTL/BasicThreadPool.h>
#include <NTL/ZZ.h>

#include "Ciphertext.h"
#include "EvaluatorUtils.h"
#include "Ring.h"
#include "Scheme.h"
#include "SchemeAlgo.h"
#include "SecretKey.h"
#include "StringUtils.h"
#include "TimeUtils.h"
#include "SerializationUtils.h"

#include <iostream>
#include <thread>
#include <fstream> // 파일 입출력을 위한 헤더 파일
#include <ctime> // 현재 시간 알기 위함
#include<bitset>
#include "Client.h"

#include <Python.h> //파이썬 코드를 위함
#define CLIENTSNUM 2

using namespace std;
using namespace NTL;


namespace heaan {

	mutex my_mutex;
	//bool initialized = false;
	PyGILState_STATE pystate;

//----------------------------------------------------------------------------------
//   STANDARD TESTS
//----------------------------------------------------------------------------------


void TestScheme::testEncrypt(long logq, long logp, long logn) {
	cout << "!!! START TEST ENCRYPT !!!" << endl;
	srand(time(NULL));
	SetNumThreads(8);
	TimeUtils timeutils;
	Ring ring;
	SecretKey secretKey(ring);
	Scheme scheme(secretKey, ring);

	long n = (1 << logn);
	complex<double>* mvec = EvaluatorUtils::randomComplexArray(n);
	
	Ciphertext cipher;

	timeutils.start("Encrypt");
	scheme.encrypt(cipher, mvec, n, logp, logq);
	timeutils.stop("Encrypt");

	timeutils.start("Decrypt");
	complex<double>* dvec = scheme.decrypt(secretKey, cipher);
	
	timeutils.stop("Decrypt");

	StringUtils::compare(mvec, dvec, n, "val");

	cout << "!!! END TEST ENCRYPT !!!" << endl;
}

void TestScheme::testEncryptBySk(long logq, long logp, long logn) {
	cout << "!!! START TEST ENCRYPT by SK !!!" << endl;
	srand(time(NULL));
	SetNumThreads(8);
	TimeUtils timeutils;
	Ring ring;
	SecretKey secretKey(ring);
	Scheme scheme(secretKey, ring);

	long n = (1 << logn);
	complex<double>* mvec = EvaluatorUtils::randomComplexArray(n);
	Ciphertext cipher;

	timeutils.start("Encrypt by sk");
	scheme.encryptBySk(cipher, secretKey, mvec, n, logp, logq);
	timeutils.stop("Encrypt by sk");

	timeutils.start("Decrypt");
	complex<double>* dvec = scheme.decrypt(secretKey, cipher);
	timeutils.stop("Decrypt");

	StringUtils::compare(mvec, dvec, n, "val");

	cout << "!!! END TEST ENCRYPT By SK !!!" << endl;
}

void TestScheme::testDecryptForShare(long logq, long logp, long logn, long logErrorBound) {
	cout << "!!! START TEST Decrypt for Share !!!" << endl;

	double sigma1 = 3.2 * sqrt(2);

	cout << "Note : encryption std is changed to sigma1 = " << sigma1 << endl;
	srand(time(NULL));
	SetNumThreads(8);
	TimeUtils timeutils;
	Ring ring;
	SecretKey secretKey(ring);
	Scheme scheme(secretKey, ring);

	long n = (1 << logn);
	complex<double>* mvec = EvaluatorUtils::randomComplexArray(n);
	Ciphertext cipher;

	timeutils.start("Encrypt by sk");
	scheme.encryptBySk(cipher, secretKey, mvec, n, logp, logq, sigma1);
	timeutils.stop("Encrypt by sk");

	timeutils.start("Decrypt by share");
	complex<double>* dvecShare = scheme.decryptForShare(secretKey, cipher, logErrorBound);
	complex<double>* dvec = scheme.decrypt(secretKey, cipher);
	timeutils.stop("Decrypt by share");

	for (long i = 0; i < n; ++i) {
		cout << "---------------------" << endl;
		cout << "plain : " << i << " :" << mvec[i] << endl;
		cout << "decrypt : " << i << " :" << dvec[i] << endl;
		cout << "decryptForShare : " << i << " :" << dvecShare[i] << endl;
		cout << "dec error : " << i << " :" << (mvec[i]-dvec[i]) << endl;
		cout << "dec and decForShare error : " << i << " :" << (dvec[i]-dvecShare[i]) << endl;
		cout << "---------------------" << endl;
	}

	cout << "!!! END TEST Decrypt for Share !!!" << endl;
}

void TestScheme::testEncryptSingle(long logq, long logp) {
	cout << "!!! START TEST ENCRYPT SINGLE !!!" << endl;
	srand(time(NULL));
	SetNumThreads(8);
	TimeUtils timeutils;
	Ring ring;
	SecretKey secretKey(ring);
	Scheme scheme(secretKey, ring);

	complex<double> mval = EvaluatorUtils::randomComplex();
	Ciphertext cipher;

	timeutils.start("Encrypt Single");
	scheme.encryptSingle(cipher, mval, logp, logq);
	timeutils.stop("Encrypt Single");

	complex<double> dval = scheme.decryptSingle(secretKey, cipher);

	StringUtils::compare(mval, dval, "val");

	cout << "!!! END TEST ENCRYPT SINGLE !!!" << endl;
}

void TestScheme::testAdd(long logq, long logp, long logn) {
	cout << "!!! START TEST ADD !!!" << endl;

	srand(time(NULL));
	SetNumThreads(8);
	TimeUtils timeutils;
	Ring ring;
	SecretKey secretKey(ring);
	Scheme scheme(secretKey, ring);

	long n = (1 << logn);
	complex<double>* mvec1 = EvaluatorUtils::randomComplexArray(n);
	complex<double>* mvec2 = EvaluatorUtils::randomComplexArray(n);
	complex<double>* madd = new complex<double>[n];

	for(long i = 0; i < n; i++) {
		madd[i] = mvec1[i] + mvec2[i];
	}

	Ciphertext cipher1, cipher2;
	scheme.encrypt(cipher1, mvec1, n, logp, logq);
	scheme.encrypt(cipher2, mvec2, n, logp, logq);

	timeutils.start("Addition");
	scheme.addAndEqual(cipher1, cipher2);
	timeutils.stop("Addition");

	complex<double>* dadd = scheme.decrypt(secretKey, cipher1);

	StringUtils::compare(madd, dadd, n, "add");

	cout << "!!! END TEST ADD !!!" << endl;
}

void TestScheme::testAdd100(long logq, long logp, long logn, long user_num) {
	cout << "!!! START TEST ADD !!!" << endl;

	srand(time(NULL));
	SetNumThreads(8);
	TimeUtils timeutils;
	Ring ring;
	SecretKey secretKey(ring);
	Scheme scheme(secretKey, ring);

	long n = (1 << logn);

	// Generate mvec1 ~ mvec(user_num)
	// 유저i가 크기 n짜리 mvce을 만들어서 mvecs[i]에 저장
	complex<double>** mvecs = new complex<double>*[user_num];
	for (int i = 0; i < user_num; ++i) {
		mvecs[i] = EvaluatorUtils::randomComplexArray(n);
	}

	// madd : 유저별 mvec를 다 더한값
	complex<double>* madd = new complex<double>[n];
	for (int i = 0; i < user_num; ++i) {
		for (long j = 0; j < n; ++j) {
			madd[j] += mvecs[i][j]; // Accumulate the sum
		}
	}

	Ciphertext cipher1;
	scheme.encrypt(cipher1, mvecs[0], n, logp, logq);

	timeutils.start("Addition");

	// Encrypt and add all mvecs to resultCipher
	for (int i = 1; i < user_num; ++i) {
		Ciphertext tempCipher;
		scheme.encrypt(tempCipher, mvecs[i], n, logp, logq);
		scheme.addAndEqual(cipher1, tempCipher); // Add to resultCipher
		delete[] mvecs[i]; // Free memory for mvecs[i]
	}

	timeutils.stop("Addition");

	complex<double>* dadd = scheme.decrypt(secretKey, cipher1);

	StringUtils::compare(madd, dadd, n, "add");

	delete[] madd;
	delete[] mvecs;

	cout << "!!! END TEST ADD !!!" << endl;
}

void TestScheme::testMult(long logq, long logp, long logn) {
	cout << "!!! START TEST MULT !!!" << endl;

	srand(time(NULL));
	SetNumThreads(8);
	TimeUtils timeutils;
	Ring ring;
	SecretKey secretKey(ring);
	Scheme scheme(secretKey, ring);

	long n = (1 << logn);
	complex<double>* mvec1 = EvaluatorUtils::randomComplexArray(n);
	complex<double>* mvec2 = EvaluatorUtils::randomComplexArray(n);
	complex<double>* mmult = new complex<double>[n];
	for(long i = 0; i < n; i++) {
		mmult[i] = mvec1[i] * mvec2[i];
	}

	Ciphertext cipher1, cipher2;
	scheme.encrypt(cipher1, mvec1, n, logp, logq);
	scheme.encrypt(cipher2, mvec2, n, logp, logq);

	timeutils.start("Multiplication");
	scheme.multAndEqual(cipher1, cipher2);
	timeutils.stop("Multiplication");

	complex<double>* dmult = scheme.decrypt(secretKey, cipher1);

	StringUtils::compare(mmult, dmult, n, "mult");

	cout << "!!! END TEST MULT !!!" << endl;
}

void TestScheme::testiMult(long logq, long logp, long logn) {
	cout << "!!! START TEST i MULTIPLICATION !!!" << endl;

	srand(time(NULL));
	SetNumThreads(8);
	TimeUtils timeutils;
	Ring ring;
	SecretKey secretKey(ring);
	Scheme scheme(secretKey, ring);

	long n = (1 << logn);

	complex<double>* mvec = EvaluatorUtils::randomComplexArray(n);
	complex<double>* imvec = new complex<double>[n];
	for (long i = 0; i < n; ++i) {
		imvec[i].real(-mvec[i].imag());
		imvec[i].imag(mvec[i].real());
	}

	Ciphertext cipher;
	scheme.encrypt(cipher, mvec, n, logp, logq);

	timeutils.start("Multiplication by i");
	scheme.imultAndEqual(cipher);
	timeutils.stop("Multiplication by i");

	complex<double>* idvec = scheme.decrypt(secretKey, cipher);

	StringUtils::compare(imvec, idvec, n, "imult");

	cout << "!!! END TEST i MULTIPLICATION !!!" << endl;
}


//----------------------------------------------------------------------------------
//   ROTATE & CONJUGATE
//----------------------------------------------------------------------------------


void TestScheme::testRotateFast(long logq, long logp, long logn, long logr) {
	cout << "!!! START TEST ROTATE FAST !!!" << endl;

	srand(time(NULL));
	SetNumThreads(8);
	TimeUtils timeutils;
	Ring ring;
	SecretKey secretKey(ring);
	Scheme scheme(secretKey, ring);

	long n = (1 << logn);
	long r = (1 << logr);
	scheme.addLeftRotKey(secretKey, r);
	complex<double>* mvec = EvaluatorUtils::randomComplexArray(n);
	Ciphertext cipher;
	scheme.encrypt(cipher, mvec, n, logp, logq);

	timeutils.start("Left Rotate Fast");
	scheme.leftRotateFastAndEqual(cipher, r);
	timeutils.stop("Left Rotate Fast");

	complex<double>* dvec = scheme.decrypt(secretKey, cipher);

	EvaluatorUtils::leftRotateAndEqual(mvec, n, r);
	StringUtils::compare(mvec, dvec, n, "rot");

	cout << "!!! END TEST ROTATE BY POWER OF 2 BATCH !!!" << endl;
}

void TestScheme::testConjugate(long logq, long logp, long logn) {
	cout << "!!! START TEST CONJUGATE !!!" << endl;

	srand(time(NULL));
	SetNumThreads(8);
	TimeUtils timeutils;
	Ring ring;
	SecretKey secretKey(ring);
	Scheme scheme(secretKey, ring);

	scheme.addConjKey(secretKey);

	long n = (1 << logn);

	complex<double>* mvec = EvaluatorUtils::randomComplexArray(n);
	complex<double>* mvecconj = new complex<double>[n];
	for (long i = 0; i < n; ++i) {
		mvecconj[i] = conj(mvec[i]);
	}

	Ciphertext cipher;
	scheme.encrypt(cipher, mvec, n, logp, logq);

	timeutils.start("Conjugate");
	scheme.conjugateAndEqual(cipher);
	timeutils.stop("Conjugate");

	complex<double>* dvecconj = scheme.decrypt(secretKey, cipher);
	StringUtils::compare(mvecconj, dvecconj, n, "conj");

	cout << "!!! END TEST CONJUGATE !!!" << endl;
}


//----------------------------------------------------------------------------------
//   POWER & PRODUCT TESTS
//----------------------------------------------------------------------------------


void TestScheme::testPowerOf2(long logq, long logp, long logn, long logdeg) {
	cout << "!!! START TEST POWER OF 2 !!!" << endl;

	srand(time(NULL));
	SetNumThreads(8);
	TimeUtils timeutils;
	Ring ring;
	SecretKey secretKey(ring);
	Scheme scheme(secretKey, ring);
	SchemeAlgo algo(scheme);

	long n = 1 << logn;
	long degree = 1 << logdeg;
	complex<double>* mvec = new complex<double>[n];
	complex<double>* mpow = new complex<double>[n];
	for (long i = 0; i < n; ++i) {
		mvec[i] = EvaluatorUtils::randomCircle();
		mpow[i] = pow(mvec[i], degree);
	}

	Ciphertext cipher, cpow;
	scheme.encrypt(cipher, mvec, n, logp, logq);

	timeutils.start("Power of 2");
	algo.powerOf2(cpow, cipher, logp, logdeg);
	timeutils.stop("Power of 2");

	complex<double>* dpow = scheme.decrypt(secretKey, cpow);
	StringUtils::compare(mpow, dpow, n, "pow2");

	cout << "!!! END TEST POWER OF 2 !!!" << endl;
}

//-----------------------------------------

void TestScheme::testPower(long logq, long logp, long logn, long degree) {
	cout << "!!! START TEST POWER !!!" << endl;

	srand(time(NULL));
	SetNumThreads(8);
	TimeUtils timeutils;
	Ring ring;
	SecretKey secretKey(ring);
	Scheme scheme(secretKey, ring);
	SchemeAlgo algo(scheme);

	long n = 1 << logn;
	complex<double>* mvec = EvaluatorUtils::randomCircleArray(n);
	complex<double>* mpow = new complex<double>[n];
	for (long i = 0; i < n; ++i) {
		mpow[i] = pow(mvec[i], degree);
	}

	Ciphertext cipher, cpow;
	scheme.encrypt(cipher, mvec, n, logp, logq);

	timeutils.start("Power");
	algo.power(cpow, cipher, logp, degree);
	timeutils.stop("Power");

	complex<double>* dpow = scheme.decrypt(secretKey, cpow);
	StringUtils::compare(mpow, dpow, n, "pow");

	cout << "!!! END TEST POWER !!!" << endl;
}


//----------------------------------------------------------------------------------
//   FUNCTION TESTS
//----------------------------------------------------------------------------------


void TestScheme::testInverse(long logq, long logp, long logn, long steps) {
	cout << "!!! START TEST INVERSE !!!" << endl;

	srand(time(NULL));
	SetNumThreads(8);
	TimeUtils timeutils;
	Ring ring;
	SecretKey secretKey(ring);
	Scheme scheme(secretKey, ring);
	SchemeAlgo algo(scheme);

	long n = 1 << logn;
	complex<double>* mvec = EvaluatorUtils::randomCircleArray(n, 0.1);
	complex<double>* minv = new complex<double>[n];
	for (long i = 0; i < n; ++i) {
		minv[i] = 1. / mvec[i];
	}

	Ciphertext cipher, cinv;
	scheme.encrypt(cipher, mvec, n, logp, logq);

	timeutils.start("Inverse");
	algo.inverse(cinv, cipher, logp, steps);
	timeutils.stop("Inverse");

	complex<double>* dinv = scheme.decrypt(secretKey, cinv);
	StringUtils::compare(minv, dinv, n, "inv");

	cout << "!!! END TEST INVERSE !!!" << endl;
}

void TestScheme::testLogarithm(long logq, long logp, long logn, long degree) {
	cout << "!!! START TEST LOGARITHM !!!" << endl;

	srand(time(NULL));
	SetNumThreads(8);
	TimeUtils timeutils;
	Ring ring;
	SecretKey secretKey(ring);
	Scheme scheme(secretKey, ring);
	SchemeAlgo algo(scheme);

	long n = 1 << logn;
	complex<double>* mvec = EvaluatorUtils::randomComplexArray(n, 0.1);
	complex<double>* mlog = new complex<double>[n];
	for (long i = 0; i < n; ++i) {
		mlog[i] = log(mvec[i] + 1.);
	}

	Ciphertext cipher, clog;
	scheme.encrypt(cipher, mvec, n, logp, logq);

	timeutils.start(LOGARITHM);
	algo.function(clog, cipher, LOGARITHM, logp, degree);
	timeutils.stop(LOGARITHM);

	complex<double>* dlog = scheme.decrypt(secretKey, clog);
	StringUtils::compare(mlog, dlog, n, LOGARITHM);

	cout << "!!! END TEST LOGARITHM !!!" << endl;
}

void TestScheme::testExponent(long logq, long logp, long logn, long degree) {
	cout << "!!! START TEST EXPONENT !!!" << endl;

	srand(time(NULL));
	SetNumThreads(8);
	TimeUtils timeutils;
	Ring ring;
	SecretKey secretKey(ring);
	Scheme scheme(secretKey, ring);
	SchemeAlgo algo(scheme);

	long n = 1 << logn;
	complex<double>* mvec = EvaluatorUtils::randomComplexArray(n);
	complex<double>* mexp = new complex<double>[n];
	for (long i = 0; i < n; ++i) {
		mexp[i] = exp(mvec[i]);
	}

	Ciphertext cipher, cexp;
	scheme.encrypt(cipher, mvec, n, logp, logq);

	timeutils.start(EXPONENT);
	algo.function(cexp, cipher, EXPONENT, logp, degree);
	timeutils.stop(EXPONENT);

	complex<double>* dexp = scheme.decrypt(secretKey, cexp);
	StringUtils::compare(mexp, dexp, n, EXPONENT);

	cout << "!!! END TEST EXPONENT !!!" << endl;
}

void TestScheme::testExponentLazy(long logq, long logp, long logn, long degree) {
	cout << "!!! START TEST EXPONENT LAZY !!!" << endl;

	srand(time(NULL));
	SetNumThreads(8);
	TimeUtils timeutils;
	Ring ring;
	SecretKey secretKey(ring);
	Scheme scheme(secretKey, ring);
	SchemeAlgo algo(scheme);

	long n = 1 << logn;
	complex<double>* mvec = EvaluatorUtils::randomComplexArray(n);
	complex<double>* mexp = new complex<double>[n];
	for (long i = 0; i < n; ++i) {
		mexp[i] = exp(mvec[i]);
	}
	Ciphertext cipher, cexp;
	scheme.encrypt(cipher, mvec, n, logp, logQ);

	timeutils.start(EXPONENT + " lazy");
	algo.functionLazy(cexp, cipher, EXPONENT, logp, degree);
	timeutils.stop(EXPONENT + " lazy");

	complex<double>* dexp = scheme.decrypt(secretKey, cexp);
	StringUtils::compare(mexp, dexp, n, EXPONENT);

	cout << "!!! END TEST EXPONENT LAZY !!!" << endl;
}

//-----------------------------------------

void TestScheme::testSigmoid(long logq, long logp, long logn, long degree) {
	cout << "!!! START TEST SIGMOID !!!" << endl;

	srand(time(NULL));
	SetNumThreads(8);
	TimeUtils timeutils;
	Ring ring;
	SecretKey secretKey(ring);
	Scheme scheme(secretKey, ring);
	SchemeAlgo algo(scheme);

	long n = 1 << logn;

	complex<double>* mvec = EvaluatorUtils::randomComplexArray(n);
	complex<double>* msig = new complex<double>[n];
	for (long i = 0; i < n; ++i) {
		msig[i] = exp(mvec[i]) / (1. + exp(mvec[i]));
	}

	Ciphertext cipher, csig;
	scheme.encrypt(cipher, mvec, n, logp, logq);

	timeutils.start(SIGMOID);
	algo.function(csig, cipher, SIGMOID, logp, degree);
	timeutils.stop(SIGMOID);

	complex<double>* dsig = scheme.decrypt(secretKey, csig);
	StringUtils::compare(msig, dsig, n, SIGMOID);

	cout << "!!! END TEST SIGMOID !!!" << endl;
}

void TestScheme::testSigmoidLazy(long logq, long logp, long logn, long degree) {
	cout << "!!! START TEST SIGMOID LAZY !!!" << endl;

	srand(time(NULL));
//	SetNumThreads(8);
	TimeUtils timeutils;
	Ring ring;
	SecretKey secretKey(ring);
	Scheme scheme(secretKey, ring);
	SchemeAlgo algo(scheme);

	long n = 1 << logn;
	complex<double>* mvec = EvaluatorUtils::randomComplexArray(n);
	complex<double>* msig = new complex<double>[n];
	for (long i = 0; i < n; ++i) {
		msig[i] = exp(mvec[i]) / (1. + exp(mvec[i]));
	}

	Ciphertext cipher, csig;
	scheme.encrypt(cipher, mvec, n, logp, logq);

	timeutils.start(SIGMOID + " lazy");
	algo.functionLazy(csig, cipher, SIGMOID, logp, degree);
	timeutils.stop(SIGMOID + " lazy");

	complex<double>* dsig = scheme.decrypt(secretKey, csig);
	StringUtils::compare(msig, dsig, n, SIGMOID);

	cout << "!!! END TEST SIGMOID LAZY !!!" << endl;
}


void TestScheme::testWriteAndRead(long logq, long logp, long logSlots) {
	cout << "!!! START TEST WRITE AND READ !!!" << endl;

	cout << "!!! END TEST WRITE AND READ !!!" << endl;
}


void TestScheme::testBootstrap(long logq, long logp, long logSlots, long logT) {
	cout << "!!! START TEST BOOTSTRAP !!!" << endl;

	srand(time(NULL));
	SetNumThreads(8);
	TimeUtils timeutils;
	Ring ring;
	SecretKey secretKey(ring);
	Scheme scheme(secretKey, ring);

	timeutils.start("Key generating");
	scheme.addBootKey(secretKey, logSlots, logq + 4);
	timeutils.stop("Key generated");

	long slots = (1 << logSlots);
	complex<double>* mvec = EvaluatorUtils::randomComplexArray(slots);

	Ciphertext cipher;
	scheme.encrypt(cipher, mvec, slots, logp, logq);

	cout << "cipher logq before: " << cipher.logq << endl;

	scheme.modDownToAndEqual(cipher, logq);
	scheme.normalizeAndEqual(cipher);
	cipher.logq = logQ;
	cipher.logp = logq + 4;

	Ciphertext rot;
	timeutils.start("SubSum");
	for (long i = logSlots; i < logNh; ++i) {
		scheme.leftRotateFast(rot, cipher, (1 << i));
		scheme.addAndEqual(cipher, rot);
	}
	scheme.divByPo2AndEqual(cipher, logNh);
	timeutils.stop("SubSum");

	timeutils.start("CoeffToSlot");
	scheme.coeffToSlotAndEqual(cipher);
	timeutils.stop("CoeffToSlot");

	timeutils.start("EvalExp");
	scheme.evalExpAndEqual(cipher, logT);
	timeutils.stop("EvalExp");

	timeutils.start("SlotToCoeff");
	scheme.slotToCoeffAndEqual(cipher);
	timeutils.stop("SlotToCoeff");

	cipher.logp = logp;
	cout << "cipher logq after: " << cipher.logq << endl;

	complex<double>* dvec = scheme.decrypt(secretKey, cipher);

	StringUtils::compare(mvec, dvec, slots, "boot");

	cout << "!!! END TEST BOOTSRTAP !!!" << endl;
}

void TestScheme::testBootstrapSingleReal(long logq, long logp, long logT) {
	cout << "!!! START TEST BOOTSTRAP SINGLE REAL !!!" << endl;

	srand(time(NULL));
	SetNumThreads(8);
	TimeUtils timeutils;
	Ring ring;
	SecretKey secretKey(ring);
	Scheme scheme(secretKey, ring);

	timeutils.start("Key generating");
	scheme.addBootKey(secretKey, 0, logq + 4);
	timeutils.stop("Key generated");

	double mval = EvaluatorUtils::randomReal();

	Ciphertext cipher;
	scheme.encryptSingle(cipher, mval, logp, logq);

	cout << "cipher logq before: " << cipher.logq << endl;
	scheme.modDownToAndEqual(cipher, logq);
	scheme.normalizeAndEqual(cipher);
	cipher.logq = logQ;

	Ciphertext rot, cconj;
	timeutils.start("SubSum");
	for (long i = 0; i < logNh; ++i) {
		scheme.leftRotateFast(rot, cipher, 1 << i);
		scheme.addAndEqual(cipher, rot);
	}
	scheme.conjugate(cconj, cipher);
	scheme.addAndEqual(cipher, cconj);
	scheme.divByPo2AndEqual(cipher, logN);
	timeutils.stop("SubSum");

	timeutils.start("EvalExp");
	scheme.evalExpAndEqual(cipher, logT);
	timeutils.stop("EvalExp");

	cout << "cipher logq after: " << cipher.logq << endl;

	cipher.logp = logp;
	complex<double> dval = scheme.decryptSingle(secretKey, cipher);

	StringUtils::compare(mval, dval.real(), "boot");

	cout << "!!! END TEST BOOTSRTAP SINGLE REAL !!!" << endl;
}

//test
void TestScheme::testEncryptMN(long logq, long logp) {
	cout << "!!! START TEST ENCRYPT my numbers !!!" << endl;
	srand(time(NULL));
	SetNumThreads(8);
	TimeUtils timeutils;
	Ring ring;
	SecretKey secretKey(ring);
	Scheme scheme(secretKey, ring);

	long n, nh;
	char ch;
	double num1, num2;
	complex<double> num;
	complex<double>* mvec;

	cout << "number of numbers: ";
	cin >> n;
	cout << "numbers type(int->i, double->d, complex->c): ";
	cin >> ch;
	if (ch == 'c') {
		mvec = new complex<double>[n];
		for (long i = 0; i < n; ++i) {
			cout << "input number (real, img): ";
			cin >> num;
			mvec[i] = num;
		}
	}
	else {
		nh = ceil(n / 2);
		mvec = new complex<double>[nh];
		for (long i = 0; i < nh; ++i) {
			cout << "input number: ";
			cin >> num1;
			if (n % 2 != 0 && i == (nh - 1))
				num2 = 0;
			else {
				cout << "input number: ";
				cin >> num2;
			}
			
			mvec[i] = complex<double>(num1, num2);
		}
		n = nh;
	}

	Ciphertext cipher;

	timeutils.start("Encrypt");
	scheme.encrypt(cipher, mvec, n, logp, logq);
	timeutils.stop("Encrypt");

	timeutils.start("Decrypt");
	complex<double>* dvec = scheme.decrypt(secretKey, cipher);

	timeutils.stop("Decrypt");

	StringUtils::compare(mvec, dvec, n, "val");

	cout << "!!! END TEST ENCRYPT !!!" << endl;
}

/** 테스트 코드 */
void TestScheme::testFed(long logq, long logp, long logn, int user_num) {
	cout << "!!! START TEST FED !!!" << endl;

	srand(time(NULL));
	SetNumThreads(8);
	TimeUtils timeutils;
	Ring ring;
	SecretKey secretKey(ring);
	Scheme scheme(secretKey, ring);

	long n = (1 << logn);

	timeutils.start("wVec 생성");
	// user_num 만큼의 w배열 생성(2차원 배열)
	std::complex<double>** wVec = EvaluatorUtils::generateRandomRealArrays(n, user_num);
	timeutils.stop("wVec 생성");

	// W벡터 로그
	for (int j = 0; j < user_num; j++) {
		cout << "wVec[" << j << "][] = ";
		for (int i = 0; i < n; i++) {
			cout << wVec[j][i] << " ";
		}
		cout << endl;
	}

	timeutils.start("aVec 생성");
	// user_num 만큼의 -5부터 5까지의 랜덤값 생성
	//std::complex<double>* aVec = EvaluatorUtils::generateRandomIntValues(user_num, -5, 5);
	std::complex<double>* aVec = EvaluatorUtils::generateRandomAlphaValues(user_num, -5, 5); //alpha값 실수
	timeutils.stop("aVec 생성");

	// alpha 벡터 로그
	cout << endl;
	for (int j = 0; j < user_num; j++) {
		cout << "aVec[" << j << "] = ";
		cout << aVec[j] << " ";
		cout << endl;
	}

	/****************************************************/

	/*Wi+alphai를 수행해서 sVec 만들기*/
	timeutils.start("sVec 생성");
	complex<double>** sVec = new complex<double>*[user_num];
	for (int j = 0; j < user_num; j++) {
		timeutils.start("W + alpha vector " + std::to_string(j));
		sVec[j] = new complex<double>[n];
		for (int i = 0; i < n; i++) {
			sVec[j][i] = wVec[j][i] + aVec[j];  // 각 사용자의 Wi + alphai 계산
		}
		timeutils.stop("W + alpha vector " + std::to_string(j));
	}
	timeutils.stop("sVec 생성");

	/**alpha_vecs 각각를 암호화해서 C_vecs 생성하기*/
	timeutils.start("cVec 생성");
	Ciphertext* cVec = new Ciphertext[user_num];
	for (int i = 0; i < user_num; i++) {
		timeutils.start("Encrypting alpha vector " + std::to_string(i));
		scheme.encryptSingle(cVec[i], aVec[i], logp, logq);
		timeutils.stop("Encrypting alpha vector " + std::to_string(i));
		cVec[i].n = n;
	}
	timeutils.stop("cVec 생성");



	// cVec 로그
	//cout << endl;
	//cout << "Ci = ai의 암호화" << endl;
	//for (int j = 0; j < user_num; j++) {
	//	cout << "cVec[" << j << "] = ";
	//	cVec[j].print();
	//	cout << endl;
	//}

	cout << "Server에서 수행하는 연산" << endl;
	timeutils.start("cSum");
	/**cSum 구하기*/
	Ciphertext cSum;
	cSum = cVec[0];
	for (int j = 1; j < user_num; j++) {
		scheme.addAndEqual(cSum, cVec[j]);
	}
	timeutils.stop("cSum");

	// cSum 로그
	//cout << endl;
	//cSum.print();

	/**sSum*/
	timeutils.start("sSum");
	complex<double>* sSum = new complex<double>[n];
	for (int i = 0; i < n; i++) {
		for (int j = 0; j < user_num; j++) {
			sSum[i] += sVec[j][i];  // alpha_vecs 합산
		}
	}
	timeutils.stop("sSum");

	// sSum 로그
	cout << endl;
	for (int i = 0; i < n; i++) {
		cout << "sSum[" << i << "] = " << sSum[i] << endl;
	}

	cout << "사용자가 수행하는 연산" << endl;
	/*사용자*/
	/* cSum 복호화하여 aSum 얻기 */
	complex<double>* aSum = scheme.decrypt(secretKey, cSum);

	//aSum 로그
	cout << endl;
	cout << "cSum 복호화해서 aSum을 얻는다." << endl;
	for (int i = 0; i < n; i++) {
		cout << "aSum[" << i << "] = " << aSum[i] << endl;
	}

	// sSum에서 aSum을 빼서 sSum 최종저장
	for (int i = 0; i < n; i++) {
		sSum[i] -= aSum[i];
	}


	complex<double>* wSum = new complex<double>[n]();
	/*wVec 있는 w배열들을 다 더하기 = w1+w2+w3+w4+...*/
	for (int i = 0; i < n; i++) {
		for (int j = 0; j < user_num; j++) {
			wSum[i] += wVec[j][i];
		}
	}
	StringUtils::compare(wSum, sSum, n, "fed");

	cout << "!!! END TEST FED !!!" << endl;
}

/** 테스트 코드 */
void TestScheme::testFedV2(long logq, long logp, long logn, int user_num) {
	cout << "!!! START TEST FED !!!" << endl;

	srand(time(NULL));
	SetNumThreads(8);
	TimeUtils timeutils;
	Ring ring;
	SecretKey secretKey(ring);
	Scheme scheme(secretKey, ring);

	long n = (1 << logn);

	timeutils.start("wVec 생성");
	// user_num 만큼의 w배열 생성(2차원 배열)
	//std::complex<double>** wVec = EvaluatorUtils::generateRandomRealArrays(n, user_num);

	//*변경 0, 1, 2, 3, 4, 5, 24376, 24377, 24378 중 하나, 각사용자마다 32개
	//std::complex<double>** wVec = EvaluatorUtils::generateRandomArrays(n, user_num);
	std::complex<double>** wVec = EvaluatorUtils::generateFLArrays(n, user_num);
	timeutils.stop("wVec 생성");

	// W벡터 로그
	for (int j = 0; j < user_num; j++) {
		cout << "wVec[" << j << "][] = ";
		for (int i = 0; i < n; i++) {
			cout << wVec[j][i] << " ";
		}
		cout << endl;
	}

	timeutils.start("aVec 생성");
	// user_num 만큼의 -5부터 5까지의 랜덤값 생성
	//std::complex<double>* aVec = EvaluatorUtils::generateRandomIntValues(user_num,-5,5);

	//*범위변경 
	std::complex<double>* aVec = EvaluatorUtils::generateRandomIntValues(user_num, -20000, 20000);
	timeutils.stop("aVec 생성");

	// alpha 벡터 로그
	cout << endl;
	for (int j = 0; j < user_num; j++) {
		cout << "aVec[" << j << "] = ";
		cout << aVec[j] << " ";
		cout << endl;
	}

	/****************************************************/

	/*Wi+alphai를 수행해서 sVec 만들기*/
	timeutils.start("sVec 생성");
	complex<double>** sVec = new complex<double>*[user_num];
	for (int j = 0; j < user_num; j++) {
		sVec[j] = new complex<double>[n];
		for (int i = 0; i < n; i++) {
			sVec[j][i] = wVec[j][i] + aVec[j];  // 각 사용자의 Wi + alphai 계산
		}
	}
	timeutils.stop("sVec 생성");

	/**alpha_vecs 각각를 암호화해서 C_vecs 생성하기*/
	timeutils.start("cVec 생성");
	Ciphertext* cVec = new Ciphertext[user_num];
	for (int i = 0; i < user_num; i++) {
		scheme.encryptSingle(cVec[i], aVec[i], logp, logq);
		cVec[i].n = n;
	}
	timeutils.stop("cVec 생성");

	// cVec 로그
	//cout << endl;
	//cout << "Ci = ai의 암호화" << endl;
	//for (int j = 0; j < user_num; j++) {
	//	cout << "cVec[" << j << "] = ";
	//	cVec[j].print();
	//	cout << endl;
	//}

	cout << "Server에서 수행하는 연산" << endl;
	timeutils.start("cSum");
	/**cSum 구하기*/
	Ciphertext cSum;
	cSum = cVec[0];
	for (int j = 1; j < user_num; j++) {
		scheme.addAndEqual(cSum, cVec[j]);
	}
	timeutils.stop("cSum");

	// cSum 로그
	//cout << endl;
	//cSum.print();

	/**sSum*/
	timeutils.start("sSum");
	complex<double>* sSum = new complex<double>[n];
	for (int i = 0; i < n; i++) {
		for (int j = 0; j < user_num; j++) {
			sSum[i] += sVec[j][i];  // alpha_vecs 합산
		}
	}
	timeutils.stop("sSum");

	// sSum 로그
	cout << endl;
	for (int i = 0; i < n; i++) {
		cout << "sSum[" << i << "] = " << sSum[i] << endl;
	}

	cout << "사용자가 수행하는 연산" << endl;
	/*사용자*/
	/* cSum 복호화하여 aSum 얻기 */
	complex<double>* aSum = scheme.decrypt(secretKey, cSum);

	//aSum 로그
	cout << endl;
	cout << "cSum 복호화해서 aSum을 얻는다." << endl;
	for (int i = 0; i < n; i++) {
		cout << "aSum[" << i << "] = " << aSum[i] << endl;
	}

	// sSum에서 aSum을 빼서 sSum 최종저장
	for (int i = 0; i < n; i++) {
		sSum[i] -= aSum[i];
	}


	complex<double>* wSum = new complex<double>[n]();
	/*wVec 있는 w배열들을 다 더하기 = w1+w2+w3+w4+...*/
	for (int i = 0; i < n; i++) {
		for (int j = 0; j < user_num; j++) {
			wSum[i] += wVec[j][i];
		}
	}
	StringUtils::compare(wSum, sSum, n, "fed");

	cout << "!!! END TEST FED !!!" << endl;
}

void TestScheme::testMKHE(long logq, long logp, long logn, int user_num) {
	cout << "!!! START TEST MKHE !!!" << endl;

	srand(time(NULL));
	SetNumThreads(8);
	TimeUtils timeutils;
	Ring ring;
	long n = (1 << logn);

	//1. generate a global A = [a1, a2, ..., aN] 
	cout << "1. generate a global A = [a1, a2, ..., aN] " << endl;
	ZZ* A = new ZZ[N];
	ring.sampleUniform2(A, logQQ);

	// A -> keyA
	uint64_t* keyA = new uint64_t[Nnprimes]();
	ring.CRT(keyA, A, nprimes);

	// 2. create a secret key si
	// SecretKey 배열을 생성하여 각 사용자에 대한 SecretKey를 저장합니다.
	cout << "2. create a secret key si" << endl;
	std::vector<SecretKey> si_array(user_num, SecretKey(ring));

	// and a public key Bi = -A*si + e0i
	cout << "and a public key Bi = -A*si + e0i" << endl;
	ZZ** bi_array = new ZZ * [user_num];
	for (int i = 0; i < user_num; ++i) {
		bi_array[i] = new ZZ[N];
		long np = ceil((1 + logQQ + logN + 2) / (double)pbnd);
		ring.mult(bi_array[i], si_array[i].sx, A, np, QQ);
		ring.subFromGaussAndEqual(bi_array[i], QQ);
	}

	delete[] A;

	// 3. choose a random vi
	cout << "3. choose a random vi" << endl;
	ZZ qQ = ring.qpows[logq + logQ];

	ZZ** vi_array = new ZZ * [user_num];
	for (int i = 0; i < user_num; ++i) {
		vi_array[i] = new ZZ[N];
		ring.sampleZO(vi_array[i]);
	}

	//generate a commitment ci = keyA*vi+e0i
	cout << "generate a commitment ci = keyA*vi+e0i" << endl;
	ZZ** ci_array = new ZZ * [user_num];
	for (int i = 0; i < user_num; i++) {
		ci_array[i] = new ZZ[N];
		long np = ceil((1 + logQQ + logN + 2) / (double)pbnd);
		ring.multNTT(ci_array[i], vi_array[i], keyA, np, qQ);
		ring.rightShiftAndEqual(ci_array[i], logQ);
		ring.addGaussAndEqual(ci_array[i], qQ);
	}

	// 4. compute c = sum(Bi) and c = sum(ci)
	cout << "4. compute B = sum(Bi)" << endl;
	ZZ* bSum = new ZZ[N];
	std::copy(bi_array[0], bi_array[0] + N, bSum);
	for (int i = 1; i < user_num; i++) {
		ZZ q = ring.qpows[logq];
		ring.addAndEqual(bSum, bi_array[i], q);
	}

	// B -> keyB
	uint64_t* keyB = new uint64_t[Nnprimes]();
	ring.CRT(keyB, bSum, nprimes);
	delete[] bSum;

	cout << "and compute c = sum(ci)" << endl;
	ZZ* cSum = new ZZ[N];
	std::copy(ci_array[0], ci_array[0] + N, cSum);

	for (int i = 1; i < user_num; i++) {
		ZZ q = ring.qpows[logq];
		ring.addAndEqual(cSum, ci_array[i], q);
	}

	// 5. choose a random mask Mi
	cout << "5. choose a random mask Mi" << endl;

	// user_num 만큼의 -5부터 5까지의 랜덤값 Mi 생성
	std::complex<double>* Mi_array = EvaluatorUtils::generateRandomIntValues(user_num);

	// and generate Di = Wi + Mi
	// user_num 만큼의 w배열 생성(2차원 배열)
	std::complex<double>** Wi_array = EvaluatorUtils::generateRandomRealArrays(n, user_num);

	/*Wi+Mi 수행해서 Di 만들기*/
	cout << "and generate Di = Wi + Mi" << endl;

	complex<double>** Di_array = new complex<double>*[user_num];
	for (int j = 0; j < user_num; j++) {
		timeutils.start("Wi+ Mi " + std::to_string(j));
		Di_array[j] = new complex<double>[n];
		for (int i = 0; i < n; i++) {
			Di_array[j][i] = Wi_array[j][i] + Mi_array[j];  // 각 사용자의 Wi + alphai 계산
		}
		timeutils.stop("Wi+ Mi " + std::to_string(j));
	}

	// and PDi = vi*B + Mi + e1i + C*si

	// vi*B + Mi + e1i -> Mi의 암호화 (근데 Mi가 double이라서 정수로 바꿔줘야함)
	cout << "and PDi = vi*keyB + Mi + e1i + C*si" << endl;
	ZZ** PDi_array = new ZZ * [user_num];
	for (int i = 0; i < user_num; ++i) {
		PDi_array[i] = new ZZ[N];
		long np = ceil((1 + logQQ + logN + 2) / (double)pbnd);
		ring.multNTT(PDi_array[i], vi_array[i], keyB, np, qQ);

		Plaintext plain;
		//Scheme::encodeSingle(plain, Mi_array[i], logp, logq); - 객체없이 호출 못해서 아래처럼 뺐다.
		plain.logp = logp;
		plain.logq = logq;
		plain.n = 1;
		plain.mx[0] = EvaluatorUtils::scaleUpToZZ(Mi_array[i].real(), logp + logQ);
		plain.mx[Nh] = EvaluatorUtils::scaleUpToZZ(Mi_array[i].imag(), logp + logQ);

		ring.addAndEqual(PDi_array[i], plain.mx, qQ);

		ring.rightShiftAndEqual(PDi_array[i], logQ);
		ring.addGaussAndEqual(PDi_array[i], qQ);

		// += C*si
		ZZ* Csi = new ZZ[N];
		ring.mult(Csi, si_array[i].sx, cSum, np, QQ); //C*si -> Csi에 저장
		ZZ q = ring.qpows[logq];
		ring.addAndEqual(PDi_array[i], Csi, q);
	}

	//6. compute D = Sum(Di), PD = Sum(PDi)
	cout << "6. compute D = Sum(Di)" << endl;
	//D는 double W + double M 
	complex<double>* Dsum = new complex<double>[n];
	for (int i = 0; i < n; i++) {
		for (int j = 0; j < user_num; j++) {
			Dsum[i] += Di_array[j][i];  // Di 합산
		}
	}

	cout << "6. compute PD = Sum(PDi)" << endl;
	ZZ* PDsum = new ZZ[N];
	for (int i = 0; i < N; i++) {
		PDsum[i] = 0; // 초기화
		for (int j = 0; j < user_num; j++) {
			PDsum[i] += PDi_array[j][i];  // PDi 합산
		}
	}

	// decode_PDsum_array
	complex<double>* decode_PDsum = new complex<double>[n];
	ring.decode(PDsum, decode_PDsum, n, logp, logq);


	// decode_Wsum = D-PD
	complex<double>* decode_Wsum = new complex<double>[n];
	for (int i = 0; i < n; i++) {
		decode_Wsum[i] = Dsum[i] - decode_PDsum[i];
	}

	complex<double>* wSum = new complex<double>[n]();
	/*Wi_array 있는 w배열들을 다 더하기 = w1+w2+w3+w4+...*/
	for (int i = 0; i < n; i++) {
		for (int j = 0; j < user_num; j++) {
			wSum[i] += Wi_array[j][i];
		}
	}

	StringUtils::compare(wSum, decode_Wsum, n, "MKHE");

	cout << "!!! END TEST MKHE !!!" << endl;
}

void TestScheme::labClients(long logq, long logp, long logn, int user_num) {
	const string server_ip = "127.0.0.1";
	const int server_port = 8080;

	// スレッド用の関数
	auto createClient = [&server_ip, server_port]() {
		heaan::Client client(server_ip, server_port);
		//cout << "Response from server: " << client.getResponse() << endl;
		};

	//cout << "initialize" << endl;
	//Py_Initialize(); //PyEval_InitThreads()내용 포함

	// 10個のスレッドを生成し、それぞれでcreateClient関数を実行
	thread threads[CLIENTSNUM];
	for (int i = 0; i < CLIENTSNUM; ++i) {
		threads[i] = thread(createClient);
	}

	// 全てのスレッドの終了を待機
	for (int i = 0; i < CLIENTSNUM; ++i) {
		threads[i].join();
	}

	return;
}

void TestScheme::testMKHERound(long logq, long logp, long logn, int user_num, int round_num) {
	//Py_Initialize();
	int print_num = 4;
	cout << "!!! START TEST MKHERound !!!" << endl;

	// 로그를 저장할 파일 경로
	std::string filename = "log.txt";

	// 로그 내용
	std::time_t currentTime = std::time(nullptr);
	std::string currentTimeStr = std::ctime(&currentTime);
	std::string logMessage = currentTimeStr + " MKHERound 테스트 시작\n";

	// 파일 열기
	std::ofstream logfile;
	logfile.open(filename, std::ios_base::trunc); // trunc 모드: 파일을 열 때 내용을 지우고 새로운 내용을 추가
	//logfile.open(filename, std::ios_base::app); // app 모드: 파일 끝에 내용을 추가

	// 파일이 정상적으로 열렸는지 확인
	if (!logfile.is_open()) {
		std::cerr << "Error: Unable to open log file " << filename << std::endl;
	}

	logfile << logMessage << std::endl;

	srand(time(NULL));
	SetNumThreads(8);
	TimeUtils timeutils;
	Ring ring;
	long n = (1 << logn);

	//1. generate a global A = [a1, a2, ..., aN] 
	cout << "1. generate a global A = [a1, a2, ..., aN] " << endl;
	logfile << "1. generate a global A = [a1, a2, ..., aN]\n " << std::endl;
	ZZ* A = new ZZ[N];
	ring.sampleUniform2(A, logQQ);

	// A -> keyA
	uint64_t* keyA = new uint64_t[Nnprimes]();
	ring.CRT(keyA, A, nprimes);

	// 2. create a secret key si
	// SecretKey 배열을 생성하여 각 사용자에 대한 SecretKey를 저장합니다.
	cout << endl;
	cout << "2. create a secret key si" << endl;
	logfile << "2. create a secret key si\n" << std::endl;
	std::vector<SecretKey> si_array;
	for (int i = 0; i < user_num; ++i) {
		si_array.push_back(SecretKey(ring));
	}
	for (int i = 0; i < user_num; i++) {
		for (int j = 0; j < N; j++) {
			if(si_array[i].sx[j]!=ZZ(0))	logfile << "zkgh user " << i << "/ sx[" << j << "]: " << si_array[i].sx[j] << " ";
		}
		logfile << endl;
	}


	// and a public key Bi = -A*si + e0i
	cout << "and a public key Bi = -A*si + e0i" << endl;
	logfile << "and a public key Bi = -A*si + e0i\n " << std::endl;
	ZZ** bi_array = new ZZ * [user_num];
	for (int i = 0; i < user_num; ++i) {
		bi_array[i] = new ZZ[N];
		long np = ceil((1 + logQQ + logN + 2) / (double)pbnd);
		ring.mult(bi_array[i], si_array[i].sx, A, np, QQ);
		ring.subFromGaussAndEqual(bi_array[i], QQ);
	}

	delete[] A;

	// 3. choose a random vi
	cout << endl;
	cout << "3. choose a random vi" << endl;
	logfile << "3. choose a random vi\n " << std::endl;
	ZZ qQ = ring.qpows[logq + logQ];

	ZZ** vi_array = new ZZ * [user_num];
	for (int i = 0; i < user_num; ++i) {
		vi_array[i] = new ZZ[N];
		ring.sampleZO(vi_array[i]);
	}

	//generate a commitment ci = keyA*vi+e0i
	cout << "generate a commitment ci = keyA*vi+e0i" << endl;
	logfile << "generate a commitment ci = keyA*vi+e0i\n " << std::endl;
	ZZ** ci_array = new ZZ * [user_num];
	for (int i = 0; i < user_num; i++) {
		ci_array[i] = new ZZ[N];
		long np = ceil((1 + logQQ + logN + 2) / (double)pbnd);
		ring.multNTT(ci_array[i], vi_array[i], keyA, np, qQ);
		ring.rightShiftAndEqual(ci_array[i], logQ);
		ring.addGaussAndEqual(ci_array[i], qQ);
	}

	// Bi, Ci 만들고 keyA안 쓰니까 삭제
	delete[] keyA;

	// 4. compute b = sum(Bi) and c = sum(ci)
	cout << endl;
	cout << "4. compute B = sum(Bi)" << endl;
	logfile << "4. compute B = sum(Bi)\n " << std::endl;
	ZZ* bSum = new ZZ[N];
	std::copy(bi_array[0], bi_array[0] + N, bSum);
	for (int i = 1; i < user_num; i++) {
		ZZ q = ring.qpows[logq];
		cout << "bsum[0](before): " << bSum[0] << endl;//zkgh
		cout << "bi_array[0]: " << bi_array[i][0] << endl;
		ring.addAndEqual(bSum, bi_array[i], q);
		cout << "bsum[0](after): " << bSum[0] << endl;
		cout << endl;
	}

	//b를 만들었으므로, bi_array 이제 필요없음. 삭제
	for (int i = 0; i < user_num; ++i) {
		delete[] bi_array[i];
	}
	delete[] bi_array;

	// B -> keyB
	uint64_t* keyB = new uint64_t[Nnprimes]();
	ring.CRT(keyB, bSum, nprimes);
	delete[] bSum;

	cout << "and compute C = sum(ci)" << endl;
	logfile << "and compute C = sum(ci)\n " << std::endl;
	ZZ* cSum = new ZZ[N];
	std::copy(ci_array[0], ci_array[0] + N, cSum);

	for (int i = 1; i < user_num; i++) {
		ZZ q = ring.qpows[logq];

		cout << "csum[0](before): " << cSum[0] << endl;//zkgh
		cout << "ci_array[0]: " << ci_array[i][0] << endl;
		ring.addAndEqual(cSum, ci_array[i], q);
		cout << "csum[0](after): " << cSum[0] << endl;
		cout << endl;
	}

	//C를 만들었으므로, ci_array 이제 필요없음. 삭제
	for (int i = 0; i < user_num; ++i) {
		delete[] ci_array[i];
	}
	delete[] ci_array;


	// 라운드 시작~!!
	int totalMsumDiffError = 0;
	int totalWsumDiffError = 0;
	for (int round = 0; round < round_num; round++) {
		cout << "\n============= round " << round + 1 << " start ===============" << endl;
		logfile << "\n============= round " << round + 1 << " start ===============\n " << std::endl;

		// 5. choose a random mask Mi
		cout << endl;
		cout << "5. choose a random mask Mi" << endl;
		logfile << "5. choose a random mask Mi\n " << std::endl;

		// user_num 만큼의 -5부터 5까지의 랜덤값 Mi 생성 ✨✨
		//std::complex<double>* Mi_array = EvaluatorUtils::generateRandomIntValues(user_num);
		std::complex<double>* Mi_array = EvaluatorUtils::generateRandomRealValues(user_num);
		for (int i = 0; i < user_num; i++) {
			logfile << "client " << i << "'s M = " << Mi_array[i] << endl;
		}

		// and generate Di = Wi + Mi
		// user_num 만큼의 w배열 생성(2차원 배열)
		// cout << "[print Wi]" << endl;
		std::complex<double>** Wi_array = EvaluatorUtils::generateRandomRealArrays(n, user_num);

		// for (int i = 0; i < user_num; ++i) {
		//     for (int j = 0; j < n; ++j) {
		//             cout << "W" << i << "[" << j << "]: " << Wi_array[i][j].real() << endl; // 실수부만 출력 (실수부에만 값 할당함)
		//     }
		// }

		/*Wi+Mi 수행해서 Di 만들기*/
		cout << endl;
		cout << "and generate Di = Wi + Mi" << endl;
		logfile << "and generate Di = Wi + Mi" << endl;

		complex<double>** Di_array = new complex<double>*[user_num];
		for (int j = 0; j < user_num; j++) {
			Di_array[j] = new complex<double>[n];
			for (int i = 0; i < n; i++) {
				Di_array[j][i] = Wi_array[j][i] + Mi_array[j];  // 각 사용자의 Wi + Mi 계산

			}
		}

		for (int i = 0; i < user_num; ++i) {
			logfile << ">> client " << i << endl;
			for (int j = 0; j < print_num; ++j) {
				logfile << "D" << i << "[" << j << "]: " << Di_array[i][j].real() << " = W" << i << "[" << j << "](" << Wi_array[i][j].real() << ") + M" << i << "(" << Mi_array[i].real() << ")" << endl;
			}
			logfile << n - print_num << "more ... " << endl;
		}

		// and PDi = vi*B + Mi + e1i + C*si

		// vi*B + Mi + e1i -> Mi의 암호화 (근데 Mi가 double이라서 정수로 바꿔줘야함) ✨✨
		cout << endl;
		cout << "and PDi = vi*keyB + Mi + e1i + C*si" << endl;
		logfile << endl;
		logfile << "and PDi = vi*keyB + Mi + e1i + C*si" << endl;
		ZZ** PDi_array = new ZZ * [user_num];
		for (int i = 0; i < user_num; ++i) {
			PDi_array[i] = new ZZ[N];
			long np = ceil((1 + logQQ + logN + 2) / (double)pbnd);
			ring.multNTT(PDi_array[i], vi_array[i], keyB, np, qQ);

			Plaintext plain;
			// encode 과정 ✨✨
			// Scheme::encodeSingle(plain, Mi_array[i], logp, logq); - 객체없이 호출 못해서 아래처럼 뺐다.
			plain.logp = logp;
			plain.logq = logq;
			plain.n = 1;
			plain.mx[0] = EvaluatorUtils::scaleUpToZZ(Mi_array[i].real(), logp + logQ);
			plain.mx[Nh] = EvaluatorUtils::scaleUpToZZ(Mi_array[i].imag(), logp + logQ);

			//encryptMsg
			ring.addAndEqual(PDi_array[i], plain.mx, qQ);

			ring.rightShiftAndEqual(PDi_array[i], logQ);
			ring.addGaussAndEqual(PDi_array[i], qQ);

			// += C*si
			ZZ* Csi = new ZZ[N];
			ring.mult(Csi, si_array[i].sx, cSum, np, QQ); //C*si -> Csi에 저장
			ZZ q = ring.qpows[logq];
			ring.addAndEqual(PDi_array[i], Csi, q);
			delete[] Csi; //zkgh
		}


		//6. compute D = Sum(Di), PD = Sum(PDi)
		cout << endl;
		cout << "6. compute D = Sum(Di)" << endl;

		logfile << endl;
		logfile << "6. compute D = Sum(Di)" << endl;
		//D는 double W + double M 
		complex<double>* Dsum = new complex<double>[n];
		for (int i = 0; i < n; i++) {
			for (int j = 0; j < user_num; j++) {
				Dsum[i] += Di_array[j][i];  // Di 합산
			}
		}

		for (int i = 0; i < print_num; i++) {
			logfile << "D[" << i << "] = " << Dsum[i].real() << " = ";
			for (int j = 0; j < user_num; j++) {
				logfile << "D" << j << "[" << i << "](" << Di_array[j][i].real() << ")";  // Di 합산
				if (j == user_num - 1) {
					logfile << endl;
				}
				else {
					logfile << " + ";
				}
			}
		}
		logfile << n - print_num << "more ... " << endl;
		logfile << endl;

		// Di_array의 메모리 해제
		for (int j = 0; j < user_num; j++) {
			delete[] Di_array[j];
		}
		delete[] Di_array;


		cout << "and compute PD = Sum(PDi)" << endl;
		logfile << "and compute PD = Sum(PDi)" << endl;
		ZZ* PDsum = new ZZ[N];

		// //addAndEqual 사용 x 버전
		//for (int i = 0; i < N; i++) {
		//	PDsum[i] = 0; // 초기화
		//	for (int j = 0; j < user_num; j++) {
		//		logfile << "zkgh pdi[0]" << PDi_array[j][0] << endl;
		//		PDsum[i] += PDi_array[j][i];  // PDi 합산
		//	}
		//}

		// addAndEqual 사용 o 버전
		logfile << "user_num: 0"  << endl;
		logfile << "zkgh PDSum[0](before)" << PDsum[0] << endl;
		logfile << "zkgh PDi_array[0]" << PDi_array[0][0] << endl;
		std::copy(PDi_array[0], PDi_array[0] + N, PDsum);
		logfile << "zkgh PDSum[0](after)" << PDsum[0] << endl;
		for (int i = 1; i < user_num; i++) {
			cout << "user_num: " << i << endl;
			logfile << "zkgh PDSum[0](before)" << PDsum[0] << endl;
			logfile << "zkgh PDi_array[0]" << PDi_array[i][0] << endl;
			ZZ q = ring.qpows[logq];
			ring.addAndEqual(PDsum, PDi_array[i], q);
			logfile << "zkgh PDSum[0](after)" << PDsum[0] << endl;
		}


		for (int i = 0; i < user_num; ++i) { //zkgh
			delete[] PDi_array[i];
		}
		delete[] PDi_array;

		//decodeSingle - 객체없이 호출 못해서 아래처럼 뺐다. ✨✨
		ZZ q = ring.qpows[logq];

		complex<double> decode_PDsum;

		ZZ tmp = PDsum[0] % q;
		logfile << "zkgh tmp" << tmp << endl;
		if (NumBits(tmp) == logq) {
			logfile << "zkgh did" << q << endl;
			tmp -= q;
		}
		decode_PDsum.real(EvaluatorUtils::scaleDownToReal(tmp, logp));
		logfile << "zkgh PDsum[0]" << PDsum[0] << endl;
		logfile << "zkgh q" << q << endl;
		logfile << "zkgh decode_PDsum" << decode_PDsum << endl;

		tmp = PDsum[Nh] % q;
		if (NumBits(tmp) == logq) tmp -= q;
		decode_PDsum.imag(EvaluatorUtils::scaleDownToReal(tmp, logp));
		//

		logfile << "PD (decoded)= " << decode_PDsum << endl;
		logfile << endl;

		//decoded_PDsum 만들고 PDsum 삭제
		delete[] PDsum;


		cout << "[compare Msum]" << endl;
		logfile << "[compare Msum]" << endl;
		logfile << "PD = Sum(PDi)는 Msum = Sum(Mi)와 같아야한다." << endl;
		logfile << "PD (decoded)= " << decode_PDsum << endl;
		complex<double> Msum;
		for (int i = 0; i < user_num; i++) {
			Msum += Mi_array[i]; // Msum에 Mi_array[i] 추가
		}

		// Msum 출력
		logfile << "Msum = " << Msum.real() << " = ";
		for (int i = 0; i < user_num; i++) {
			logfile << "M" << i << "(" << Mi_array[i].real() << ")";
			if (i == user_num - 1) {
				logfile << endl;
			}
			else {
				logfile << " + ";
			}
		}
		delete[] Mi_array;

		logfile << "---------------------" << endl;
		logfile << "★round : " << round + 1 << " / Msum - PD (두 값의 차이 비교) ★:" << Msum - decode_PDsum << endl;
		logfile << "---------------------" << endl;

		if (std::abs(Msum - decode_PDsum) > 1e-5) {
			totalMsumDiffError++;
		}

		logfile << endl;
		//cout << "mMsum = Msum = Sum(Mi) , dMsum = PD (decoded) = Sum(PDi)" << endl;
		//StringUtils::compare(Msum, decode_PDsum, n, "Msum");

		//------------------------------

		// decode_Wsum = D-PD
		complex<double>* decode_Wsum = new complex<double>[n];
		for (int i = 0; i < n; i++) {
			decode_Wsum[i] = Dsum[i] - decode_PDsum;
		}

		cout << "[compare Wsum]" << endl;
		logfile << endl;
		logfile << "[compare Wsum]" << endl;
		logfile << "(PD-D로 얻어진) Wsum" << endl;
		for (int i = 0; i < print_num; i++) {
			logfile << "Wsum[" << i << "] = " << decode_Wsum[i].real() << " = D[" << i << "](" << Dsum[i].real() << ") - PD[" << i << "](" << decode_PDsum.real() << ")" << endl;
		}
		logfile << n - print_num << "more ... " << endl;

		logfile << endl;

		complex<double>* wSum = new complex<double>[n]();
		/*Wi_array 있는 w배열들을 다 더하기 = w1+w2+w3+w4+...*/
		for (int i = 0; i < n; i++) {
			for (int j = 0; j < user_num; j++) {
				wSum[i] += Wi_array[j][i];
			}
		}

		logfile << "(Wi의 합으로 얻어진) Wsum" << endl;
		for (int i = 0; i < print_num; i++) {
			logfile << "wSum[" << i << "] = " << wSum[i].real() << " = ";
			for (int j = 0; j < user_num; j++) {
				logfile << "W" << j << "[" << i << "](" << Wi_array[j][i].real() << ")";
				if (j == user_num - 1) {
					logfile << endl;
				}
				else {
					logfile << " + ";
				}
			}
		}
		logfile << n - print_num << "more ... " << endl;
		// Wi_array 삭제
		for (int i = 0; i < user_num; ++i) {
			delete[] Wi_array[i];
		}
		delete[] Wi_array;

		logfile << endl;
		logfile << "★ [설명 : mMKHE = (Wi의 합으로 얻어진) Wsum , dMKHE = (PD-D로 얻어진) Wsum] ★" << endl;
		//StringUtils::compare(wSum, decode_Wsum, n, "MKHE");

		int WsumDiffError = 0;
		for (long i = 0; i < n; ++i) {
			if (i < print_num) {
				logfile << "---------------------" << endl;
				logfile << "mMKHE : " << i << " :" << wSum[i] << endl;
				logfile << "dMKHE : " << i << " :" << decode_Wsum[i] << endl;
				logfile << "eMKHE : " << i << " :" << std::abs(wSum[i] - decode_Wsum[i]) << endl;
				logfile << "---------------------" << endl;
			}
			double diff = std::abs(wSum[i] - decode_Wsum[i]);
			if (diff > 1e-5) {
				WsumDiffError++;
				totalWsumDiffError++;
			}
		}
		logfile << n - print_num << "more ... " << endl;

		delete[] Dsum;
		delete[] decode_Wsum; //= D-PD
		delete[] wSum;



		cout << "round : " << round + 1 << " / WsumDiffError : " << WsumDiffError << endl;
		logfile << "round : " << round + 1 << " / WsumDiffError : " << WsumDiffError << endl;

		cout << "\n============= round " << round + 1 << " end ===============" << endl;
		logfile << "\n============= round " << round + 1 << " end ===============" << endl;

	}

	cout << endl;
	cout << "!!! END TEST MKHE !!!" << endl;
	logfile << endl;
	logfile << "!!! END TEST MKHE !!!" << endl;

	cout << "logn : " << logn << ", user_num : " << user_num << ", round_num : " << round_num << endl;
	logfile << "logn : " << logn << ", user_num : " << user_num << ", round_num : " << round_num << endl;
	cout << "totalMsumDiffError : " << totalMsumDiffError << " / totalWsumDiffError : " << totalWsumDiffError << endl;
	logfile << "totalMsumDiffError : " << totalMsumDiffError << " / totalWsumDiffError : " << totalWsumDiffError << endl;

	// 파일 닫기
	logfile.close();
}

void TestScheme::testMKHEFinal(long logq, long logp, long logn, int user_num, int round_num, bool iid_mode) {
	
	// [파이썬 설정]
	Py_Initialize();
	PyObject* pModule_fl, * pFunc, * pValue;
	PyRun_SimpleString("from time import time,ctime\n"
		"print('Today is', ctime(time()))\n");

	// 모듈이 위치한 디렉토리 추가 (환경에 따라 수정 필요!!)
	PyRun_SimpleString("import sys");
	PyRun_SimpleString("sys.path.append(\"/home/lab/CSA-2/\")");
	PyRun_SimpleString("sys.path.append(\"/home/lab/learning/\")");

	// sys.path를 가져오기 위한 코드 실행
	PyObject *sys_path = PyObject_GetAttrString(PyImport_ImportModule("sys"), "path");
	pModule_fl = PyImport_ImportModule("learning.federated_mainV2");
	// 모듈이 제대로 가져와졌는지 확인
	if (pModule_fl != NULL) {
		// Python 모듈 내용 출력
		PyObject_Print(pModule_fl, stdout, 0);
		//cout << endl;
	}
	else {
		std::cerr << "Failed to import module" << std::endl;
		PyErr_Print();
	}

	/////////////////////////////////////////////////////////////////////////////////////////////////////
	// [로그 설정]
	cout << "!!! START TEST FINAL !!!" << endl;

	// 로그를 저장할 파일 경로
	std::string filename = "FINAL.txt";

	// 로그 내용
	std::time_t currentTime = std::time(nullptr);
	std::string currentTimeStr = std::ctime(&currentTime);
	std::string logMessage = currentTimeStr + " FINAL 테스트 시작\n";

	// 파일 열기
	std::ofstream logfile;
	logfile.open(filename, std::ios_base::trunc); // trunc 모드: 파일을 열 때 내용을 지우고 새로운 내용을 추가
	logfile << logMessage << std::endl;

	// 파일이 정상적으로 열렸는지 확인
	if (!logfile.is_open()) {
		std::cerr << "Error: Unable to open log file " << filename << std::endl;
	}
	/////////////////////////////////////////////////////////////////////////////////////////////////////
	// [프로젝트 설정]
	user_num = user_num;
	round_num = 101;
	int print_num = 4;

	srand(time(NULL));
	TimeUtils timeutils;
	Ring ring;
	//long n = (1 << logn);
	long n = 21840;

	//1. generate a global A = [a1, a2, ..., aN] 
	cout << "1. generate a global A = [a1, a2, ..., aN] " << endl;
	logfile << "1. generate a global A = [a1, a2, ..., aN]\n " << std::endl;
	ZZ* A = new ZZ[N];
	ring.sampleUniform2(A, logQQ);

	// A -> keyA
	uint64_t* keyA = new uint64_t[Nnprimes]();
	ring.CRT(keyA, A, nprimes);

	// 2. create a secret key si
	// SecretKey 배열을 생성하여 각 사용자에 대한 SecretKey를 저장합니다.
	cout << endl;
	cout << "2. create a secret key si" << endl;
	logfile << "2. create a secret key si\n" << std::endl;
	std::vector<SecretKey> si_array;
	for (int i = 0; i < user_num; ++i) {
		si_array.push_back(SecretKey(ring));
	}
	for (int i = 0; i < user_num; i++)   logfile << "user " << i << "'s si: " << si_array[i].sx << endl;

	// and a public key Bi = -A*si + e0i
	cout << "and a public key Bi = -A*si + e0i" << endl;
	logfile << "and a public key Bi = -A*si + e0i\n " << std::endl;
	ZZ** bi_array = new ZZ * [user_num];
	for (int i = 0; i < user_num; ++i) {
		bi_array[i] = new ZZ[N];
		long np = ceil((1 + logQQ + logN + 2) / (double)pbnd);
		ring.mult(bi_array[i], si_array[i].sx, A, np, QQ);
		ring.subFromGaussAndEqual(bi_array[i], QQ);
	}

	delete[] A;

	// 3. choose a random vi
	cout << endl;
	cout << "3. choose a random vi" << endl;
	logfile << "3. choose a random vi\n " << std::endl;
	ZZ qQ = ring.qpows[logq + logQ];

	ZZ** vi_array = new ZZ * [user_num];
	for (int i = 0; i < user_num; ++i) {
		vi_array[i] = new ZZ[N];
		ring.sampleZO(vi_array[i]);
	}
	for (int i = 0; i < user_num; i++) {
		for (int j = 0; j < 10; j++) {
			logfile << "user " << i << "의 vi (크기는 ZZ[N]): " << vi_array[i][j] << endl;
		}
		logfile << N - n << " more..\n";
	}


	//generate a commitment ci = keyA*vi+e0i
	cout << "generate a commitment ci = keyA*vi+e0i" << endl;
	logfile << "generate a commitment ci = keyA*vi+e0i\n " << std::endl;
	ZZ** ci_array = new ZZ * [user_num];
	for (int i = 0; i < user_num; i++) {
		ci_array[i] = new ZZ[N];
		long np = ceil((1 + logQQ + logN + 2) / (double)pbnd);
		ring.multNTT(ci_array[i], vi_array[i], keyA, np, qQ);
		ring.rightShiftAndEqual(ci_array[i], logQ);
		ring.addGaussAndEqual(ci_array[i], qQ);
	}

	// Bi, Ci 만들고 keyA안 쓰니까 삭제
	delete[] keyA;

	// 4. compute b = sum(Bi) and c = sum(ci)
	cout << endl;
	cout << "4. compute B = sum(Bi)" << endl;
	logfile << "4. compute B = sum(Bi)\n " << std::endl;
	ZZ* bSum = new ZZ[N];
	std::copy(bi_array[0], bi_array[0] + N, bSum); //첫번째 유저를 초기값으로 넣어두고
	for (int i = 1; i < user_num; i++) { //같은 배열에 나머지 유저들 값 넣어서 sum구함
		ZZ q = ring.qpows[logq];
		ring.addAndEqual(bSum, bi_array[i], q);
	}

	//b를 만들었으므로, bi_array 이제 필요없음. 삭제
	for (int i = 0; i < user_num; ++i) {
		delete[] bi_array[i];
	}
	delete[] bi_array;

	// B -> keyB
	uint64_t* keyB = new uint64_t[Nnprimes]();
	ring.CRT(keyB, bSum, nprimes);
	delete[] bSum;

	cout << "and compute C = sum(ci)" << endl;
	logfile << "and compute C = sum(ci)\n " << std::endl;
	ZZ* cSum = new ZZ[N];
	std::copy(ci_array[0], ci_array[0] + N, cSum);

	for (int i = 1; i < user_num; i++) {
		ZZ q = ring.qpows[logq];
		ring.addAndEqual(cSum, ci_array[i], q);
	}

	//C를 만들었으므로, ci_array 이제 필요없음. 삭제
	for (int i = 0; i < user_num; ++i) {
		delete[] ci_array[i];
	}
	delete[] ci_array;

	int totalMsumDiffError = 0;
	int totalWsumDiffError = 0;
	complex<double>** my_Wi = new complex<double>*[user_num];
    for (int i = 0; i < user_num; ++i) {
    	my_Wi[i] = new complex<double>[n];
    }
	// 라운드 시작~!!
	for (int round = 0; round < round_num; round++) {
		cout << "\n============= round " << round + 1 << " start ===============" << endl;
		logfile << "\n============= round " << round + 1 << " start ===============\n " << std::endl;

		// 5. choose a random mask Mi
		cout << endl;
		cout << "5. choose a random mask Mi" << endl;
		logfile << "5. choose a random mask Mi\n " << std::endl;

		// user_num 만큼의 -5부터 5까지의 랜덤값 Mi 생성 ✨✨
		//std::complex<double>* Mi_array = EvaluatorUtils::generateRandomIntValues(user_num);
		std::complex<double>* Mi_array = EvaluatorUtils::generateRandomRealValues(user_num);
		for (int i = 0; i < user_num; i++) {
			logfile << "client " << i << "'s M = " << Mi_array[0] << endl;
		}

		//////////////////////////////////////////////////////////
		cout << "\n=========setup==========" << endl;
		cout << "[사용자마다의 모델 생성 - setup]" << std::endl;
		// 사용자 각각의 모델 생성
    	PyObject** pGlobalModels = new PyObject*[user_num];
    	// Initialize all pointers to NULL
    	for (int i = 0; i < user_num; i++) {
        	pGlobalModels[i] = NULL;
    	}
		// 파이썬 함수 호출
		// setup 함수 호출(global model얻기 위함)
		pystate = PyGILState_Ensure();
		pFunc = PyObject_GetAttrString(pModule_fl, "setup");
		if (pFunc == NULL) {
			std::cerr << "Failed to get function pointer" << std::endl;
			PyErr_Print();
		}
		else {
			cout << "setup 시작" << endl;
			for (int i = 0; i < user_num; ++i) { //사용자마다 모델 생성
				 // Boolean 값을 인자로 전달 (예: true 값)
			    PyObject* pArgs = Py_BuildValue("(O)", iid_mode ? Py_True : Py_False); // Py_True 또는 Py_False 사용

        		PyObject* pValue = PyObject_CallObject(pFunc, pArgs); // 함수호출
        		Py_DECREF(pArgs); // pArgs 해제
				
				if (pValue != NULL) {
            		pGlobalModels[i] = pValue;  // Store the returned value
					cout << "user " << i << "의 globalModel = " << pGlobalModels[i] << endl;
            		Py_INCREF(pGlobalModels[i]); // Increase reference count
        		} else {
            		std::cerr << "Error occurred during the execution of the setup function for user " << i << std::endl;
            		PyErr_Print(); // Print error details from the Python interpreter
        		}
    		}
		}


		if (round > 0) {
			//////////////////////////////////////////////////////////
			cout << "\n=========finalAggregationV2==========" << endl;
			pFunc = PyObject_GetAttrString(pModule_fl, "finalAggregationV2");
			if (pFunc == NULL || !PyCallable_Check(pFunc)) { // 함수가 존재하고 callable 한지 확인
				std::cerr << "Failed to get function pointer or function is not callable" << std::endl;
				PyErr_Print(); // 에러 출력
			}
			else {
				for (int idx =0; idx<user_num; idx++){ //사용자마다 반복
					PyObject* pyList = PyList_New(n);
					if (!pyList) {
						cout << "pyLIST생성실패" << endl;
					}
					for (int i = 0; i < n; i++) {
						//decodeWsum -> python list
						PyObject* pyVal = PyFloat_FromDouble(my_Wi[idx][i].real());
						PyList_SetItem(pyList, i, pyVal);
					}
					cout << "\n---- user " << idx << "의 finalAggregationV2 (모델에 기존 W를 입히는 작업) ----"<<endl;
					pValue = PyObject_CallFunctionObjArgs(pFunc, pGlobalModels[idx], pyList, PyLong_FromLong(round), PyLong_FromLong(idx), NULL); // 함수 호출
					if (pValue != NULL) {
						// 반환값 처리
						Py_XDECREF(pGlobalModels[idx]); // 기존에 참조된 객체 해제
						pGlobalModels[idx] = pValue; // 새로운 객체 참조로 할당
					}
					else {
						// 함수 호출 중 오류 발생
						PyErr_Print(); // 에러 출력
					}
				}
			}
		}else{ // 첫번째라운드면 초기값으로 설정
			cout << "\n=========setInitalWeight==========" << endl;
			pFunc = PyObject_GetAttrString(pModule_fl, "setInitalWeight");
			if (pFunc == NULL || !PyCallable_Check(pFunc)) { // 함수가 존재하고 callable 한지 확인
				std::cerr << "Failed to get function pointer or function is not callable" << std::endl;
				PyErr_Print(); // 에러 출력
			}
			else {
				for (int idx =0; idx<user_num; idx++){ //사용자마다 반복
					cout << "\n---- user " << idx << "의 setInitalWeight (모델에 초기값 W를 입히는 작업) ----"<<endl;
					pValue = PyObject_CallFunctionObjArgs(pFunc, pGlobalModels[idx], PyLong_FromLong(round), NULL); // 함수 호출
					if (pValue != NULL) {
						// 반환값 처리
						Py_XDECREF(pGlobalModels[idx]); // 기존에 참조된 객체 해제
						pGlobalModels[idx] = pValue; // 새로운 객체 참조로 할당
					}
					else {
						// 함수 호출 중 오류 발생
						PyErr_Print(); // 에러 출력
					}
				}
			}
		}

		//////////////////////////////////////////////////////////
		cout << "\n=========local_update==========" << endl;
		cout << "\n[사용자마다의 모델 학습(새로운 W 갱신) - local_update]" << std::endl;
		pFunc = PyObject_GetAttrString(pModule_fl, "local_update");
		if (pFunc == NULL || !PyCallable_Check(pFunc)) { // 함수가 존재하고 callable 한지 확인
			std::cerr << "Failed to get function pointer or function is not callable" << std::endl;
			PyErr_Print(); // 에러 출력
		}
		else {
			for (int idx =0; idx<user_num; idx++){ //사용자마다 반복
				cout << "---- user " << idx << "의 local_update ----"<<endl;
				pValue = PyObject_CallFunctionObjArgs(pFunc, PyLong_FromLong(user_num), pGlobalModels[idx], PyLong_FromLong(idx), PyLong_FromLong(round), NULL); // 함수 호출
				if (pValue != NULL) {
					cout << "pvalue null아님" << endl;
					// 반환값 처리
					if (PyList_Check(pValue)) {
						cout << "pvalue list임" << endl;
						Py_ssize_t size = PyList_Size(pValue); // 리스트의 길이
						for (Py_ssize_t i = 0; i < size; ++i) {
							PyObject* pItem = PyList_GetItem(pValue, i); // 리스트의 i번째 요소 가져오기
							if (PyFloat_Check(pItem)) { // 요소가 float 형태인지 확인
								double value = PyFloat_AsDouble(pItem); // float를 double로 변환
								//cout << "my_Wi갱신" << endl;
								my_Wi[idx][i].real(value);
								//Py_DECREF(pItem);
							}
							else {
								cout << "pvalue list item float아님" << endl;
							}
						}
						cout << "user " << idx<< "의 W 갱신 완료\n" << endl;
					}
					else {
						cout << "pvalue list아님" << endl;
					}
				}
				else {
					cout << "pvalue null임" << endl;
					PyErr_Print();
				}
			}
		}

		PyGILState_Release(pystate); //GIL해방
		cout << endl;
	
		//////////////////////////////////////////////////////////	
		// Wsum 구하기 전에, W값에 가중치 부여
		// for (int idx =0; idx<user_num; idx++){ //사용자마다 반복
		// 	double trainning_weight = 1.0/user_num; // 동일 사이즈 가정 - 가중치
		// 	for (int i = 0; i < n; i++) { //가중치 적용
		// 		my_Wi[idx][i].real(my_Wi[idx][i].real() * trainning_weight);
		// 	}
		// }

		// and generate Di = Wi + Mi
		// user_num 만큼의 w배열 생성(2차원 배열) 💡😇
		// cout << "[print Wi]" << endl;
	 	//std::complex<double>* just_Wi_sum = new std::complex<double>[n];

		// for (int i = 0; i < user_num; i++) {
		// 	double weight = userDataNum[i] / static_cast<double>(totalDataNum); //가중치
		// 	cout << "user " << i << "의 weight 가중치 = " << weight << "= " << userDataNum[i] << "/" << totalDataNum << endl;
		// 	for (int j = 0; j < n; j++) {
		// 		just_Wi_sum[j] += my_Wi[i][j];
		// 		cout << my_Wi[i][j].real() << "->";
		// 		my_Wi[i][j] *= weight;
		// 		cout << my_Wi[i][j].real() << endl;
		// 	}
		// }


	// 	// W 배열 출력하는 코드
	// 	// for (int i = 0; i < user_num; ++i) {
	// 	//     for (int j = 0; j < n; ++j) {
	// 	//             cout << "W" << i << "[" << j << "]: " << Wi_array[i][j].real() << endl; // 실수부만 출력 (실수부에만 값 할당함)
	// 	//     }
	// 	// }

		/*Wi+Mi 수행해서 Di 만들기*/
		cout << endl;
		cout << "and generate Di = Wi + Mi" << endl;
		logfile << "and generate Di = Wi + Mi" << endl;

		complex<double>** Di_array = new complex<double>*[user_num];
		for (int j = 0; j < user_num; j++) {
			Di_array[j] = new complex<double>[n];
			for (int i = 0; i < n; i++) {
				Di_array[j][i] = my_Wi[j][i] + Mi_array[0];  // 각 사용자의 Wi + Mi 계산

			}
		}

	// 	for (int i = 0; i < user_num; ++i) {
	// 		logfile << ">> client " << i << endl;
	// 		for (int j = 0; j < print_num; ++j) {
	// 			logfile << "D" << i << "[" << j << "]: " << Di_array[i][j].real() << " = W" << i << "[" << j << "](" << my_Wi[i][j].real() << ") + M" << i << "(" << Mi_array[0].real() << ")" << endl;
	// 		}
	// 		logfile << n - print_num << "more ... " << endl;
	// 	}

	 	// and PDi = vi*B + Mi + e1i + C*si

	 	// vi*B + Mi + e1i -> Mi의 암호화 (근데 Mi가 double이라서 정수로 바꿔줘야함) ✨✨
	 	cout << endl;
	 	cout << "and PDi = vi*keyB + Mi + e1i + C*si" << endl;
	// 	logfile << endl;
	// 	logfile << "and PDi = vi*keyB + Mi + e1i + C*si" << endl;
	 	ZZ** PDi_array = new ZZ * [user_num];
	 	for (int i = 0; i < user_num; ++i) {
	 		timeutils.start("user" + std::to_string(i) + "의 M을 PD로");
	 		PDi_array[i] = new ZZ[N];
	 		long np = ceil((1 + logQQ + logN + 2) / (double)pbnd);
	 		ring.multNTT(PDi_array[i], vi_array[i], keyB, np, qQ);

	 		Plaintext plain;
	 		// encode 과정 ✨✨
	 		// Scheme::encodeSingle(plain, Mi_array[i], logp, logq); - 객체없이 호출 못해서 아래처럼 뺐다.
	 		plain.logp = logp;
	 		plain.logq = logq;
	 		plain.n = 1;
	 		plain.mx[0] = EvaluatorUtils::scaleUpToZZ(Mi_array[0].real(), logp + logQ);
	 		plain.mx[Nh] = EvaluatorUtils::scaleUpToZZ(Mi_array[0].imag(), logp + logQ);

	 		//encryptMsg
	 		ring.addAndEqual(PDi_array[i], plain.mx, qQ); // + Mi(스케일업된거)

	 		ring.rightShiftAndEqual(PDi_array[i], logQ);
	 		ring.addGaussAndEqual(PDi_array[i], qQ); // + e1i

	// 		for (int j = 0; j < N; j++) {
	// 			logfile << "user " << i << " : cipher of M" << j << " = " << PDi_array[i][j] << endl;
	// 		}

			// += C*si
			ZZ* Csi = new ZZ[N];
			ring.mult(Csi, si_array[i].sx, cSum, np, QQ); //C*si -> Csi에 저장
			ZZ q = ring.qpows[logq];
			ring.addAndEqual(PDi_array[i], Csi, q);
			delete[] Csi; //zkgh
			timeutils.stop("user" + std::to_string(i) + "의 M을 PD로");
		}


	 	//6. compute D = Sum(Di), PD = Sum(PDi)
	 	cout << endl;
	 	cout << "6. compute D = Sum(Di)" << endl;

	// 	logfile << endl;
	// 	logfile << "6. compute D = Sum(Di)" << endl;
		//D는 double W + double M 
		complex<double>* Dsum = new complex<double>[n];
		for (int i = 0; i < n; i++) {
			for (int j = 0; j < user_num; j++) {
				Dsum[i] += Di_array[j][i];  // Di 합산
			}
		}

		for (int i = 0; i < print_num; i++) {
			logfile << "D[" << i << "] = " << Dsum[i].real() << " = ";
			for (int j = 0; j < user_num; j++) {
				logfile << "D" << j << "[" << i << "](" << Di_array[j][i].real() << ")";  // Di 합산
				if (j == user_num - 1) {
					logfile << endl;
				}
				else {
					logfile << " + ";
				}
			}
		}
		logfile << n - print_num << "more ... " << endl;
		logfile << endl;

		// Di_array의 메모리 해제
		for (int j = 0; j < user_num; j++) {
			delete[] Di_array[j];
		}
		delete[] Di_array;


		cout << "and compute PD = Sum(PDi)" << endl;
		logfile << "and compute PD = Sum(PDi)" << endl;
		ZZ* PDsum = new ZZ[N];

		// //addAndEqual 사용 x 버전
		//for (int i = 0; i < N; i++) {
		//   PDsum[i] = 0; // 초기화
		//   for (int j = 0; j < user_num; j++) {
		//      logfile << "zkgh pdi[0]" << PDi_array[j][0] << endl;
		//      PDsum[i] += PDi_array[j][i];  // PDi 합산
		//   }
		//}

		// addAndEqual 사용 o 버전
		// logfile << "user_num: 0" << endl;
		// logfile << "zkgh PDSum[0](before)" << PDsum[0] << endl;
		// logfile << "zkgh PDi_array[0]" << PDi_array[0][0] << endl;
		std::copy(PDi_array[0], PDi_array[0] + N, PDsum);
		// logfile << "zkgh PDSum[0](after)" << PDsum[0] << endl;
		for (int i = 1; i < user_num; i++) {
			//cout << "user_num: " << i << endl;
			// logfile << "zkgh PDSum[0](before)" << PDsum[0] << endl;
			// logfile << "zkgh PDi_array[0]" << PDi_array[i][0] << endl;
			ZZ q = ring.qpows[logq];
			ring.addAndEqual(PDsum, PDi_array[i], q);
			//logfile << "zkgh PDSum[0](after)" << PDsum[0] << endl;
		}


		for (int i = 0; i < user_num; ++i) { //zkgh
			delete[] PDi_array[i];
		}
		delete[] PDi_array;

		//decodeSingle - 객체없이 호출 못해서 아래처럼 뺐다. ✨✨
		ZZ q = ring.qpows[logq];

		complex<double> decode_PDsum;

		ZZ tmp = PDsum[0] % q;
		logfile << "zkgh tmp" << tmp << endl;
		if (NumBits(tmp) == logq) {
			logfile << "zkgh did" << q << endl;
			tmp -= q;
		}
		decode_PDsum.real(EvaluatorUtils::scaleDownToReal(tmp, logp));
		logfile << "zkgh PDsum[0]" << PDsum[0] << endl;
		logfile << "zkgh q" << q << endl;
		logfile << "zkgh decode_PDsum" << decode_PDsum << endl;

		tmp = PDsum[Nh] % q;
		if (NumBits(tmp) == logq) tmp -= q;
		decode_PDsum.imag(EvaluatorUtils::scaleDownToReal(tmp, logp));
		//

		logfile << "PD (decoded)= " << decode_PDsum << endl;
		logfile << endl;

		//decoded_PDsum 만들고 PDsum 삭제
		delete[] PDsum;


		//cout << "[compare Msum]" << endl;
		logfile << "[compare Msum]" << endl;
		logfile << "PD = Sum(PDi)는 Msum = Sum(Mi)와 같아야한다." << endl;
		logfile << "PD (decoded)= " << decode_PDsum << endl;
		
		complex<double> Msum;
		for (int i = 0; i < user_num; i++) {
			Msum += Mi_array[0]; // Msum에 Mi_array[i] 추가
		}

		// Msum 출력
		logfile << "Msum = " << Msum.real() << " = ";
		for (int i = 0; i < user_num; i++) {
			logfile << "M" << i << "(" << Mi_array[0].real() << ")";
			if (i == user_num - 1) {
				logfile << endl;
			}
			else {
				logfile << " + ";
			}
		}
		delete[] Mi_array;

		logfile << "---------------------" << endl;
		logfile << "★round : " << round + 1 << " / Msum - PD (두 값의 차이 비교) ★:" << Msum - decode_PDsum << endl;
		logfile << "---------------------" << endl;

		if (std::abs(Msum - decode_PDsum) > 1e-5) {
			totalMsumDiffError++;
		}

		logfile << endl;
		//cout << "mMsum = Msum = Sum(Mi) , dMsum = PD (decoded) = Sum(PDi)" << endl;
		//StringUtils::compare(Msum, decode_PDsum, n, "Msum");

		//------------------------------

		// decode_Wsum = D-PD
		complex<double>* decode_Wsum = new complex<double>[n];
		for (int i = 0; i < n; i++) {
			decode_Wsum[i] = Dsum[i] - decode_PDsum;
		}

		cout << "[compare Wsum]" << endl;
		// logfile << endl;
		// logfile << "[compare Wsum]" << endl;
		// logfile << "(PD-D로 얻어진) Wsum" << endl;
		// for (int i = 0; i < print_num; i++) {
		// 	logfile << "Wsum[" << i << "] = " << decode_Wsum[i].real() << " = D[" << i << "](" << Dsum[i].real() << ") - PD[" << i << "](" << decode_PDsum.real() << ")" << endl;
		// }

		// logfile << n - print_num << "more ... " << endl;


		cout << "(PD-D로 얻어진) Wsum" << endl;
		for (int i = 0; i < print_num; i++) {
			cout << "Wsum[" << i << "] = " << decode_Wsum[i].real() << " = D[" << i << "](" << Dsum[i].real() << ") - PD[" << i << "](" << decode_PDsum.real() << ")" << endl;
		}

		// logfile << endl;

		complex<double>* wSum = new complex<double>[n]();
		/*Wi_array 있는 w배열들을 다 더하기 = w1+w2+w3+w4+...*/
		for (int i = 0; i < n; i++) {
			for (int j = 0; j < user_num; j++) {
				wSum[i] += my_Wi[j][i];
			}
		}

		// logfile << "(Wi의 합으로 얻어진) Wsum" << endl;
		// for (int i = 0; i < print_num; i++) {
		// 	logfile << "wSum[" << i << "] = " << wSum[i].real() << " = ";
		// 	for (int j = 0; j < user_num; j++) {
		// 		logfile << "W" << j << "[" << i << "](" << my_Wi[j][i].real() << ")";
		// 		if (j == user_num - 1) {
		// 			logfile << endl;
		// 		}
		// 		else {
		// 			logfile << " + ";
		// 		}
		// 	}
		// }
		// logfile << n - print_num << "more ... " << endl;

		// cout << "(Wi의 합으로 얻어진) Wsum" << endl;
		// for (int i = 0; i < print_num; i++) {
		// 	cout << "wSum[" << i << "] = " << wSum[i].real() << " = ";
		// 	for (int j = 0; j < user_num; j++) {
		// 		cout << "W" << j << "[" << i << "](" << my_Wi[j][i].real() << ")";
		// 		if (j == user_num - 1) {
		// 			cout << endl;
		// 		}
		// 		else {
		// 			cout << " + ";
		// 		}
		// 	}
		// }

		cout << "=== my_Wi에 decode_Wsum 적용 ===" << endl;
		for (int user = 0; user < user_num; user++) {
			for (int i = 0; i < n; i++) {
				my_Wi[user][i].real(decode_Wsum[i].real());
			}
		}
		cout << "=== my_Wi에 decode_Wsum 적용완료 ===" << endl;
		
		// 로그를 저장할 파일 경로
		std::string filename = "weight_log.txt";

		// 파일 열기
		std::ofstream logfile2;
		logfile2.open(filename, std::ios_base::app); // trunc 모드: 파일을 열 때 내용을 지우고 새로운 내용을 추가
		logfile2 << "=== " <<round<< " ==="<<endl;
		logfile2 << "decode_Wsum[0].real() = " <<decode_Wsum[0].real()<<endl;
		logfile2 << "decode_Wsum[n-1].real() = " <<decode_Wsum[n-1].real()<<endl;

		// cout << "가중치 x Wsum" << endl;
		// for (int i = 0; i < n; i++) {
		// 	cout << "just_wSum[" << i << "] = " << just_Wi_sum[i].real() << endl;
		// }

		// cout << "가중치 x Wsum 평균낸 값" << endl;
		// for (int i = 0; i < n; i++) {
		// 	cout << "just_wSum[" << i << "] average = " << just_Wi_sum[i].real() / totalDataNum << endl;
		// }

		//==================

		// Wi_array 삭제
		// for (int i = 0; i < user_num; ++i) {
		// 	delete[] my_Wi[i];
		// }
		// delete[] my_Wi;

		logfile << endl;
		logfile << "★ [설명 : mMKHE = (Wi의 합으로 얻어진) Wsum , dMKHE = (PD-D로 얻어진) Wsum] ★" << endl;
		//StringUtils::compare(wSum, decode_Wsum, n, "MKHE");

		int WsumDiffError = 0;
		for (long i = 0; i < n; ++i) {
			if (i < print_num) {
				logfile << "---------------------" << endl;
				logfile << "mMKHE : " << i << " :" << wSum[i] << endl;
				logfile << "dMKHE : " << i << " :" << decode_Wsum[i] << endl;
				logfile << "eMKHE : " << i << " :" << std::abs(wSum[i] - decode_Wsum[i]) << endl;
				logfile << "---------------------" << endl;
			}
			double diff = std::abs(wSum[i] - decode_Wsum[i]);
			if (diff > 1e-5) {
				WsumDiffError++;
				totalWsumDiffError++;
			}
		}
		logfile << n - print_num << "more ... " << endl;

		delete[] Dsum;
		delete[] decode_Wsum; //= D-PD
		delete[] wSum;



		cout << "round : " << round + 1 << " / WsumDiffError : " << WsumDiffError << endl;
		logfile << "round : " << round + 1 << " / WsumDiffError : " << WsumDiffError << endl;

		cout << "\n============= round " << round + 1 << " end ===============" << endl;
		logfile << "\n============= round " << round + 1 << " end ===============" << endl;

	}
	//라운드 끝!

	//<결과 기록>
	cout << "\n============= 결과 기록 =============" << endl;
	pystate = PyGILState_Ensure();
	pFunc = PyObject_GetAttrString(pModule_fl, "write_result");
	if (pFunc == NULL || !PyCallable_Check(pFunc)) { // 함수가 존재하고 callable 한지 확인
		std::cerr << "Failed to get function pointer or function is not callable" << std::endl;
		PyErr_Print(); // 에러 출력
	}
	else {
		pValue = PyObject_CallFunctionObjArgs(pFunc, NULL); // 함수 호출
		if (pValue != NULL) {
			// 반환값 처리
		}
		else {
			// 함수 호출 중 오류 발생
			PyErr_Print(); // 에러 출력
		}
	}
	PyGILState_Release(pystate); //GIL해방

	for (int i = 0; i < user_num; ++i) {
		delete[] my_Wi[i];
	}
	delete[] my_Wi;

	cout << endl;
	cout << "!!! END TEST MKHE !!!" << endl;
	logfile << endl;
	logfile << "!!! END TEST MKHE !!!" << endl;

	cout << "logn : " << logn << ", user_num : " << user_num << ", round_num : " << round_num << endl;
	logfile << "logn : " << logn << ", user_num : " << user_num << ", round_num : " << round_num << endl;
	cout << "totalMsumDiffError : " << totalMsumDiffError << " / totalWsumDiffError : " << totalWsumDiffError << endl;
	logfile << "totalMsumDiffError : " << totalMsumDiffError << " / totalWsumDiffError : " << totalWsumDiffError << endl;

	// 파일 닫기
	logfile.close();
}


}  // namespace heaan
