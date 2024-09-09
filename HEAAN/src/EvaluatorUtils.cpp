/*
* Copyright (c) by CryptoLab inc.
* This program is licensed under a
* Creative Commons Attribution-NonCommercial 3.0 Unported License.
* You should have received a copy of the license along with this
* work.  If not, see <http://creativecommons.org/licenses/by-nc/3.0/>.
*/
#include "EvaluatorUtils.h"

#include <cmath>
#include <complex>
#include <cstdlib>

using namespace std;
using namespace NTL;

namespace heaan {

//----------------------------------------------------------------------------------
//   RANDOM REAL AND COMPLEX NUMBERS
//----------------------------------------------------------------------------------


double EvaluatorUtils::randomReal(double bound)  {
	return (double) rand()/(RAND_MAX) * bound;
}

complex<double> EvaluatorUtils::randomComplex(double bound) {
	complex<double> res;
	res.real(randomReal(bound));
	res.imag(randomReal(bound));
	return res;
}

complex<double> EvaluatorUtils::randomCircle(double anglebound) {
	double angle = randomReal(anglebound);
	complex<double> res;
	res.real(cos(angle * 2 * M_PI));
	res.imag(sin(angle * 2 * M_PI));
	return res;
}

double* EvaluatorUtils::randomRealArray(long n, double bound) {
	double* res = new double[n];
	for (long i = 0; i < n; ++i) {
		res[i] = randomReal(bound);
	}
	return res;
}

complex<double>* EvaluatorUtils::randomComplexArray(long n, double bound) {
	complex<double>* res = new complex<double>[n];
	for (long i = 0; i < n; ++i) {
		res[i] = randomComplex(bound);
	}
	return res;
}

complex<double>* EvaluatorUtils::randomCircleArray(long n, double bound) {
	complex<double>* res = new complex<double>[n];
	for (long i = 0; i < n; ++i) {
		res[i] = randomCircle(bound);
	}
	return res;
}

complex<double>** EvaluatorUtils::generateRandomRealArrays(long n, int user_num) {
	std::complex<double>** result = new std::complex<double>*[user_num];

	for (int i = 0; i < user_num; ++i) {
		result[i] = new std::complex<double>[n];
		for (int j = 0; j < n; ++j) {
			result[i][j].real(randomReal(1.0));
		}
	}

	return result;
}

complex<double>* EvaluatorUtils::generateRandomIntValues(int user_num, int min, int max) {
	std::complex<double>* result = new std::complex<double>[user_num];

	for (int i = 0; i < user_num; ++i) {
		result[i].real(rand() % (max - min + 1) + min);
	}

	return result;
}

complex<double>* EvaluatorUtils::generateRandomAlphaValues(int user_num, int min, int max) {
	std::complex<double>* result = new std::complex<double>[user_num];

	for (int i = 0; i < user_num; ++i) {
		double randomValue = randomReal(max);
		if (rand() % 2 == 0) {
			randomValue *= -1.0;
		}
		result[i].real(randomValue);
	}

	return result;
}

complex<double>** EvaluatorUtils::generateFLArrays(long n, int user_num) {
	std::complex<double>** result = new std::complex<double>*[user_num];

	for (int i = 0; i < user_num; ++i) {
		result[i] = new std::complex<double>[n];
		for (int j = 0; j < n; ++j) {
			int rnum = rand() % 9;
			switch (rnum) {
			case 0: rnum = 0; break;
			case 1: rnum = 1; break;
			case 2: rnum = 2; break;
			case 3: rnum = 3; break;
			case 4: rnum = 4; break;
			case 5: rnum = 5; break;
			case 6: rnum = 24376; break;
			case 7: rnum = 24377; break;
			default: rnum = 24378; break;
			}
			result[i][j].real(rnum);
		}
	}

	return result;
}

std::complex<double>* EvaluatorUtils::generateRandomRealValues(int user_num, double min, double max) {
	std::complex<double>* result = new std::complex<double>[user_num];

	for (int i = 0; i < user_num; ++i) {
		result[i].real(randomReal(max - min) + min);
	}

	return result;
}

//----------------------------------------------------------------------------------
//   DOUBLE & RR <-> ZZ
//----------------------------------------------------------------------------------


double EvaluatorUtils::scaleDownToReal(const ZZ& x, const long logp) {
	RR xp = to_RR(x);
	xp.e -= logp;
	return to_double(xp);
}

ZZ EvaluatorUtils::scaleUpToZZ(const double x, const long logp) {
	return scaleUpToZZ(to_RR(x), logp);
}

ZZ EvaluatorUtils::scaleUpToZZ(const RR& x, const long logp) {
	RR xp = MakeRR(x.x, x.e + logp);
	return RoundToZZ(xp);
}


//----------------------------------------------------------------------------------
//   ROTATIONS
//----------------------------------------------------------------------------------


void EvaluatorUtils::leftRotateAndEqual(complex<double>* vals, const long n, const long r) {
	long rem = r % n;
	if(rem != 0) {
		long divisor = GCD(rem, n);
		long steps = n / divisor;
		for (long i = 0; i < divisor; ++i) {
			complex<double> tmp = vals[i];
			long idx = i;
			for (long j = 0; j < steps - 1; ++j) {
				vals[idx] = vals[(idx + rem) % n];
				idx = (idx + rem) % n;
			}
			vals[idx] = tmp;
		}
	}
}

void EvaluatorUtils::rightRotateAndEqual(complex<double>* vals, const long n, const long r) {
	long rem = r % n;
	rem = (n - rem) % n;
	leftRotateAndEqual(vals, n, rem);
}

}  // namespace heaan
