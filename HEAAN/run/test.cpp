/*
* Copyright (c) by CryptoLab inc.
* This program is licensed under a
* Creative Commons Attribution-NonCommercial 3.0 Unported License.
* You should have received a copy of the license along with this
* work.  If not, see <http://creativecommons.org/licenses/by-nc/3.0/>.
*/

#include "../src/HEAAN.h"

#include <string>

using namespace std;
using namespace heaan;

/**
  * This file is for test HEAAN library
  * You can find more in src/TestScheme.h
  * "./TestHEAAN Encrypt" will run Encrypt Test
  * There are Encrypt, EncryptSingle, Add, Mult, iMult, RotateFast, Conjugate Tests
  */
int main(int argc, char **argv) {

	long logq = 800; ///< Ciphertext Modulus
	long logp = 30; ///< Real message will be quantized by multiplying 2^40
	long logn = 2; ///< log2(The number of slots)
	//long logn = 1; //user���� 2^1=2���� weight��(fed���� ���)
	//long logn = 7; //user���� 2^5=32���� weight��(fedv2���� ���)
	int user_num = 100; //10���� user
	int round_num = 100;

//----------------------------------------------------------------------------------
//   STANDARD TESTS
//----------------------------------------------------------------------------------

	if(string(argv[1]) == "Encrypt") TestScheme::testEncrypt(logq, logp, logn);
	if(string(argv[1]) == "EncryptBySk") TestScheme::testEncryptBySk(logq, logp, logn);
	if(string(argv[1]) == "DecryptForShare") TestScheme::testDecryptForShare(logq, logp, logn, stol(argv[2]));
	if(string(argv[1]) == "EncryptSingle") TestScheme::testEncryptSingle(logq, logp);
	if(string(argv[1]) == "Add") TestScheme::testAdd(logq, logp, logn);
	if (string(argv[1]) == "Add100") TestScheme::testAdd100(logq, logp, logn, user_num);
	if(string(argv[1]) == "Mult") TestScheme::testMult(logq, logp, logn);
	if(string(argv[1]) == "iMult") TestScheme::testiMult(logq, logp, logn);
	if (string(argv[1]) == "myNumbers") TestScheme::testEncryptMN(logq, logp);
	if (string(argv[1]) == "Fed") TestScheme::testFed(logq, logp, logn, user_num);
	if (string(argv[1]) == "Fedv2") TestScheme::testFedV2(logq, logp, logn, user_num);
	if (string(argv[1]) == "MKHE") TestScheme::testMKHE(logq, logp, logn, user_num);
	if (string(argv[1]) == "lab") TestScheme::labClients(logq, logp, logn, user_num);
	if (string(argv[1]) == "MKHERound") TestScheme::testMKHERound(logq, logp, logn, user_num, round_num);

	// Parse iid_mode (expected to be 0 or 1)
    bool iid_mode = std::atoi(argv[3]) != 0;

	if (string(argv[1]) == "final") TestScheme::testMKHEFinal(logq, logp, logn, atoi(argv[2]), round_num, iid_mode);

//----------------------------------------------------------------------------------
//   ROTATE & CONJUGATE
//----------------------------------------------------------------------------------

	long r = 1; ///< The amout of rotation
	if(string(argv[1]) == "RotateFast") TestScheme::testRotateFast(logq, logp, logn, r);
	if(string(argv[1]) == "Conjugate") TestScheme::testConjugate(logq, logp, logn);

//----------------------------------------------------------------------------------
//   BOOTSTRAPPING
//----------------------------------------------------------------------------------

	logq = logp + 10; //< suppose the input ciphertext of bootstrapping has logq = logp + 10
	logn = 3; //< larger logn will make bootstrapping tech much slower
	long logT = 4; //< this means that we use Taylor approximation in [-1/T,1/T] with double angle fomula
	if(string(argv[1]) == "Bootstrapping") TestScheme::testBootstrap(logq, logp, logn, logT);

	return 0;
}
