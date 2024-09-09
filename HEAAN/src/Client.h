#ifndef CLIENT_H
#define CLIENT_H

#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdexcept>
#include <vector>
#include <sstream>
#include <nlohmann/json.hpp> // nlohmann/json 라이브러리 추가
#include<mutex>



//HEAAN관련 해더들
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

#include <Python.h> //파이썬 코드를 위함
using namespace std;
using namespace NTL;
using json = nlohmann::json;


namespace heaan {
	//#undef ARRAY_SIZE
	//#define ARRAY_SIZE 4
#define ROUNDNUM 100
#define CLIENTSNUM 2

	extern std::mutex my_mutex;
	//extern bool initialized;
	extern PyGILState_STATE pystate;


	class Client {
	public:
		Client(const string& server_ip, int server_port)
			: server_ip(server_ip), server_port(server_port) {
			if (!connectToServer()) {
				throw runtime_error("Unable to connect to server");
			}

			srand(time(NULL));
			SetNumThreads(8);


			// 로그를 저장할 파일 경로
			string filename = "ClientsLog.txt";

			// 로그 내용
			time_t currentTime = time(nullptr);
			string currentTimeStr = ctime(&currentTime);
			string logMessage = currentTimeStr + " clients 테스트 시작\n";

			// 파일 열기
			std::ofstream logfile;
			//logfile.open(filename, ios_base::trunc); // trunc 모드: 파일을 열 때 내용을 지우고 새로운 내용을 추가
			logfile.open(filename, std::ios_base::app); // app 모드: 파일 끝에 내용을 추가

			// 파일이 정상적으로 열렸는지 확인
			if (!logfile.is_open()) {
				cerr << "Error: Unable to open log file " << filename << endl;
			}

			logfile << logMessage << endl;


			unique_lock<mutex> lock(my_mutex);
			//python코드 연결
			cout << "initialize" << endl;
			Py_Initialize(); //PyEval_InitThreads()내용 포함
			lock.unlock();

			cout << "ensure" << endl;
			//PyGILState_STATE pystate = PyGILState_Ensure(); //GIL가져오기
			pystate = PyGILState_Ensure(); //GIL가져오기
			cout << "ensure end" << endl;

			PyRun_SimpleString("from time import time,ctime\n"
				"print('Today is', ctime(time()))\n");

			// 모듈이 위치한 디렉토리 추가
			PyRun_SimpleString("import sys");
			PyRun_SimpleString("sys.path.append(\"/home/lab/CSA-2/\")");
			PyRun_SimpleString("sys.path.append(\"/home/lab/CSA-2//learning/\")");
			PyRun_SimpleString("sys.path.append(\"/home/lab/CSA-2/server/\")");

			// sys.path를 가져오기 위한 코드 실행
			PyObject* sys_path = PyObject_GetAttrString(PyImport_ImportModule("sys"), "path");

			//PyObject* pModule_fl, * pModule_s, * pFunc, * pValue, * pArg;

			cout << "import module federated_main" << endl;
			pModule_fl = PyImport_ImportModule("learning.federated_mainV2");
			// 모듈이 제대로 가져와졌는지 확인
			if (pModule_fl != NULL) {
				// Python 모듈 내용 출력
				PyObject_Print(pModule_fl, stdout, 0);
				cout << endl;
			}
			else {
				std::cerr << "Failed to import module" << std::endl;
				PyErr_Print();
			}

			cout << "import module serverV3" << endl;
			pModule_s = PyImport_ImportModule("server.CSAServerV3");
			// 모듈이 제대로 가져와졌는지 확인
			if (pModule_s != NULL) {
				// Python 모듈 내용 출력
				PyObject_Print(pModule_s, stdout, 0);
				cout << endl;
			}
			else {
				std::cerr << "Failed to import module" << std::endl;
				PyErr_Print();
			}
			PyGILState_Release(pystate); //GIL해방


			//cout << "setup실행" << endl;
			////double* train_dataset[60000];
			//pFunc = PyObject_GetAttrString(pModule, (const char*)"setup"); // 실행할 함수인 test_func을 PyObject에 전달한다.
			//if (pFunc == NULL) {
			//	std::cerr << "Failed to get function pointer" << std::endl;
			//	PyErr_Print(); // エラー詳細を出力
			//	// ここで適切なエラー処理を行う
			//}
			//else {
			//	//pArg = Py_BuildValue("(d*)", train_dataset);
			//	pValue = PyObject_CallObject(pFunc, pArg); // pFunc에 매개변수를 전달해서 실행한다. 현재 매개변수가 NULL인 경우이다.
			//}
			//PyGILState_Release(pystate); //GIL해방
			//lock.unlock();

			//for (int i = 0; i < 60000; i++)  cout << "train_dataset[" << i << "]: " << train_dataset[i] << endl;

			//cout << "get_user_dataset실행" << endl;
			////double* train_dataset[60000];
			//pFunc = PyObject_GetAttrString(pModule, (const char*)"get_user_dataset"); // 실행할 함수인 test_func을 PyObject에 전달한다.
			//if (pFunc == NULL) {
			//	std::cerr << "Failed to get function pointer" << std::endl;
			//	PyErr_Print(); // エラー詳細を出力
			//	// ここで適切なエラー処理を行う
			//}
			//else {
			//	pArg = Py_BuildValue("(i|Oii))", CLIENTSNUM, Py_False);
			//	pValue = PyObject_CallObject(pFunc, pArg); // pFunc에 매개변수를 전달해서 실행한다. 현재 매개변수가 NULL인 경우이다.
			//}

			//Py_Finalize();

			cout << "round: " << rounds << endl;
			logfile << " receive A " << endl;
			my_A = receiveA();
			//for (int i = 0; i < ARRAY_SIZE; i++) cout << "my_A" << i << ": " << my_A[i] << endl;
			cout << " array_A[0]: " << my_A[0] << endl;
			cout << " array_A[N]: " << my_A[N - 1] << endl;

			// A -> keyA
			keyA = new uint64_t[Nnprimes]();
			ring.CRT(keyA, my_A.data(), nprimes);

			//receive random index
			my_idx = new int[2];
			recv(client_socket, &my_idx[0], sizeof(int), 0); 
			recv(client_socket, &my_idx[1], sizeof(int), 0); 

			cout << "my_idx: " << my_idx[0] << " " << my_idx[1] << endl;


			// 2. create a secret key si
			// SecretKey 배열을 생성하여 각 사용자에 대한 SecretKey를 저장합니다.
			cout << "2. create a secret key si" << endl;
			SecretKey secretKey(ring);

			// 3. choose a random vi
			cout << "3. choose a random vi" << endl;
			ZZ qQ = ring.qpows[logq + logQ];

			vector<ZZ> my_vi(N, ZZ(0));
			ring.sampleZO(my_vi.data());

			response = culcBiCi(my_A, secretKey, my_vi, qQ);
			my_B = response.first;
			my_C = response.second;

			cout << " my_B[0]: " << my_B[0] << endl;
			cout << " my_B[N-1]: " << my_B[N - 1] << endl;
			cout << " my_C[0]: " << my_C[0] << endl;
			cout << " my_C[N-1]: " << my_C[N - 1] << endl;

			sendArrays(my_B, my_C);
			//response = receiveVectors();
			//my_B = response.first;
			//my_C = response.second;

			//sum_B, sum_C받기
			logfile << " receive B " << endl;
			my_B = receiveA();
			logfile << " receive C " << endl;
			my_C = receiveA();

			cout << " sum_B[0]: " << my_B[0] << endl;
			cout << " sum_B[N-1]: " << my_B[N - 1] << endl;
			cout << " sum_C[0]: " << my_C[0] << endl;
			cout << " sum_C[N-1]: " << my_C[N - 1] << endl;

			cout << endl;

			keyB = new uint64_t[Nnprimes]();
			ring.CRT(keyB, my_B.data(), nprimes);

			//여기부터 매라운드 수행할 작업
			while (rounds <= ROUNDNUM) {
				int totalMsumDiffError = 0;
				int totalWsumDiffError = 0;

				if (rounds != 1)   cout << "rounds: " << rounds << endl;
				logfile << "rounds: " << rounds << endl;


				//pthread_mutex_lock(&c_Mutex);

				my_Wi = new complex<double>*[1];
				my_Wi[0] = new complex<double>[n];

				pystate = PyGILState_Ensure();

				logfile << "clientnum: " << client_socket << " culcDiPDi" << endl;
				response2 = culcDiPDi(my_B, my_C, my_vi, secretKey, qQ);

				PyGILState_Release(pystate); //GIL해방

				my_D = response2.first;
				my_PD = response2.second;

				//sendArrays(my_D, my_PD);

				logfile << "clientnum: " << client_socket << "send D and PD " << endl;
				sendMyD(my_D);
				sendAnArray(my_PD);


				//여기에 my_Mi를 보내는 코드를 추가(PDi, Mi_sum비교용)
				logfile << "clientnum: " << client_socket << "send W and M " << endl;
				sendMyWeights(my_Wi[0], my_Mi);

				//sleep(100);

				logfile << "clientnum: " << client_socket << "delete memories " << endl;
				delete[] my_D;
				delete[] my_PD;
				delete[] my_Wi[0]; // 2次元配列の1行目を解放
				delete[] my_Wi;    // 2次元配列全体を解放
				delete[] my_Mi;

				my_D = nullptr;
				my_PD = nullptr;
				my_Wi = nullptr;
				my_Mi = nullptr;
				//pthread_mutex_unlock(&c_Mutex);

				rounds++;
			}
			logfile.close();
		}

		~Client() {
			closeConnection(); // 연결 종료

			// 동적으로 할당된 메모리 해제
			if (keyA != nullptr) {
				delete[] keyA;
				keyA = nullptr;
			}
			if (keyB != nullptr) {
				delete[] keyB;
				keyB = nullptr;
			}
			if (my_D != nullptr) {
				delete[] my_D;
				my_D = nullptr;
			}
			if (my_PD != nullptr) {
				delete[] my_PD;
				my_PD = nullptr;
			}
			if (my_Wi != nullptr) {
				delete[] my_Wi[0];
				delete[] my_Wi;
				my_Wi = nullptr;
			}
			if (my_Mi != nullptr) {
				delete[] my_Mi;
				my_Mi = nullptr;
			}

			Py_Finalize();
		}

		pair<vector<ZZ>, vector<ZZ>> getResponse() const {
			return response;
		}

	//public: pthread_mutex_t c_Mutex = PTHREAD_MUTEX_INITIALIZER;

		  //public: mutex g_mutex;
	private:
		int client_socket;
		string server_ip;
		int server_port;
		string message;
		pair<vector<ZZ>, vector<ZZ>> response;
		pair<complex<double>*, ZZ*> response2;
		vector<ZZ> my_A;
		vector<ZZ> my_B;
		vector<ZZ> my_C;
		//vector<ZZ> my_D;
		complex<double>* my_D;
		//vector<ZZ> my_PD;
		ZZ* my_PD;
		int rounds = 1;
		const int ARRAY_SIZE = N;
		const int MAX_BUFFER_SIZE = 1024 * 10;  // 10キロバイト
		long logq = 800; ///< Ciphertext Modulus
		long logp = 30; ///< Real message will be quantized by multiplying 2^40
		long logn = 7; //user마다 2^5=32개의 weight값(fedv2에서 사용)
		//int user_num = 10; //10명의 user
		Ring ring;
		TimeUtils timeutils;
		long n = (1 << logn);
		uint64_t* keyA;
		uint64_t* keyB;
		//mutex my_mutex;

		//double trainning_weight = 0.1;
		double trainning_weight = 1.0 / CLIENTSNUM;

		complex<double>* my_Mi;
		complex<double>** my_Wi;

		int* my_idx;
		PyObject* pModule_fl, * pModule_s, * pFunc, * pValue, * pArg;


		ZZ stringToZZ(const string& str) {
			ZZ zz;
			istringstream iss(str);
			iss >> zz;
			return zz;
		}

		//// 문자열을 ZZ 형식으로 변환하는 함수
		//NTL::ZZ stringToZZ(const std::string& str) {
		//    NTL::ZZ result;
		//    NTL::conv(result, str.c_str());
		//    return result;
		//}

		string zzToString(const ZZ& zz) {
			stringstream ss;
			ss << zz;
			return ss.str();
		}

		bool connectToServer() {
			client_socket = socket(AF_INET, SOCK_STREAM, 0);
			if (client_socket == -1) {
				cerr << "Error: Unable to create client socket\n";
				return false;
			}

			sockaddr_in server_address;
			server_address.sin_family = AF_INET;
			server_address.sin_addr.s_addr = inet_addr(server_ip.c_str());
			server_address.sin_port = htons(server_port);

			if (connect(client_socket, reinterpret_cast<sockaddr*>(&server_address), sizeof(server_address)) == -1) {
				cerr << "Error: Unable to connect to server\n";
				close(client_socket);
				return false;
			}

			return true;
		}

		void sendArrays(const vector<ZZ>& array_B, const vector<ZZ>& array_C) {
			// my_B をサーバーに送信
			//send(client_socket, array_B.data(), sizeof(ZZ) * ARRAY_SIZE, 0);
			//string serializedValue[ARRAY_SIZE];
			//for (int i = 0; i < ARRAY_SIZE; ++i) {
			//    serializedValue[i] = zzToString(array_B[i]); // ZZ를 string으로 변환
			//    const char* data = serializedValue[i].c_str();
			//    size_t data_length = serializedValue[i].length();
			//    send(client_socket, data, data_length, 0);
			//}

			// 로그를 저장할 파일 경로
			string filename = "ClientsLog.txt";

			// 파일 열기
			std::ofstream logfile;
			//logfile.open(filename, ios_base::trunc); // trunc 모드: 파일을 열 때 내용을 지우고 새로운 내용을 추가
			logfile.open(filename, std::ios_base::app); // app 모드: 파일 끝에 내용을 추가

			// 파일이 정상적으로 열렸는지 확인
			if (!logfile.is_open()) {
				cerr << "Error: Unable to open log file " << filename << endl;
			}

			//JSON 배열 생성
			json jsonData_b;
			for (int i = 0; i < ARRAY_SIZE; ++i) {
				jsonData_b.push_back(zzToString(array_B[i]));
			}
			// JSON 데이터를 문자열로 변환하여 송신
			string jsonString = jsonData_b.dump();
			//data size 먼저 송신
			size_t jsonSize = jsonString.size();
			logfile << "JSONString(B) 길이: " << jsonSize << endl;
			if (send(client_socket, &jsonSize, sizeof(jsonSize), 0) < 0) {
				cerr << "Error: JSON 데이터 크기 송신 실패" << std::endl;
				close(client_socket);
				return;
			}
			if (send(client_socket, jsonString.c_str(), jsonString.size(), 0) < 0) {
				cerr << "Error: JSON 데이터 송신 실패" << std::endl;
				close(client_socket);
				return;
			}
			else {
				cout << "B송신완료" << endl;
			}

			// my_C をサーバーに送信
			//send(client_socket, array_C.data(), sizeof(ZZ) * ARRAY_SIZE, 0);
			//for (int i = 0; i < ARRAY_SIZE; ++i) {
			//    serializedValue[i] = "";
			//}
			//for (int i = 0; i < ARRAY_SIZE; ++i) {
			//    serializedValue[i] = zzToString(array_C[i]); // ZZ를 string으로 변환
			//    const char* data = serializedValue[i].c_str();
			//    size_t data_length = serializedValue[i].length();
			//    send(client_socket, data, data_length, 0);
			//}

			//JSON 배열 생성
			json jsonData_c;
			for (int i = 0; i < ARRAY_SIZE; ++i) {
				jsonData_c.push_back(zzToString(array_C[i]));
			}
			// JSON 데이터를 문자열로 변환하여 송신
			jsonString = jsonData_c.dump();
			//data size 먼저 송신
			jsonSize = jsonString.size();
			logfile << "JSONString(C) 길이: " << jsonSize << endl;
			if (send(client_socket, &jsonSize, sizeof(jsonSize), 0) < 0) {
				cerr << "Error: JSON 데이터 크기 송신 실패" << std::endl;
				close(client_socket);
				return;
			}
			if (send(client_socket, jsonString.c_str(), jsonString.size(), 0) < 0) {
				cerr << "Error: JSON 데이터 송신 실패" << std::endl;
				close(client_socket);
				return;
			}
			else {
				cout << "C송신완료" << endl;

				cout << " array_B[0]: " << array_B[0] << endl;
				cout << " array_B[N-1]: " << array_B[N - 1] << endl;
				cout << " array_C[0]: " << array_C[0] << endl;
				cout << " array_C[N-1]: " << array_C[N - 1] << endl;
			}
		}


		//void sendAnArray(const vector<ZZ>& array_PD) {
		//	
		//	//JSON 배열 생성
		//	json jsonData;
		//	for (int i = 0; i < ARRAY_SIZE; ++i) {
		//		jsonData.push_back(zzToString(array_PD[i]));
		//	}
		//	// JSON 데이터를 문자열로 변환하여 송신
		//	string jsonString = jsonData.dump();
		//	//data size 먼저 송신
		//	size_t jsonSize = jsonString.size();
		//	if (send(client_socket, &jsonSize, sizeof(jsonSize), 0) < 0) {
		//		cerr << "Error: JSON 데이터 크기 송신 실패" << std::endl;
		//		close(client_socket);
		//		return;
		//	}
		//	if (send(client_socket, jsonString.c_str(), jsonString.size(), 0) < 0) {
		//		cerr << "Error: JSON 데이터 송신 실패" << std::endl;
		//		close(client_socket);
		//		return;
		//	}
		//	else {
		//		cout << "PD송신완료" << endl;
		//	}
		//
		//	cout << " array_PD[0]: " << array_PD[0] << endl;
		//	cout << " array_PD[N-1]: " << array_PD[N - 1] << endl;
		//
		//}


		//정적배열로 보내보기
		void sendAnArray(const ZZ array_PD[]) {

			// 로그를 저장할 파일 경로
			string filename = "ClientsLog.txt";

			// 파일 열기
			std::ofstream logfile;
			//logfile.open(filename, ios_base::trunc); // trunc 모드: 파일을 열 때 내용을 지우고 새로운 내용을 추가
			logfile.open(filename, std::ios_base::app); // app 모드: 파일 끝에 내용을 추가

			// 파일이 정상적으로 열렸는지 확인
			if (!logfile.is_open()) {
				cerr << "Error: Unable to open log file " << filename << endl;
			}

			// JSON 배열 생성
			json jsonData;
			for (size_t i = 0; i < ARRAY_SIZE; ++i) {
				jsonData.push_back(zzToString(array_PD[i]));
			}

			// JSON 데이터를 문자열로 변환하여 송신
			string jsonString = jsonData.dump();
			size_t jsonSize = jsonString.size(); // 데이터 크기 계산
			logfile << "Jsonstring(PD) 길이" << jsonSize << endl;
			// 데이터 크기를 먼저 송신
			if (send(client_socket, &jsonSize, sizeof(jsonSize), 0) < 0) {
				cerr << "Error: JSON 데이터 크기 송신 실패" << endl;
				close(client_socket);
				return;
			}

			// JSON 데이터 송신
			if (send(client_socket, jsonString.c_str(), jsonSize, 0) < 0) {
				cerr << "Error: JSON 데이터 송신 실패" << endl;
				close(client_socket);
				return;
			}
			else {
				cout << "PD 송신 완료" << endl;
			}

			cout << "array_PD[0]: " << array_PD[0] << endl;
			cout << "array_PD[N-1]: " << array_PD[ARRAY_SIZE - 1] << endl;
		}


		pair<vector<ZZ>, vector<ZZ>> culcBiCi(vector<ZZ>& array_A, SecretKey secretkey, vector<ZZ>& vi_array, ZZ qQ) {
			cout << "a public key Bi = -A * si + e0i and a commitment ci = keyA * vi + e0i" << endl;
			vector<ZZ> B(ARRAY_SIZE, ZZ(0)), C(ARRAY_SIZE, ZZ(0));

			//B구하는 부분
			long np = ceil((1 + logQQ + logN + 2) / (double)pbnd);
			ring.mult(B.data(), secretkey.sx, array_A.data(), np, QQ);
			ring.subFromGaussAndEqual(B.data(), QQ);
			cout << "B구하는부분" << endl;

			//C구하는 부분
			ring.multNTT(C.data(), vi_array.data(), keyA, np, qQ);
			ring.rightShiftAndEqual(C.data(), logQ);
			ring.addGaussAndEqual(C.data(), qQ);
			cout << "C구하는부분" << endl;

			return { B, C };
		}

		void receiveW() {
			// 로그를 저장할 파일 경로
			string filename = "ClientsLog.txt";

			// 파일 열기
			std::ofstream logfile;
			//logfile.open(filename, ios_base::trunc); // trunc 모드: 파일을 열 때 내용을 지우고 새로운 내용을 추가
			logfile.open(filename, std::ios_base::app); // app 모드: 파일 끝에 내용을 추가

			// 파일이 정상적으로 열렸는지 확인
			if (!logfile.is_open()) {
				cerr << "Error: Unable to open log file " << filename << endl;
			}

			complex<double>* array_Wi = new complex<double>[n];
			int receiveByte = 0;

			if (array_Wi == nullptr) {
				// 메모리 할당에 실패한 경우
				std::cerr << "메모리 할당에 실패했습니다!" << std::endl;
				exit(0);
			}
			else {
				receiveByte = recv(client_socket, array_Wi, sizeof(complex<double>) * n, 0);
				cout << "receiveByte" << receiveByte << endl;
				for (int i = 0; i < n; i++) {
					logfile << "receiveW" << endl;
					//logfile << "my_Wi[" << i << "]: " << my_Wi[0][i].real() << " / ";
					logfile << "array_Wi[" << i << "]: " << array_Wi[i].real() << " / ";
					my_Wi[0][i].real(array_Wi[i].real());
					logfile << "my_Wi[" << i << "]: " << my_Wi[0][i].real() << " / ";
				}
			}
			delete[] array_Wi;
		}

		pair<complex<double>*, ZZ*> culcDiPDi(const vector<ZZ>& array_B, vector<ZZ>& array_C, vector<ZZ>& vi_array, SecretKey secretkey, ZZ qQ) {
			// 로그를 저장할 파일 경로
			string filename = "ClientsLog.txt";

			// 파일 열기
			std::ofstream logfile;
			//logfile.open(filename, ios_base::trunc); // trunc 모드: 파일을 열 때 내용을 지우고 새로운 내용을 추가
			logfile.open(filename, std::ios_base::app); // app 모드: 파일 끝에 내용을 추가

			// 파일이 정상적으로 열렸는지 확인
			if (!logfile.is_open()) {
				cerr << "Error: Unable to open log file " << filename << endl;
			}

			complex<double>* D = new complex<double>[n];
			ZZ* PD = new ZZ[ARRAY_SIZE];
			PyObject* pyList = PyList_New(n);
			PyObject* pyList2 = PyList_New(2);
			PyObject* pGlobalModel = NULL;

			// 5. choose a random mask Mi
			my_Mi = EvaluatorUtils::generateRandomRealValues(1);
			cout << "my_Mi: " << my_Mi << endl;

			// w배열 생성
			//원래 코드는 모든 클라이언트의 wi백터 한번에 만드는 함수라, 한명의 wi만드는 함수로 수정해도 ㅇ
			if (rounds == 1) { my_Wi = EvaluatorUtils::generateRandomRealArrays(n, 1); }
			else
			{
				receiveW(); //global weight가져오기

				//apply tranning weight
				for (int i = 0; i < n; i++) {
					my_Wi[0][i].real(my_Wi[0][i].real() * trainning_weight);
					
					//decodeWsum -> python list
					PyObject* pyVal = PyLong_FromLong(my_Wi[0][i].real());
					PyList_SetItem(pyList, i, pyVal);
					logfile << "my_Wi[" << i << "]: " << my_Wi[0][i].real() << " / ";
				}
				logfile << endl;

				// 파이썬 함수 호출
				// setup 함수 호출(global model얻기 위함)
				pFunc = PyObject_GetAttrString(pModule_fl, "setup");
				if (pFunc == NULL) {
					std::cerr << "Failed to get function pointer" << std::endl;
					PyErr_Print();
				}
				else {
					pValue = PyObject_CallObject(pFunc, NULL);
					if (pValue != NULL) {
						pGlobalModel = pValue; // setup 함수의 반환 값을 저장
						Py_INCREF(pGlobalModel); // 참조 횟수 증가
						Py_DECREF(pValue);
					}
					else {
						std::cerr << "setup 함수 실행 중 오류 발생" << std::endl;
					}
					Py_DECREF(pFunc);
				}

				//finalAggregation()
				pFunc = PyObject_GetAttrString(pModule_s, "finalAggregation");
				if (pFunc == NULL || !PyCallable_Check(pFunc)) { // 함수가 존재하고 callable 한지 확인
					std::cerr << "Failed to get function pointer or function is not callable" << std::endl;
					PyErr_Print(); // 에러 출력
				}else {
					pValue = PyObject_CallFunctionObjArgs(pFunc, pGlobalModel, pyList, NULL); // 함수 호출
					if (pValue != NULL) {
						// 반환값 처리
						Py_XDECREF(pGlobalModel); // 기존에 참조된 객체 해제
						pGlobalModel = pValue; // 새로운 객체 참조로 할당
					}
					else {
						// 함수 호출 중 오류 발생
						PyErr_Print(); // 에러 출력
					}
				}

				//local UpDate()
				for (int i = 0; i < 2; i++) {
					PyObject* pyVal = PyLong_FromLong(my_idx[i]);
					PyList_SetItem(pyList2, i, pyVal);
				}


				pFunc = PyObject_GetAttrString(pModule_fl, "local_update");
				if (pFunc == NULL || !PyCallable_Check(pFunc)) { // 함수가 존재하고 callable 한지 확인
					std::cerr << "Failed to get function pointer or function is not callable" << std::endl;
					PyErr_Print(); // 에러 출력
				}
				else {
					pValue = PyObject_CallFunctionObjArgs(pFunc, pGlobalModel, pyList2, NULL); // 함수 호출
					if (pValue != NULL) {
						// 반환값 처리
						if (PyList_Check(pValue)) {
							Py_ssize_t size = PyList_Size(pValue); // 리스트의 길이
							for (Py_ssize_t i = 0; i < size; ++i) {
								PyObject* pItem = PyList_GetItem(pValue, i); // 리스트의 i번째 요소 가져오기
								if (PyFloat_Check(pItem)) { // 요소가 float 형태인지 확인
									double value = PyFloat_AsDouble(pItem); // float를 double로 변환
									my_Wi[0][i].real(value);
								}
							}
						}
						else {
							// 함수 호출 중 오류 발생
							PyErr_Print(); // 에러 출력
						}
					}
						// 불필요한 파이썬 객체 해제
						Py_DECREF(pyList);
				}

			}

			// and generate Di = Wi + Mi
			timeutils.start("Wi+ Mi ");
			for (int i = 0; i < n; i++) {
				D[i] = my_Wi[0][i] + my_Mi[0];
			}
			timeutils.stop("Wi+ Mi ");

			//cout << "D[0](" << D[0] << ") = W[0][0](" << my_Wi[0][0] << ")+M[0](" << my_Mi[0] << ")" << endl;

			// and PDi = vi*B + Mi + e1i + C*si

			// vi*B + Mi + e1i -> Mi의 암호화 (근데 Mi가 double이라서 정수로 바꿔줘야함)
			cout << "and PDi = vi*keyB + Mi + e1i + C*si" << endl;

			long np = ceil((1 + logQQ + logN + 2) / (double)pbnd);
			ring.multNTT(PD, vi_array.data(), keyB, np, qQ);

			Plaintext plain;
			//Scheme::encodeSingle(plain, Mi_array[i], logp, logq); - 객체없이 호출 못해서 아래처럼 뺐다.
			plain.logp = logp;
			plain.logq = logq;
			plain.n = 1;
			plain.mx[0] = EvaluatorUtils::scaleUpToZZ(my_Mi[0].real(), logp + logQ);
			plain.mx[Nh] = EvaluatorUtils::scaleUpToZZ(my_Mi[0].imag(), logp + logQ);

			ring.addAndEqual(PD, plain.mx, qQ);

			ring.rightShiftAndEqual(PD, logQ);
			ring.addGaussAndEqual(PD, qQ);

			// += C*si
			ZZ* Csi = new ZZ[N];
			ring.mult(Csi, secretkey.sx, array_C.data(), np, QQ); //C*si -> Csi에 저장
			ZZ q = ring.qpows[logq];
			ring.addAndEqual(PD, Csi, q);

			delete[] Csi;

			return { D, PD };
		}

		// 서버에서 JSON 문자열을 받아 ZZ 형식의 벡터로 변환하여 반환하는 함수
		vector<ZZ> receiveA() {
			vector<ZZ> A(ARRAY_SIZE, ZZ(0)); // A의 크기를 먼저 할당하고 모든 요소를 0으로 초기화

			// 로그를 저장할 파일 경로
			string filename = "ClientsLog.txt";

			// 파일 열기
			std::ofstream logfile;
			//logfile.open(filename, ios_base::trunc); // trunc 모드: 파일을 열 때 내용을 지우고 새로운 내용을 추가
			logfile.open(filename, std::ios_base::app); // app 모드: 파일 끝에 내용을 추가

			// 파일이 정상적으로 열렸는지 확인
			if (!logfile.is_open()) {
				cerr << "Error: Unable to open log file " << filename << endl;
			}

			size_t total_bytes_received = 0;
			string received_string; // JSON 문자열을 저장할 변수

			// JSON 문자열의 크기를 수신
			size_t jsonSize;
			int bytes_received = recv(client_socket, &jsonSize, sizeof(jsonSize), 0);
			if (bytes_received <= 0) {
				cerr << "Error: 서버에서 JSON 문자열의 크기 수신 실패\n";
				close(client_socket);
				throw runtime_error("서버에서 JSON 문자열의 크기 수신 실패");
			}

			logfile << "JSONString 길이: " << jsonSize << endl;

			// JSON 문자열을 수신
			received_string.resize(jsonSize); // 수신할 문자열의 크기를 미리 할당
			total_bytes_received = 0;
			while (total_bytes_received < jsonSize) {
				bytes_received = recv(client_socket, &received_string[total_bytes_received], jsonSize - total_bytes_received, 0);
				//cout << "Received JSON string: " << received_string << endl; // received_string 내용 출력
				//cout << "jsonsize" << jsonSize << endl;
				//cout << "receivedSize" << bytes_received << endl;
				if (bytes_received <= 0) {
					cerr << "Error: 서버에서 JSON 문자열 수신 실패\n";
					close(client_socket);
					throw runtime_error("서버에서 JSON 문자열 수신 실패");
				}
				total_bytes_received += bytes_received;
			}

			cout << "반복문 나옴" << endl;
			// 받은 JSON 문자열을 ZZ 형식으로 변환하여 A에 저장
			json jsonData = json::parse(received_string);
			for (int i = 0; i < ARRAY_SIZE; i++) A[i] = stringToZZ(jsonData[i]);
			return A;
		}





		pair<vector<ZZ>, vector<ZZ>> receiveVectors() {
			vector<ZZ> B, C;
			constexpr size_t BUFFER_SIZE = 4096; // バッファーサイズを設定
			char buffer[BUFFER_SIZE];
			size_t total_bytes_received = 0;

			// sum_Bの受信
			for (size_t i = 0; i < ARRAY_SIZE; ++i) {
				ZZ received_value;
				int bytes_received = recv(client_socket, &received_value, sizeof(int), 0);
				if (bytes_received == -1) {
					cerr << "Error: Unable to receive data from server\n";
					close(client_socket);
					throw runtime_error("Unable to receive data from server");
				}
				else if (bytes_received == 0) {
					// 接続が閉じられた場合
					break;
				}
				else {
					B.push_back(received_value);
					total_bytes_received += bytes_received;
				}
			}

			// sum_Cの受信
			for (size_t i = 0; i < ARRAY_SIZE; ++i) {
				ZZ received_value;
				int bytes_received = recv(client_socket, &received_value, sizeof(int), 0);
				if (bytes_received == -1) {
					cerr << "Error: Unable to receive data from server\n";
					close(client_socket);
					throw runtime_error("Unable to receive data from server");
				}
				else if (bytes_received == 0) {
					// 接続が閉じられた場合
					break;
				}
				else {
					C.push_back(received_value);
					total_bytes_received += bytes_received;
				}
			}

			return { B, C };
		}



		void sendMyWeights(const complex<double>* array_Wi, const complex<double>* array_Mi) {
			send(client_socket, array_Wi, sizeof(complex<double>) * n, 0);
			send(client_socket, array_Mi, sizeof(complex<double>), 0);

			cout << "array_W[0]: " << array_Wi[0] << endl;
			cout << "array_W[n-1]: " << array_Wi[n - 1] << endl;
			cout << "array_M[0]: " << array_Mi[0] << endl;
		}

		void sendMyD(const std::complex<double>* my_vector) {
			// 배열의 데이터를 전송합니다.
			if (send(client_socket, my_vector, sizeof(complex<double>) * n, 0) < 0) {
				std::cerr << "Failed to send data." << std::endl;
				return;
			}

			cout << "array_D[0]: " << my_vector[0] << endl;
			cout << "array_D[n-1]: " << my_vector[n - 1] << endl;
		}


		void closeConnection() {
			close(client_socket);
		}
	};

#endif // CLIENT_H
}