#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <pthread.h>
#include <vector>
#include "Client.h"
#include <nlohmann/json.hpp>

#include<algorithm> //index생성을 위함
#include<random>
//#include "models.h"
#define CLIENTSNUM 2
#define ROUNDNUM 100

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

//#include <Python.h> //파이썬 코드를 위함

using namespace std;
using namespace NTL;
using namespace heaan;
using json = nlohmann::json;

void* handle_client(void* arg);
const int ARRAY_SIZE = N; // A,B,Cの次元数
vector<ZZ> array_A(ARRAY_SIZE, ZZ(0));
vector<ZZ> sum_B(ARRAY_SIZE, ZZ(0));
vector<ZZ> sum_C(ARRAY_SIZE, ZZ(0));
//vector<ZZ> sum_D(ARRAY_SIZE, ZZ(0));
complex<double>* sum_D;
//vector<ZZ> sum_PD(ARRAY_SIZE, ZZ(0));
ZZ* sum_PD = new ZZ[ARRAY_SIZE];
complex<double> decode_PDsum;
complex<double>* decode_Wsum;

int** data_idx;
int mcount = 0;


complex<double>* sum_Wi;
complex<double> sum_Mi;

pthread_mutex_t myMutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t condition = PTHREAD_COND_INITIALIZER;
int joinNum = 0;
int threadNum = 0;
bool first = true;

long logq = 800; ///< Ciphertext Modulus
long logp = 30; ///< Real message will be quantized by multiplying 2^40
long logn = 7; //user마다 2^5=32개의 weight값(fedv2에서 사용)
//int user_num = 10; //10명의 user


int main() {

    // socket 생성
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        cerr << "Error: Unable to create server socket\n";
        return 1;
    }

    // 서버 주소 설정
    sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = INADDR_ANY; // 모든 인터페이스에 바인딩
    server_address.sin_port = htons(8080); // 포트 번호 8080을 사용

    // 소켓을 주소에 바인딩
    if (bind(server_socket, reinterpret_cast<sockaddr*>(&server_address), sizeof(server_address)) == -1) {
        cerr << "Error: Unable to bind server socket\n";
        close(server_socket);
        return 1;
    }



    // 클라이언트의 연결을 기다림
    listen(server_socket, 10);

    vector<pthread_t> threads; // 스레드를 저장하는 벡터

    // 클라이언트가 종료될 때까지 스레드를 생성하고 대기합니다.
    for (int i = 0; i < CLIENTSNUM; i++) {
        // 클라이언트로부터의 연결을 수락합니다.
        sockaddr_in client_address;
        socklen_t client_address_size = sizeof(client_address);
        int* client_socket = new int;
        *client_socket = accept(server_socket, reinterpret_cast<sockaddr*>(&client_address), &client_address_size);
        if (*client_socket == -1) {
            cerr << "Error: Unable to accept client connection\n";
            close(server_socket);
            return 1;
        }

        // 클라이언트마다 새로운 스레드를 생성하고 통신을 처리합니다.
        pthread_t tid;
        pthread_create(&tid, NULL, handle_client, client_socket);
        threads.push_back(tid); // 생성된 스레드를 벡터에 저장
    }

    // 스레드 종료를 대기합니다.
    for (pthread_t& tid : threads) {
        pthread_join(tid, NULL);
    }

    // 소켓을 닫습니다.
    cout << "close server socket" << endl;
    close(server_socket);

    return 0;
}


string zzToString(const ZZ& zz) {
    stringstream ss;
    ss << zz;
    return ss.str();
}

ZZ stringToZZ(const string& str) {
    ZZ zz;
    istringstream iss(str);
    iss >> zz;
    return zz;
}

void sendVector(int client_socket, const vector<ZZ>& array_A) {
    // 로그를 저장할 파일 경로
    string filename = "ServerLog.txt";

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
    for (int i = 0; i < ARRAY_SIZE; ++i) {
        //jsonData.push_back(array_A[i].ToString()); //A행렬의 값 string로 변환해서 넣기
        jsonData.push_back(zzToString(array_A[i]));
    }

    // JSON 데이터 출력
    //std::cout << "JSON 데이터:\n" << jsonData.dump(4) << std::endl;

    // JSON 데이터를 문자열로 변환하여 송신
    std::string jsonString = jsonData.dump();
    //logfile << "송신할 JSON 문자열:\n" << jsonString << endl;

    size_t jsonSize = jsonString.size();
    logfile << "JSONString 길이: " << jsonSize << endl;
    if (send(client_socket, &jsonSize, sizeof(jsonSize), 0) < 0) {
        std::cerr << "Error: JSON 데이터 크기 송신 실패" << std::endl;
        close(client_socket);
        return;
    }

    if (send(client_socket, jsonString.c_str(), jsonString.size(), 0) < 0) {
        std::cerr << "Error: JSON 데이터 송신 실패" << std::endl;
        close(client_socket);
        return;
    }
    else {
        //cout << "송신완료" << endl;
    }

    return;
}

vector<ZZ> receiveBC(int client_socket) {
    vector<ZZ> A(ARRAY_SIZE, ZZ(0)); // A의 크기를 먼저 할당하고 모든 요소를 0으로 초기화

    size_t total_bytes_received = 0;
    string received_string; // JSON 문자열을 저장할 변수

    // JSON 문자열의 크기를 수신
    size_t jsonSize;
    int bytes_received = recv(client_socket, &jsonSize, sizeof(jsonSize), 0);
    if (bytes_received <= 0) {
        cerr << "Error: 클라이언트에서 JSON 문자열의 크기 수신 실패\n";
        close(client_socket);
        throw runtime_error("클라이언트에서 JSON 문자열의 크기 수신 실패");
    }

    // JSON 문자열을 수신
    received_string.resize(jsonSize); // 수신할 문자열의 크기를 미리 할당
    total_bytes_received = 0;
    while (total_bytes_received < jsonSize) {
        bytes_received = recv(client_socket, &received_string[total_bytes_received], jsonSize - total_bytes_received, 0);
        //cout << "Received JSON string: " << received_string << endl; // received_string 내용 출력
        //cout << "jsonsize" << jsonSize << endl;
        //cout << "receivedSize" << bytes_received << endl;
        if (bytes_received <= 0) {
            cerr << "Error: 클라이언트에서 JSON 문자열 수신 실패\n";
            close(client_socket);
            throw runtime_error("클라이언트에서 JSON 문자열 수신 실패");
        }
        total_bytes_received += bytes_received;
    }

    //cout << "반복문 나옴" << endl;
    // 받은 JSON 문자열을 ZZ 형식으로 변환하여 A에 저장
    json jsonData = json::parse(received_string);
    for (int i = 0; i < ARRAY_SIZE; i++) A[i] = stringToZZ(jsonData[i]);
    return A;
}


ZZ* receivePD(int client_socket) {
    //vector<ZZ> A(ARRAY_SIZE, ZZ(0)); // A의 크기를 먼저 할당하고 모든 요소를 0으로 초기화
    ZZ* A = new ZZ[ARRAY_SIZE];

    size_t total_bytes_received = 0;
    string received_string; // JSON 문자열을 저장할 변수

    // JSON 문자열의 크기를 수신
    size_t jsonSize;
    int bytes_received = recv(client_socket, &jsonSize, sizeof(jsonSize), 0);
    if (bytes_received <= 0) {
        cerr << "Error: 클라이언트에서 JSON 문자열의 크기 수신 실패\n";
        close(client_socket);
        throw runtime_error("클라이언트에서 JSON 문자열의 크기 수신 실패");
    }

    // JSON 문자열을 수신
    received_string.resize(jsonSize); // 수신할 문자열의 크기를 미리 할당
    total_bytes_received = 0;
    while (total_bytes_received < jsonSize) {
        bytes_received = recv(client_socket, &received_string[total_bytes_received], jsonSize - total_bytes_received, 0);
        //cout << "Received JSON string: " << received_string << endl; // received_string 내용 출력
        //cout << "jsonsize" << jsonSize << endl;
        //cout << "receivedSize" << bytes_received << endl;
        if (bytes_received <= 0) {
            cerr << "Error: 클라이언트에서 JSON 문자열 수신 실패\n";
            close(client_socket);
            throw runtime_error("클라이언트에서 JSON 문자열 수신 실패");
        }
        total_bytes_received += bytes_received;
    }

    //cout << "반복문 나옴" << endl;
    // 받은 JSON 문자열을 ZZ 형식으로 변환하여 A에 저장
    json jsonData = json::parse(received_string);
    for (int i = 0; i < ARRAY_SIZE; i++) A[i] = stringToZZ(jsonData[i]);
    return A;
}

vector<vector<double>> convertUserGroups(PyObject* userGroups) {
    vector<vector<double>> result;

    if (PyDict_Check(userGroups)) {
        Py_ssize_t dictSize = PyDict_Size(userGroups);
        result.reserve(dictSize);

        PyObject* key, * value;
        Py_ssize_t pos = 0;

        while (PyDict_Next(userGroups, &pos, &key, &value)) {
            // Assuming the key is an integer and value is a list of doubles
            long userIndex = PyLong_AsLong(key);
            vector<double> userData;

            if (PyList_Check(value)) {
                Py_ssize_t listSize = PyList_Size(value);
                userData.reserve(listSize);

                for (Py_ssize_t i = 0; i < listSize; ++i) {
                    PyObject* item = PyList_GetItem(value, i);
                    if (PyFloat_Check(item)) {
                        double val = PyFloat_AsDouble(item);
                        userData.push_back(val);
                    }
                }
            }

            result.push_back(userData);
        }
    }

    return result;
}


void* handle_client(void* arg) {
    // 로그를 저장할 파일 경로
    string filename = "ServerLog.txt";

    // 로그 내용
    time_t currentTime = time(nullptr);
    string currentTimeStr = ctime(&currentTime);
    string logMessage = currentTimeStr + " server 테스트 시작\n";

    // 파일 열기
    std::ofstream logfile;
    //logfile.open(filename, ios_base::trunc); // trunc 모드: 파일을 열 때 내용을 지우고 새로운 내용을 추가
    logfile.open(filename, std::ios_base::app); // app 모드: 파일 끝에 내용을 추가

    // 파일이 정상적으로 열렸는지 확인
    if (!logfile.is_open()) {
        cerr << "Error: Unable to open log file " << filename << endl;
    }

    logfile << logMessage << endl;




    int rounds = 1;
    int client_socket = *((int*)arg);
    delete (int*)arg; // メモリリークを避けるため、動的に確保されたintポインタを削除
    cout << "server is ready.." << endl;

    srand(time(NULL));
    SetNumThreads(8);
    TimeUtils timeutils;
    Ring ring;
    long n = (1 << logn);

    cout << "client_num: " << client_socket << "rounds: " << rounds << endl;

    // n次元配列 A
    //int array_A[ARRAY_SIZE] = { 1, 2, 3, 4 };
    pthread_mutex_lock(&myMutex);
    if (first) {
        logfile << "1. generate a global A = [a1, a2, ..., aN]" << endl;
        first = false;
        //ring.sampleUniform2(array_A, logQQ); //한명만 A 샘플링
        for (int i = 0; i < ARRAY_SIZE; ++i) {
            RandomBits(array_A[i], logQQ); // 임의의 32비트 정수 생성
            //logfile << "array_A[" << i << "]: " << array_A[i] << endl;
        }
        
        //random index를 위한 코드
        int* shuffledNums;
        shuffledNums = new int[300]; //300개의 shard에서 2개를 선택
        for (int i = 0; i < 300; i++) {
            shuffledNums[i] = i;
        }
        random_device rd;
        mt19937 g(rd()); //난수생성기 초기화
        shuffle(shuffledNums, shuffledNums + 300, g);

        
        data_idx = new int*[CLIENTSNUM];
        
        for (int i = 0; i < CLIENTSNUM; i++) {
            data_idx[i] = new int[2];

            data_idx[i][0] = shuffledNums[mcount++];
            data_idx[i][1] = shuffledNums[mcount++];
        }
        delete[] shuffledNums;
        mcount = 0;
    }
    if (!first) {
        // 조건(=1명이 행렬A를 만듦)이 만족됨을 알림
        pthread_cond_broadcast(&condition);
        joinNum = 0;
    }
    else {
        // 조건이 만족될때까지 대기
        pthread_cond_wait(&condition, &myMutex);
    }
    pthread_mutex_unlock(&myMutex);

    logfile << "send A to the clients" << endl;
    sendVector(client_socket, array_A);

    pthread_mutex_lock(&myMutex);

    //random index 송신
    cout << "data_idx[" << mcount << "]: " << data_idx[mcount][0] << " " << data_idx[mcount][1] << endl;

    send(client_socket, &data_idx[mcount][0], sizeof(int), 0); // data_idx[i][0] 전송
    send(client_socket, &data_idx[mcount++][1], sizeof(int), 0); // data_idx[i][1] 전송

    pthread_mutex_unlock(&myMutex);

    logfile << endl;

    // Bi, Ci 수신
    logfile << "receive Bi, Ci from each client" << endl;
    vector<ZZ> array_B(ARRAY_SIZE, ZZ(0)), array_C(ARRAY_SIZE, ZZ(0));

    array_B = receiveBC(client_socket);
    array_C = receiveBC(client_socket);

    pthread_mutex_lock(&myMutex);

    cout << "joinNum: " << joinNum << endl;
    if (joinNum == 0) { //첫번째 사람은 sum_B, sum_C초기화
        copy(array_B.begin(), array_B.begin() + N, sum_B.begin());
        copy(array_C.begin(), array_C.begin() + N, sum_C.begin());
    }
    else { //나머지 사용자는 addandequal로 더하기
        ZZ q = ring.qpows[logq];
        ring.addAndEqual(sum_B.data(), array_B.data(), q);
        ring.addAndEqual(sum_C.data(), array_C.data(), q);
    }

    array_B.clear();
    array_C.clear();
    array_B.shrink_to_fit(); //메모리 최소화
    array_C.shrink_to_fit(); //메모리 최소화


    joinNum++;
    //cout << joinNum << endl;


    // 모든 클라이언트가 자신의 array_B,C를 sum_B에 더할 때까지 대기
    if (joinNum == CLIENTSNUM) {
        // 조건이 만족됨을 알림
        array_A.clear(); //array_A 데이터 삭제
        array_A.shrink_to_fit(); //메모리 최소화
        logfile << "array_A사이즈: " << array_A.size() << endl;
        pthread_cond_broadcast(&condition);
        joinNum = 0;
        first = true;
    }
    else {
        // 조건이 만족될때까지 대기
        pthread_cond_wait(&condition, &myMutex);
    }
    pthread_mutex_unlock(&myMutex);

    logfile << " sum_B[0]: " << sum_B[0] << endl;
    logfile << " sum_B[N-1]: " << sum_B[N - 1] << endl;
    logfile << " sum_C[0]: " << sum_C[0] << endl;
    logfile << " sum_C[N-1]: " << sum_C[N - 1] << endl;

    logfile << "send Bsum, Csum to the clients" << endl;
    sendVector(client_socket, sum_B);
    sendVector(client_socket, sum_C);


    //여기부터 매라운드 수행할 작업

    while (rounds <= ROUNDNUM) {
        int totalMsumDiffError = 0;
        int totalWsumDiffError = 0;
        if (rounds != 1)   cout << "rounds: " << rounds << endl;

        pthread_mutex_lock(&myMutex);
        joinNum++;

        if (joinNum == CLIENTSNUM) {
            if (first) {
                //sum_D, sum_PD 초기화
                delete[] sum_D;
                sum_D = new complex<double>[n];
                if (sum_D == nullptr) {
                    std::cerr << "할당 실패: 메모리 부족" << std::endl;
                    return nullptr; // 오류 상태 반환
                }
                for (int i = 0; i < n; ++i) {
                    sum_D[i] = complex<double>(0, 0); // 초기화
                }
                //sum_PD.assign(ARRAY_SIZE, ZZ(0));
                for (int i = 0; i < ARRAY_SIZE; i++) {
                    sum_PD[i] = ZZ(0);
                }
                delete[] decode_Wsum;
                sum_Wi = new complex<double>[n];
                sum_Mi.real(0);
                sum_Mi.imag(0);
                first = false;
                joinNum = 0;

            }

            if (rounds == 1) {
                sum_B.clear(); //sum_B, sum_C지우기
                sum_C.clear();
                sum_B.shrink_to_fit();
                sum_C.shrink_to_fit();
            }
            pthread_cond_broadcast(&condition);
        }
        else {
            pthread_cond_wait(&condition, &myMutex);
        }
        pthread_mutex_unlock(&myMutex);

        // 배열D과 PD를 수신
        complex<double>* array_D = new complex<double>[n];
        ZZ* array_PD = new ZZ[ARRAY_SIZE];

        logfile << "reseive D and PD" << endl;
        recv(client_socket, array_D, sizeof(complex<double>) * n, 0);
        array_PD = receivePD(client_socket);

        cout << "sum_D구하는부분" << endl;
        pthread_mutex_lock(&myMutex);
        for (int i = 0; i < n; ++i) {
            sum_D[i] += array_D[i];
        }

        cout << "sum_PD구하는부분" << endl;
        // addAndEqual 사용 o 버전
        if (joinNum == 0) {
            copy(array_PD, array_PD + N, sum_PD);
        }
        else {
            ZZ q = ring.qpows[logq];
            ring.addAndEqual(sum_PD, array_PD, q);
        }

        delete[] array_PD;
        joinNum++;
        //cout << joinNum << endl;


        decode_Wsum = new complex<double>[n];

        if (joinNum == CLIENTSNUM) {
            //decodeSingle - 객체없이 호출 못해서 아래처럼 뺐다. ✨✨
            ZZ q = ring.qpows[logq];

            ZZ tmp = sum_PD[0] % q;
            cout << "tmp: " << tmp << endl;
            if (NumBits(tmp) == logq) {
                cout << "did" << endl;
                tmp -= q;
            }
            decode_PDsum.real(EvaluatorUtils::scaleDownToReal(tmp, logp));

            tmp = sum_PD[Nh] % q;
            if (NumBits(tmp) == logq) tmp -= q;
            decode_PDsum.imag(EvaluatorUtils::scaleDownToReal(tmp, logp));
            //

            // decode_Wsum = D-PD
            for (int i = 0; i < n; i++) {
                decode_Wsum[i] = sum_D[i] - decode_PDsum;
            }
            cout << "decode_Wsum구하는 부분" << endl;

            cout << endl;
            pthread_cond_broadcast(&condition);
            joinNum = 0;
        }
        else {
            pthread_cond_wait(&condition, &myMutex);
        }

        pthread_mutex_unlock(&myMutex);

        //실제로는 송수신 안하지만 오차 즉정을 위해 W, M 수신하는 코드
        complex<double>* array_Wi = new complex<double>[n];
        complex<double> my_Mi = complex<double>(0, 0);

        recv(client_socket, array_Wi, sizeof(complex<double>) * n, 0);
        //recv(client_socket, my_Mi, sizeof(complex<double>), 0);
        // 
        // recv 대신에 read를 사용하여 데이터를 읽음
        if (read(client_socket, &my_Mi, sizeof(complex<double>)) < 0) {
            cerr << "Error: 데이터 수신 실패" << endl;
            close(client_socket);
            pthread_exit(NULL);
        }


        logfile << "[compare Msum]" << endl;
        pthread_mutex_lock(&myMutex);
        sum_Mi += my_Mi;
        joinNum++;
        cout << joinNum << endl;

        if (joinNum == CLIENTSNUM) {
            logfile << "sum_Mi: " << sum_Mi.real() << endl;
            logfile << "PD (decoded)= " << decode_PDsum << endl;
            logfile << "★round : " << rounds << " / Msum - PD (두 값의 차이 비교) ★:" << sum_Mi - decode_PDsum << endl;

            if (abs(sum_Mi - decode_PDsum) > 1e-5) {
                totalMsumDiffError++;
            }

            pthread_cond_broadcast(&condition);
            joinNum = 0;
        }
        else {
            pthread_cond_wait(&condition, &myMutex);
        }
        pthread_mutex_unlock(&myMutex);

        logfile << "[compare Wsum]" << endl;
        pthread_mutex_lock(&myMutex);
        for (int i = 0; i < n; i++) {
            sum_Wi[i] += array_Wi[i];
        }
        joinNum++;
        cout << joinNum << endl;

        if (joinNum == CLIENTSNUM) {
            cout << "sum_Wi[0]: " << sum_Wi[0].real() << endl;
            cout << "sum_Wi[n-1]: " << sum_Wi[n - 1].real() << endl;

            int print_num = 5;
            int WsumDiffError = 0;
            for (long i = 0; i < n; ++i) {
                if (i < print_num) {
                    logfile << "---------------------" << endl;
                    logfile << "mMKHE : " << i << " :" << sum_Wi[i] << endl;
                    logfile << "dMKHE : " << i << " :" << decode_Wsum[i] << endl;
                    logfile << "eMKHE : " << i << " :" << abs(sum_Wi[i] - decode_Wsum[i]) << endl;
                    logfile << "---------------------" << endl;
                }
                double diff = std::abs(sum_Wi[i] - decode_Wsum[i]);
                if (diff > 1e-5) {
                    WsumDiffError++;
                    totalWsumDiffError++;
                }
            }
            logfile << n - print_num << "more ... " << endl;
            logfile << "round : " << rounds << " / WsumDiffError : " << WsumDiffError << endl;

            delete[] array_Wi;

            pthread_cond_broadcast(&condition);
            joinNum = 0;
        }
        else {
            pthread_cond_wait(&condition, &myMutex);
        }
        pthread_mutex_unlock(&myMutex);

        send(client_socket, decode_Wsum, sizeof(complex<double>) * n, 0);
        for (int i = 0; i < n; i++) {
            //send(client_socket, decode_Wsum[i], sizeof(complex<double>), 0);
            logfile << "decode_Wsum[" << i << "]: " << decode_Wsum[i].real() << " / ";
        }

        //for (int i = 0; i < ARRAY_SIZE; i++) send(client_socket, &sum_D[i], sizeof(int), 0);
        pthread_mutex_lock(&myMutex);
        first = true;
        pthread_mutex_unlock(&myMutex);
        delete[] array_D;

        logfile << "totalMsumDiffError : " << totalMsumDiffError << " / totalWsumDiffError : " << totalWsumDiffError << endl;


        cout << rounds << "라운드 종료" << endl;
        rounds++;

    }


    logfile.close();
    // クライアントのソケットをクローズ
    //close(client_socket);

    pthread_exit(NULL);
}