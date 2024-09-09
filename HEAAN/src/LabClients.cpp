#include <iostream>
#include <thread>
#include "Client.h"
using namespace std;
#define CLIENTSNUM 10

int main() {
    const string server_ip = "127.0.0.1";
    const int server_port = 8080;

    // スレッド用の関数
    auto createClient = [&server_ip, server_port]() {
        heaan::Client client(server_ip, server_port);
        //cout << "Response from server: " << client.getResponse() << endl;
    };

    // 10個のスレッドを生成し、それぞれでcreateClient関数を実行
    thread threads[CLIENTSNUM];
    for (int i = 0; i < CLIENTSNUM; ++i) {
        threads[i] = thread(createClient);
    }

    // 全てのスレッドの終了を待機
    for (int i = 0; i < CLIENTSNUM; ++i) {
        threads[i].join();
    }

    return 0;
}