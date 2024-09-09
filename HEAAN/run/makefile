SRC_DIR = ../src
RUN_DIR = .

SOURCES = $(SRC_DIR)/TestScheme.cpp $(RUN_DIR)/test.cpp $(SRC_DIR)/Scheme.cpp $(SRC_DIR)/EvaluatorUtils.cpp $(SRC_DIR)/EvaluatorUtils.h 

EXECUTABLE = TestHEAAN
SERVER_EXECUTABLE = server

all: clean TestHEAAN CSAServer

TestHEAAN:
	@echo 'Building target: $@'
	@echo 'Invoking: GCC C++ Linker'
	g++ $(SOURCES) -o $(EXECUTABLE)  ../lib/libHEAAN.a -lntl -lgmp -lm -std=c++11 -O2 -I$(SRC_DIR) -pthread -lpython3.8
	@echo 'Finished building target: $@'
	@echo ' '

CSAServer:
	@echo 'Building target: $@'
	@echo 'Invoking: GCC C++ Linker'
	g++ $(SRC_DIR)/CSAServer.cpp -o $(SERVER_EXECUTABLE) -L/usr/local/lib ../lib/libHEAAN.a -lntl -lgmp -lm -std=c++11 -O2 -I$(SRC_DIR) -pthread -lpython3.8
	@echo 'Finished building target: $@'
	@echo ' '

run_server: CSAServer
	./$(SERVER_EXECUTABLE)

clean:
	rm -rf $(EXECUTABLE) $(SERVER_EXECUTABLE)
