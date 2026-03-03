#include "sniffer.h"
#include "handlers.h"
#include <iostream>

using namespace std;

int main(int argc, char* argv[])
{
    argv[1] = const_cast <char*>(argv[1]); //НЕ ЗАБЫТЬ убрать захардкоженный путь
    argc = 2;

    int a = readFile(argc, argv);
    if (a == 0) { return 0; }

    startHandlers();
    int b = readPCAP(argv);

    cout << "Успешно достигнут конец программы" << endl;
    stopHandlers();
    return 0;
}
