#include <windows.h>
#include <iostream>
#include <string>
#include <tlhelp32.h>
#include "PrivEscalationClass.h"

int main(){
    PrivEscalationClass privEsc;
    
    bool success = privEsc.runProcAsSystemFromAdmin("cmd.exe");
    if(success){
        std::cout << "Successfully ran process as admin\n";
    } else {
        std::cout << "Failed to run process as admin\n";
    }



    return 0;
}