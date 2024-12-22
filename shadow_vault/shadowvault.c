#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void setup()
{
    setvbuf(stdin, 0LL, 2, 0LL);
    setvbuf(stdout, 0LL, 2, 0LL);
    setvbuf(stderr, 0LL, 2, 0LL);
}

void escape_success() {
    printf("Creaaaak. The gate opens!!!\n");
    printf("[Gatekeeper] Her Majesty asks you to pass a message: ");
    system("cat ./flag.txt");
    printf("[Gatekeeper] Fly safely!\n");
}

void escape_fail() {
    printf("[Falklore] HOW DARE YOU IMPERSONATE MY DEAR!\n");
    printf("Falklore comes and breathes in :(((\n");
    printf("This was your last moment...\n");
}

void banner(){
    printf("                              ______________                    \n");           
    printf("                    ,===:'.,            `-._                    \n");       
    printf("                         `:.`---.__         `-._                \n");       
    printf("                          `:.     `--.         `.               \n");      
    printf("                             \\.        `.         `.            \n");       
    printf("                     (,,(,    \\.         `.   ____,-`.,         \n");       
    printf("                  (,'     `/   \\.   ,--.___`.'                  \n");       
    printf("              ,  ,'  ,--.  `,   \\.;'         `                  \n");       
    printf("               `{D, {    \\  :    \\;                             \n");       
    printf("                 V,,'    /  /    //                             \n");       
    printf("                 j;;    /  ,' ,-//.    ,---.      ,             \n");       
    printf("                 \\;'   /  ,' /  _  \\  /  _  \\   ,'/             \n");       
    printf("                       \\   `'  / \\  `'  / \\  `.' /              \n");       
    printf("                        `.___,'   `.__,'   `.__,'               \n");       
    printf("You reached the gate: \n");
}

int main(int argc, char** argv) {
    setup();
    banner();
    char input_buffer[20];
    int gate;
    int secret;
    
    memset(input_buffer, 0, sizeof(input_buffer));
    secret = 0xf1eebabe; // 28
    gate = 0x0657ac1e; // 24

    printf("[Gatekeeper] You have only one chance. What is Her Majesty's secret?\n");
    scanf("%s", input_buffer);
    printf("\n");

    if (gate != 0x0657ac1e){ // Need to skip this
        printf("[Gatekeeper] The gate is breached! The gate is breached!\n");
        printf("This was your last moment...\n");
    }
    else {
        if (secret == 0xdefec7ed) {
            escape_success(); // Go this
        } else {
            escape_fail();
        }
    }
    return 0;
}
