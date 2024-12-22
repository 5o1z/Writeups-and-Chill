#include <stdio.h>

int main() {

    int detrust;
    int trust_level; // Không khởi tạo

    printf("How much should I not trust you? >:)\n: ");
    scanf("%d", &detrust);

    trust_level -= detrust; // Phép trừ với giá trị rác

    printf("Trust level: %d\n", trust_level);

    return 0;
}
