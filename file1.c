#include <stdio.h>

int main()
{
    int inputValue;

    printf("Enter a value: ");

    scanf("%d", &inputValue);

    if (inputValue % 2) {
        printf("%d is a odd integer\n", inputValue);
    } else {
        printf("%d is a even integer\n", inputValue);
    }

    return 0;
}
