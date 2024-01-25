#include <iostream>
#include <string>

using namespace std;

int add(int a, int b)
{
    return a + b;
}

string add(const string &str1, const string &str2)
{
    return str1 + str2;
}

double add(double x, double y, double z)
{
    return x + y + z;
}

int main()
{
    int result1 = add(5, 3);
    cout << "Result of adding integers: " << result1 << endl;

    string result2 = add("Hello, ", "world!");
    cout << "Result of concatenating strings: " << result2 << endl;

    double result3 = add(2.5, 3.5, 1.0);
    cout << "Result of adding doubles: " << result3 << endl;

    return 0;
}
