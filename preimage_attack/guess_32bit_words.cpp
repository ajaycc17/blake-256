// guess all possible 32-bit words and store it in a guess.txt file
#include <bits/stdc++.h>
using namespace std;

// Convert a number in binary (string) to decimal
int bin2dec(string binary)
{
    int decimal = 0;
    int counter = 0;
    int size = binary.length();
    for (int i = size - 1; i >= 0; i--)
    {
        if (binary[i] == '1')
        {
            decimal += pow(2, counter);
        }
        counter++;
    }
    return decimal;
}

// Convert a number from decimal to binary
string dec2bin(int decimal)
{
    string binary;
    while (decimal != 0)
    {
        binary = (decimal % 2 == 0 ? "0" : "1") + binary;
        decimal = decimal / 2;
    }
    while (binary.length() < 32)
    {
        binary = "0" + binary;
    }
    return binary;
}

// convert binary string to hexadecimal string - 6bit binary only
string bin2hex(string s)
{
    // binary to hexadecimal conversion
    string mp[16];
    mp[0] = "0";
    mp[1] = "1";
    mp[2] = "2";
    mp[3] = "3";
    mp[4] = "4";
    mp[5] = "5";
    mp[6] = "6";
    mp[7] = "7";
    mp[8] = "8";
    mp[9] = "9";
    mp[10] = "A";
    mp[11] = "B";
    mp[12] = "C";
    mp[13] = "D";
    mp[14] = "E";
    mp[15] = "F";

    string hex = "";
    int bin_len = 32 - s.length();
    if (bin_len > 0)
    {
        for (int j = 0; j < bin_len; j++)
        {
            s = "0" + s;
        }
    }
    for (int i = 0; i < s.length(); i += 4)
    {
        string ch = "";
        ch = s[i];
        ch += s[i + 1];
        ch += s[i + 2];
        ch += s[i + 3];
        int x = bin2dec(ch);
        hex += mp[x];
    }
    return hex;
}

// main function
int main()
{
    ofstream fw("guess.txt", ofstream::out);
    if (fw.is_open())
    {
        string temp = "";
        // store contents to text file
        // change 1024 to 2^32 to get all possible 32-bit words
        for (int i = 0; i < 1024; i++)
        {
            temp = bin2hex(dec2bin(i));
            fw << temp << "\n";
        }
        fw.close();
    }
    else
        cout << "Problem with opening file";
    return 0;
}