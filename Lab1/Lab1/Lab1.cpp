#include <iostream>
#include <fstream>
#include <string>
#include "Encryptor.h"
#include <windows.h>

using namespace std;

// переменная для хранения ввода
wstring input;

// функция для вывода сообщения о неправильном вводе
void inputIncorrect( string a ) 
{
	cout << "Input incorrect (";
	cout << a << ")." << endl;
}
// функция для обработки строкового ввода
wstring strInput()
{
	getline( wcin, input );
	return input;
}
// функция для обработки числового ввода
int intInput()
{
	wcin >> input;
	try
	{
		return stoi( input );
	}
	catch ( const std::exception & )
	{
		inputIncorrect( "Input type incorrect, please retry" );
		intInput();
	}
}

int main()
{
	// настройки параметров для отображения символов unicode
	SetConsoleCP( 1251 );
	SetConsoleOutputCP( 1251 );
	setlocale( LC_ALL, "" );
	// инициализация шифровальщика
	Encryptor enc = Encryptor();
	wstring alph;
	// выбор алфавита
	while ( true )
	{
		cout << "Select the alphabet (ru/en): ";
		alph = strInput();
		if ( alph == L"ru" )
		{
			enc.setAlphToRU();
			break;
		}
		else if ( alph == L"en" )
		{
			enc.setAlphToEN();
			break;
		}
		else
			inputIncorrect( "There is no such an option, please retry" );
	}
	// выбор операции
	wchar_t op;
	while ( true )
	{
		cout << "Do you want to (e)ncrypt or to (d)ecrypt a message? (e/d): ";
		op = strInput()[0];
		if ( op == 'e' )
		{
			cout << "Enter your message: " << endl;
			wstring msg = strInput();
			cout << "Enter the key (numeric): ";
			wstring key = to_wstring( intInput() );
			wcout << "Your encrypted message is: " << endl << enc.encrypt( msg, key ) << endl;
			break;
		}
		else if ( op == 'd' )
		{
			cout << "Enter your encrypted message: " << endl;
			wstring msg = strInput();
			cout << "Enter the key (numeric): ";
			wstring key = to_wstring( intInput() );
			wcout << "Your decrypted message is: " << endl << enc.uncrypt( msg, key ) << endl;
			break;
		}
		else
			inputIncorrect( "There is no such an option, please retry" );
	}
}