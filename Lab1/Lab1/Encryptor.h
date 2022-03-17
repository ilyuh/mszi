#include <string>
#include <iostream>

using namespace std;

class Encryptor
{
private:
	wstring alphEN = L"ABCDEFGHIJKLMNOPQRSTUVWXYZ ";
	wstring alphRU = L"�����Ũ�������������������������� ";
	wstring alph;
	// ������� ��� ���������� ������� ��������� �����
	wstring matchKey( wstring data, wstring key )
	{
		int keyLength = key.length();
		wstring keyNew = key;
		if ( keyLength < data.length() )
		{
			double keyRepeats = (double)data.length() / key.length();
			keyRepeats = ceil( keyRepeats );
			for ( int i = 1; i < keyRepeats; i++ )
			{
				keyNew += key;
			}
		}
		return keyNew;
	}
public:
	Encryptor()
	{
		this->alph = alphEN;
	}
	bool setAlphToRU()
	{
		this->alph = alphRU;
		return true;
	}
	bool setAlphToEN()
	{
		this->alph = alphEN;
		return true;
	}
	// ������� ����������
	wstring encrypt( wstring data, wstring key )
	{
		wstring output = L"";
		key = matchKey( data, key );
		for ( int i = 0; i < data.length(); i++ )
		{
			// ��������� ��������� �� �������
			wchar_t c = data[i];
			if ( !iswspace( c ) )
				c = towupper( c );
			int charIndex = alph.find_first_of( c );
			// ����� ������� �� ��������������� ����� ���������� �������� ������
			int encCharIndex = charIndex + ( key[i] - '0' );
			if ( encCharIndex >= alph.length() )
				encCharIndex -= alph.length();
			output += alph[encCharIndex];
		}
		return output;
	}
	// ������� �������������
	wstring uncrypt( wstring data, wstring key )
	{
		wstring output = L"";
		key = matchKey( data, key );
		for ( int i = 0; i < data.length(); i++ )
		{
			// ��������� ��������� �� �������
			wchar_t c = data[i];
			if ( !iswspace( c ) )
				c = towupper( c );
			int charIndex = alph.find_first_of( c );
			// ����� ������� �� ��������������� ����� ���������� �������� �����
			int encCharIndex = charIndex - ( key[i] - '0' );
			if ( encCharIndex < 0 )
				encCharIndex += alph.length();
			output += alph[encCharIndex];
		}
		return output;
	}
};