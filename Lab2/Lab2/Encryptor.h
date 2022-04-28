#include <string>
#include <iostream>

using namespace std;

class Encryptor
{
private:
	wstring alphEN = L"ABCDEFGHIJKLMNOPQRSTUVWXYZ 1234567890";
	wstring alphRU = L"јЅ¬√ƒ≈®∆«»… ЋћЌќѕ–—“”‘’÷„ЎўЏџ№Ёёя 1234567890";
	wstring alph;
	int bit_depth;
	// функци€ обрезки числа
	unsigned long long numCut( unsigned long long num, int left, int right )
	{
		int numLength = to_string( num ).length();
		if ( numLength < left )
			left = 0;
		num = num % ( unsigned long long )pow( 10, numLength - left );
		num = num / ( unsigned long long )pow( 10, right );
		return num;
	}
	// функци€ генерации гаммы 
	wstring gamma( unsigned long long key, int msgLength )
	{
		wstring output = L"";
		int keyLen = to_string( key ).length();
		while ( output.length() < msgLength )
		{
			key = key * key;
			// отсечение крайних цифр квадрата ключа
			if ( to_string( key ).length() < keyLen * 2 )
				key = numCut( key, (int)keyLen / 2 - 1, (int)ceil( keyLen / 2 ) );
			else
				key = numCut( key, (int)keyLen / 2, (int)ceil( keyLen / 2 ) );
			output = output + to_wstring( key );
		}
		return output;
	}
	// функци€ преобразовани€ символа в двоичный код
	wstring charToBinary( wchar_t c )
	{
		c = towupper( c );
		wstring output = L"";
		int charIndex = alph.find_first_of( c );
		while ( charIndex != 0 )
		{
			output = to_wstring( charIndex % 2 ) + output;
			charIndex = charIndex / 2;
		}
		if ( output.length() < bit_depth )
		{
			int nullc = bit_depth - output.length();
			for ( int i = 0; i < nullc; i++ )
			{
				output = L'0' + output;
			}
		}
		return output;
	}
	// функци€ преобразовани€ числа в двоичный код
	wstring numToBinary( int num )
	{
		wstring output = L"";
		while ( num != 0 )
		{
			output = to_wstring( num % 2 ) + output;
			num = num / 2;
		}
		if ( output.length() < bit_depth )
		{
			int nullc = bit_depth - output.length();
			for ( int i = 0; i < nullc; i++ )
			{
				output = L'0' + output;
			}
		}
		return output;
	}
	// функци€ преобразовани€ двоичного кода в символ
	wchar_t binaryToChar( wstring binary )
	{
		int num = 0;
		for ( int i = 0; i < bit_depth; i++ )
		{
			if ( binary[bit_depth - 1 - i] == L'1' )
				num = num + pow( 2, i );
		}
		if ( num > alph.length() )
			num = num - alph.length();
		return alph[num];
	}
	// функци€ сложени€ по модулю 2
	wstring binSum( wstring x, wstring y )
	{
		wstring output = L"";
		int lenDiff = abs( (long)( x.length() - y.length() ) );
		if ( x.length() > y.length() )
		{
			swap( x, y );
		}
		for ( int i = x.length() - 1; i >= 0; i-- )
		{
			if ( x[i] == y[i + lenDiff] )
				output = L'0' + output;
			else if ( x[i] != y[i + lenDiff] )
				output = L'1' + output;
		}
		for ( int i = lenDiff - 1; i >= 0; i-- )
		{
			output = y[i] + output;
		}
		return output;
	}
public:
	Encryptor()
	{
		this->alph = alphEN;
		bit_depth = 6;
	}
	bool setAlphToRU()
	{
		this->alph = alphRU;
		bit_depth = 6;
		return true;
	}
	bool setAlphToEN()
	{
		this->alph = alphEN;
		bit_depth = 6;
		return true;
	}
	// функци€ шифровани€
	wstring encrypt( wstring data, unsigned long long key )
	{
		wstring output = L"";
		wstring gam = gamma( key, data.length() );
		for ( int i = 0; i < data.length(); i++ )
		{
			// разбиение сообщени€ на двоичный код
			wchar_t c = data[i];
			if ( !iswspace( c ) )
				c = towupper( c );
			wstring binChar = charToBinary( c );
			wstring gamBinChar = numToBinary( gam[i] - L'0' );
			// сложение с соответствующим символом гаммы
			wstring encBinChar = binSum( binChar, gamBinChar );
			output += binaryToChar( encBinChar );
		}
		return output;
	}
	// функци€ расшифровани€
	wstring uncrypt( wstring data, unsigned long long key )
	{
		wstring output = L"";
		wstring gam = gamma( key, data.length() );
		for ( int i = 0; i < data.length(); i++ )
		{
			// разбиение сообщени€ на двоичный код
			wchar_t c = data[i];
			if ( !iswspace( c ) )
				c = towupper( c );
			wstring binChar = charToBinary( c );
			wstring gamBinChar = numToBinary( gam[i] - L'0' );
			// сложение с соответствующим символом гаммы
			wstring uncBinChar = binSum( binChar, gamBinChar );
			output += binaryToChar( uncBinChar );
		}
		return output;
	}
};