#include <string>
#include <iostream>

using namespace std;

class Encryptor
{
private:
	wstring alphEN = L"ABCDEFGHIJKLMNOPQRSTUVWXYZ 12345";
	wstring alphRU = L"АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ 1234567890!@#$%^&*()_+{}|:-<>?";
	wstring alph;
	int bit_depth;

	// таблица начальных перестановок сообщения
	int IP[64] = {
		58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
		62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
		57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
		61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
	};
	// таблица расширения сообщения
	int E[48] = {
		32, 1, 2, 3, 4, 5,
		4, 5, 6, 7, 8, 9,
		8, 9, 10, 11, 12, 13,
		12, 13, 14, 15, 16, 17,
		16, 17, 18, 19, 20, 21,
		20, 21, 22, 23, 24, 25,
		24, 25, 26, 27, 28, 29,
		28, 29, 30, 31, 32, 1
	};
	// таблица перестановок ключа
	int G[56] = {
		57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
		10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
		63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
		14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4
	};
	// значения сдвигов ключей для каждого раунда
	int Sh[16] = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };
	// таблица сжатия ключа
	int Compr[48] = {
		14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4,
		26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40,
		51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
	};
	// таблица преобразований Si
	int SBoxes[8][4][16] = {
		{
			{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
			{0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
			{4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
			{15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
		},
		{
			{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
			{3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
			{0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
			{13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
		},
		{
			{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
			{13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
			{13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
			{1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
		},
		{
			{7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
			{13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
			{10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
			{3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
		},
		{
			{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
			{14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
			{4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
			{11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
		},
		{
			{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
			{10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
			{9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
			{4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
		},
		{
			{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
			{13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
			{1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
			{6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
		},
		{
			{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
			{1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
			{7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
			{2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
		}
	};
	// таблица перестановок S-блоков
	int P[32] = {
		16, 7, 20, 21, 29, 12, 28, 17,
		1, 15, 23, 26, 5, 18, 31, 10,
		2, 8, 24, 14, 32, 27, 3, 9,
		19, 13, 30, 6, 22, 11, 4, 25
	};
	// таблица конечной перестановки
	int IP1[64] = {
		40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
		38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
		36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
		34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25
	};

	// функция перестановки
	wstring transform( wstring binData, int *pbox, int boxSize )
	{
		wstring output = L"";
		for ( int i = 0; i < boxSize; i++ )
		{
			output += binData[pbox[i] - 1];
		}
		return output;
	}
	// функция преобразования ключа к 56-битному виду 
	wstring keyTo64( wstring binKey )
	{
		wstring output = binKey;
		if ( binKey.length() < 64 )
		{
			for ( int i = 0; i < 64 / binKey.length(); i++ )
			{
				output.append( binKey );
			}
		}
		output = output.substr( 0, 64 );
		return output;
	}
	// функция цикличного сдвига влево
	wstring shiftL( wstring str, int s )
	{
		str = str + str.substr( 0, s );
		str = str.substr( s, str.length() - s );
		return str;
	}
	// функция преобразования S-блоков
	wstring substitute( wstring R )
	{
		int a, b, B;
		wstring output = L"";
		wstring bin = L"";
		wstring *blocks = new wstring[8];

		binDataSplit( R, blocks, 6.0f );
		for ( int i = 0; i < 8; i++ )
		{
			bin.append(1, blocks[i][0]);
			bin.append( 1, blocks[i][5] );
			a = binaryToInt( bin, 2 );

			bin = L"";
			bin.append( 1, blocks[i][1] );
			bin.append( 1, blocks[i][2] );
			bin.append( 1, blocks[i][3] );
			bin.append( 1, blocks[i][4] );
			b = binaryToInt( bin, 4 );

			B = SBoxes[i][a][b];
			output += numToBinary( B, 4 );
		}
		return output;
	}
	// функция преобразования символа в двоичный код
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
	// функция преобразования числа в двоичный код
	wstring numToBinary( int num,  int bit_depth )
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
	// функция преобразования двоичного кода в символ
	wchar_t binaryToChar( wstring binary )
	{
		if ( binary.length() < bit_depth )
			binary.append( bit_depth - binary.length(), '0' );
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
	// функция преобразования двоичного кода в строку
	wstring binaryToStr( wstring binary )
	{
		wstring output = L"";
		wstring buffer = L"";

		for ( int i = 0; i < binary.length(); i++ )
		{
			if ( buffer.length() == bit_depth )
			{
				output += binaryToChar( buffer );
				buffer = L"";
			}
			buffer += binary[i];
		}
		output += binaryToChar( buffer );
		return output;
	}
	// функция преобразования двоичного кода в десятичное число
	int binaryToInt( wstring binary, int bit_depth )
	{
		int num = 0;
		for ( int i = 0; i < bit_depth; i++ )
		{
			if ( binary[bit_depth - 1 - i] == L'1' )
				num = num + pow( 2, i );
		}
		return num;
	}
	// функция преобразования строки в двоичный код
	wstring wstringToBinary( wstring str )
	{
		wstring output = L"";
		for ( int i = 0; i < str.length(); i++ )
		{
			output += charToBinary( str[i] );
		}
		return output;
	}
	// функция разбиения сообщения на блоки по n бит
	void binDataSplit( wstring binData, wstring *arr, float n )
	{
		int blockCount = ceil( binData.length() / n );
		for ( int i = 0; i < blockCount; i++ )
		{
			arr[i] = binData.substr( i * n, n );
			if ( arr[i].length() < n )
			{
				arr[i].append( n - arr[i].length(), L'0' );
			}
		}
	}
	// функция сложения по модулю 2
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
	// функция генерации ключей раундов
	void keyGen( wstring binKey, wstring *keyStorage )
	{
		wstring C, D, CD, roundKey;

		C = transform( binKey, &G[0], 28 );
		D = transform( binKey, &G[28], 28 );
		for ( int i = 0; i < 16; i++ )
		{
			C = shiftL( C, Sh[i] );
			D = shiftL( D, Sh[i] );
			CD = C + D;
			roundKey = transform( CD, Compr, 48 );
			keyStorage[i] = roundKey;
		}
	}
	// функция Фейстеля
	wstring feistel( wstring binData32, wstring roundKey )
	{
		binData32 = transform( binData32, E, 48 );
		binData32 = binSum( binData32, roundKey );

		binData32 = substitute( binData32 );
		binData32 = transform( binData32, P, 32 );
		return binData32;
	}
	// функция шифрования одного блока
	wstring encrypt( wstring binData, wstring binKey )
	{
		wstring output = L"";
		wstring L, Li, R;

		wstring roundKeys[16];
		keyGen( binKey, roundKeys );

		binData = transform( binData, IP, 64 );
		L = binData.substr( 0, 32 );
		R = binData.substr( 32, 32 );

		for ( int i = 0; i < 16; i++ )
		{
			Li = R;
			R = feistel( R, roundKeys[i] );
			R = binSum( R, L );
			L = Li;
		}
		output = transform( L + R, IP1, 64 );
		return output;
	}
	// функция расшифрования одного блока
	wstring uncrypt( wstring binData, wstring binKey )
	{
		wstring output = L"";
		wstring L, Ri, R;

		wstring roundKeys[16];
		keyGen( binKey, roundKeys );

		binData = transform( binData, IP, 64 );
		L = binData.substr( 0, 32 );
		R = binData.substr( 32, 32 );

		for ( int i = 0; i < 16; i++ )
		{
			Ri = L;
			L = feistel( L, roundKeys[16-i-1] );
			L = binSum( L, R );
			R = Ri;
		}
		output = transform( L + R, IP1, 64 );
		return output;
	}
public:
	Encryptor()
	{
		this->alph = alphRU;
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
		bit_depth = 5;
		return true;
	}
	// функция шифрования
	wstring Encrypt( wstring data, wstring key )
	{
		wstring output = L"";
		wstring binData = wstringToBinary( data );
		wstring binKey = keyTo64( wstringToBinary( key ) );

		int blockCount = ceil( binData.length() / 64.0 );
		wstring *blocks = new wstring[blockCount];
		binDataSplit( binData, blocks, 64.0f );

		for ( int i = 0; i < blockCount; i++ )
		{
			output += encrypt( blocks[i], binKey );
		}
		output = binaryToStr( output );

		return output;
	}
	// функция расшифрования
	wstring Uncrypt( wstring data, wstring key )
	{
		wstring output = L"";
		wstring binData = wstringToBinary( data );
		wstring binKey = keyTo64( wstringToBinary( key ) );

		int blockCount = ceil( binData.length() / 64.0 );
		wstring *blocks = new wstring[blockCount];
		binDataSplit( binData, blocks, 64.0f );

		for ( int i = 0; i < blockCount; i++ )
		{
			output += uncrypt( blocks[i], binKey );
		}
		output = binaryToStr( output );

		return output;
	}
};
