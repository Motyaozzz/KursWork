#include <iostream>
#include <fstream>
#include <ctime>
#include <windows.h>
#include <wincrypt.h>

#define fileway "Students.txt"
#pragma comment(lib, "crypt32.lib")

using namespace std;

struct Sub {
	char* name = new char[21];
	int* mark = new int();
};

class Overload {
private:
	char* data = nullptr;

public:
	Overload(const char in[]) {
		data = new char[strlen(in) + 1]();
		for (int i = 0; i < strlen(in); i++) {
			*(data + i) = in[i];
		}
		data[strlen(data)] = '\0';
	}

	~Overload() {
		delete[] data;
	}

	void operator += (const char other[]) {
		char* temp = new char[strlen(data) + strlen(other) + 1]();
		int i = 0;
		for (; i < strlen(data); i++) {
			*(temp + i) = *(data + i);
		}
		for (int j = 0; j < strlen(other); j++) {
			*(temp + i + j) = *(other + j);
		}
		temp[strlen(temp)] = '\0';

		delete[] data;

		data = new char[strlen(temp) + 1]();
		for (i = 0; i < strlen(temp); i++) {
			*(data + i) = *(temp + i);
		}
		data[strlen(data)] = '\0';
		delete[] temp;
	}
	char* Get() {
		return data;
	}
};

class Crypt {
private:
	char* Gen_pass() {
		srand(time(NULL));
		char* pass = new char[17];
		for (int i = 0; i < 16; ++i)
		{
			switch (rand() % 3) {
			case 0:
				pass[i] = rand() % 10 + '0';
				break;
			case 1:
				pass[i] = rand() % 26 + 'A';
				break;
			case 2:
				pass[i] = rand() % 26 + 'a';
			}
		}
		pass[16] = '\0';

		return pass;
	}

public:
	void Encrypt() {
		Overload fileway_ENC(fileway);
		fileway_ENC += ".enc";

		ifstream File;
		File.open(fileway, ios::binary);
		ofstream File_enc;
		File_enc.open(fileway_ENC.Get(), ios::binary | ios::app);
		File_enc.seekp(0, ios::beg);

		int file_length;
		File.seekg(0, ios::end);
		file_length = File.tellg();
		File.seekg(0, ios::beg);

		char* szPassword = Gen_pass();

		int dwLength = strlen(szPassword);
		File_enc.write((char*)&dwLength, sizeof(dwLength));
		File_enc.write((char*)szPassword, dwLength + 1);

		HCRYPTPROV hProv;
		HCRYPTKEY hKey;
		HCRYPTHASH hHash;

		if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
		{
			cout << "Error during CryptAcquireContext!";
		}

		if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
		{
			cout << "Error during CryptCreateHash!";
		}

		if (!CryptHashData(hHash, (BYTE*)szPassword, (DWORD)dwLength, 0))
		{
			cout << "Error during CryptHashData!";
		}

		if (!CryptDeriveKey(hProv, CALG_RC4, hHash, CRYPT_EXPORTABLE, &hKey))
		{
			cout << "Error during CryptDeriveKey!";
		}

		size_t enc_length = 8;
		DWORD dwBlockLen = 1000 - 1000 % enc_length;
		DWORD dwBufferLen = 0;

		if (enc_length > 1)
		{
			dwBufferLen = dwBlockLen + enc_length;
		}
		else
		{
			dwBufferLen = dwBlockLen;
		}

		int count = 0;
		bool final = false;

		while (count != file_length) {
			if (file_length - count < dwBlockLen) {
				dwBlockLen = file_length - count;
				final = true;
			}

			BYTE* temp = new BYTE[dwBufferLen]();
			File.read((char*)temp, dwBlockLen);

			if (!CryptEncrypt(hKey, NULL, final, 0, temp, &dwBlockLen, dwBufferLen))
			{
				cout << "Error during CryptEncrypt. \n";
			}

			File_enc.write((char*)temp, dwBlockLen);

			count = count + dwBlockLen;
		}

		if (hHash)
		{
			if (!(CryptDestroyHash(hHash)))
				cout << "Error during CryptDestroyHash";
		}

		if (hKey)
		{
			if (!(CryptDestroyKey(hKey)))
				cout << "Error during CryptDestroyKey";
		}

		if (hProv)
		{
			if (!(CryptReleaseContext(hProv, 0)))
				cout << "Error during CryptReleaseContext";
		}

		File.close();
		File_enc.close();

		if (remove(fileway) != 0) {
			cout << "ERROR -- ошибка при удалении файла\n";
		}
	}

	void Decrypt() {
		Overload fileway_ENC(fileway);
		fileway_ENC += ".enc";

		ofstream File;
		File.open(fileway, ios::binary | ios::app);
		ifstream File_enc;
		File_enc.open(fileway_ENC.Get(), ios::binary);

		int file_length;
		File_enc.seekg(0, ios::end);
		file_length = File_enc.tellg();
		File_enc.seekg(0, ios::beg);

		if (file_length == -1 || file_length == 0) {
			return;
		}

		int dwLength;
		File_enc.read((char*)&dwLength, sizeof(dwLength));
		char* szPassword = new char[dwLength];
		File_enc.read((char*)szPassword, dwLength + 1);

		HCRYPTPROV hProv;
		HCRYPTKEY hKey;
		HCRYPTHASH hHash;

		if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
		{
			cout << "Error during CryptAcquireContext!";
		}

		if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
		{
			cout << "Error during CryptCreateHash!";
		}

		if (!CryptHashData(hHash, (BYTE*)szPassword, (DWORD)dwLength, 0))
		{
			cout << "Error during CryptHashData!";
		}

		if (!CryptDeriveKey(hProv, CALG_RC4, hHash, CRYPT_EXPORTABLE, &hKey))
		{
			cout << "Error during CryptDeriveKey!";
		}

		size_t enc_length = 8;
		DWORD dwBlockLen = 1000 - 1000 % enc_length;
		DWORD dwBufferLen = 0;

		if (enc_length > 1)
		{
			dwBufferLen = dwBlockLen + enc_length;
		}
		else
		{
			dwBufferLen = dwBlockLen;
		}

		int count = sizeof(dwLength) + strlen(szPassword) + 1;
		bool final = false;

		while (count != file_length) {
			if (file_length - count < dwBlockLen) {
				dwBlockLen = file_length - count;
				final = true;
			}

			BYTE* temp = new BYTE[dwBlockLen];
			File_enc.read((char*)temp, dwBlockLen);

			if (!CryptDecrypt(hKey, 0, final, 0, temp, &dwBlockLen))
			{
				cout << "Error during CryptEncrypt. \n";
			}

			File.write((char*)temp, dwBlockLen);
			count = count + dwBlockLen;
		}

		if (hHash)
		{
			if (!(CryptDestroyHash(hHash)))
				cout << "Error during CryptDestroyHash";
		}

		if (hKey)
		{
			if (!(CryptDestroyKey(hKey)))
				cout << "Error during CryptDestroyKey";
		}

		if (hProv)
		{
			if (!(CryptReleaseContext(hProv, 0)))
				cout << "Error during CryptReleaseContext";
		}

		File.close();
		File_enc.close();
		if (remove(fileway_ENC.Get()) != 0) {
			cout << "ERROR -- ошибка при удалении файла\n";
		}
	}
};

class Functions {
public:
	virtual bool Edit() = 0;

	void printer(char* val) {
		cout << val;
	}

	void printer(int val) {
		cout << val;
	}

	void printer(const char val[]) {
		cout << val;
	}

	void cleaner() {
		cin.seekg(0, ios::end);
		cin.clear();
	}

	bool checkLetters(char* line, int n) {
		int i = 0;
		int x = 1;
		while (line[i] != '\0') {
			if (!((line[i] >= 'а' && line[i] <= 'я') || (line[i] >= 'А' && line[i] <= 'Я'))) {
				x = 0;
				break;
			}
			i++;
		}
		if (x == 0) {
			return false;
		}
		else {
			return true;
		}
	}

	void checkEmptyStr(char* in, int len) {
		char* buf = new char[len]();
		cleaner();
		cin.get(buf, len);
		cleaner();
		if (strlen(buf) == 0) {
			printer("Вы ввели пустую строку! Повторите ввод: ");
			checkEmptyStr(in, len);
		}
		else {
			for (int i = 0; i < len; i++) {
				in[i] = *(buf + i);
			}
			delete[] buf;
		}
	}

	void backMenu() {
		char temp[2];
		printer("Чтобы вернуться в меню нажмите [Enter]");
		cleaner();
		cin.get(temp, 2);
		cleaner();
	}

	int charToInt(char* a) {
		int d = 0;
		for (int i = strlen(a) - 1; i >= 0; i--) {
			d += (a[i] - '0') * (pow(10, strlen(a) - i - 1));
		}
		return d;
	}
};

class Student : Functions {
	friend class File;
public:
	Student() {
		surname = new char[31]();
		name = new char[31]();
		patr = new char[31]();
		day = new int(0);
		month = new int(0);
		year = new int(0);
		admit_year = new int(0);
		sex = new char[2]();
		fac = new char[25]();
		depart = new char[25]();
		group = new char[11]();
		book = new char[21]();
	}

	~Student() {
		delete surname;
		delete name;
		delete patr;
		delete day;
		delete month;
		delete year;
		delete admit_year;
		delete fac;
		delete depart;
		delete group;
		delete book;
	}

	void Set() {
		printer("Фамилия: ");
		Set(surname, 31);
		if (!strcmp(surname, "-1")) {
			return;
		}
		while (!(checkLetters(surname, 31))) {
			printer("Ожидался ввод букв. Повторите ввод:");
			Set(surname, 31);

		}

		printer("Имя: ");
		Set(name, 31);
		while (!(checkLetters(name, 31))) {
			printer("Ожидался ввод букв. Повторите ввод:");
			Set(name, 31);

		}

		printer("Отчество: ");
		Set(patr, 31);
		while (!(checkLetters(patr, 31))) {
			printer("Ожидался ввод букв. Повторите ввод:");
			Set(patr, 31);

		}

		printer("Дата рождения [дд/мм/гггг]: ");
		while (!checkBirthDay()) {
			printer("Дата Рождения [дд/мм/гггг]: ");
		};

		printer("Год поступления [1980-2021]: ");
		checkAdmissionYear();

		printer("Пол [М/Ж]: ");
		*sex = checkSex();
		*(sex + 1) = '\0';

		printer("Факультет: ");
		Set(fac, 25);
		while (!(checkLetters(fac, 25))) {
			printer("Ожидался ввод букв. Повторите ввод:");
			Set(fac, 25);

		}

		printer("Кафедра: ");
		Set(depart, 25);

		printer("Группа: ");
		Set(group, 11);

		printer("Номер зачетной книжки: ");
		checkEmptyStr(book, 21);
		cleaner();
		while (!checkStudentBook()) {
			printer("Такой номер уже есть в базе\nПопробуйте ввести ещё раз: ");
			checkEmptyStr(book, 21);
			cleaner();
		}
	}

	bool Edit() override {
		int ans;
		cin >> ans;
		while (ans < 1 || ans>11) {
			if (cin.fail()) {
				cin.clear();
				cin.ignore(32767, '\n');
				printer("Ошибка! Введите номер пункта меню, который хотите вывести\n-----> ");
				cin >> ans;
				continue;
			}
			if (ans < 1 || ans>11) {
				printer("Вы ввели число не из диапозона [1;11]. Повторите ввод\n-----> ");
				cin.ignore(32767, '\n');
				cin >> ans;
			}
		}
		cleaner();
		switch (ans) {
		case 1:
			printer("Фамилия: ");
			Set(surname, 31);
			while (!(checkLetters(surname, 31))) {
				printer("Ожидался ввод букв. Повторите ввод:");
				Set(surname, 31);

			}
			break;
		case 2:
			printer("Имя: ");
			Set(name, 31);
			while (!(checkLetters(name, 31))) {
				printer("Ожидался ввод букв. Повторите ввод:");
				Set(name, 31);

			}
			break;
		case 3:
			printer("Отчество: ");
			Set(patr, 31);
			while (!(checkLetters(patr, 31))) {
				printer("Ожидался ввод букв. Повторите ввод:");
				Set(patr, 31);

			}
			break;
		case 4:
			printer("Дата рождения [дд/мм/гггг]: ");
			while (!checkBirthDay()) {
				printer("Дата рождения [дд/мм/гггг]: ");
			};
			while (*admit_year - *year <= 15 || *admit_year < 1980 || *admit_year > 2021 || *admit_year <= *year) {
				printer("С учётом введённой даты рождения, невозможно поступление в таком возрасте!\nИзмените год поступления [1980-2021]:");
				cin >> *admit_year;
			}
			break;
		case 5:
			printer("Год Поступления [1980-2021]: ");
			checkAdmissionYear();
			break;
		case 6:
			printer("Пол [м/ж]: ");
			*sex = checkSex();
			*(sex + 1) = '\0';
			break;
		case 7:
			printer("Факультет: ");
			Set(fac, 25);
			while (!(checkLetters(fac, 25))) {
				printer("Ожидался ввод букв. Повторите ввод:");
				Set(fac, 25);

			}
			break;
		case 8:
			printer("Кафедра: ");
			Set(depart, 25);
			break;
		case 9:
			printer("Группа: ");
			Set(group, 11);
			break;
		case 10:
			char book1[21];
			for (int i = 0; i < 21; i++) {
				book1[i] = book[i];
			}
			printer("Номер зачетной книжки: ");
			checkEmptyStr(book, 21);
			cleaner();
			while (!checkStudentBook()) {
				if (!checkStudentBook()) {
					if (strcmp(book1, book)) {
						printer("Такой номер зачетной книжки уже существует\n");
						printer("Введите Номер зачетной книжки: ");
						checkEmptyStr(book, 21);
						cleaner();
					}
					else break;
				}
				else break;
			}
			break;
		case 11: return true;
		default: {
			printer("Введен неверный вариант\n");
			Edit();
		}
		}
		return false;
	}

private:
	char* surname = nullptr;
	char* name = nullptr;
	char* patr = nullptr;
	int* day = nullptr;
	int* month = nullptr;
	int* year = nullptr;
	int* admit_year = nullptr;
	char* sex = nullptr;
	char* fac = nullptr;
	char* depart = nullptr;
	char* group = nullptr;
	char* book = nullptr;

	void Set(char* in, int len) {
		checkEmptyStr(in, len);
		cleaner();
	}

	bool checkBirthDay() {
		char* temp = new char[12]();
		*day = 0;
		*month = 0;
		*year = 0;
		cin.get(temp, 12);
		cleaner();
		int i = 0;
		while (*(temp + i) != '\0') {
			if (!((*(temp + i) >= '0' && *(temp + i) <= '9') || *(temp + i) == ' ' || *(temp + i) == '.' || *(temp + i) == '/' || *(temp + i) == '\0' || *(temp + i) == '\n') || i >= 10) {
				cout << "Ошибка!\nПовторите ввод в формате дата рождения [дд/мм/гггг]:";
				cleaner();
				cin.get(temp, 12);
				cleaner();
				i = 0;
				continue;
			}
			if (i == 2 || i == 5) {
				if (*(temp + i) >= '0' && *(temp + i) <= '9') {
					cout << "Ошибка!\nПовторите ввод в формате дата рождения [дд/мм/гггг]:";
					cleaner();
					cin.get(temp, 12);
					cleaner();
					i = 0;
					continue;
				}
			}

			i++;
		}
		for (int i = 0; *(temp + i) != '\0'; i++) {
			if (*(temp + i) >= 48 && *(temp + i) <= 57 && ((i >= 0 && i <= 1) || (i >= 3 && i <= 4) || (i >= 6 && i <= 9))) {
				switch (i) {
				case 0: case 1:
					*day = *day * 10 + *(temp + i) - 0x30;
					break;
				case 3: case 4:
					*month = *month * 10 + *(temp + i) - 0x30;
					break;
				case 6: case 7: case 8: case 9:
					*year = *year * 10 + *(temp + i) - 0x30;
					break;
				}
			}
		}
		delete[] temp;
		if (checkDate(*day, *month, *year)) return true;
		else return false;
	}

	void checkAdmissionYear() {
		char* temp1 = new char[6]();
		cleaner();
		int i = 0;
		bool flag2;
		while (true) {
			flag2 = true;
			i = 0;
			cleaner();
			cin.get(temp1, 6);
			cleaner();
			while (*(temp1 + i) != '\0') {
				if (!flag2) {
					break;
				}
				if (!(*(temp1 + i) >= '0' && *(temp1 + i) <= '9') || i >= 4) {
					cout << "Ошибка!\nПовторите ввод в формате Год поступления [1980-2021]: ";
					i = 0;
					flag2 = false;
					continue;
				}
				i++;
			}
			if (!flag2) {
				continue;
			}
			*admit_year = charToInt(temp1);
			if (*admit_year - *year <= 15 || *admit_year < 1980 || *admit_year > 2021 || *admit_year <= *year) {
				printer("Поступление невозможно в таком возрасте!\nИзмените год поступления [1980-2021]:");
				i = 0;
				continue;
			}
			break;
		}
		cleaner();
	}

	bool checkStudentBook() {
		int* length = new int(0);
		int* len_file = new int(0);
		char* buf = new char[21];
		Crypt crypt;
		crypt.Decrypt();

		ifstream File;
		File.open(fileway, ios::binary);

		File.seekg(0, ios::end);
		*len_file = File.tellg();
		File.seekg(0, ios::beg);

		while (*length != *len_file) {
			File.seekg(171, ios::cur);
			File.read(buf, 21);

			if (!strcmp(buf, book)) {
				File.close();
				crypt.Encrypt();
				return false;
			}

			int* session_count = new int(0);
			int* subject_count = new int(0);
			int* sum = new int(0);

			File.read((char*)&*session_count, 4);


			for (int i = 0; i < *session_count; i++) {
				File.read((char*)subject_count, 4);
				*sum += *subject_count;
			}
			File.seekg((*sum) * 25, ios::cur);


			*length += 196;
			*length = *length + *session_count * 4;
			*length = *length + (*sum) * 25;
		}
		File.close();
		crypt.Encrypt();
		return true;

	}

	bool checkDate(int day, int month, int year) {
		if (day != 0 && month != 0 && year != 0) {
			if (year >= 1900 && year <= 2005) {
				if (month >= 1 && month <= 12) {
					switch (month) {
					case 1: case 3: case 5: case 7: case 8: case 10: case 12:
						if (day >= 1 && day <= 31) {
							return true;
						}
						break;
					case 2:
						if (year % 4 != 0 || year % 100 == 0 && year % 400 != 0) {
							if (day >= 1 && day <= 28) {
								return true;
							}
						}
						else {
							if (day >= 1 && day <= 29) {
								return true;
							}
						}
						break;
					case 4: case 6: case 9: case 11:
						if (day >= 1 && day <= 30) {
							return true;
						}
						break;
					default:
						printer("Ошибка! Повторите ввод\n");
						break;
					}
					printer("Ошибка! Введите день месяца правильно\n");
				}
				else {
					printer("Ошибка! Введите месяц от 1 до 12\n");
				}
			}
			else {
				printer("Ошибка! Введите год рождения от 1900 до 2005\n");
			}
		}
		return false;
	}

	char checkSex() {
		char value;
		while (true) {
			cin >> value;
			if (value == 'М' || value == 'Ж' || value == 'ж' || value == 'м') {
				cleaner();
				return value;
			}
			printer("Ошибка! Вводите только буквы М(м)/Ж(ж) \n");
			cleaner();
		}
	}
};

class Session : Functions {
	friend class File;
public:
	Session() {
		session_count = new int(0);
		sub_count = nullptr;
	}

	~Session() {
		delete session_count;
		delete sub_count;
		delete subject;
	}

	void setSession() {
		setSessionCount();
		setSubjCount();
		setSubjects();
	}

	bool Edit() override {
		int sub_sum = 0;
		for (int i = 0; i < *session_count; i++) {
			sub_sum = sub_sum + *(sub_count + i);
		}
		int pos = -1;
		Sub* temp = nullptr;
		int* temp_2 = nullptr;
		int sum = 0;
		int ans, num = -1, ses;
		cin >> ans;
		while (ans < 1 || ans>5) {
			if (cin.fail()) {
				cin.clear();
				cin.ignore(32767, '\n');
				printer("Ошибка! Введите номер пункта меню, который хотите вывести\n-----> ");
				cin >> ans;
				continue;
			}
			if (ans < 1 || ans>5) {
				printer("Вы ввели число не из диапозона [1;5]. Повторите ввод\n-----> ");
				cin.ignore(32767, '\n');
				cin >> ans;
			}
		}
		cleaner();
		if (ans == 1) {
			if (*session_count < 9) {
				system("cls");
				int sub_new = 0;
				printer("Введите количество предметов в новой сессии: ");
				cin >> sub_new;
				cleaner();
				int sub_sum = 0;
				for (int i = 0; i < *session_count; i++) {
					sub_sum = sub_sum + *(sub_count + i);
				}

				temp = new Sub[sub_sum + sub_new]();
				*session_count = *session_count + 1;
				temp_2 = new int[*session_count]();

				for (int i = 0; i < sub_sum; i++) {
					for (int j = 0; j < 31; j++) {
						*((temp + i)->name + j) = *((subject + i)->name + j);
					}
					*((temp + i)->mark) = *((subject + i)->mark);
				}

				for (int i = sub_sum; i < sub_sum + sub_new; i++) {
					printer("Введите название ");
					printer(i - sub_sum + 1);
					printer("-го предмета в новой сессии: ");
					checkEmptyStr((temp + i)->name, 21);
					printer("Введите оценку за ");
					cout << (temp + i)->name;
					printer(": ");
					int buf;
					while (true) {
						cin >> buf;
						cleaner();
						if (buf >= 2 && buf <= 5) {
							*((temp + i)->mark) = buf;
							break;
						}
						printer("Неверные данные! Вводите значения от 2 до 5\n");
					}
				}

				for (int i = 0; i < *session_count - 1; i++) {
					*(temp_2 + i) = *(sub_count + i);
				}

				*(temp_2 + *session_count - 1) = sub_new;

				delete[] subject;
				delete[] sub_count;

				*&subject = temp;
				*&sub_count = temp_2;
			}
			else {
				printer("Достигнуто максимальное количество сессий\n");
				backMenu();
			}
		}
		else if (ans == 2 || ans == 3 || ans == 4) {
			printer("Введите номер сессии -----> ");
			cin >> ses;
			if (!(ses != 0 && ses <= *session_count)) {
				printer("Номер такой сессии не найден, повторите ввод\n");
				backMenu();
				return false;
			}
			ses -= 1;
			if (ans == 2 || ans == 4)
			{
				printer("Введите номер предмета -----> ");
				cin >> num;
				if (!(num <= *(sub_count + ses) && num != 0)) {
					printer("Номер такого предмета не найден, повторите ввод\n");
					backMenu();
					return false;
				}
				num -= 1;
			}
			if (ans == 3) {
				if (*(sub_count + ses) == 10) {
					printer("Достигнуто максимальное кол-во предметов\n");
					backMenu();
					return false;
				}
				temp = new Sub[sub_sum + 1]();
			}
			else if (ans == 4) temp = new Sub[sub_sum + 1]();

			system("cls");
			int sum_new = 0;
			for (int i = 0; i < *session_count; i++) {
				for (int j = 0; j < *(sub_count + i); j++) {
					if (((!(ses == i && num == j) || ans != 4) && ans != 2) || (ans == 3 && num == -1)) {
						for (int k = 0; k < 21; k++) {
							*((temp + sum_new)->name + k) = *((subject + sum)->name + k);
						}
						*((temp + sum_new)->mark) = *((subject + sum)->mark);
						sum_new++;
					}

					else if (i == ses && j == num && ans == 2) {
						printer("Выбранный предмет: ");
						cout << (subject + sum)->name << "\nОценка: " << *(subject + sum)->mark << "\n";
						printer("\nЧто нужно изменить:\n\n[1] Название предмета\n[2] Оценку по предмету\n[3] Вернуться в блок редактирования\n");
						printer("-----> ");
						int ans1;
						cin >> ans1;
						switch (ans1) {
						case 1:
							printer("Введите название предмета: ");
							checkEmptyStr((subject + sum)->name, 21);
							break;
						case 2:
							printer("Введите оценку: ");
							int buf;
							while (true) {
								cleaner();
								cin >> buf;
								cleaner();
								if (buf >= 2 && buf <= 5) {
									*(subject + sum)->mark = buf;
									break;
								}
								printer("Неверные данные! Вводите значения от 2 до 5\n");
							}
							break;
						case 3:
							return false;
						}
					}
					if (ans == 3 && ses == i && j + 1 == *(sub_count + i)) {
						printer("Введите название нового предмета: ");
						checkEmptyStr((temp + sum_new)->name, 21);
						cleaner();
						printer("Введите оценку за ");
						cout << (temp + sum_new)->name;
						printer(": ");
						int buf;
						while (true) {
							cleaner();
							cin >> buf;
							cleaner();
							if (buf >= 2 && buf <= 5) {
								*(temp + sum_new)->mark = buf;
								break;
							}
							printer("Неверные данные! Вводите значения от 2 до 5\n");
						}
						sum_new++;
					}
					sum++;
				}
			}

			if (ans == 4) {
				*(sub_count + ses) = *(sub_count + ses) - 1;
				if (*(sub_count + ses) == 0) {
					sum = 0;
					*session_count = *session_count - 1;
					int* temp_1 = new int[*session_count];
					for (int i = 0; i <= *session_count + 1; i++) {
						if (i != ses) {
							*(temp_1 + sum) = *(sub_count + i);
							sum++;
						}
					}
					delete[] sub_count;
					sub_count = temp_1;
				}
			}
			else if (ans == 3) {
				*(sub_count + ses) = *(sub_count + ses) + 1;
			}
			if (ans == 3 || ans == 4) {
				delete[] subject;
				subject = temp;
			}
		}
		else if (ans == 5) {
			return true;
		}
		else {
			printer("Такого варианта не найдено\n");
			backMenu();
			return false;
		}
		return false;
	}

private:
	int* session_count = nullptr;
	int* sub_count = nullptr;
	Sub* subject = nullptr;

	void setSessionCount() {
		printer("Введите количество семестров: ");
		int value;
		cin >> value;
		while (value < 1 || value > 9) {
			if (cin.fail()) {
				cin.clear();
				cin.ignore(32767, '\n');
				printer("Ошибка! Вводите значения от 1 до 9 \n-----> ");
				cin >> value;
				continue;
			}
			if (value < 1 || value > 9) {
				printer("Ошибка! Вводите значения от 1 до 9\n-----> ");
				cin.ignore(32767, '\n');
				cin >> value;
			}
		}
		*session_count = value;
	}

	void setSubjCount() {
		sub_count = new int[*session_count];
		bool flag = true;
		for (int i = 0; i < *session_count; i++) {
			bool flag = true;
			printer("Введите количество предметов в ");
			printer(i + 1);
			printer("-м семестре: ");
			int* buf = new int();
			cin >> *buf;
			while (*buf < 1 || *buf > 10) {
				if (cin.fail()) {
					cin.clear();
					cin.ignore(32767, '\n');
					printer("Ошибка! Вводите значения от 1 до 10 \n-----> ");
					cin >> *buf;
					continue;
				}
				if (*buf < 1 || *buf > 10) {
					printer("Ошибка! Вводите значения от 1 до 10\n-----> ");
					cin.ignore(32767, '\n');
					cin >> *buf;
				}
			}
			*(sub_count + i) = *buf;
		}
	}

	void setSubjects() {
		int* sum = new int(0);
		for (int i = 0; i < *session_count; i++) {
			*sum = *sum + *(sub_count + i);
		}
		subject = new Sub[*sum];
		int* session_num = new int(0);
		int* subject_num = new int(0);
		for (int i = 0; i < *sum; i++) {
			if (*subject_num >= sub_count[*session_num]) {
				(*session_num)++;
				*subject_num = 0;
			}
			(*subject_num)++;
			(subject + i)->name = new char[21]();
			(subject + i)->mark = new int(0);
			printer("Укажите название ");
			printer(*subject_num);
			printer("-го предмета в ");
			printer(*session_num + 1);
			printer("-й сессии: ");
			checkEmptyStr((subject + i)->name, 21);
			cleaner();
			printer("Введите оценку за ");
			cout << (subject + i)->name;
			printer(": ");
			int buf;
			while (true) {
				cleaner();
				cin >> buf;
				cleaner();
				if (buf >= 2 && buf <= 5) {
					*(subject + i)->mark = buf;
					break;
				}
				printer("Неверные данные! Вводите значения от 2 до 5\n");
			}
		}
		delete sum;
		delete session_num;
		delete subject_num;
	}
};

class File : Functions {
public:

	File() {
		file_length = new int(0);
		length = new int(0);
		pos = new int(0);
		count = new int(0);
		sum = new int(0);
		rec_book_num = new char[21]();
	}

	~File() {
		delete file_length;
		delete count;
		delete sum;
	}

	void addStudent() {
		Student* student = new Student;
		Session* session = new Session;
		student->Set();
		if (!strcmp(student->surname, "-1")) {
			delete student;
			delete session;
			return;
		}
		session->setSession();

		Crypt crypt;
		crypt.Decrypt();

		ofstream file(fileway, ios::binary | ios::app);

		file.write(student->surname, 31);
		file.write(student->name, 31);
		file.write(student->patr, 31);
		file.write((char*)student->day, 4);
		file.write((char*)student->month, 4);
		file.write((char*)student->year, 4);
		file.write((char*)student->sex, 1);
		file.write((char*)student->admit_year, 4);
		file.write(student->fac, 25);
		file.write(student->depart, 25);
		file.write(student->group, 11);
		file.write(student->book, 21);

		file.write((char*)session->session_count, 4);

		for (int i = 0; i < *session->session_count; i++) {
			file.write((char*)(&*(session->sub_count + i)), 4);
		}
		*sum = 0;
		for (int i = 0; i < *session->session_count; i++) {
			*sum = *sum + *(session->sub_count + i);
		}
		for (int i = 0; i < *sum; i++) {
			file.write((char*)(session->subject + i)->name, 21);
			file.write((char*)(session->subject + i)->mark, 4);
		}

		delete student;
		delete session;
		file.close();

		crypt.Encrypt();
	}

	bool Edit() override {
		ofstream test("Students.new.txt", ios::binary);
		test.close();
		Crypt crypt;
		int ans;
		int ans_2;
		if (!isThereStudent()) return false;
		system("cls");
		printer("Редактирование информации о студенте\n\n");
		printStudents(1, false, 0, 0);
		while (!findStudent()) {
			printer("Такой студент не найден\n");
			printer("[1] Чтобы ввести номер другой зачетной книжки, нажмите [1]\n");
			printer("[2] Чтобы вернуться в блок редактирования, нажмите [2]\n-----> ");
			cin >> ans_2;
			while (ans_2 < 1 || ans_2>2) {
				if (cin.fail()) {
					cin.clear();
					cin.ignore(32767, '\n');
					printer("Ошибка! Введите номер пункта меню, который хотите вывести\n-----> ");
					cin >> ans_2;
					continue;
				}
				if (ans_2 < 1 || ans_2>2) {
					printer("Вы ввели число не из диапозона [1;2]. Повторите ввод\n-----> ");
					cin.ignore(32767, '\n');
					cin >> ans_2;
				}
			}
			while (ans_2 != 1 && ans_2 != 2) {
				printer("[1] Чтобы ввести другого студента\n");
				printer("[2] Чтобы вернуться в блок редактирования, нажмите [2]\n-----> ");
				cin >> ans_2;
			}
			if (ans_2 == 2) return false;
		}
		if (*pos == -1) {
			return false;
		}
		bool flag = true;
		while (flag) {
			printer("[1] Чтобы редактировать данные о студенте, нажмите [1]\n");
			printer("[2] Чтобы редактировать данные о сессии студента, нажмите [2]\n");
			printer("[3] Чтобы вернуться в меню, нажмите [3]\n-----> ");
			cin >> ans;
			while (ans < 1 || ans>3) {
				if (cin.fail()) {
					cin.clear();
					cin.ignore(32767, '\n');
					printer("Ошибка! Введите номер пункта меню, который хотите вывести\n-----> ");
					cin >> ans;
					continue;
				}
				if (ans < 1 || ans>3) {
					printer("Вы ввели число не из диапозона [1;3]. Повторите ввод\n-----> ");
					cin.ignore(32767, '\n');
					cin >> ans;
				}
			}
			length = new int(0);
			for (int i = 0; i < *count; i++) {
				getStudent();
				if (i != *pos) {
					fileWriter();
				}
				else {
					switch (ans) {
					case 1:
						while (true) {
							system("cls");
							studentsPrinter(2);
							printer("Это блок редактирования информации о студенте, выберите нужный пункт\n\n");
							printer("[1] Чтобы редактировать фамилию студента, нажмите [1]\n");
							printer("[2] Чтобы редактировать имя студента, нажмите [2]\n");
							printer("[3] Чтобы редактировать отчество студента, нажмите [3]\n");
							printer("[4] Чтобы редактировать дату рождения студента, нажмите [4]\n");
							printer("[5] Чтобы редактировать год приема студента в университет, нажмите [5]\n");
							printer("[6] Чтобы редактировать пол студента, нажмите [6]\n");
							printer("[7] Чтобы редактировать факультет студента, нажмите [7]\n");
							printer("[8] Чтобы редактировать кафедру студента, нажмите [8]\n");
							printer("[9] Чтобы редактировать группу студента, нажмите [9]\n");
							printer("[10] Чтобы редактировать номер зачетной книжки студента, нажмите [10]\n");
							printer("[11] Чтобы сохранить изменения, нажмите [11]\n\n");
							printer("-----> ");
							if (edit_student->Edit()) {
								break;
							}
						}
						break;
					case 2:
						while (true) {
							system("cls");
							printer("Это блок редактирования информации о сессии студента\n\n");
							studentsPrinter(1);
							studentsPrinter(3);
							printer("[1] Чтобы добавить новую сессию, нажмите [1]\n");
							printer("[2] Чтобы редактировать информацию о предметах студента, нажмите [2]\n");
							printer("[3] Чтобы добавить новый предмет в сессию, нажмите [3]\n");
							printer("[4] Чтобы удалить предмет из сессии, нажмите [4]\n");
							printer("[5] Чтобы сохранить изменения, нажмите [5]\n\n");
							printer("-----> ");
							if (edit_session->Edit()) {
								break;
							};
						}
						break;
					case 3:
						flag = false;
						break;
					default:
						if (remove("Students.new.txt") != 0) {
							printer("Ошибка при удалении файла!!!\n");
							backMenu();
						}
						printer("Такого варианта не найдено\n");
						backMenu();
						break;
					}
					fileWriter();
					delete edit_student;
					delete edit_session;
				}
			}
			if (remove("Students.txt.enc") != 0) {
				printer("Ошибка при удалении файла!!!\n");
				backMenu();
			}
			if (rename("Students.new.txt", fileway) != 0) {
				printer("Ошибка при переименовании файла!!!\n");
				backMenu();
			}
			crypt.Encrypt();
			delete length;
			flag = false;
		}
		delete pos;
		delete rec_book_num;
	}

	void delStudent() {
		Crypt crypt;
		if (!isThereStudent()) return;
		*pos = -1;
		rec_book_num = new char[21]();
		printStudents(1, false, 0, 0);
		printer("Введите номер зачетной книжки(-1 чтобы вернуться назад) >> ");
		cleaner();
		length = new int(0);
		checkEmptyStr(rec_book_num, 21);
		cleaner();
		if (!strcmp(rec_book_num, "-1")) {
			return;
		}

		for (int i = 0; i < *count; i++) {
			getStudent();
			if (!strcmp(rec_book_num, edit_student->book)) {
				*pos = i;
				break;
			}
			delete edit_student;
			delete edit_session;
		}

		if (*pos != -1) {
			*length = 0;
			for (int i = 0; i < *count; i++) {
				getStudent();
				if (i != *pos) {
					fileWriter();
				}
				delete edit_student;
				delete edit_session;
			}
			if (remove("Students.txt.enc") != 0) {
				printer("Ошибка при удалении файла!!!\n");
				backMenu();
			};
			if (rename("Students.new.txt", fileway) != 0) {
				printer("Ошибка при переименовании файла!!!\n");
				backMenu();
			}
			crypt.Encrypt();
		}
		else {
			printer("Такой студент не найден\n");
			delStudent();
		}

		delete pos;
		delete rec_book_num;
	}

	void printStudents(int rez, bool Task, int m1, int m2) {
		if (!isThereStudent()) return;
		length = new int(0);
		for (int i = 0; i < *count; i++) {
			getStudent();
			if (!Task) {
				switch (rez) {
				case 1:
					studentsPrinter(1);
					break;
				case 2:
					studentsPrinter(2);
					break;
				case 3:
					studentsPrinter(1);
					studentsPrinter(3);
					break;
				case 4:
					studentsPrinter(2);
					studentsPrinter(3);
					break;
				}
			}
			else {
				if (checkMarks(m1, m2)) {
					studentsPrinter(2);
					studentsPrinter(3);

				}
			}
			delete edit_student;
			delete edit_session;
		}
		delete length;
	}

private:
	Student* edit_student = nullptr;
	Session* edit_session = nullptr;
	int* file_length;
	int* length;
	int* pos;
	int* count;
	int* sum;
	char* rec_book_num;

	bool findStudent() {
		*pos = -1;
		length = new int(0);
		rec_book_num = new char[21]();
		printer("Введите номер зачетной книжки(-1 чтобы вернуться обратно) >> ");
		cleaner();
		checkEmptyStr(rec_book_num, 21);
		cleaner();

		if (!strcmp(rec_book_num, "-1")) {
			return true;
		}

		for (int i = 0; i < *count; i++) {
			getStudent();
			if (!strcmp(rec_book_num, edit_student->book)) {
				*pos = i;
				delete edit_student;
				delete edit_session;
				delete length;
				return true;
			}
			delete edit_student;
			delete edit_session;
		}
		delete length;
		return false;
	}

	void getStudent() {
		Crypt crypt;
		crypt.Decrypt();

		ifstream File;
		File.open(fileway, ios::binary);

		File.seekg(0, ios::end);
		*file_length = File.tellg();
		File.seekg(*length, ios::beg);
		if (*length != *file_length) {
			edit_student = new Student();
			edit_session = new Session();

			File.read(edit_student->surname, 31);
			File.read(edit_student->name, 31);
			File.read(edit_student->patr, 31);
			File.read((char*)edit_student->day, 4);
			File.read((char*)edit_student->month, 4);
			File.read((char*)edit_student->year, 4);
			File.read(edit_student->sex, 1);
			File.read((char*)edit_student->admit_year, 4);
			File.read(edit_student->fac, 25);
			File.read(edit_student->depart, 25);
			File.read(edit_student->group, 11);
			File.read(edit_student->book, 21);

			File.read((char*)edit_session->session_count, 4);

			edit_session->sub_count = new int[*edit_session->session_count];
			*sum = 0;
			for (int i = 0; i < *edit_session->session_count; i++) {
				File.read((char*)(&*(edit_session->sub_count + i)), 4);
				*sum = *sum + *(edit_session->sub_count + i);
			}

			edit_session->subject = new Sub[*sum]();

			for (int i = 0; i < *sum; i++) {
				File.read((char*)(edit_session->subject + i)->name, 21);
				File.read((char*)(edit_session->subject + i)->mark, 4);
			}
			*length += 196;
			*length += *edit_session->session_count * 4;
			*length += *sum * 25;
		}
		File.close();
		crypt.Encrypt();
	}

	void fileWriter() {
		char newname[] = "Students.new.txt";
		ofstream FILE_NEW;
		FILE_NEW.open(newname, ios::binary | ios::app);

		FILE_NEW.write(edit_student->surname, 31);
		FILE_NEW.write(edit_student->name, 31);
		FILE_NEW.write(edit_student->patr, 31);
		FILE_NEW.write((char*)edit_student->day, 4);
		FILE_NEW.write((char*)edit_student->month, 4);
		FILE_NEW.write((char*)edit_student->year, 4);
		FILE_NEW.write((char*)edit_student->sex, 1);
		FILE_NEW.write((char*)edit_student->admit_year, 4);
		FILE_NEW.write(edit_student->fac, 25);
		FILE_NEW.write(edit_student->depart, 25);
		FILE_NEW.write(edit_student->group, 11);
		FILE_NEW.write(edit_student->book, 21);

		FILE_NEW.write((char*)edit_session->session_count, 4);

		for (int i = 0; i < *edit_session->session_count; i++) {
			FILE_NEW.write((char*)(&*(edit_session->sub_count + i)), 4);
		}
		*sum = 0;
		for (int i = 0; i < *edit_session->session_count; i++) {
			*sum = *sum + *(edit_session->sub_count + i);
		}
		for (int i = 0; i < *sum; i++) {
			FILE_NEW.write((char*)(edit_session->subject + i)->name, 21);
			FILE_NEW.write((char*)(edit_session->subject + i)->mark, 4);
		}
		FILE_NEW.close();
	}

	bool isThereStudent() {
		fstream file("Students.txt.enc", ios::binary | ios::in);
		file.seekg(0, ios::end);
		if (file.tellg() == -1 || file.tellg() == 0) {
			file.close();
			printer("Файл пустой, доступна только функция добавления студентов\n");
			return false;
		}
		file.close();

		Crypt* crypt = new Crypt;
		crypt->Decrypt();
		ifstream File;
		File.open(fileway, ios::binary);

		*length = 0;
		*count = 0;
		File.seekg(0, ios::end);
		*file_length = File.tellg();
		File.seekg(0, ios::beg);

		while (*file_length != *length) {
			File.seekg(192, ios::cur);
			*length = *length + 192;

			int session_count = 0;
			int subject_count = 0;

			File.read((char*)&session_count, 4);
			*length = *length + 4;

			*length = *length + session_count * 4;
			*sum = 0;
			for (int i = 0; i < session_count; i++) {
				File.read((char*)&subject_count, 4);
				*sum = *sum + subject_count;
			}
			File.seekg((*sum * 25), ios::cur);
			*length = *length + (*sum * 25);
			(*count)++;
		}
		File.close();
		crypt->Encrypt();
		return true;
	}

	void studentsPrinter(int rez) {
		switch (rez) {
		case 1:
			printer("--------------------------------------------------------------------------------------------\n\nДАННЫЕ О СТУДЕНТЕ\n\n");
			cout << "ФИО: " << edit_student->surname << " " << edit_student->name << " " << edit_student->patr << "\n";
			cout << "Номер зачетной книжки: " << edit_student->book << "\n\n";
			break;
		case 2:
			printer("--------------------------------------------------------------------------------------------\n\nДАННЫЕ О СТУДЕНТЕ\n\n");
			cout << "ФИО: " << edit_student->surname << " " << edit_student->name << " " << edit_student->patr << "\n";
			cout << "Дата рождения: " << *edit_student->day << "." << *edit_student->month << "." << *edit_student->year << " Год приема: " << *edit_student->admit_year << "\n";
			cout << "Пол: " << edit_student->sex << " Факультет: " << edit_student->fac << " Кафедра: " << edit_student->depart << " Группа: " << edit_student->group << "\n";
			cout << "Номер зачетной книжки: " << edit_student->book << "\n\n";
			break;
		case 3:
			printer("ОЦЕНКИ \n\n");
			int sum = 0;
			for (int i = 0; i < *edit_session->session_count; i++) {
				cout << "Cессия " << i + 1 << "\n\n";
				for (int j = 0; j < *((edit_session->sub_count) + i); j++) {
					cout << j + 1 << ") " << ((edit_session->subject) + sum)->name << " ::: " << *(((edit_session->subject) + sum)->mark) << "\n";
					sum++;
				}
				printer("\n");
			}
			break;
		}
	}

	bool checkMarks(int s, int s2) {
		int sum1 = 0;
		for (int i = 0; i < *edit_session->session_count; i++) {
			for (int j = 0; j < *(edit_session->sub_count + i); j++) {
				if ((*((edit_session->subject + sum1)->mark) == s) || (*((edit_session->subject + sum1)->mark) == s2)) {
					return false;
				}
				sum1++;
			}
		}
		return true;
	}
};

class Menu : Functions {
public:
	Menu() {
		ans = new int;
		file = new File;
	}

	~Menu() {
		delete file;
		delete ans;
	}

	bool hub() {
		file = new File;
		system("cls");
		printer("ДОБРО ПОЖАЛОВАТЬ В МЕНЮ ПРОГРАММЫ\n\n");
		printer("Нажмите соответствующую цифру, для выбора действия: \n\n");
		printer("[1] Чтобы выполнить задание, нажмите [1]\n");
		printer("[2] Чтобы добавить в базу нового студента, нажмите [2]\n");
		printer("[3] Чтобы удалить студента из базы, нажмите [3]\n");
		printer("[4] Чтобы изменить данные о студенте, нажмите [4]\n");
		printer("[5] Чтобы вывести на экран всю базу студентов, нажмите [5]\n");
		printer("[6] Чтобы выйти из программы, нажмите [6]\n\n-----> ");
		cin >> *ans;
		while (*ans < 1 || *ans>6) {
			if (cin.fail()) {
				cin.clear();
				cin.ignore(32767, '\n');
				printer("Ошибка! Введите номер пункта меню, который хотите вывести\n-----> ");
				cin >> *ans;
				continue;
			}
			if (*ans < 1 || *ans>6) {
				printer("Вы ввели число не из диапозона [1;6]. Повторите ввод\n-----> ");
				cin.ignore(32767, '\n');
				cin >> *ans;
			}
		}
		cleaner();
		switch (*ans) {
		case 1: {
			system("cls");
			printer("Выберите 1 или несколько вариантов через [ПРОБЕЛ] (чтобы вернуться в меню, введите -1)\n\n");
			printer("Вывести студентов у которых нет оценки:\nа)3\nб)3 и 4\nв)5\nг)3 и 5\nд)4 и 5\n\n----->");
			int size = 15;
			char* str = new char[size];
			cin.getline(str, size);
			int masElem[15] = { 0 }, counter = 0;
			for (int i = 0; i < size; i++) {
				if (str[i] == '\0') { break; }
				if (str[i] != ' ') {
					masElem[counter] = str[i];
					counter++;
				}
			}
			for (int j = 0; j < counter; j++) {
				switch (masElem[j] + 32) {
				case 0:
					printer("--------------------------------------------------------------------------------------------\n\nСтуденты без оценки 3\n\n");
					file->printStudents(4, true, 3, 0);
					break;
				case 1:
					printer("--------------------------------------------------------------------------------------------\n\nСтуденты без оценкок 3 и 4\n\n");
					file->printStudents(4, true, 3, 4);
					break;
				case 2:
					printer("--------------------------------------------------------------------------------------------\n\nСтуденты без оценки 5\n\n");
					file->printStudents(4, true, 0, 5);
					break;
				case 3:
					printer("--------------------------------------------------------------------------------------------\n\nСтуденты без оценкок 3 и 5\n\n");
					file->printStudents(4, true, 5, 3);
					break;
				case 4:
					printer("--------------------------------------------------------------------------------------------\n\nСтуденты без оценкок 4 и 5\n\n");
					file->printStudents(4, true, 4, 5);
					break;
				default:
					cout << "Найден несуществующий вариант! Пропуск элемента!" << endl;
					break;
				}
			}
			cout << endl;

			backMenu();
			break;
		}
		case 2: {
			system("cls");
			printer("Добавление нового студента(Введите -1, чтобы вернуться назад)\n\n");
			file->addStudent();
			backMenu();
			break;
		}
		case 3: {
			system("cls");
			printer("Удаление студента\n");
			file->delStudent();
			backMenu();
			break;
		}
		case 4: {
			file->Edit();
			backMenu();
			break;
		}
		case 5: {
			system("cls");
			printer("Какую информацию вы хотите получить:\n\n");
			printer("Чтобы получить краткую информацию (без данных о сессии), нажмите [1]\n");
			printer("Чтобы получить всю информацию о студентах, нажмите [2]\n");
			printer("Чтобы вернуться в меню, нажмите [3]\n\n");
			printer("-----> ");
			cin >> *ans;
			while (*ans < 1 || *ans>3) {
				if (cin.fail()) {
					cin.clear();
					cin.ignore(32767, '\n');
					printer("Ошибка! Введите номер пункта меню, который хотите вывести\n-----> ");
					cin >> *ans;
					continue;
				}
				if (*ans < 1 || *ans>3) {
					printer("Вы ввели число не из диапозона [1;3]. Повторите ввод\n-----> ");
					cin.ignore(32767, '\n');
					cin >> *ans;
				}
			}
			cleaner();
			switch (*ans) {
			case 1: {
				file->printStudents(2, false, 0, 0);
				backMenu();
				break;
			}
			case 2: {
				file->printStudents(4, false, 0, 0);
				backMenu();
				break;
			}
			case 3: {
				break;
			}
			}
			break;
		}
		case 6:
			return false;
		}
		return true;
		delete file;
	}
private:
	File* file = nullptr;
	int* ans = nullptr;
	bool Edit() override { file->Edit(); return true; }
};

int main() {
	SetConsoleCP(1251);
	SetConsoleOutputCP(1251);
	Menu* menu = new Menu();
	while (menu->hub());
	delete menu;
	return 0;
}