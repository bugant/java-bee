/*
 *   Copyright (c) 2010 Matteo Centenaro
 *   
 *   Permission is hereby granted, free of charge, to any person obtaining a copy
 *   of this software and associated documentation files (the "Software"), to deal
 *   in the Software without restriction, including without limitation the rights
 *   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *   copies of the Software, and to permit persons to whom the Software is
 *   furnished to do so, subject to the following conditions:
 *   
 *   The above copyright notice and this permission notice shall be included in
 *   all copies or substantial portions of the Software.
 *   
 *   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 *   THE SOFTWARE.
 */

package bee;
public class Pkcs11Errors
{
    public static String getError(int index)
    {
        switch (index)
        {
            case 0x00000000: return "CKR_OK";
            case 0x00000001: return "CKR_CANCEL";
            case 0x00000002: return "CKR_HOST_MEMORY";
            case 0x00000003: return "CKR_SLOT_ID_INVALID";
            case 0x00000005: return "CKR_GENERAL_ERROR";
            case 0x00000006: return "CKR_FUNCTION_FAILED";
            case 0x00000007: return "CKR_ARGUMENTS_BAD";
            case 0x00000008: return "CKR_NO_EVENT";
            case 0x00000009: return "CKR_NEED_TO_CREATE_THREADS";
            case 0x0000000A: return "CKR_CANT_LOCK";
            case 0x00000010: return "CKR_ATTRIBUTE_READ_ONLY";
            case 0x00000011: return "CKR_ATTRIBUTE_SENSITIVE";
            case 0x00000012: return "CKR_ATTRIBUTE_TYPE_INVALID";
            case 0x00000013: return "CKR_ATTRIBUTE_VALUE_INVALID";
            case 0x00000020: return "CKR_DATA_INVALID";
            case 0x00000021: return "CKR_DATA_LEN_RANGE";
            case 0x00000030: return "CKR_DEVICE_ERROR";
            case 0x00000031: return "CKR_DEVICE_MEMORY";
            case 0x00000032: return "CKR_DEVICE_REMOVED";
            case 0x00000040: return "CKR_ENCRYPTED_DATA_INVALID";
            case 0x00000041: return "CKR_ENCRYPTED_DATA_LEN_RANGE";
            case 0x00000050: return "CKR_FUNCTION_CANCELED";
            case 0x00000051: return "CKR_FUNCTION_NOT_PARALLEL";
            case 0x00000054: return "CKR_FUNCTION_NOT_SUPPORTED";
            case 0x00000060: return "CKR_KEY_HANDLE_INVALID";
            case 0x00000062: return "CKR_KEY_SIZE_RANGE";
            case 0x00000063: return "CKR_KEY_TYPE_INCONSISTENT";
            case 0x00000064: return "CKR_KEY_NOT_NEEDED";
            case 0x00000065: return "CKR_KEY_CHANGED";
            case 0x00000066: return "CKR_KEY_NEEDED";
            case 0x00000067: return "CKR_KEY_INDIGESTIBLE";
            case 0x00000068: return "CKR_KEY_FUNCTION_NOT_PERMITTED";
            case 0x00000069: return "CKR_KEY_NOT_WRAPPABLE";
            case 0x0000006A: return "CKR_KEY_UNEXTRACTABLE";
            case 0x00000070: return "CKR_MECHANISM_INVALID";
            case 0x00000071: return "CKR_MECHANISM_PARAM_INVALID";
            case 0x00000082: return "CKR_OBJECT_HANDLE_INVALID";
            case 0x00000090: return "CKR_OPERATION_ACTIVE";
            case 0x00000091: return "CKR_OPERATION_NOT_INITIALIZED";
            case 0x000000A0: return "CKR_PIN_INCORRECT";
            case 0x000000A1: return "CKR_PIN_INVALID";
            case 0x000000A2: return "CKR_PIN_LEN_RANGE";
            case 0x000000A3: return "CKR_PIN_EXPIRED";
            case 0x000000A4: return "CKR_PIN_LOCKED";
            case 0x000000B0: return "CKR_SESSION_CLOSED";
            case 0x000000B1: return "CKR_SESSION_COUNT";
            case 0x000000B3: return "CKR_SESSION_HANDLE_INVALID";
            case 0x000000B4: return "CKR_SESSION_PARALLEL_NOT_SUPPORTED";
            case 0x000000B5: return "CKR_SESSION_READ_ONLY";
            case 0x000000B6: return "CKR_SESSION_EXISTS";
            case 0x000000B7: return "CKR_SESSION_READ_ONLY_EXISTS";
            case 0x000000B8: return "CKR_SESSION_READ_WRITE_SO_EXISTS";
            case 0x000000C0: return "CKR_SIGNATURE_INVALID";
            case 0x000000C1: return "CKR_SIGNATURE_LEN_RANGE";
            case 0x000000D0: return "CKR_TEMPLATE_INCOMPLETE";
            case 0x000000D1: return "CKR_TEMPLATE_INCONSISTENT";
            case 0x000000E0: return "CKR_TOKEN_NOT_PRESENT";
            case 0x000000E1: return "CKR_TOKEN_NOT_RECOGNIZED";
            case 0x000000E2: return "CKR_TOKEN_WRITE_PROTECTED";
            case 0x000000F0: return "CKR_UNWRAPPING_KEY_HANDLE_INVALID";
            case 0x000000F1: return "CKR_UNWRAPPING_KEY_SIZE_RANGE";
            case 0x000000F2: return "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT";
            case 0x00000100: return "CKR_USER_ALREADY_LOGGED_IN";
            case 0x00000101: return "CKR_USER_NOT_LOGGED_IN";
            case 0x00000102: return "CKR_USER_PIN_NOT_INITIALIZED";
            case 0x00000103: return "CKR_USER_TYPE_INVALID";
            case 0x00000104: return "CKR_USER_ANOTHER_ALREADY_LOGGED_IN";
            case 0x00000105: return "CKR_USER_TOO_MANY_TYPES";
            case 0x00000110: return "CKR_WRAPPED_KEY_INVALID";
            case 0x00000112: return "CKR_WRAPPED_KEY_LEN_RANGE";
            case 0x00000113: return "CKR_WRAPPING_KEY_HANDLE_INVALID";
            case 0x00000114: return "CKR_WRAPPING_KEY_SIZE_RANGE";
            case 0x00000115: return "CKR_WRAPPING_KEY_TYPE_INCONSISTENT";
            case 0x00000120: return "CKR_RANDOM_SEED_NOT_SUPPORTED";
            case 0x00000121: return "CKR_RANDOM_NO_RNG";
            case 0x00000130: return "CKR_DOMAIN_PARAMS_INVALID";
            case 0x00000150: return "CKR_BUFFER_TOO_SMALL";
            case 0x00000160: return "CKR_SAVED_STATE_INVALID";
            case 0x00000170: return "CKR_INFORMATION_SENSITIVE";
            case 0x00000180: return "CKR_STATE_UNSAVEABLE";
            case 0x00000190: return "CKR_CRYPTOKI_NOT_INITIALIZED";
            case 0x00000191: return "CKR_CRYPTOKI_ALREADY_INITIALIZED";
            case 0x000001A0: return "CKR_MUTEX_BAD";
            case 0x000001A1: return "CKR_MUTEX_NOT_LOCKED";
            case 0x000001B0: return "CKR_NEW_PIN_MODE";
            case 0x000001B1: return "CKR_NEXT_OTP";
            case 0x00000200: return "CKR_FUNCTION_REJECTED";
            case 0x80000000: return "CKR_VENDOR_DEFINED";
        }

        return "PKCS#11 Error Not Found";
    }
}
