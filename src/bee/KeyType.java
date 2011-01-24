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
import com.sun.jna.*;

public class KeyType
{
    private NativeLong type;
    public static final int RSA = 0;
    public static final int DSA = 1;
    public static final int DH = 2;
    public static final int DES = 0x13;
    public static final int DES2 = 0x14;
    public static final int DES3 = 0x15;
    public static final int AES = 0x1F;

    public KeyType(NativeLong type)
    {
        this.type = type;
    }

    public KeyType(int type)
    {
        this.type = new NativeLong(type);
    }

    public NativeLong getType()
    {
        return type;
    }

    public boolean isRSAKey() {return getType().intValue() == KeyType.RSA;}

    public boolean isDSAKey() {return getType().intValue() == KeyType.DSA;}

    public boolean isDHKey() {return getType().intValue() == KeyType.DH;}

    public boolean isDESKey() {return getType().intValue() == KeyType.DES;}

    public boolean isDES2Key() {return getType().intValue() == KeyType.DES2;}

    public boolean isDES3Key() {return getType().intValue() == KeyType.DES3;}

    public boolean isAESKey() {return getType().intValue() == KeyType.AES;}

    public String toString()
    {
        switch (type.intValue())
        {
            case KeyType.RSA: return "CKK_RSA";
            case KeyType.DSA: return "CKK_DSA";
            case KeyType.DH: return "CKK_DH";
            case KeyType.DES: return "CKK_DES";
            case KeyType.DES2: return "CKK_DES2";
            case KeyType.DES3: return "CKK_DES3";
            case KeyType.AES: return "CKK_AES";
        }

        return "Unsupported KeyType";
    }
}
