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

public class Pkcs11Class
{
    private NativeLong cl;
    public static final int SECRET_KEY = 4;
    public static final int PUBLIC_KEY = 2;
    public static final int PRIVATE_KEY = 3;

    public Pkcs11Class(NativeLong cl)
    {
        this.cl = cl;
    }

    public Pkcs11Class(int cl)
    {
        this.cl = new NativeLong(cl);
    }

    public NativeLong getCl()
    {
        return cl;
    }

    public boolean isSecretKey() {return getCl().intValue() == Pkcs11Class.SECRET_KEY;}

    public boolean isPublicKey() {return getCl().intValue() == Pkcs11Class.PUBLIC_KEY;}

    public boolean isPrivateKey() {return getCl().intValue() == Pkcs11Class.PRIVATE_KEY;}

    public String toString()
    {
        switch (cl.intValue())
        {
            case Pkcs11Class.SECRET_KEY:
                return "CKO_SECRET_KEY";
            case Pkcs11Class.PUBLIC_KEY:
                return "CKO_PUBLIC_KEY";
            case Pkcs11Class.PRIVATE_KEY:
                return "CKO_PRIVATE_KEY";
        }

        return "Unsupported Class";
    }
}
