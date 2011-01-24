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
import com.sun.jna.Memory;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;

public class Utility
{
    public static String byteArrayToString(byte[] b)
    {
        int i;
        String by;
        String txt = "";

        for (i = 0; i < b.length; i++)
        {
            by = Integer.toHexString(0xFF & b[i]);
            if (by.length() == 1)
                by = "0".concat(by);
            txt = txt.concat(by);
        }
        return txt;
    }

    protected static String uncapitalize(String s)
    {
        if (s.length() == 0)
            return s;

        return s.substring(0, 1).toLowerCase() + s.substring(1);
    }

    protected static PointerByReference toNativeByteArray(byte[] a)
    {
        int i;
        PointerByReference copy = new PointerByReference();
        copy.setPointer(new Memory(a.length));
        Pointer p = copy.getPointer();
        for (i = 0; i < a.length; i++)
            p.setByte(i, a[i]);

        return copy;
    }
}
