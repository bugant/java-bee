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
import java.lang.reflect.Method;
import java.lang.reflect.Field;

public class ObjectHandle
{
    private static BeeLibrary lib = BeeLibrary.INSTANCE;
    private NativeLong handle;
    private Pointer bee;

    public ObjectHandle(NativeLong handle, Bee bee)
    {
        this.handle = handle;
        this.bee = bee.getPointer();
    }

    public void destroy() throws BeeException
    {
        lib.bee_reset_error();
        lib.bee_destroy_object(bee, handle);
        Errors.checkError();

        handle = null;
        bee = null;
    }

    protected int getHandle() {return handle.intValue();}

    private void getByteKeyAttr(Template t, String attr)
    {
        Template s = null;
        boolean noEx = true;
        Method m;
        byte[] v;

        try {s = new Template();}
        catch (BeeException e) {
            try {
                m = t.getClass().getMethod("set" + attr + "Exception", e.getClass());
                m.invoke(t, e);
            } catch (Exception ex) {return;}
        }

        try {
            m = s.getClass().getMethod("add" + attr);
            m.invoke(s);
        } catch (Exception e) {return;}

        try {
            lib.bee_get_attrs(bee, handle, s.getPointer());
            Errors.checkError();
        } catch (BeeException e) {
            noEx = false;
            try {
                m = s.getClass().getDeclaredMethod("set" + attr + "Exception", e.getClass());
                m.invoke(t, e);
            } catch (Exception ex) {return;}
        }

        if (noEx)
        {
            try {
                m = s.getClass().getMethod("set" + attr, byte[].class);
                Method g = s.getClass().getMethod("get" + attr);
                v = (byte[]) g.invoke(s);
                m.invoke(t, v);
            } catch (Exception e) {return;}
        }
    }

    public Template getTemplate() throws BeeException
    {
        Pkcs11Class c = null;
        boolean foundClass = true;
        boolean noEx = true;
        Template t = new Template();

        t.addToken();
        t.addPrivate();
        t.addModifiable();
        t.addLabel();
        t.addClass();
        t.addKeyType();
        t.addId();
        t.addDerive();
        t.addLocal();

        lib.bee_reset_error();
        lib.bee_get_attrs(bee, handle, t.getPointer());
        Errors.checkError();

        try {c = t.getObjClass();} catch (BeeException e) {foundClass = false;}

        if (foundClass)
        {
            Template keyAttrs = new Template();
            switch (c.getCl().intValue())
            {
                case Pkcs11Class.SECRET_KEY:
                    keyAttrs.addEncrypt();
                    keyAttrs.addDecrypt();
                    keyAttrs.addWrap();
                    keyAttrs.addUnwrap();
                    keyAttrs.addSign();
                    keyAttrs.addVerify();
                    keyAttrs.addNeverExtractable();
                    keyAttrs.addExtractable();
                    keyAttrs.addAlwaysSensitive();
                    keyAttrs.addSensitive();

                    getByteKeyAttr(t, "Value");
                    break;
                case Pkcs11Class.PUBLIC_KEY:
                    keyAttrs.addEncrypt();
                    keyAttrs.addWrap();
                    keyAttrs.addVerify();

                    // CKA_MODULUS_BITS
                    Template p = new Template();
                    p.addModulusBits();
                    try {
                        lib.bee_get_attrs(bee, handle, p.getPointer());
                        Errors.checkError();
                    } catch (BeeException e) {
                        noEx = false;
                        t.setModulusBits(-1);
                    }

                    if (noEx)
                        t.setModulusBits(p.getModulusBits());

                    //CKA_MODULUS
                    getByteKeyAttr(t, "Modulus");

                    //CKA_PUBLIC_EXPONENT
                    getByteKeyAttr(t, "PublicExponent");
                    break;
                case Pkcs11Class.PRIVATE_KEY:
                    keyAttrs.addDecrypt();
                    keyAttrs.addUnwrap();
                    keyAttrs.addSign();
                    keyAttrs.addNeverExtractable();
                    keyAttrs.addExtractable();
                    keyAttrs.addAlwaysSensitive();
                    keyAttrs.addSensitive();

                    //CKA_MODULUS
                    getByteKeyAttr(t, "Modulus");
                    //CKA_PRIVATE_EXPONENT
                    getByteKeyAttr(t, "PrivateExponent");
                    break;
            }
            lib.bee_reset_error();
            lib.bee_get_attrs(bee, handle, keyAttrs.getPointer());
            Errors.checkError();
            t.merge(keyAttrs);
        }

        return t;
    }

    public void setTemplate(Template t) throws BeeException
    {
        lib.bee_reset_error();
        lib.bee_set_attrs(bee, handle, t.getPointer());
        Errors.checkError();
    }
}
