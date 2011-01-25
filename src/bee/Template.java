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
import com.sun.jna.ptr.PointerByReference;
import java.lang.reflect.Method;
import java.lang.reflect.InvocationTargetException;

public class Template implements Cloneable
{
    private static BeeLibrary lib = BeeLibrary.INSTANCE;
    private Pointer t;

    private Pointer labelAttribute;
    private Pointer idAttribute;

    private Pointer classAttribute;
    private Pointer keyTypeAttribute;
    private Pointer modulusBitsAttribute;
    private Pointer valueLenAttribute;

    private Pointer valueAttribute;
    private Pointer modulusAttribute;
    private Pointer publicExponentAttribute;
    private Pointer privateExponentAttribute;
    private Pointer prime1Attribute;
    private Pointer prime2Attribute;
    private Pointer exponent1Attribute;
    private Pointer exponent2Attribute;

    private BeeException valueException;
    private BeeException modulusException;
    private BeeException publicExponentException;
    private BeeException privateExponentException;
    private BeeException prime1Exception;
    private BeeException prime2Exception;
    private BeeException exponent1Exception;
    private BeeException exponent2Exception;

    public Template() throws BeeException
    {
        t = lib.bee_new_attrs();
        if (t == null)
            throw new BeeException(lib.bee_get_last_error().intValue());

        initAttributesPointers();
    }

    private void initAttributesPointers()
    {
        labelAttribute = null;
        classAttribute = null;
        keyTypeAttribute = null;
        idAttribute = null;
        modulusBitsAttribute = null;
        valueLenAttribute = null;
        valueAttribute = null;
        modulusAttribute = null;
        publicExponentAttribute = null;
        privateExponentAttribute = null;
        prime1Attribute = null;
        prime2Attribute = null;

        modulusException = null;
        publicExponentException = null;
        privateExponentException = null;
        prime1Exception = null;
        prime2Exception = null;
    }

    public Template getACopy()
    {
        Template copy = null;
        try {copy = (Template) this.clone();}
        catch (CloneNotSupportedException c) {
            System.out.println("Cannot clone the template");
            c.printStackTrace();
        }
        copy.t = lib.bee_copy_attrs(this.t);
        copy.initAttributesPointers();
        return copy;
    }

    private void freeAttr(Pointer p)
    {
        if (p != null)
            lib.bee_free_mem(p);
    }

    protected void finalize()
    {
        lib.bee_deep_free_attrs(t);
    }

    private Pointer copyByteArray(byte[] v) throws BeeException
    {
        int i;
        Pointer val = lib.bee_malloc(new NativeLong(v.length));
        if (val == null)
            return null;

        for (i = 0; i < v.length; i++)
            val.setByte(i, v[i]);

        return val;
    }

    private Pointer copyNativeLong(NativeLong n) throws BeeException
    {
        Pointer val = lib.bee_malloc(new NativeLong(NativeLong.SIZE));
        if (val == null)
            return null;

        val.setNativeLong(0, n);
        return val;
    }

    protected Pointer getPointer() {return t;}

    public void addToken() throws BeeException
    {
        lib.bee_reset_error();
        lib.bee_add_token(t);
        Errors.checkError();
    }

    public boolean getToken() throws BeeException
    {
        boolean flag;

        lib.bee_reset_error();
        flag = lib.bee_get_token(t);
        Errors.checkError();
        return flag;
    }

    public void setToken(boolean token) throws BeeException
    {
        lib.bee_reset_error();
        lib.bee_set_token(t, token);
        Errors.checkError();
    }

    public void addPrivate() throws BeeException
    {
        lib.bee_reset_error();
        lib.bee_add_private(t);
        Errors.checkError();
    }

    public boolean getPrivate() throws BeeException
    {
        boolean flag;

        lib.bee_reset_error();
        flag = lib.bee_get_private(t);
        Errors.checkError();
        return flag;
    }

    public void setPrivate(boolean priv) throws BeeException
    {
        lib.bee_reset_error();
        lib.bee_set_private(t, priv);
        Errors.checkError();
    }

    public void addModifiable() throws BeeException
    {
        lib.bee_reset_error();
        lib.bee_add_modifiable(t);
        Errors.checkError();
    }

    public boolean getModifiable() throws BeeException
    {
        boolean flag;

        lib.bee_reset_error();
        flag = lib.bee_get_modifiable(t);
        Errors.checkError();
        return flag;
    }

    public void setModifiable(boolean modifiable) throws BeeException
    {
        lib.bee_reset_error();
        lib.bee_set_modifiable(t, modifiable);
        Errors.checkError();
    }

    public void addLabel() throws BeeException
    {
        lib.bee_reset_error();
        lib.bee_add_label(t);
        Errors.checkError();
    }

    public String getLabel() throws BeeException
    {
        Pointer val;
        String s;

        lib.bee_reset_error();
        val = lib.bee_get_label(t);
        if (val == null)
            throw new BeeException(lib.bee_get_last_error().intValue());

        s = val.getString(0);
        lib.bee_free_mem(val); // <- string has been copied to add a leading '\0'
        return s;
    }

    public void setLabel(String label) throws BeeException
    {
        freeAttr(labelAttribute);
        labelAttribute = null;
        lib.bee_reset_error();

        Pointer val = copyByteArray(label.getBytes());
        if (val != null)
            lib.bee_set_label(t, val, new NativeLong(label.length()));
        Errors.checkError();

        labelAttribute = val;
    }

    public void addClass() throws BeeException
    {
        lib.bee_reset_error();
        lib.bee_add_class(t);
        Errors.checkError();
    }

    public Pkcs11Class getObjClass() throws BeeException
    {
        NativeLong cl;

        lib.bee_reset_error();
        cl = lib.bee_get_class(t);
        if (cl.intValue() == -1)
            throw new BeeException(lib.bee_get_last_error().intValue());

        return new Pkcs11Class(cl);
    }

    public void setObjClass(Pkcs11Class c) throws BeeException
    {
        freeAttr(classAttribute);
        classAttribute = null;
        lib.bee_reset_error();
        Pointer val = copyNativeLong(c.getCl());
        if (val != null)
            lib.bee_set_class(t, val);
        Errors.checkError();

        classAttribute = val;
    }

    public void addKeyType() throws BeeException
    {
        lib.bee_reset_error();
        lib.bee_add_key_type(t);
        Errors.checkError();
    }

    public KeyType getKeyType() throws BeeException
    {
        NativeLong type;

        lib.bee_reset_error();
        type = lib.bee_get_key_type(t);
        if (type.intValue() == -1)
            throw new BeeException(lib.bee_get_last_error().intValue());

        return new KeyType(type);
    }

    public void setKeyType(KeyType type) throws BeeException
    {
        freeAttr(keyTypeAttribute);
        keyTypeAttribute = null;
        lib.bee_reset_error();
        Pointer val = copyNativeLong(type.getType());
        if (val != null)
            lib.bee_set_key_type(t, val);
        Errors.checkError();

        keyTypeAttribute = val;
    }

    public void addId() throws BeeException
    {
        lib.bee_reset_error();
        lib.bee_add_id(t);
        Errors.checkError();
    }

    public String getId() throws BeeException
    {
        Pointer val;
        String s;

        lib.bee_reset_error();
        val = lib.bee_get_id(t);
        if (val == null)
            throw new BeeException(lib.bee_get_last_error().intValue());

        s = val.getString(0);
        lib.bee_free_mem(val); // <- string has been copied to add a leading '\0'
        return s;
    }

    public void setId(String id) throws BeeException
    {
        freeAttr(idAttribute);
        idAttribute = null;
        lib.bee_reset_error();

        Pointer val = copyByteArray(id.getBytes());
        if (val != null)
            lib.bee_set_id(t, val, new NativeLong(id.length()));
        Errors.checkError();

        idAttribute = val;
    }

    public void addDerive() throws BeeException
    {
        lib.bee_reset_error();
        lib.bee_add_derive(t);
        Errors.checkError();
    }

    public boolean getDerive() throws BeeException
    {
        boolean flag;

        lib.bee_reset_error();
        flag = lib.bee_get_derive(t);
        Errors.checkError();
        return flag;
    }

    public void setDerive(boolean derive) throws BeeException
    {
        lib.bee_reset_error();
        lib.bee_set_derive(t, derive);
        Errors.checkError();
    }

    public void addLocal() throws BeeException
    {
        lib.bee_reset_error();
        lib.bee_add_local(t);
        Errors.checkError();
    }

    public boolean getLocal() throws BeeException
    {
        boolean flag;

        lib.bee_reset_error();
        flag = lib.bee_get_local(t);
        Errors.checkError();
        return flag;
    }

    public void setLocal(boolean local) throws BeeException
    {
        lib.bee_reset_error();
        lib.bee_set_local(t, local);
        Errors.checkError();
    }

    public void addEncrypt() throws BeeException
    {
        lib.bee_reset_error();
        lib.bee_add_encrypt(t);
        Errors.checkError();
    }

    public boolean getEncrypt() throws BeeException
    {
        boolean flag;

        lib.bee_reset_error();
        flag = lib.bee_get_encrypt(t);
        Errors.checkError();
        return flag;
    }

    public void setEncrypt(boolean encrypt) throws BeeException
    {
        lib.bee_reset_error();
        lib.bee_set_encrypt(t, encrypt);
        Errors.checkError();
    }

    public void addDecrypt() throws BeeException
    {
        lib.bee_reset_error();
        lib.bee_add_decrypt(t);
        Errors.checkError();
    }

    public boolean getDecrypt() throws BeeException
    {
        boolean flag;

        lib.bee_reset_error();
        flag = lib.bee_get_decrypt(t);
        Errors.checkError();
        return flag;
    }

    public void setDecrypt(boolean decrypt) throws BeeException
    {
        lib.bee_reset_error();
        lib.bee_set_decrypt(t, decrypt);
        Errors.checkError();
    }

    public void addWrap() throws BeeException
    {
        lib.bee_reset_error();
        lib.bee_add_wrap(t);
        Errors.checkError();
    }

    public boolean getWrap() throws BeeException
    {
        boolean flag;

        lib.bee_reset_error();
        flag = lib.bee_get_wrap(t);
        Errors.checkError();
        return flag;
    }

    public void setWrap(boolean wrap) throws BeeException
    {
        lib.bee_reset_error();
        lib.bee_set_wrap(t, wrap);
        Errors.checkError();
    }

    public void addWrapWithTrusted() throws BeeException
    {
        lib.bee_reset_error();
        lib.bee_add_wrap_with_trusted(t);
        Errors.checkError();
    }

    public boolean getWrapWithTrusted() throws BeeException
    {
        boolean flag;

        lib.bee_reset_error();
        flag = lib.bee_get_wrap_with_trusted(t);
        Errors.checkError();
        return flag;
    }

    public void setWrapWithTrusted(boolean wrap) throws BeeException
    {
        lib.bee_reset_error();
        lib.bee_set_wrap_with_trusted(t, wrap);
        Errors.checkError();
    }

    public void addUnwrap() throws BeeException
    {
        lib.bee_reset_error();
        lib.bee_add_unwrap(t);
        Errors.checkError();
    }

    public boolean getUnwrap() throws BeeException
    {
        boolean flag;

        lib.bee_reset_error();
        flag = lib.bee_get_unwrap(t);
        Errors.checkError();
        return flag;
    }

    public void setUnwrap(boolean unwrap) throws BeeException
    {
        lib.bee_reset_error();
        lib.bee_set_unwrap(t, unwrap);
        Errors.checkError();
    }


    public void addSign() throws BeeException
    {
        lib.bee_reset_error();
        lib.bee_add_sign(t);
        Errors.checkError();
    }

    public boolean getSign() throws BeeException
    {
        boolean flag;

        lib.bee_reset_error();
        flag = lib.bee_get_sign(t);
        Errors.checkError();
        return flag;
    }

    public void setSign(boolean sign) throws BeeException
    {
        lib.bee_reset_error();
        lib.bee_set_sign(t, sign);
        Errors.checkError();
    }

    public void addSignRecover() throws BeeException
    {
        lib.bee_reset_error();
        lib.bee_add_sign_recover(t);
        Errors.checkError();
    }

    public boolean getSignRecover() throws BeeException
    {
        boolean flag;

        lib.bee_reset_error();
        flag = lib.bee_get_sign_recover(t);
        Errors.checkError();
        return flag;
    }

    public void setSignRecover(boolean sign) throws BeeException
    {
        lib.bee_reset_error();
        lib.bee_set_sign_recover(t, sign);
        Errors.checkError();
    }

    public void addVerify() throws BeeException
    {
        lib.bee_reset_error();
        lib.bee_add_verify(t);
        Errors.checkError();
    }

    public boolean getVerify() throws BeeException
    {
        boolean flag;

        lib.bee_reset_error();
        flag = lib.bee_get_verify(t);
        Errors.checkError();
        return flag;
    }

    public void setVerify(boolean verify) throws BeeException
    {
        lib.bee_reset_error();
        lib.bee_set_verify(t, verify);
        Errors.checkError();
    }

    public void addVerifyRecover() throws BeeException
    {
        lib.bee_reset_error();
        lib.bee_add_verify_recover(t);
        Errors.checkError();
    }

    public boolean getVerifyRecover() throws BeeException
    {
        boolean flag;

        lib.bee_reset_error();
        flag = lib.bee_get_verify_recover(t);
        Errors.checkError();
        return flag;
    }

    public void setVerifyRecover(boolean verify) throws BeeException
    {
        lib.bee_reset_error();
        lib.bee_set_verify_recover(t, verify);
        Errors.checkError();
    }

    public void addNeverExtractable() throws BeeException
    {
        lib.bee_reset_error();
        lib.bee_add_never_extractable(t);
        Errors.checkError();
    }

    public boolean getNeverExtractable() throws BeeException
    {
        boolean flag;

        lib.bee_reset_error();
        flag = lib.bee_get_never_extractable(t);
        Errors.checkError();
        return flag;
    }

    public void setNeverExtractable(boolean neverExtractable) throws BeeException
    {
        lib.bee_reset_error();
        lib.bee_set_never_extractable(t, neverExtractable);
        Errors.checkError();
    }

    public void addExtractable() throws BeeException
    {
        lib.bee_reset_error();
        lib.bee_add_extractable(t);
        Errors.checkError();
    }

    public boolean getExtractable() throws BeeException
    {
        boolean flag;

        lib.bee_reset_error();
        flag = lib.bee_get_extractable(t);
        Errors.checkError();
        return flag;
    }

    public void setExtractable(boolean extractable) throws BeeException
    {
        lib.bee_reset_error();
        lib.bee_set_extractable(t, extractable);
        Errors.checkError();
    }

    public void addAlwaysSensitive() throws BeeException
    {
        lib.bee_reset_error();
        lib.bee_add_always_sensitive(t);
        Errors.checkError();
    }

    public boolean getAlwaysSensitive() throws BeeException
    {
        boolean flag;

        lib.bee_reset_error();
        flag = lib.bee_get_always_sensitive(t);
        Errors.checkError();
        return flag;
    }

    public void setAlwaysSensitive(boolean alwaysSensitive) throws BeeException
    {
        lib.bee_reset_error();
        lib.bee_set_always_sensitive(t, alwaysSensitive);
        Errors.checkError();
    }

    public void addSensitive() throws BeeException
    {
        lib.bee_reset_error();
        lib.bee_add_sensitive(t);
        Errors.checkError();
    }

    public boolean getSensitive() throws BeeException
    {
        boolean flag;

        lib.bee_reset_error();
        flag = lib.bee_get_sensitive(t);
        Errors.checkError();
        return flag;
    }

    public void setSensitive(boolean sensitive) throws BeeException
    {
        lib.bee_reset_error();
        lib.bee_set_sensitive(t, sensitive);
        Errors.checkError();
    }

    public void addTrusted() throws BeeException
    {
        lib.bee_reset_error();
        lib.bee_add_trusted(t);
        Errors.checkError();
    }

    public boolean getTrusted() throws BeeException
    {
        boolean flag;

        lib.bee_reset_error();
        flag = lib.bee_get_trusted(t);
        Errors.checkError();
        return flag;
    }

    public void setTrusted(boolean trusted) throws BeeException
    {
        lib.bee_reset_error();
        lib.bee_set_trusted(t, trusted);
        Errors.checkError();
    }

    public void addValue() throws BeeException
    {
        lib.bee_reset_error();
        lib.bee_add_value(t);
        Errors.checkError();
    }

    public byte[] getValue() throws BeeException
    {
        NativeLong[] len = new NativeLong[1];
        Pointer val;

        if (valueException != null)
            throw valueException;

        lib.bee_reset_error();
        val = lib.bee_get_value(t, len);
        if (val == null)
            throw new BeeException(lib.bee_get_last_error().intValue());

        return val.getByteArray(0, len[0].intValue());
    }

    public void setValue(byte[] v) throws BeeException
    {
        freeAttr(valueAttribute);
        valueAttribute = null;
        lib.bee_reset_error();

        Pointer val = copyByteArray(v);
        if (val != null)
            lib.bee_set_value(t, val, new NativeLong(v.length));
        Errors.checkError();

        valueAttribute = val;
        valueException = null;
    }

    protected void setValueException(BeeException e) {valueException = e;}

    public void addValueLen() throws BeeException
    {
        lib.bee_reset_error();
        lib.bee_add_value_len(t);
        Errors.checkError();
    }

    public int getValueLen() throws BeeException
    {
        NativeLong len;

        lib.bee_reset_error();
        len = lib.bee_get_value_len(t);
        if (len.intValue() == -1)
            throw new BeeException(lib.bee_get_last_error().intValue());

        return len.intValue();
    }

    public void setValueLen(int len) throws BeeException
    {
        freeAttr(valueLenAttribute);
        valueLenAttribute = null;
        lib.bee_reset_error();
        Pointer val = copyNativeLong(new NativeLong(len));
        if (val != null)
            lib.bee_set_value_len(t, val);
        Errors.checkError();

        valueLenAttribute = val;
    }

    public void addModulusBits() throws BeeException
    {
        lib.bee_reset_error();
        lib.bee_add_modulus_bits(t);
        Errors.checkError();
    }

    public int getModulusBits() throws BeeException
    {
        NativeLong bits;

        lib.bee_reset_error();
        bits = lib.bee_get_modulus_bits(t);
        if (bits.intValue() == -1)
            throw new BeeException(lib.bee_get_last_error().intValue());

        return bits.intValue();
    }

    public void setModulusBits(int bits) throws BeeException
    {
        freeAttr(modulusBitsAttribute);
        modulusBitsAttribute = null;
        lib.bee_reset_error();
        Pointer val = copyNativeLong(new NativeLong(bits));
        if (val != null)
            lib.bee_set_modulus_bits(t, val);
        Errors.checkError();

        modulusBitsAttribute = val;
    }

    public void addModulus() throws BeeException
    {
        lib.bee_reset_error();
        lib.bee_add_modulus(t);
        Errors.checkError();
    }

    public byte[] getModulus() throws BeeException
    {
        NativeLong[] len = new NativeLong[1];
        Pointer val;

        if (modulusException != null)
            throw modulusException;

        lib.bee_reset_error();
        val = lib.bee_get_modulus(t, len);
        if (val == null)
            throw new BeeException(lib.bee_get_last_error().intValue());

        return val.getByteArray(0, len[0].intValue());
    }

    public void setModulus(byte[] v) throws BeeException
    {
        freeAttr(modulusAttribute);
        modulusAttribute = null;
        lib.bee_reset_error();

        Pointer val = copyByteArray(v);
        if (val != null)
            lib.bee_set_modulus(t, val, new NativeLong(v.length));
        Errors.checkError();

        modulusException = null;
        modulusAttribute = val;
    }

    protected void setModulusException(BeeException e) {modulusException = e;}

    public void addPublicExponent() throws BeeException
    {
        lib.bee_reset_error();
        lib.bee_add_public_exponent(t);
        Errors.checkError();
    }

    public byte[] getPublicExponent() throws BeeException
    {
        NativeLong[] len = new NativeLong[1];
        Pointer val;

        if (publicExponentException != null)
            throw publicExponentException;

        lib.bee_reset_error();
        val = lib.bee_get_public_exponent(t, len);
        if (val == null)
            throw new BeeException(lib.bee_get_last_error().intValue());

        return val.getByteArray(0, len[0].intValue());
    }

    public void setPublicExponent(byte[] v) throws BeeException
    {
        freeAttr(publicExponentAttribute);
        publicExponentAttribute = null;
        lib.bee_reset_error();

        Pointer val = copyByteArray(v);
        if (val != null)
            lib.bee_set_public_exponent(t, val, new NativeLong(v.length));
        Errors.checkError();

        publicExponentAttribute = val;
        publicExponentException = null;
    }

    protected void setPublicExponentException(BeeException e) {publicExponentException = e;}

    public void addPrivateExponent() throws BeeException
    {
        lib.bee_reset_error();
        lib.bee_add_private_exponent(t);
        Errors.checkError();
    }

    public byte[] getPrivateExponent() throws BeeException
    {
        NativeLong[] len = new NativeLong[1];
        Pointer val;

        if (privateExponentException != null)
            throw privateExponentException;

        lib.bee_reset_error();
        val = lib.bee_get_private_exponent(t, len);
        if (val == null)
            throw new BeeException(lib.bee_get_last_error().intValue());

        return val.getByteArray(0, len[0].intValue());
    }

    public void setPrivateExponent(byte[] v) throws BeeException
    {
        freeAttr(privateExponentAttribute);
        privateExponentAttribute = null;
        lib.bee_reset_error();

        Pointer val = copyByteArray(v);
        if (val != null)
            lib.bee_set_private_exponent(t, val, new NativeLong(v.length));
        Errors.checkError();

        privateExponentAttribute = val;
        privateExponentException = null;
    }

    protected void setPrivateExponentException(BeeException e) {privateExponentException = e;}

    public void addPrime1() throws BeeException
    {
        lib.bee_reset_error();
        lib.bee_add_prime_1(t);
        Errors.checkError();
    }

    public byte[] getPrime1() throws BeeException
    {
        NativeLong[] len = new NativeLong[1];
        Pointer val;

        if (prime1Exception != null)
            throw prime1Exception;

        lib.bee_reset_error();
        val = lib.bee_get_prime_1(t, len);
        if (val == null)
            throw new BeeException(lib.bee_get_last_error().intValue());

        return val.getByteArray(0, len[0].intValue());
    }

    public void setPrime1(byte[] v) throws BeeException
    {
        freeAttr(prime1Attribute);
        prime1Attribute = null;
        lib.bee_reset_error();

        Pointer val = copyByteArray(v);
        if (val != null)
            lib.bee_set_prime_1(t, val, new NativeLong(v.length));
        Errors.checkError();

        prime1Attribute = val;
        prime1Exception = null;
    }

    protected void setPrime1Exception(BeeException e) {prime1Exception = e;}

    public void addPrime2() throws BeeException
    {
        lib.bee_reset_error();
        lib.bee_add_prime_2(t);
        Errors.checkError();
    }

    public byte[] getPrime2() throws BeeException
    {
        NativeLong[] len = new NativeLong[1];
        Pointer val;

        if (prime2Exception != null)
            throw prime2Exception;

        lib.bee_reset_error();
        val = lib.bee_get_prime_2(t, len);
        if (val == null)
            throw new BeeException(lib.bee_get_last_error().intValue());

        return val.getByteArray(0, len[0].intValue());
    }

    public void setPrime2(byte[] v) throws BeeException
    {
        freeAttr(prime2Attribute);
        prime2Attribute = null;
        lib.bee_reset_error();

        Pointer val = copyByteArray(v);
        if (val != null)
            lib.bee_set_prime_2(t, val, new NativeLong(v.length));
        Errors.checkError();

        prime2Attribute = val;
        prime2Exception = null;
    }

    protected void setPrime2Exception(BeeException e) {prime2Exception = e;}

    public void addExponent1() throws BeeException
    {
        lib.bee_reset_error();
        lib.bee_add_exponent_1(t);
        Errors.checkError();
    }

    public byte[] getExponent1() throws BeeException
    {
        NativeLong[] len = new NativeLong[1];
        Pointer val;

        if (exponent1Exception != null)
            throw exponent1Exception;

        lib.bee_reset_error();
        val = lib.bee_get_exponent_1(t, len);
        if (val == null)
            throw new BeeException(lib.bee_get_last_error().intValue());

        return val.getByteArray(0, len[0].intValue());
    }

    public void setExponent1(byte[] v) throws BeeException
    {
        freeAttr(exponent1Attribute);
        exponent1Attribute = null;
        lib.bee_reset_error();

        Pointer val = copyByteArray(v);
        if (val != null)
            lib.bee_set_exponent_1(t, val, new NativeLong(v.length));
        Errors.checkError();

        exponent1Attribute = val;
        exponent1Exception = null;
    }

    protected void setExponent1Exception(BeeException e) {exponent1Exception = e;}

    public void addExponent2() throws BeeException
    {
        lib.bee_reset_error();
        lib.bee_add_exponent_2(t);
        Errors.checkError();
    }

    public byte[] getExponent2() throws BeeException
    {
        NativeLong[] len = new NativeLong[1];
        Pointer val;

        if (exponent2Exception != null)
            throw exponent2Exception;

        lib.bee_reset_error();
        val = lib.bee_get_exponent_2(t, len);
        if (val == null)
            throw new BeeException(lib.bee_get_last_error().intValue());

        return val.getByteArray(0, len[0].intValue());
    }

    public void setExponent2(byte[] v) throws BeeException
    {
        freeAttr(exponent2Attribute);
        exponent2Attribute = null;
        lib.bee_reset_error();

        Pointer val = copyByteArray(v);
        if (val != null)
            lib.bee_set_exponent_2(t, val, new NativeLong(v.length));
        Errors.checkError();

        exponent2Attribute = val;
        exponent2Exception = null;
    }

    protected void setExponent2Exception(BeeException e) {exponent2Exception = e;}

    private void mergeBoolAttr(Template t, String attr)
    {
        boolean val;
        try {
            Method m = t.getClass().getMethod("get" + attr);
            try {val = ((Boolean) m.invoke(t)).booleanValue();}
            catch (Exception be) {return;}
            m = this.getClass().getMethod("set" + attr, boolean.class);
            m.invoke(this, val); 
        } catch (Exception e) {return;}
    }

    private void mergeBoolAttributes(Template t)
    {
        String[] boolAttrs = {"Token", "Private", "Modifiable", "Derive", "Local", "Encrypt",
            "Decrypt", "Wrap", "Unwrap", "Sign", "Verify", "NeverExtractable", "Extractable",
            "AlwaysSensitive", "Sensitive"};

        for (String a : boolAttrs)
            mergeBoolAttr(t, a);
    }

    private void mergeByteAttr(Template t, String attr)
    {
        byte[] val;
        try {
            Method m = t.getClass().getMethod("get" + attr);
            try {val = (byte[]) m.invoke(t);}
            catch (Exception be) {return;}
            m = this.getClass().getMethod("set" + attr, byte[].class);
            m.invoke(this, val);
        } catch (Exception e) {return;}
    }

    private void mergeByteAttributes(Template t)
    {
        String[] byteAttrs = {"Value", "Modulus", "PublicExponent", "PrivateExponent"};

        for (String a : byteAttrs)
            mergeByteAttr(t, a);
    }

    public void merge(Template t) throws BeeException
    {
        String s = null;
        Pkcs11Class c = null;
        KeyType k = null;
        boolean setIt;

        mergeBoolAttributes(t);
        mergeByteAttributes(t);

        setIt = true;
        try {s = t.getLabel();}
        catch (BeeException e) {setIt = false;}
        if (setIt)
            setLabel(s);

        setIt = true;
        try {s = t.getId();}
        catch (BeeException e) {setIt = false;}
        if (setIt)
            setId(s);

        setIt = true;
        try {c = t.getObjClass();}
        catch (BeeException e) {setIt = false;}
        if (setIt)
            setObjClass(c);

        setIt = true;
        try {k = t.getKeyType();}
        catch (BeeException e) {setIt = false;}
        if (setIt)
            setKeyType(k);
    }

    private String byteAttrToString(String attr)
    {
        byte[] val;
        int i;

        try {
            Method m = this.getClass().getMethod("get" + attr);
            val = (byte[]) m.invoke(this);
        }
        catch (InvocationTargetException be) {return be.getCause().getMessage();}
        catch (Exception e) {return "-";}
      
        return Utility.byteArrayToString(val);
    }

    private String stringAttrToString(String attr)
    {
        String val;

        try {
            Method m = this.getClass().getMethod("get" + attr);
            val = (String) m.invoke(this);
        }
        catch (InvocationTargetException be) {return be.getCause().getMessage();}
        catch (Exception e) {return "-";}

        return val;
    }

    private String boolAttrToString(String attr)
    {
        try {
            Method m = this.getClass().getMethod("get" + attr);
            try {
                Object str = m.invoke(this);
                return str.toString();
            } catch (Exception be) {
                return be.getMessage();
            }
        } catch (Exception e) {e.printStackTrace(); return "-";}
    }

    public String toString()
    {
        return "CKA_TOKEN: " + boolAttrToString("Token") + "\n" +
            "CKA_PRIVATE: " + boolAttrToString("Private") + "\n" +
            "CKA_MODIFIABLE: " + boolAttrToString("Modifiable") + "\n" +
            "CKA_LABEL: " + stringAttrToString("Label") + "\n" +
            "CKA_CLASS: " + boolAttrToString("ObjClass") + "\n" +
            "CKA_KEY_TYPE: " + boolAttrToString("KeyType") + "\n" +
            "CKA_ID: " + stringAttrToString("Id") + "\n" +
            "CKA_DERIVE: " + boolAttrToString("Derive") + "\n" +
            "CKA_LOCAL: " + boolAttrToString("Local") + "\n" +
            "CKA_ENCRYPT: " + boolAttrToString("Encrypt") + "\n" +
            "CKA_DECRYPT: " + boolAttrToString("Decrypt") + "\n" +
            "CKA_WRAP: " + boolAttrToString("Wrap") + "\n" +
            "CKA_UNWRAP: " + boolAttrToString("Unwrap") + "\n" +
            "CKA_SIGN: " + boolAttrToString("Sign") + "\n" +
            "CKA_VERIFY: " + boolAttrToString("Verify") + "\n" +
            "CKA_NEVER_EXTRACTABLE: " + boolAttrToString("NeverExtractable") + "\n" +
            "CKA_EXTRACTABLE: " + boolAttrToString("Extractable") + "\n" +
            "CKA_ALWAYS_SENSITIVE: " + boolAttrToString("AlwaysSensitive") + "\n" +
            "CKA_SENSITIVE: " + boolAttrToString("Sensitive") + "\n" +
            "CKA_VALUE: " + byteAttrToString("Value") + "\n" +
            "CKA_MODULUS_BITS: " + boolAttrToString("ModulusBits") + "\n" + 
            "CKA_MODULUS: " + byteAttrToString("Modulus") + "\n" +
            "CKA_PUBLIC_EXPONENT: " + byteAttrToString("PublicExponent") + "\n" +
            "CKA_PRIVATE_EXPONENT: " + byteAttrToString("PrivateExponent") + "\n";
    }
}
